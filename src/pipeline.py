import os
import time
import threading
import pandas as pd
from datetime import datetime
from subprocess import Popen
import xgboost
import signal
import joblib
import pexpect  # giữ lại nếu bạn dùng suricatasc theo dạng shell

# Configuration
INTERFACE = "ens33"
MODEL_PATH = "/etc/suricata/model/random_forest_model_balanced.pkl"  # Cập nhật đường dẫn tới mô hình
CSV_DIR = "traffic-csv"
BLACKLIST_FILE = "/etc/suricata/rules/blacklist.txt"
FLOW_TIMEOUT = 3.0

# Load model
model = joblib.load(MODEL_PATH)

# Labels
MALICIOUS_LABELS = {
    0: 'BENIGN',
    1: 'Bot',
    2: 'Brute Force',
    3: 'DDoS',
    4: 'DoS',
    5: 'Heartbleed',
    6: 'Infiltration',
    7: 'Port Scan',
    8: 'Web Attack'
}

# Required columns and their data types
FEATURE_COLUMNS = {
    'flow_duration': 'float32',
    'bwd_pkts_s': 'float32',
    'bwd_pkt_len_max': 'float32',
    'bwd_pkt_len_mean': 'float32',
    'bwd_pkt_len_std': 'float32',
    'pkt_len_max': 'float32',
    'pkt_len_mean': 'float32',
    'pkt_len_std': 'float32',
    'pkt_len_var': 'float32',
    'flow_iat_mean': 'float32',
    'flow_iat_max': 'float32',
    'flow_iat_min': 'float32',
    'flow_iat_std': 'float32',
    'fwd_iat_tot': 'float32',
    'fwd_iat_max': 'float32',
    'fwd_iat_mean': 'float32',
    'fwd_iat_std': 'float32',
    'bwd_iat_max': 'float32',
    'bwd_iat_mean': 'float32',
    'bwd_iat_std': 'float32',
    'fin_flag_cnt': 'int32',
    'psh_flag_cnt': 'int32',
    'ack_flag_cnt': 'int32',
    'pkt_size_avg': 'float32',
    'init_fwd_win_byts': 'int32',
    'active_min': 'float32',
    'active_mean': 'float32',
    'idle_max': 'float32',
    'idle_min': 'float32',
    'idle_mean': 'float32',
    'idle_std': 'float32',
    'bwd_seg_size_avg': 'float32'
}

# IP blacklist set (in-memory)
blacklisted_ips = set()
blacklist_lock = threading.Lock()

# Blacklist IP via Suricata and write to file
def add_ip_to_blacklist(ip):
    with blacklist_lock:
        if ip in blacklisted_ips:
            print(f"[BLACKLIST] {ip} already blacklisted.")
            return

        try:
            # Ghi IP vào file blacklist
            with open(BLACKLIST_FILE, "a") as f:
                f.write(f"{ip}\n")

            # Thêm IP vào danh sách đen trong bộ nhớ
            blacklisted_ips.add(ip)
            print(f"[BLACKLIST] IP {ip} has been added to {BLACKLIST_FILE}.")

            # Reload Suricata rules
            cmds = [
                "sudo suricatasc -c 'reload-rules'"
            ]
            for cmd in cmds:
                pexpect.run(cmd)

        except Exception as e:
            print(f"[ERROR] Failed to blacklist {ip}: {e}")

# Hàm xử lý và dự đoán
def process_and_predict(csv_file=None, input_data=None, source_ips=None):
    try:
        # Nếu có file CSV, xử lý file CSV
        if csv_file:
            # Đọc file CSV
            df = pd.read_csv(csv_file)

            # Lấy địa chỉ IP nguồn (nếu không tồn tại, sử dụng giá trị mặc định là "10.81.50.100")
            source_ips = df.get("src_ip", pd.Series(["10.81.50.100"] * len(df)))

            # Kiểm tra và thêm các cột bị thiếu với giá trị mặc định
            for column in FEATURE_COLUMNS.keys():
                if column not in df.columns:
                    print(f"[WARNING] Missing column: {column}. Filling with default value 0.")
                    df[column] = 0  # Thêm cột bị thiếu với giá trị mặc định

            # Lọc và sắp xếp các cột theo thứ tự mà mô hình yêu cầu
            input_data = df[list(FEATURE_COLUMNS.keys())].astype(FEATURE_COLUMNS)

        # Nếu không có dữ liệu đầu vào, báo lỗi
        if input_data is None or source_ips is None:
            print("[ERROR] No input data or source IPs provided.")
            return

        # Dự đoán bằng mô hình
        predictions = model.predict(input_data)

        # Xử lý kết quả dự đoán
        for idx, prediction in enumerate(predictions):
            src_ip = source_ips.iloc[idx] if idx < len(source_ips) else "10.81.50.100"
            if src_ip == "0.0.0.0":
                src_ip = "10.81.50.100"
            if prediction in MALICIOUS_LABELS:
                attack_type = MALICIOUS_LABELS[prediction]
                print(f"[ALERT] 🚨 Detected {attack_type} from IP: {src_ip}")
                add_ip_to_blacklist(src_ip)
            else:
                print(f"[INFO] ✅ Benign traffic from IP: {src_ip}")

    except Exception as e:
        print(f"[ERROR] Processing or prediction failed: {e}")

# Modified: Start CICFlowMeter for exactly 60 seconds, then stop it
def run_cicflowmeter_timed(interface, output_csv, duration=60):
    try:
        process = Popen(["cicflowmeter", "-i", interface, "-c", output_csv])
        time.sleep(duration)
        process.send_signal(signal.SIGINT)
        process.wait(timeout=10)
    except Exception as e:
        print(f"[ERROR] CICFlowMeter failed: {e}")
        if process:
            process.kill()

# Traffic capture loop
def capture_and_process_traffic():
    while True:
        try:
            start_time = datetime.now()
            timestamp = start_time.strftime("%H-%M-%S-%d-%m-%Y")
            output_csv = os.path.join(CSV_DIR, f"{timestamp}.csv")

            print(f"[CAPTURE] Capturing on {INTERFACE}, saving to {output_csv}...")
            run_cicflowmeter_timed(INTERFACE, output_csv, duration=60)

            print(f"[PROCESS] Analyzing {output_csv}...")
            process_and_predict(csv_file=output_csv)
        except Exception as e:
            print(f"[ERROR] Traffic capture or processing failed: {e}")

# Main
if __name__ == "__main__":
    os.makedirs(CSV_DIR, exist_ok=True)
    thread = threading.Thread(target=capture_and_process_traffic, daemon=True)
    thread.start()
    while True:
        time.sleep(1)