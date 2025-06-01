#!/bin/bash

echo "---------------------------------------------"
echo "Installing Suricata..."
echo "---------------------------------------------"
sudo apt-get update
sudo apt-get install -y suricata

echo "---------------------------------------------"
echo "Backing up existing Suricata config files..."
echo "---------------------------------------------"
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak
sudo cp /etc/suricata/classification.config /etc/suricata/classification.config.bak
sudo cp /etc/suricata/threshold.config /etc/suricata/threshold.config.bak

echo "---------------------------------------------"
echo "Copying new config files..."
echo "---------------------------------------------"
sudo cp config/suricata.yaml /etc/suricata/
sudo cp config/classification.config /etc/suricata/

echo "---------------------------------------------"
echo "Copying custom rules..."
echo "---------------------------------------------"
sudo cp config/snids.rules /etc/suricata/rules/
sudo cp config/blacklist.txt /etc/suricata/rules/

echo "---------------------------------------------"
echo "Setting correct permissions for Suricata rules..."
echo "---------------------------------------------"
sudo chmod 644 /etc/suricata/rules/*.rules
sudo chmod 644 /etc/suricata/rules/blacklist.txt

echo "---------------------------------------------"
echo "Restarting Suricata..."
echo "---------------------------------------------"
sudo systemctl restart suricata
sudo systemctl stop suricata

echo "---------------------------------------------"
echo "Copying snids.py pipeline.py to Desktop..."
echo "---------------------------------------------"
cp src/snids.py ~/Desktop/
cp src/pipeline.py

echo "---------------------------------------------"
echo "Creating model directory and copying model files..."
echo "---------------------------------------------"
sudo mkdir -p /etc/suricata/model/
sudo cp src/model/random_forest_model_balanced.pkl /etc/suricata/model/
sudo cp src/model/xgboost_model_4class.pkl /etc/suricata/model/

echo "✅ Setup complete!"
echo "➡️  Suricata is configured for use with Machine Learning."
echo "📌 Please ensure Python and required dependencies are installed."
echo "🔁 Use 'sudo systemctl start/restart/stop suricata' to manage Suricata."
echo "🚀 Run snids.py or pipeline.py from the Desktop to launch detection logic."
