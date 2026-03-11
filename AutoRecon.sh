#!/bin/bash

set -e

echo "======================================"
echo "       AutoRecon Installer"
echo "======================================"

INSTALL_DIR="/opt/autorecon"
GO_VERSION="1.24.6"

echo "[+] Updating system"
sudo apt update

echo "[+] Installing system dependencies"
sudo apt install -y \
    git \
    python3 \
    python3-pip \
    python3-venv \
    masscan \
    nmap \
    wget \
    curl

echo "[+] Installing Go $GO_VERSION"

cd /tmp
wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz

sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz

echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc

export PATH=$PATH:/usr/local/go/bin
export PATH=$PATH:$HOME/go/bin

echo "[+] Go installed:"
go version

echo "[+] Installing ProjectDiscovery tools"

go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo "[+] Updating nuclei templates"
nuclei -update-templates

echo "[+] Clone Sublist3r repository"

cd $INSTALL_DIR
sudo git clone https://github.com/aboul3la/Sublist3r.git

echo "[+] Creating Python virtual environment"

python3 -m venv autorecon_env

source autorecon_env/bin/activate

echo "[+] Installing Python dependencies"

pip install --upgrade pip
pip install -r requirements.txt

deactivate

echo "[+] Creating global AutoRecon command"

sudo tee /usr/local/bin/AutoRecon > /dev/null <<EOF
#!/bin/bash
source $INSTALL_DIR/autorecon_env/bin/activate
python3 $INSTALL_DIR/AutoRecon.py "\$@"
EOF

sudo chmod +x /usr/local/bin/AutoRecon

echo "======================================"
echo "       Installation Completed"
echo "======================================"

echo ""
echo "Run AutoRecon using:"
echo ""
echo "AutoRecon"
echo ""
