#!/bin/bash

set -e

echo "======================================"
echo "       AutoRecon Installer"
echo "======================================"

INSTALL_DIR="/opt/autorecon"
GO_VERSION="1.26.1"

sudo chown -R $USER:$USER $INSTALL_DIR

# -------------------------------
# OS Detection
# -------------------------------
echo "[+] Detecting OS..."

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "[!] Cannot detect OS"
    exit 1
fi

case "$OS" in
    kali)
        echo "[+] Kali Linux detected"
        ;;
    ubuntu)
        echo "[+] Ubuntu detected"
        ;;
    debian)
        echo "[+] Debian detected"
        ;;
    *)
        echo "[!] Unsupported OS: $OS"
        echo "Supported: Kali / Ubuntu / Debian"
        exit 1
        ;;
esac

# -------------------------------
# Update system
# -------------------------------
echo "[+] Updating system"
sudo apt update

# -------------------------------
# Dependency check
# -------------------------------
echo "[+] Checking dependencies"

DEPS=(
git
python3
python3-pip
python3-venv
masscan
nmap
wget
curl
)

for pkg in "${DEPS[@]}"; do
    if dpkg -s "$pkg" &> /dev/null; then
        echo "[✓] $pkg already installed"
    else
        echo "[+] Installing $pkg"
        sudo apt install -y "$pkg"
    fi
done

sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which masscan)

# -------------------------------
# Install Go
# -------------------------------
if command -v go &> /dev/null; then
    echo "[✓] Go already installed"
    go version
else
    echo "[+] Installing Go $GO_VERSION"

    cd /tmp
    wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz

    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz

    echo "[+] Configuring PATH"

    sudo tee /etc/profile.d/golang.sh > /dev/null <<EOF
export PATH=\$PATH:/usr/local/go/bin
export PATH=\$PATH:\$HOME/go/bin
EOF

    export PATH=$PATH:/usr/local/go/bin
    export PATH=$PATH:$HOME/go/bin

    echo "[✓] Go installed"
    go version
fi

# -------------------------------
# Install ProjectDiscovery tools
# -------------------------------
echo "[+] Configuring Go environment"

export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

mkdir -p $GOPATH/bin

install_go_tool() {

    TOOL_NAME=$1
    GO_PATH=$2

    if command -v $TOOL_NAME &> /dev/null; then
        echo "[✓] $TOOL_NAME already installed"
        return
    fi

    echo "[+] Installing $TOOL_NAME"

    for i in {1..3}; do
        echo "[+] Attempt $i to install $TOOL_NAME"

        go install -v $GO_PATH@latest && break

        echo "[!] Retry installing $TOOL_NAME..."
        sleep 2
    done

    if [ -f "$GOPATH/bin/$TOOL_NAME" ]; then
        sudo cp "$GOPATH/bin/$TOOL_NAME" /usr/local/bin/
        echo "[✓] $TOOL_NAME installed"
    else
        echo "[✗] Failed to install $TOOL_NAME"
        exit 1
    fi
}

install_go_tool httpx github.com/projectdiscovery/httpx/cmd/httpx
install_go_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei

echo "[+] Updating nuclei templates"
nuclei -update-templates

# -------------------------------
# Clone Sublist3r
# -------------------------------
echo "[+] Checking Sublist3r"

if [ ! -d "$INSTALL_DIR/Sublist3r" ]; then
    cd $INSTALL_DIR
    sudo git clone https://github.com/aboul3la/Sublist3r.git
else
    echo "[✓] Sublist3r already present"
fi

# -------------------------------
# Python environment
# -------------------------------
echo "[+] Creating Python virtual environment"

cd $INSTALL_DIR

if [ ! -d "$INSTALL_DIR/autorecon_env" ]; then
    python3 -m venv autorecon_env
fi

source autorecon_env/bin/activate

echo "[+] Installing Python dependencies"

pip install --upgrade pip
pip install -r requirements.txt

deactivate

# -------------------------------
# Create global command
# -------------------------------
echo "[+] Creating global AutoRecon command"

sudo tee /usr/local/bin/AutoRecon > /dev/null <<EOF
#!/bin/bash
source $INSTALL_DIR/autorecon_env/bin/activate
exec python3 $INSTALL_DIR/AutoRecon.py
EOF

sudo chmod +x /usr/local/bin/AutoRecon

# -------------------------------
# Replace user in his home repository
# -------------------------------
cd ~

echo "======================================"
echo "       Installation Completed"
echo "======================================"

echo ""
echo "Run AutoRecon using:"
echo ""
echo "AutoRecon"
echo ""