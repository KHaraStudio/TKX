#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "    ████████╗██╗  ██╗██╗  ██╗"
echo "    ╚══██╔══╝██║ ██╔╝╚██╗██╔╝"
echo "       ██║   █████╔╝  ╚███╔╝ "
echo "       ██║   ██╔═██╗  ██╔██╗ "
echo "       ██║   ██║  ██╗██╔╝ ██╗"
echo "       ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝"
echo ""
echo "   TKX - SQL Injection Tool v1.1"
echo "   by KHara Xyra Taiz"
echo -e "${NC}"
echo "=========================================="

# Function to print status
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    print_warning "Running as root is not recommended!"
    sleep 2
fi

# Check Python
print_status "Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    print_error "Python3 not found!"
    
    # Detect package manager
    if command -v apt &> /dev/null; then
        print_status "Installing Python3 via apt..."
        apt update && apt install -y python3 python3-pip
    elif command -v pkg &> /dev/null; then
        print_status "Installing Python3 via pkg (Termux)..."
        pkg update && pkg install -y python python-pip
    elif command -v yum &> /dev/null; then
        print_status "Installing Python3 via yum..."
        yum install -y python3 python3-pip
    elif command -v pacman &> /dev/null; then
        print_status "Installing Python3 via pacman..."
        pacman -Syu --noconfirm python python-pip
    else
        print_error "Cannot detect package manager. Please install Python3 manually."
        exit 1
    fi
fi

# Verify Python installation
python3 --version
if [ $? -ne 0 ]; then
    print_error "Python3 installation failed!"
    exit 1
fi
print_success "Python3 is installed"

# Check pip
print_status "Checking pip installation..."
if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
    print_warning "pip not found, installing..."
    
    if command -v apt &> /dev/null; then
        apt install -y python3-pip
    elif command -v pkg &> /dev/null; then
        pkg install -y python-pip
    elif command -v yum &> /dev/null; then
        yum install -y python3-pip
    elif command -v pacman &> /dev/null; then
        pacman -S --noconfirm python-pip
    fi
fi

# Use pip3 if available, otherwise pip
if command -v pip3 &> /dev/null; then
    PIP_CMD="pip3"
elif command -v pip &> /dev/null; then
    PIP_CMD="pip"
else
    print_error "pip not found and installation failed!"
    exit 1
fi

print_success "pip is available as: $PIP_CMD"

# Install dependencies
print_status "Installing Python dependencies..."
$PIP_CMD install requests --quiet --disable-pip-version-check

if [ $? -eq 0 ]; then
    print_success "Dependencies installed successfully"
else
    print_error "Failed to install dependencies!"
    print_status "Trying alternative method..."
    python3 -m pip install requests --quiet
    if [ $? -ne 0 ]; then
        print_error "Still failed. Please install manually: pip install requests"
        exit 1
    fi
fi

# Make scripts executable
print_status "Setting up permissions..."
chmod +x tkx_cli.py tkx_autopwn.py tkx_report.py 2>/dev/null

# Create installation directory if needed
TKX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
print_status "TKX installed in: $TKX_DIR"

# Setup aliases
print_status "Setting up aliases..."

# Detect shell
CURRENT_SHELL=$(basename "$SHELL")

if [ "$CURRENT_SHELL" = "bash" ]; then
    SHELL_RC="$HOME/.bashrc"
elif [ "$CURRENT_SHELL" = "zsh" ]; then
    SHELL_RC="$HOME/.zshrc"
else
    print_warning "Unknown shell: $CURRENT_SHELL"
    SHELL_RC="$HOME/.bashrc"
fi

# Backup original shell rc
if [ -f "$SHELL_RC" ]; then
    cp "$SHELL_RC" "$SHELL_RC.backup.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
fi

# Add aliases to shell rc
if ! grep -q "alias tkx=" "$SHELL_RC" 2>/dev/null; then
    echo "" >> "$SHELL_RC"
    echo "# TKX - SQL Injection Tool" >> "$SHELL_RC"
    echo "alias tkx='python $TKX_DIR/tkx_cli.py'" >> "$SHELL_RC"
    echo "alias tkx-autopwn='python $TKX_DIR/tkx_autopwn.py'" >> "$SHELL_RC"
    print_success "Aliases added to $SHELL_RC"
else
    print_warning "Aliases already exist in $SHELL_RC"
fi

# Create symbolic links in /usr/local/bin (requires sudo)
if [ -w "/usr/local/bin" ] && [ "$EUID" -eq 0 ]; then
    print_status "Creating system-wide symbolic links..."
    ln -sf "$TKX_DIR/tkx_cli.py" /usr/local/bin/tkx 2>/dev/null
    ln -sf "$TKX_DIR/tkx_autopwn.py" /usr/local/bin/tkx-autopwn 2>/dev/null
    print_success "System-wide links created"
elif [ -w "/data/data/com.termux/files/usr/bin" ]; then
    # Termux specific
    print_status "Creating Termux symbolic links..."
    ln -sf "$TKX_DIR/tkx_cli.py" /data/data/com.termux/files/usr/bin/tkx 2>/dev/null
    ln -sf "$TKX_DIR/tkx_autopwn.py" /data/data/com.termux/files/usr/bin/tkx-autopwn 2>/dev/null
    print_success "Termux links created"
fi

# Create quick test script
cat > quick_test.sh << 'QTEOF'
#!/bin/bash
echo "Quick test of TKX installation..."
echo "Testing scanner on demo site..."
python tkx_cli.py -u "http://testphp.vulnweb.com/artists.php?artist=1" --no-crawl --max-payloads 2 --output simple
QTEOF
chmod +x quick_test.sh

# Create uninstall script
cat > uninstall.sh << 'UNEOF'
#!/bin/bash
echo "Uninstalling TKX..."
read -p "Are you sure? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Remove aliases
    sed -i '/alias tkx=/d' ~/.bashrc 2>/dev/null
    sed -i '/alias tkx-autopwn=/d' ~/.bashrc 2>/dev/null
    sed -i '/# TKX - SQL Injection Tool/d' ~/.bashrc 2>/dev/null
    
    # Remove symlinks
    rm -f /usr/local/bin/tkx /usr/local/bin/tkx-autopwn 2>/dev/null
    rm -f /data/data/com.termux/files/usr/bin/tkx 2>/dev/null
    rm -f /data/data/com.termux/files/usr/bin/tkx-autopwn 2>/dev/null
    
    echo "TKX removed. You can delete the folder manually."
else
    echo "Uninstall cancelled."
fi
UNEOF
chmod +x uninstall.sh

# Final message
echo ""
echo "=========================================="
echo -e "${GREEN}[+] TKX INSTALLATION COMPLETE!${NC}"
echo "=========================================="
echo ""
echo -e "${CYAN}QUICK START:${NC}"
echo "  tkx -u http://target.com/page?id=1"
echo "  tkx-autopwn http://target.com/page?id=1"
echo ""
echo -e "${CYAN}EXAMPLES:${NC}"
echo "  tkx -u http://testphp.vulnweb.com/artists.php?artist=1"
echo "  tkx -u http://target.com --no-crawl --max-payloads 10 --output json"
echo "  tkx-autopwn http://testphp.vulnweb.com/listproducts.php?cat=1"
echo ""
echo -e "${CYAN}AVAILABLE COMMANDS:${NC}"
echo "  ./quick_test.sh    - Test installation"
echo "  ./uninstall.sh     - Remove TKX"
echo ""
echo -e "${CYAN}DOCUMENTATION:${NC}"
echo "  Run 'tkx --help' for all options"
echo "  Check README.txt for detailed usage"
echo ""
echo -e "${YELLOW}⚠️  LEGAL DISCLAIMER:${NC}"
echo "  Use only on authorized systems you own"
echo "  or have explicit permission to test."
echo "=========================================="

# Reload shell configuration
if [ -f "$SHELL_RC" ]; then
    print_status "Reloading shell configuration..."
    source "$SHELL_RC" 2>/dev/null || . "$SHELL_RC" 2>/dev/null
fi

print_success "Ready to use! Restart terminal or run: source $SHELL_RC"
