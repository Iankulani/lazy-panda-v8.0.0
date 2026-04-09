#!/bin/bash
# Lazy Panda v8.0.0 - Linux/Mac Installation Script
# Author: Ian Carter Kulani

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}         ${GREEN}LAZY PANDA v8.0.0 - Installation Script${NC}          ${BLUE}║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check Python version
echo -e "${YELLOW}[1/6] Checking Python version...${NC}"
if command -v python3 &>/dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    if [[ $(echo "$PYTHON_VERSION >= 3.7" | bc) -eq 1 ]]; then
        echo -e "${GREEN}✓ Python $PYTHON_VERSION found${NC}"
    else
        echo -e "${RED}✗ Python 3.7+ required (found $PYTHON_VERSION)${NC}"
        exit 1
    fi
else
    echo -e "${RED}✗ Python3 not found. Please install Python 3.7 or higher${NC}"
    exit 1
fi

# Check pip
echo -e "\n${YELLOW}[2/6] Checking pip...${NC}"
if command -v pip3 &>/dev/null; then
    echo -e "${GREEN}✓ pip3 found${NC}"
else
    echo -e "${RED}✗ pip3 not found. Installing...${NC}"
    python3 -m ensurepip --upgrade
fi

# Create virtual environment (optional)
echo -e "\n${YELLOW}[3/6] Setting up virtual environment...${NC}"
read -p "Create virtual environment? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    python3 -m venv lazy_panda_env
    source lazy_panda_env/bin/activate
    echo -e "${GREEN}✓ Virtual environment created and activated${NC}"
else
    echo -e "${BLUE}ℹ Skipping virtual environment${NC}"
fi

# Install dependencies
echo -e "\n${YELLOW}[4/6] Installing Python dependencies...${NC}"
if [ -f "requirements.txt" ]; then
    pip3 install --upgrade pip
    pip3 install -r requirements.txt
    echo -e "${GREEN}✓ Dependencies installed${NC}"
else
    echo -e "${RED}✗ requirements.txt not found${NC}"
    exit 1
fi

# Install system tools (Linux only)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo -e "\n${YELLOW}[5/6] Checking system tools...${NC}"
    
    if command -v apt-get &>/dev/null; then
        sudo apt-get update
        sudo apt-get install -y iputils-ping traceroute net-tools
        echo -e "${GREEN}✓ System tools installed${NC}"
    elif command -v yum &>/dev/null; then
        sudo yum install -y iputils traceroute net-tools
        echo -e "${GREEN}✓ System tools installed${NC}"
    else
        echo -e "${YELLOW}⚠ Please ensure ping, traceroute, and netstat are installed${NC}"
    fi
fi

# Create directories
echo -e "\n${YELLOW}[6/6] Creating directories...${NC}"
mkdir -p .lazy_panda
mkdir -p lazy_panda_reports
mkdir -p lazy_panda_reports/scans
mkdir -p lazy_panda_reports/blocked
mkdir -p lazy_panda_reports/graphics
mkdir -p lazy_panda_temp
echo -e "${GREEN}✓ Directories created${NC}"

# Create launcher script
echo -e "\n${YELLOW}Creating launcher script...${NC}"
cat > lazy_panda_launcher.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
if [ -d "lazy_panda_env" ]; then
    source lazy_panda_env/bin/activate
fi
python3 lazy_panda.py "$@"
EOF

chmod +x lazy_panda_launcher.sh
echo -e "${GREEN}✓ Launcher script created: ./lazy_panda_launcher.sh${NC}"

# Final message
echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}              ${GREEN}INSTALLATION COMPLETED SUCCESSFULLY!${NC}               ${GREEN}║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}To start Lazy Panda:${NC}"
echo -e "  ${BLUE}./lazy_panda_launcher.sh${NC}"
echo ""
echo -e "${YELLOW}Or directly:${NC}"
echo -e "  ${BLUE}python3 lazy_panda.py${NC}"
echo ""
echo -e "${YELLOW}For Discord bot integration:${NC}"
echo -e "  1. Create a bot at https://discord.com/developers/applications"
echo -e "  2. Run setup and configure Discord token"
echo ""