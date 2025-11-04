#!/bin/bash
# Install dependencies for eBPF bridge benchmark

echo "Installing eBPF Bridge Benchmark Dependencies"
echo "=============================================="

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS"
    exit 1
fi

echo "Detected OS: $OS"

case $OS in
    ubuntu|debian)
        echo "Installing for Ubuntu/Debian..."
        
        # Update package list
        sudo apt-get update
        
        # Install BCC tools and Python bindings
        sudo apt-get install -y \
            python3-bpfcc \
            bpfcc-tools \
            linux-headers-$(uname -r)
        
        # Install Python packages
        sudo apt-get install -y \
            python3-pip \
            python3-pyroute2 \
            python3-netaddr
        
        # Optional: iperf3 for throughput testing
        sudo apt-get install -y iperf3
        
        echo "✓ Installation completed for Ubuntu/Debian"
        ;;
        
    fedora|rhel|centos)
        echo "Installing for Fedora/RHEL/CentOS..."
        
        # Install BCC
        sudo dnf install -y \
            bcc-tools \
            python3-bcc \
            kernel-devel
        
        # Install Python packages
        sudo pip3 install pyroute2 netaddr
        
        # Optional: iperf3
        sudo dnf install -y iperf3
        
        echo "✓ Installation completed for Fedora/RHEL/CentOS"
        ;;
        
    arch)
        echo "Installing for Arch Linux..."
        
        sudo pacman -S --noconfirm \
            bcc \
            bcc-tools \
            python-bcc \
            linux-headers
        
        sudo pip3 install pyroute2 netaddr
        
        # Optional: iperf3
        sudo pacman -S --noconfirm iperf3
        
        echo "✓ Installation completed for Arch Linux"
        ;;
        
    *)
        echo "Unsupported OS: $OS"
        echo "Please install manually:"
        echo "  - BCC (https://github.com/iovisor/bcc/blob/master/INSTALL.md)"
        echo "  - Python packages: pip3 install pyroute2 netaddr"
        exit 1
        ;;
esac

echo ""
echo "Verifying installation..."
python3 -c "from bcc import BPF; import pyroute2; import netaddr; print('✓ All Python modules OK')" || {
    echo "✗ Verification failed"
    exit 1
}

echo ""
echo "=============================================="
echo "Installation successful!"
echo ""
echo "You can now run the benchmark:"
echo "  cd bridge"
echo "  sudo ./quick_test.sh"
echo "=============================================="
