#!/bin/bash
# Quick test script for eBPF bridge performance measurement

set -e

echo "==================================================================="
echo "eBPF Bridge Performance Quick Test"
echo "==================================================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: Please run as root (sudo)"
    exit 1
fi

# Check dependencies
echo "Checking dependencies..."
command -v python3 >/dev/null 2>&1 || { echo "Error: python3 not found"; exit 1; }

# Check Python packages
python3 -c "import bcc" 2>/dev/null || { echo "Error: BCC Python module not found. Install: sudo apt-get install python3-bpfcc"; exit 1; }
python3 -c "import pyroute2" 2>/dev/null || { echo "Error: pyroute2 not found. Install: pip3 install pyroute2"; exit 1; }

echo "✓ All dependencies satisfied"
echo ""

# Run benchmark
cd "$(dirname "$0")"
python3 benchmark.py

echo ""
echo "Test completed!"
