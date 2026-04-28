#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  pull-tools.sh  —  Download all Docker images for PRAWL
#  Run this ONCE before using advanced scans.
#  Requires: Docker running on Linux/macOS
# ═══════════════════════════════════════════════════════════════

echo ""
echo " PRAWL — Pulling vulnerability tool Docker images"
echo " ═══════════════════════════════════════════════════"
echo ""

# Check Docker is running
if ! docker info >/dev/null 2>&1; then
    echo " ERROR: Docker is not running."
    echo " Please start Docker daemon and try again."
    exit 1
fi

echo " [1/3] Pulling Nmap ..."
if ! docker pull instrumentisto/nmap; then
    echo " WARNING: Nmap pull failed."
else
    echo " ✓ Nmap ready."
fi

echo ""
echo " [2/3] Pulling Nikto ..."
if ! docker pull frapsoft/nikto; then
    echo " WARNING: Nikto pull failed."
else
    echo " ✓ Nikto ready."
fi

echo ""
echo " [3/4] Pulling SQLMap ..."
if ! docker pull secsi/sqlmap; then
    echo " WARNING: SQLMap pull failed."
else
    echo " ✓ SQLMap ready."
fi

echo ""
echo " [4/4] Pulling WhatWeb ..."
if ! docker pull secsi/whatweb; then
    echo " WARNING: WhatWeb pull failed."
else
    echo " ✓ WhatWeb ready."
fi

echo ""
echo " ─────────────────────────────────────────────────────"
echo " All images downloaded. You can now use Advanced Scans."
echo " ─────────────────────────────────────────────────────"
echo ""
