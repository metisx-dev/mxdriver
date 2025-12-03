#!/bin/bash

set -euo pipefail

if [[ -e /sys/firmware/acpi/tables/CEDT ]]; then
    echo "[INFO] CEDT found – building **with** CXL support."
    MAKEVAR=""
else
    echo "[INFO] CEDT not found – building **without** CXL (WO_CXL=1)."
    MAKEVAR="WO_CXL=1"
fi

make $MAKEVAR clean
make $MAKEVAR -j"$(nproc)" install

echo mx_dma | tee /etc/modules-load.d/mx_dma.conf
depmod -a

if command -v update-initramfs >/dev/null 2>&1; then
	echo "[INFO] update-initramfs found, updating initramfs..."
	update-initramfs -u
else
	echo "[INFO] update-initramfs not found, skipping initramfs update."
fi
