#!/bin/bash

set -euo pipefail

HAS_CXL=false
if [[ -e /sys/firmware/acpi/tables/CEDT ]]; then
    HAS_CXL=true
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

if [[ "$HAS_CXL" == "true" ]]; then
	echo "[INFO] Installing xcena_set_devdax_perm for CXL support..."
	install -m 0755 config/xcena_set_devdax_perm /usr/local/sbin/xcena_set_devdax_perm
	install -m 0644 config/99-xcena_set_devdax_perm.rules /etc/udev/rules.d/99-xcena_set_devdax_perm.rules
	sudo udevadm control --reload-rules
	echo "[INFO] xcena_set_devdax_perm installation completed."
fi

if command -v update-initramfs >/dev/null 2>&1; then
	echo "[INFO] update-initramfs found, updating initramfs..."
	update-initramfs -u
else
	echo "[INFO] update-initramfs not found, skipping initramfs update."
fi
