#!/bin/bash

rm -f /lib/modules/$(uname -r)/updates/mx_dma.ko
rm /etc/modules-load.d/mx_dma.conf

depmod -a

if [[ -f /usr/local/sbin/xcena_set_devdax_perm ]]; then
	echo "[INFO] Removing xcena_set_devdax_perm..."
	rm -f /usr/local/sbin/xcena_set_devdax_perm
	rm -f /etc/udev/rules.d/99-xcena_set_devdax_perm.rules
	udevadm control --reload-rules
	echo "[INFO] xcena_set_devdax_perm removal completed."
fi
