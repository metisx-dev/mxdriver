#!/bin/bash

rm -f /lib/modules/$(uname -r)/updates/mx_dma.ko
rm /etc/modules-load.d/mx_dma.conf

depmod -a
