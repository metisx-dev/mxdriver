#!/bin/bash

make clean
make install -j$(nproc)
depmod -a

kernel_version=$(uname -r)
mx_dma_path=$(find /lib/modules/${kernel_version}/ -type f -name "mx_dma.ko" 2>/dev/null)

if [ -n "$mx_dma_path" ]; then
    mx_dma_dir=$(dirname "$mx_dma_path")
    echo "Found mx_dma.ko at directory: $mx_dma_dir"
else
    echo "mx_dma.ko not found."
    exit
fi

sed -i '/cxl_/d' /etc/modules
sed -i '/mx_dma/d' /etc/modules
find "$mx_dma_dir" -type f -name "*.ko" >>/etc/modules
