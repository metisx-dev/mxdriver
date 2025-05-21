#!/bin/bash

UPDATE_PATH=/lib/modules/$(uname -r)/updates

for dir in "$UPDATE_PATH"/cxl_*; do
    if [[ -d "$dir" ]]; then
        rm -rf "$dir"
    fi
done

rm -f "$UPDATE_PATH"/mx_dma.ko

depmod -a
