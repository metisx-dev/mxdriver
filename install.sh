#!/bin/bash

make clean
make install -j$(nproc)
depmod -a
