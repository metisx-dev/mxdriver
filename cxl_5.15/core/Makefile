# SPDX-License-Identifier: GPL-2.0
obj-m += cxl_core.o

ccflags-y += -DDEFAULT_SYMBOL_NAMESPACE=CXL -I$(src)/..
cxl_core-y := bus.o
cxl_core-y += pmem.o
cxl_core-y += regs.o
cxl_core-y += memdev.o
