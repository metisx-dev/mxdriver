PWD := $(shell pwd)
BUILDSYSTEM_DIR := /lib/modules/$(shell uname -r)/build
KERNEL_VERSION := $(shell uname -r | cut -d '.' -f 1,2)

ifneq ($(KERNELRELEASE),)
ifneq ($(DEBUG),)
	EXTRA_CFLAGS += -DCONFIG_DEBUG_DMA
endif
	obj-m += mx_dma.o
	mx_dma-objs := init.o fops.o helper.o transfer.o queue_handler.o
	obj-m += cxl_$(KERNEL_VERSION)/
else
all:
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) modules
install: all
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) modules_install
	depmod -a
clean:
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) clean
	@/bin/rm -f *.ko modules.order *.mod.c *.o *.o.ur-safe .*.o.cmd
endif
