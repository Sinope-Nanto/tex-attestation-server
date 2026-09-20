# SPDX-License-Identifier: GPL-2.0
#
# Out-of-tree build of the TDX verifier helper.
#
#   make          # build tdx_verify.ko
#   make load     # insmod and show /dev/tdx_verify
#   make unload   # rmmod
#   make clean

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

obj-m := tdx_verify.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load: all
	-insmod $(PWD)/tdx_verify.ko
	@ls -l /dev/tdx_verify 2>/dev/null || true

unload:
	-rmmod tdx_verify

.PHONY: all clean load unload
