MODULE_NAME := tdxutils
KDIR := /lib/modules/$(shell uname -r)/build

$(MODULE_NAME)-y := tdxutils_main.o tdxutils_mwait.o tdxutils_pmc.o tdxutils_access_monitor.o
obj-m := $(MODULE_NAME).o

default:
	$(MAKE) -C $(KDIR) M='$(PWD)' modules -j$(shell nproc)

clean:
	$(MAKE) -C $(KDIR) M='$(PWD)' clean
