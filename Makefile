# Top-level Makefile for the vnet-driver project
# For now we only build the hello_vnet module in src/


KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

obj-m += hello_vnet.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD)/src modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/src clean
