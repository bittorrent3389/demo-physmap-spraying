PWD         := $(shell pwd) 
KVERSION    := $(shell uname -r)
KERNEL_DIR  := /lib/modules/4.1.20-11-default/build
#EXTRA_CFLAGS:= -I /lib/modules/4.1.15-8-default/kernel/security/keys
MODULE_NAME  = physmap
obj-m       := $(MODULE_NAME).o   

all:
	make -C $(KERNEL_DIR) M=$(PWD) modules
clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
