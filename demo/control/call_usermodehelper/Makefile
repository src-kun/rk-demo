obj-m += call_usermodehelper.o

CUR_PATH:=$(shell pwd)
LINUX_KERNEL_PATH:=/lib/modules/$(shell uname -r)/build
all:
	make -C $(LINUX_KERNEL_PATH) M=$(CUR_PATH) modules
clean:
	make -C $(LINUX_KERNEL_PATH) M=$(CUR_PATH) clean
