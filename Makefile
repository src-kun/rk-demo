KERNEL_DIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

obj-m := netfilter_test.o

default:
	make -C $(KERNEL_DIR) M=$(PWD) modules 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
