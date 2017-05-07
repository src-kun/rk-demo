obj-m += kerneldoor.o
kerneldoor-objs := main.o util.o icmp.o

all:
	make ARCH=x86_64 EXTRA_CFLAGS="-D_CONFIG_X86_64_ " -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
