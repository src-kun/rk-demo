obj-m += hiddendirfile.o
hiddendirfile-objs := main.o util.o

all:
	make ARCH=x86_64 EXTRA_CFLAGS="-D_CONFIG_X86_64_ " -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
