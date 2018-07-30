### Demo:
	systemcall demo根据系统修改Makefile参数
	make ARCH=target1 EXTRA_CFLAGS="target2 " -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	Supported targets1:
		x86_64
		x86	

	Supported targets2:
		-D_CONFIG_X86_ 
		-D_CONFIG_X86_64_
### Make:
	测试完整rootkit
		cp Makefile.rk Makefile
		make
	测试所有rootkit demo:
		./Makefile.all
### clean:
	./clean



