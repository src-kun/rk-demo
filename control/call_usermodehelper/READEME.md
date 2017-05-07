call_usermodehelper 执行用户空间函数会随着调用的结束而终止，不能创建常驻进程
本demo执行成功后会在root下创建一个door文件夹，返回0代表执行成功

run:
	./quick
