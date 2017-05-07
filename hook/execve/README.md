1、操作系统的sys_call_table地址未必和我的一样,使用 cat /boot/System.map$(-uname -r) | grep sys_call_table 获取地址
2、执行系统自带函数hook不会出错，但是在执行shell文件时会出现错误
