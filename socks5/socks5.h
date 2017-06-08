/////////////////////////////////////////////////////////////////////
//////////////////////////////////////////
// Socks5 代理头文件，定义协议相关数据包结构
// 版本 0.1，作者 云舒
// 2007 年 1 月 9 日凌晨 1 点 15 分，GF 回家已经 11 天了。
// 2008 年 1 月 25 日修改，今年 GF 一直在我身边，哈哈
//
// 参考：
// http://www.rfc-editor.org/rfc/rfc1928.txt
// http://www.rfc-editor.org/rfc/rfc1929.txt
/////////////////////////////////////////////////////////////////////
//////////////////////////////////////////
#ifndef SOCKS5_H
#define SOCKS5_H
#define VERSION 0x05
#define CONNECT 0x01
#define IPV4 0x01
#define DOMAIN 0x03
#define IPV6 0x04
typedef struct _method_select_response // 协商方法服务器响应
{
	char version; // 服务器支持的 Socks 版本，0x04 或者 0x05
	char select_method;// 服务器选择的方法，0x00 为匿名，0x02 为密码认证
} METHOD_SELECT_RESPONSE;
typedef struct _method_select_request // 协商方法服务端请求
{
	char version; // 客户端支持的版本，0x04 或者 0x05
	char number_methods; // 客户端支持的方法的数量
	char methods[255]; // 客户端支持的方法类型，最多 255 个，0x00 为匿名，0x02 为密码认证
} METHOD_SELECT_REQUEST;
typedef struct _AUTH_RESPONSE // 用户密码认证服务端响应
{
	char version;// 版本，此处恒定为 0x01
	char result;// 服务端认证结果，0x00 为成功，其他均为失败
} AUTH_RESPONSE;
typedef struct _AUTH_REQUEST //用户密码认证客户端请求
{
	char version; // 版本，此处恒定为 0x01
	char name_len; // 第三个字段用户名的长度，一个字节，最长为 0xff
	char name[255]; // 用户名
	char pwd_len;// 第四个字段密码的长度，一个字节，最长为 0xff
	char pwd[255]; // 密码
} AUTH_REQUEST;
typedef struct _SOCKS5_RESPONSE // 连接真实主机，Socks 代理服务器响应
{
	char version; // 服务器支持的 Socks 版本，0x04 或者 0x05
	char reply; // 代理服务器连接真实主机的结果，0x00 成功
	char reserved; // 保留位，恒定位 0x00
	char address_type; // Socks 代理服务器绑定的地址类型，IP V4 为 0x01,IPV6 为 0x04，域名为 0x03
	char address_port[1]; // 如果 address_type 为域名，此处第一字节为域名长度，其后为域名本身，无 0 字符结尾,域名后为 Socks 代理服务器绑定端口
}SOCKS5_RESPONSE;
typedef struct _SOCKS5_REQUEST // 客户端请求连接真实主机
{
	char version; // 客户端支持的 Socks 版本，0x04 或者 0x05
	char cmd; // 客户端命令，CONNECT 为 0x01 ， BIND 为 0x02 ， UDP 为 0x03，一般为 0x01
	char reserved; // 保留位，恒定位 0x00
	char address_type; 
}SOCKS5_REQUEST;
#endif