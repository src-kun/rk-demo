#include<linux/in.h>  
#include<linux/inet.h>  
#include<linux/socket.h>  
#include<net/sock.h>  
  
#include<linux/init.h>  
#include<linux/module.h>  
  
int myserver(void){  
	  
	struct socket *sock,*client_sock;  
	struct sockaddr_in s_addr;  
	unsigned short portnum=0x8870;  
	int ret=0;  
  
	memset(&s_addr,0,sizeof(s_addr));  
	s_addr.sin_family=AF_INET;  
	s_addr.sin_port=htons(portnum);  
	s_addr.sin_addr.s_addr=htonl(INADDR_ANY);  
  
  
	sock=(struct socket *)kmalloc(sizeof(struct socket),GFP_KERNEL);  
	client_sock=(struct socket *)kmalloc(sizeof(struct socket),GFP_KERNEL);  
  
	/*create a socket*/  
	ret=sock_create_kern(AF_INET, SOCK_STREAM,0,&sock);  
	if(ret){  
		printk("server:socket_create error!\n");  
	}  
	printk("server:socket_create ok!\n");  
  
	/*set the socket can be reused*/  
	int val=1;  
	ret= kernel_setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(char *)&val,sizeof(val));  
	if(ret){  
		printk("kernel_setsockopt error!!!!!!!!!!!\n");  
	}  
  
	/*bind the socket*/  
	ret=sock->ops->bind(sock,(struct sockaddr *)&s_addr,sizeof(struct sockaddr_in));  
	if(ret<0){  
		printk("server: bind error\n");  
		return ret;  
	}  
	printk("server:bind ok!\n");  
  
	/*listen*/  
	ret=sock->ops->listen(sock,10);  
	if(ret<0){  
		printk("server: listen error\n");  
		return ret;  
	}  
	printk("server:listen ok!\n");  
  
	//ret=sock->ops->accept(sock,client_sock,10);  
	ret = kernel_accept(sock,&client_sock,10);  
	if(ret<0){  
		printk("server:accept error!\n");  
		return ret;  
	}  
	  
	printk("server: accept ok, Connection Established\n");  
	  
	/*kmalloc a receive buffer*/  
	char *recvbuf=NULL;  
	recvbuf=kmalloc(1024,GFP_KERNEL);  
	if(recvbuf==NULL){  
		printk("server: recvbuf kmalloc error!\n");  
		return -1;  
	}  
	memset(recvbuf, 0, sizeof(recvbuf));  
	  
	/*receive message from client*/  
	struct kvec vec;  
	struct msghdr msg;  
	memset(&vec,0,sizeof(vec));  
	memset(&msg,0,sizeof(msg));  
	vec.iov_base=recvbuf;  
	vec.iov_len=1024;  
	ret=kernel_recvmsg(client_sock, &msg, &vec, 1, 1024, 0);  
	printk("receive message: %s\n", recvbuf);  
	printk("receive size=%d\n", ret);  
  
	sock_release(sock);  
	sock_release(client_sock);  
	return ret;  
}  
  
static int server_init(void){  
	printk("server init:\n");  
	myserver();  
	return 0;  
}         
  
static void server_exit(void){  
	printk("good bye\n");  
}  
  
module_init(server_init);  
module_exit(server_exit);  
  
MODULE_LICENSE("GPL");  