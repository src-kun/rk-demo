
    /*client.c*/  
    #include<linux/in.h>  
    #include<linux/inet.h>  
    #include<linux/socket.h>  
    #include<net/sock.h>  
      
    #include<linux/init.h>  
    #include<linux/module.h>  
      
    int myclient(void){  
            struct socket *sock;  
            struct sockaddr_in s_addr;  
            unsigned short portnum=8080;  
            int ret=0;  
      
            memset(&s_addr,0,sizeof(s_addr));  
            s_addr.sin_family=AF_INET;  
            s_addr.sin_port=htons(portnum);  
           
            s_addr.sin_addr.s_addr=in_aton("192.168.189.159"); /*server ip is 192.168.209.134*/  
            sock=(struct socket *)kmalloc(sizeof(struct socket),GFP_KERNEL);  
      
            /*create a socket*/  
            ret=sock_create_kern(AF_INET, SOCK_STREAM,0,&sock);  
            if(ret<0){  
                    printk("client:socket create error!\n");  
                    return ret;  
            }  
            printk("client: socket create ok!\n");  
      
            /*connect server*/  
            ret=sock->ops->connect(sock,(struct sockaddr *)&s_addr, sizeof(s_addr),0);  
            if(ret!=0){  
                    printk("client:connect error!\n");  
                    return ret;  
            }  
            printk("client:connect ok!\n");  
      
            /*kmalloc sendbuf*/  
            char *sendbuf=NULL;  
            sendbuf=kmalloc(1024,GFP_KERNEL);  
            if(sendbuf==NULL){  
                    printk("client: sendbuf kmalloc error!\n");  
                    return -1;  
            }  
            memset(sendbuf,1,1024);          
              
        struct kvec vec;  
            struct msghdr msg;  
      
            vec.iov_base=sendbuf;  
            vec.iov_len=1024;  
      
            memset(&msg,0,sizeof(msg));  
      
            ret=kernel_sendmsg(sock,&msg,&vec,1,1024); /*send message */  
            if(ret<0){  
                    printk("client: kernel_sendmsg error!\n");  
                    return ret;  
            }else if(ret!=1024){  
                    printk("client: ret!=1024");  
            }  
            printk("client:send ok!\n");  
      
            return ret;  
    }  
      
    static int client_init(void){  
            printk("client:init\n");  
            return (myclient());  
    }  
      
    static void client_exit(void){  
            printk("client exit!\n");  
    }  
      
    module_init(client_init);  
    module_exit(client_exit);  
    MODULE_LICENSE("GPL"); 