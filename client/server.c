#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/shm.h>

#define MYPORT  8887
#define QUEUE   20
#define BUFFER_SIZE 1024

char console[BUFFER_SIZE] = {0};

int main()
{
    ///定义sockfd
    int server_sockfd = socket(AF_INET,SOCK_STREAM, 0);

    ///定义sockaddr_in
    struct sockaddr_in server_sockaddr;
    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_port = htons(MYPORT);
    server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    ///bind，成功返回0，出错返回-1
    if(bind(server_sockfd,(struct sockaddr *)&server_sockaddr,sizeof(server_sockaddr))==-1)
    {
        perror("bind");
        exit(1);
    }

    ///listen，成功返回0，出错返回-1
    if(listen(server_sockfd,QUEUE) == -1)
    {
        perror("listen");
        exit(1);
    }

    ///客户端套接字
    char ret[BUFFER_SIZE];
	char cmd[BUFFER_SIZE];
	char tmp[BUFFER_SIZE];
	
    struct sockaddr_in client_addr;
    socklen_t length = sizeof(client_addr);

    ///成功返回非负描述字，出错返回-1
    int conn = accept(server_sockfd, (struct sockaddr*)&client_addr, &length);
    if(conn<0)
    {
        perror("connect");
        exit(1);
    }

	
	
    while(1)
    {
		int len;
		if(!strlen(console))
		{
			len = recv(conn, console, sizeof(console),0);
		}
		
		printf("%s", console);
		memset(cmd,0,sizeof(cmd));
		/*等待用户输入命令*/
		while(fgets(cmd, sizeof(cmd), stdin) != NULL)
		{
			send(conn, cmd, sizeof(cmd), 0);
			
			memset(ret,0,sizeof(ret));
			recv(conn, ret, sizeof(ret),0);
			break;
		}
		
		/*
		当输入的命令与接收数据相等时，需要再次recv取出命令执行结果和控制台()字符串
		*/
		 //printf("ret: %s cmd: %s\n", ret, cmd);
		 while(strcmp(cmd,"\n") && !strcmp(cmd, ret))
		 {
			memset(tmp, 0, sizeof(tmp));
			len = recv(conn, tmp, sizeof(tmp),0);
			
			if(strcmp(console, tmp) == 0)
			{
				break;
			}
			if(strcmp(ret,"exit\n")==0)
			{
				exit(1);
			}
			printf("%s", tmp);
		 }
		          
    }
    close(conn);
    close(server_sockfd);
    return 0;
}