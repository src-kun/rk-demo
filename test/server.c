#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#define MAXPENDING 5    /* Max connection requests */

#define MAX_USER 10
#define BUFF_SIZE 1024
#define AUTH_CODE 0x02
#define TIME_OUT 6000000

int socks5 = 0;

void Die(char *mess) { perror(mess);  }


// void forward(void *client_sock) {
	
	// int sock = *(int *)client_sock;
	// char buffer[BUFF_SIZE] = {0};
	// int received = -1;
	// /* Receive message */
	// if(((received = recv(sock, buffer, BUFF_SIZE, 0)) > 0))
	// {
		// if(!strcmp(buffer,"nihao")){
			// socks5 = sock;
		// }else if(socks5 < 1){
			// printf("no rever socks5 connect !");
			// return ;
		// }
		// if (send(socks5, buffer, received, 0) != received) {
			// Die("Failed to send bytes to real_socks");
		// }else{
			//printf("%s\n", buffer);
			// memset(buffer, 0, BUFF_SIZE);
		// }
		// return ;
	// }
	
	// while(((received = recv(socks5, buffer, received, 0)) > 0))
	// {
		
		// if (send(sock, buffer, received, 0) != received) {
			// Die("Failed to send bytes to client_sock");
		// }else{
			// printf("%d\n", received);
			// memset(buffer, 0, BUFF_SIZE);
		// }
	// }
	
	// close(sock);

// }


void forward(void *client_sock) {
	int sock_tmp = *(int *)client_sock;
	int sock = *(int *)client_sock;
	char buffer[BUFF_SIZE] = {0};
	int received = -1;
	/* Receive message */

	while ((received = recv(sock_tmp, buffer, BUFF_SIZE, 0)) > 0) {
		/* Send back received data */
		if(!strcmp(buffer,"nihao")){
			socks5 = sock_tmp;
			if (send(sock_tmp, buffer, received, 0) != received){
				Die("Failed to send bytes to client");
			}
			return ;
		}else if(socks5 < 1){
			printf("no rever socks5 connect !");
			return ;
		}
		if(sock_tmp == socks5)
		{
			sock_tmp = sock;
		}else if(sock_tmp == sock){
			sock_tmp = socks5;
		}
		if (send(sock_tmp, buffer, received, 0) != received) {
			Die("Failed to send bytes to client");
		}else{
			printf("%d\n", received);
			memset(buffer, 0, BUFF_SIZE);
		}
	}

}

int start(int argc, char **argv)
{
	if( argc != 2 )
	{
		printf( "Socks5 proxy for test\n" );
		printf( "Usage: %s <proxy_port>\n", argv[0] );
		printf( "Options:\n" );
		printf( " <proxy_port> ---which port of this proxy server will listen.\n" );
		return 1;
	}
	struct sockaddr_in sin;
	memset( (void *)&sin, 0, sizeof( struct sockaddr_in) );
	sin.sin_family = AF_INET;
	sin.sin_port = htons( atoi(argv[1]) );
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	int listen_sock = socket( AF_INET, SOCK_STREAM, 0 );
	if( listen_sock < 0 )
	{
		perror( "Socket creation failed\n");
		return -1;
	}
	int opt = SO_REUSEADDR;
	setsockopt( listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if( bind( listen_sock, (struct sockaddr*)&sin, sizeof(struct sockaddr_in) ) < 0 )
	{
		perror( "Bind error" );
		return -1;
	}
	if( listen( listen_sock, MAX_USER ) < 0 )
	{
		perror( "Listen error" );
		return -1;
	}
	struct sockaddr_in cin;
	int client_sock;
	int client_len = sizeof( struct sockaddr_in );
	while( client_sock = accept( listen_sock, (struct sockaddr *)&cin,(socklen_t *)&client_len ) )
	{
		printf( "Connected from %s, processing......\n", inet_ntoa( cin.sin_addr ) );
		pthread_t work_thread;
		if( pthread_create( &work_thread, NULL, (void *)forward, (void *)&client_sock ) ){
			perror( "Create thread error..." );
			close( client_sock );
		}else{
			pthread_detach( work_thread );
		}
	}
}

int main(int argc, char *argv[]) {
	start(argc, argv);
}