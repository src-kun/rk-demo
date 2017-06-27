#include <stdio.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "rsocks5.h"

#define MAX_USER 10
#define BUFF_SIZE 1024
#define AUTH_CODE 0x02
#define TIME_OUT 6000000
#define USER_NAME "user"
#define PASS_WORD "password"

void Die(char *mess) { perror(mess); }


// Select auth method, return 0 if success, -1 if failed
int SelectMethod( int sock )
{
	char recv_buffer[BUFF_SIZE] = { 0 };
	char reply_buffer[2] = { 0 };
	METHOD_SELECT_REQUEST *method_request;
	METHOD_SELECT_RESPONSE *method_response;
	// recv METHOD_SELECT_REQUEST
	int ret = recv( sock, recv_buffer, BUFF_SIZE, 0 );
	if( ret <= 0 )
	{
		perror( "recv error" );
		close( sock );
		return -1;
	}
	//printf( "SelectMethod: recv %d bytes\n", ret );
	// if client request a wrong version or a wrong number_method
	method_request = (METHOD_SELECT_REQUEST *)recv_buffer;
	method_response = (METHOD_SELECT_RESPONSE *)reply_buffer;
	method_response->version = VERSION;
	
	// if not socks5
	if( (int)method_request->version != VERSION )
	{
		method_response->select_method = 0xff;
		send( sock, method_response, sizeof(METHOD_SELECT_RESPONSE), 0 );
		close( sock );
		return -1;
	}
	
	method_response->select_method = AUTH_CODE;
	if( -1 == send( sock, method_response, sizeof(METHOD_SELECT_RESPONSE),0 ) )
	{
		close( sock );
		return -1;
	}
	return 0;
}

/*获取客户端传送的账户密码*/
void GetUserPwd(char *user, char *pwd, AUTH_REQUEST *auth_request)
{
	char pwd_len[2] = {0};
	/**
	内存中接收数据的结构：$3 = {version = 1 '\001', name_len = 6 '\006', user_pwd = "user\aph4nt0m", '\000' <repeats 495 times>}
	auth_request->name_len is a char, max number is 0xff
	*/
	if(!strlen((char *)auth_request))
	{
		return;
	}
	strncpy(user, auth_request->user_pwd, auth_request->user_len);
	strncpy(pwd_len, (char *)auth_request + 2 + auth_request->user_len, 1);
	strcpy(pwd, strstr(auth_request->user_pwd, pwd_len) + 1);
}

// test password, return 0 for success.
int AuthPassword( int sock )
{
	char recv_buffer[BUFF_SIZE] = { 0 };

	char recv_user[256] = { 0 };
	char recv_pwd[256] = { 0 };
	AUTH_RESPONSE *auth_response;
	// auth username and password
	int ret = recv( sock, recv_buffer, BUFF_SIZE, 0 );
	if( ret <= 0 )
	{
		perror( "recv username and password error" );
		close( sock );
		return -1;
	}
	//printf( "AuthPass: recv %d bytes\n", ret );
	
	GetUserPwd(recv_user, recv_pwd,(AUTH_REQUEST *) recv_buffer);
	printf("user: %s pwd: %s \n", recv_user, recv_pwd);
	
	auth_response->version = 0x01;
	// check username and password
	if( (strncmp( recv_user, USER_NAME, strlen(USER_NAME) ) == 0) &&(strncmp( recv_pwd, PASS_WORD, strlen(PASS_WORD) ) == 0))
	{
		auth_response->result = 0x00;
		if( -1 == send( sock, auth_response, sizeof(AUTH_RESPONSE), 0 ) )
		{
			close( sock );
			return -1;
		}else{
			return 0;
		}
	}else{
		perror("user or password faild !\n");
		auth_response->result = 0x01;
		send( sock, auth_response, sizeof(AUTH_RESPONSE), 0 );
		close( sock );
		return -1;
	}
}

int ParseCommand( int sock )
{
	int ret = -1;
	char recv_buffer[BUFF_SIZE] = { 0 };
	char reply_buffer[BUFF_SIZE] = { 0 };
	SOCKS5_REQUEST *socks5_request;
	SOCKS5_RESPONSE *socks5_response;
	struct sockaddr_in sin;
	int tryconn_sock = -1;
	
	// recv command
	ret = recv( sock, recv_buffer, BUFF_SIZE, 0 );
	if( ret <= 0 )
	{
		perror( "recv connect command error" );
		close( sock );
		return -1;
	}
	
	socks5_request = (SOCKS5_REQUEST *)recv_buffer;
	if( (socks5_request->version != VERSION) || (socks5_request->cmd != CONNECT) ||(socks5_request->address_type == IPV6) )
	{
		//printf( "connect command error.\n" );
		close( sock );
		return -1;
	}
	
	// begain process connect request
	memset( (void *)&sin, 0, sizeof(struct sockaddr_in) );
	sin.sin_family = AF_INET;
	// get real server&#39;s ip address
	if( socks5_request->address_type == IPV4 )
	{
		memcpy( &sin.sin_addr.s_addr, &socks5_request->address_type + sizeof(socks5_request->address_type) , 4 );
		memcpy( &sin.sin_port, &socks5_request->address_type + sizeof(socks5_request->address_type) + 4, 2 );
		printf( "Real Server: %s %d\n", inet_ntoa( sin.sin_addr ),ntohs( sin.sin_port ) );

	}else if( socks5_request->address_type == DOMAIN ){
		
		struct hostent *phost = NULL;
		char domain_length = *(&socks5_request->address_type + sizeof(socks5_request->address_type));
		char target_domain[ 256] = { 0 };
		
		strncpy( target_domain, &socks5_request->address_type + 2, (unsigned int)domain_length );
		printf( "target: %s\n", target_domain );
		phost = gethostbyname( target_domain );
		if( phost == NULL )
		{
			printf( "Resolve %s error!\n" , target_domain );
			close( sock );
			return -1;
		}
		memcpy( &sin.sin_addr , phost->h_addr_list[0] , phost->h_length );
		memcpy( &sin.sin_port, &socks5_request->address_type + sizeof(socks5_request->address_type) + sizeof(domain_length) + domain_length, 2 );
	}
	
	int real_server_sock = socket( AF_INET, SOCK_STREAM, 0 );
	if( real_server_sock < 0 )
	{
		perror( "Socket creation failed\n");
		close( sock );
		return -1;
	}
	memset( reply_buffer, 0, sizeof(BUFF_SIZE) );
	socks5_response = (SOCKS5_RESPONSE *)reply_buffer;
	socks5_response->version = VERSION;
	socks5_response->reserved = 0x00;
	socks5_response->address_type = 0x01;
	memset( socks5_response + 4, 0 , 6 );
	ret = connect( real_server_sock, (struct sockaddr *)&sin,
	sizeof(struct sockaddr_in) );
	if( ret == 0 )
	{
		socks5_response->reply = 0x00;
		if( -1 == send( sock, socks5_response, 10, 0 ) )
		{
			close( sock );
			return -1;
		}
	}else{
		perror( "Connect to real server error" );
		socks5_response->reply = 0x01;
		send( sock, socks5_response, 10, 0 );
		close( sock );
		return -1;
	} 
	return real_server_sock;  
	
}
int ForwardData(int client_sock, int real_socks) {
	int sock_tmp = client_sock;
	int sock = client_sock;
	char buffer[BUFF_SIZE] = {0};
	int received = -1;
	/* Receive message */
	if(((received = recv(client_sock, buffer, BUFF_SIZE, 0)) > 0))
	{
		if (send(real_socks, buffer, received, 0) != received) {
			Die("Failed to send bytes to real_socks");
		}else{
			printf("%s\n", buffer);
			memset(buffer, 0, BUFF_SIZE);
		}
	}
	
	while(((received = recv(real_socks, buffer, BUFF_SIZE, 0)) > 0))
	{
		if (send(client_sock, buffer, received, 0) != received) {
			Die("Failed to send bytes to client_sock");
		}else{
			printf("%d\n", received);
			memset(buffer, 0, BUFF_SIZE);
		}
	}

	
	
	// while ((received = recv(sock_tmp, buffer, BUFF_SIZE, 0)) > 0) {
		// /* Send back received data */
		
		// if(sock_tmp == real_socks)
		// {
			// sock_tmp = sock;
		// }else if(sock_tmp == sock){
			// sock_tmp = real_socks;
		// }
		// if (send(sock_tmp, buffer, received, 0) != received) {
			// Die("Failed to send bytes to client");
		// }else{
			// memset(buffer, 0, BUFF_SIZE);
		// }
		
	// }
}
int Socks5( void *client_sock )
{
	int sock = *(int *)client_sock;
	if( SelectMethod( sock ) == -1 )
	{
		//printf( "socks version error\n" );
		return -1;
	}
	
	if( AuthPassword( sock ) == -1 )
	{
		//printf( "auth password error\n" );
		return -1;
	}
	
	int real_server_sock = ParseCommand( sock );
	if( real_server_sock == -1 )
	{
		//printf( "parse command error.\n" );
		return -1;
	}
	
	ForwardData( sock, real_server_sock );
	close( sock );
	close( real_server_sock );
	return 0;
}

int conn_server(char *ip, char *port)
{
	int sock;
	struct sockaddr_in echoserver;


	/* Create the TCP socket */
	if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		Die("Failed to create socket");
	}

	/* Construct the server sockaddr_in structure */
	memset(&echoserver, 0, sizeof(echoserver));       /* Clear struct */
	echoserver.sin_family = AF_INET;                  /* Internet/IP */
	echoserver.sin_addr.s_addr = inet_addr(ip);  /* IP address */
	echoserver.sin_port = htons(atoi(port));       /* server port */
	/* Establish connection */
	if (connect(sock,(struct sockaddr *) &echoserver, sizeof(echoserver)) < 0) {
		Die("Failed to connect with server");
	}
	return sock;
}

int main(int argc, char *argv[]) {

	int sock;
	int received = 0;
	unsigned int echolen;
	char buffer[BUFF_SIZE];
	if (argc != 4) {
		fprintf(stderr, "USAGE: TCPecho <server_ip> <word> <port>\n");
		exit(1);
	}
	sock = conn_server(argv[1], argv[3]);
	// /* Send the word to the server */
	echolen = strlen(argv[2]);
	if (send(sock, argv[2], echolen, 0) != echolen) {
		Die("Mismatch in number of sent bytes");
		return -1;
	}
	/* Receive the word back from the server */
	fprintf(stdout, "Received: ");
	if (received < echolen) {
		int bytes = 0;
		if ((bytes = recv(sock, buffer, BUFF_SIZE-1, 0)) < 1) {
			Die("Failed to receive bytes from server");
			return -1;
		}
		received += bytes;
		buffer[bytes] = '\0';        /* Assure null terminated string */
		fprintf(stdout, buffer);
	}
	fprintf(stdout, "\n");

	while(1){
		if(Socks5(&sock) == -1)
		{
			break;
		}
	}
	
	
	// close(sock);
	// exit(0);
}