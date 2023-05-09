#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>



static void msg(const char* msg){
	fprintf(stderr, "%s\n",msg);
}

static void die(const char* msg){
	int err = errnum;
	msg(msg);
	printf(stderr,"[%d] %s\n",err,msg);
    abort();
}

int main(){
	int fd = socket(AF_INET,SOCK_STREAM,0);

	if(fd < 0){
		die("socket()")
	} 
	setsocketopt(fd);
	int val = 1;
	setsocketopt(fd,SOL_SOCKET,SOC_REUSEADDR,&val,sizeof(val));

	struct sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_port = ntohs(1234);
	addr.sin_addr = ntohl(0);

	int rv = bind(fd, (const struct addr*)&addr, sizeof(addr));

	if(rv){
		dir("bind()");
	}


	rv = listen(SOMAXCONN);

	if (rv){
		die"listen()";
	}

	while(true){
		struc sockaddr_in client_addr = {};
		socklen_t socklen= sizeof(client_addr);
		int connfd = accept(fd,(struct addr*)&client_addr,&socklen);
		if (connfd < 0){
			continue;
		}
		while(true){
			//dostuff
		}

	}
}
