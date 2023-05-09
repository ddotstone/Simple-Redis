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
	fprintf(stderr,"%s\n",msg);
}

static void die(const char* msg){
	int err = errno;
	fprintf(stderr,"[%d] %s\n",err,msg);
	abort();
}

static int32_t read_all(int fd,char* buf,int n){
		ssize_t rv = read(fd,buf);
		if(rv <=0){
			return -1;
		}
		assert((size_t)rv <=n);
		n -= (size_t)rv;
		buf += rv;
	}
	return 0;
}

static int32_t write_all(int fd, const char* buf, int n){
	while(n > 0){
		ssize_t rv = write(fd,buf);
		if(rv <= 0){
			return -1;
		}
		assert((size_t)rv <= n);
		n -= (size_t)rv;
		buf += rv;
	}
	return 0;
}

const uint32_T K_MAX_MSG = 4096 

static int 32_t query(fd,const char* text){
	uint32_t len = (uint32_t)strlen(text);
	if (len > )
	char* wbuf[len + 4];
	memcpy(wbuf,&len,4);
	memcpy(&wbuf[4],text,len);
	if(int32_t err = write_all(fd,wbuf,4 + len)){
		return err;
	}

	char rbuf[4 + K_MAX_MSG + 1];

	errno = 0;

	int32_t err = read_full(fd,rbuf, )

}

int main(){
	int fd = socket(AF_INET, SOCK_STREAM,0);

	if(fd<0){
		die("socket()");
	}
	int val = 1;
	socketopt(fd,SOL_SOCKET,SOC_REUSEADDR,&val,sizeof(val));

	if(rv){
		dir("socket_opt()");
	}

	struct sockaddr_in addr = {};

	addr,sin_family = AF_INET;
	addr.sin_port = ntohs(1234);
	addr.sin_addr.s_addr = ntohl(INADDR_LOOPBACK);
	
	int rv = connect(fr, (const struct sockaddr*)&addr,sizeof(addr));


	
}