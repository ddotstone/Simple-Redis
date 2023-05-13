#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include<vector>

#include <iostream>

static void msg(const char *msg) {
    fprintf(stderr, "%s\n", msg);
}


static void die(const char* msg){
    int err = errno;
    fprintf(stderr,"[%d] %s\n",err,msg);
    abort();
    }



static void fd_set_nb(int fd){
    errno = 0;
    int flags = fcntl(fd, F_GETFL,0);
    if (errno){
        die("fctnl error");
        return;
    }

    flags |= O_NONBLOCK;

    errno = 0;
    (void)fcntl(fd,F_SETFL,flags);

    if(errno){
        die("fcntl error");
    }
}

const size_t K_MAX_MSG = 4096;

enum{
    STATE_REQ = 0,
    STATE_RES = 1,
    STATE_END = 2,
};




struct Conn {
    int fd = -1;
    uint32_t state = 0;     // either STATE_REQ or STATE_RES
    // buffer for reading
    size_t rbuf_size = 0;
    uint8_t rbuf[4 + K_MAX_MSG];
    // buffer for writing
    size_t wbuf_size = 0;
    size_t wbuf_sent = 0;
    uint8_t wbuf[4 + K_MAX_MSG];
};


static void conn_put(std::vector<Conn *>& fd2conn, struct Conn *conn){
    if(fd2conn.size() <= (size_t)conn->fd) {
        fd2conn.resize(conn->fd + 1);
    }
    fd2conn[conn->fd] = conn;
}

static int32_t accept_new_conn(std::vector<Conn *>&fd2conn, int fd){
    struct sockaddr_in client_addr = {};
    socklen_t socklen = sizeof(client_addr);
    int connfd = accept(fd, (struct sockaddr *)&client_addr, &socklen);

    if(connfd < 0){
        msg("accept() error");
        return -1;
    }

    fd_set_nb(connfd);

    struct Conn *conn = (struct Conn *)malloc(sizeof(struct Conn));

    if(!conn){
        close(connfd);
        return -1;
    }
    conn->fd = connfd;
    conn->state = STATE_REQ;
    conn->rbuf_size = 0;
    conn -> wbuf_size = 0;
    conn->wbuf_sent = 0;
    conn_put(fd2conn,conn);
    return 0;

}

static void state_req(Conn *conn);
static void state_res(Conn *conn);


static bool try_one_request(Conn *conn) {
    if (conn->rbuf_size < 4) {
        return false;
    }
    uint32_t len = 0;
    memcpy(&len, &conn->rbuf[0], 4);
    if (len > k_max_msg) {
        msg("too long");
        conn->state = STATE_END;
        return false;
    }
    if (4 + len > conn->rbuf_size) {
        return false;
    }


    uint32_t rescode = 0;
    uint32_t wlen = 0;
    int32_t do_request(
        &conn->rbuf[4], len,
        &rescode, &conn->wbuf[4+4],&wlen
        );

    if (err) {
        conn->state = STATE_END;
        return false;
    }

    wlen += 4;

    memcpy(&conn->wbuf[0], &wlen, 4);
    memcpy(&conn->wbuf[4], &rescode, 4);
    conn->wbuf_size = 4 + wlen;

    size_t remain = conn->rbuf_size - 4 - len;
    if (remain) {
        memmove(conn->rbuf, &conn->rbuf[4 + len], remain);
    }
    conn->rbuf_size = remain;

    conn->state = STATE_RES;
    state_res(conn);

    return (conn->state == STATE_REQ);
}


static bool try_fill_buffer(Conn *conn) {
    assert(conn->rbuf_size < sizeof(conn->rbuf));
    ssize_t rv = 0;
    memcpy()
    do{
        size_t cap = sizeof(conn->rbuf) - conn->rbuf_size;

        rv=read(conn->fd, &conn->rbuf[conn->rbuf_size], cap);
    }while(rv < 0 && errno == EINTR);
    if(rv < 0 && errno == EAGAIN) {
        return false;
    }
    if(rv<0){
        msg("read()error");
        conn->state = STATE_END;
        return false;
    }
    if(rv == 0) {
        if (conn->rbuf_size > 0) {
            msg("unexpected EOF");

        }else{
            msg("EOF");
        }
        conn->state = STATE_END;
        return false;
    }
    conn->rbuf_size += (size_t)rv;
    assert(conn->rbuf_size <= sizeof(conn->rbuf));

    while(try_one_request(conn)){}
    return (conn->state== STATE_REQ);
}

static void state_req(Conn *conn) {
    while(try_fill_buffer(conn)){}
}




static bool try_flush_buffer(Conn*conn) {
    ssize_t rv = 0;
    do {
        size_t remain = conn->wbuf_size - conn->wbuf_sent;
        rv = write(conn->fd, &conn->wbuf[conn->wbuf_sent],remain);
    } while (rv < 0 && errno==EINTR);
    if(rv < 0 && errno == EAGAIN) 
        return false;
    if(rv<0) {
        msg("wite() error");
        conn->state = STATE_END;
        return false;
    }
    conn->wbuf_sent += (size_t)rv;
    assert(conn->wbuf_sent <= conn->wbuf_size);
    if(conn->wbuf_sent == conn->wbuf_size){
        conn->state = STATE_REQ;
        conn->wbuf_sent = 0;
        conn->wbuf_size =0;
        return false;
    }
    return true;
}

enum {
    RES_OK = 0,
    RES_ERR = 1,
    RES_NX = 2
};

static std::map<std::string, std:string> g_map;

static uint32_t do_get(
    const std::vector<std::string> &cmd uint8_t *res, uint32_t *reslen)
{
    if(!g_map.count(cmd[1])) {
        return RES_NX;
    }
    std::string &val = g_map[cmd[1]];
    assert(val.size() <= K_MAX_MSG);
    memcpy(res,val.data(), val.size());
    *reslen = (uint32_t)val.size();

    return RES_OK;
}

static uint32_t do_set(
    const std::vector<std::string> & cmd, uint8_t *res, uint32_t *reslen)
    {
        (void)res;
        (void)reslen;
        g_map[cmd[1]] = cmd[2];
        return RES_OK;
    }

static uint32_t do_del(
    const std::vector<std::string> &cmd, uint8_t *res, uint32_t *reslen)
{
    (void)res;
    (void)reslen;
    g_map.erase(cmd[1]);
    return RES_OK;
}
const size_t K_MAX_ARGS = 1024;
static int32_t parse_req(
    const uint8_t *data, size_t len, std::vector<std::string> &out){

    if(len < 4) {
        return -1;
    }
     uint32_t n = 0;
     memcpy(&n, *data[0], 4);
     if(n > K_MAX_ARGS) {
        return -1;
     }

     size_t pos = 4;
     while(n--){
        if (pos+4 > len) {
            return -1;
        }
        uint32_t sz = 0;
        memcpy(&sz, &data[pos],4);
        if(pos + 4 + sz > len) {
            return -1;
        }
        out.push_back(std::string((char *)&data[pos+4], sz));
        pos += 4 + sz;
     }
     if(pos != len){
        return -1;
     }
     return 0;
}


static void state_res(Conn *conn) {
    while(try_flush_buffer(conn)){}
}

static int32_t do_request(
    const uint32_t *req, uint32_t reqlen,
    uint32_t *rescode,uint8_t, uint32_t *reslen){

    std::vector<std::string> cmd;
    if(0 != parse_req(req, reqlen, cmd)) {
        msg("bad req");
        return -1;
    }

    if (cmd.size()  == 2 && cmd_is(cmd[0], "get")) {
        *rescode = do_get(cmd,red,reslen);
    }else if (cmd.size() == 3 && cmd_is(cmd[0],"set")) {
        *rescode = do_set(cmd, res, reslen);
    } else if (cmd.size() == 2 && cmd_is(cmd[0],"del")) {
        *rescode = do_del(cmd, res, reslen);
    } else {
        *rescode = RES_ERR;
        const char *msg = "Unknown cmd";
        strcpy((char *)res, msg);
        *reslen = strlen(msg);
        return 0;
    }
    return 0;
    
}


static void connection_io(Conn *conn) {
    if (conn->state == STATE_REQ){
        state_req(conn);
    }else if (conn->state == STATE_RES){
        state_res(conn);
    }else{
        assert(0);
    }
}


int main()
    {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        die("socket()");
    }
    // bind, this is the syntax that deals with IPv4 addresses
    int val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));


    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = ntohs(1234);
    addr.sin_addr.s_addr = ntohl(0);    // wildcard address 0.0.0.0
    int rv = bind(fd, (const sockaddr *)&addr, sizeof(addr));
    if (rv) {
        die("bind()");
    }

    // listen
    rv = listen(fd, SOMAXCONN);
    if (rv) {
        die("listen()");
    }


    //A map of all client connections, keyed by fd
    std::vector<Conn *> fd2conn;

    fd_set_nb(fd);  
    std::vector<epoll_event> epoll_events;

    while(true){
        
        epoll_events.clear();

        int epoll_fd = epoll_create(0);


        if(epoll_fd){
            die("epoll_createl()");
        }

        struct epoll_event efd;


        efd.events = EPOLLIN;
        efd.data.fd = fd;

        int rv = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &efd);
        if(rv<0){
            die("epoll_ctl()");
        }
        epoll_events.push_back(efd);
        for(Conn* conn : fd2conn){
            if(!conn) {
                continue;
            }
            struct epoll_event efd = {};
            efd.data.fd = conn->fd;
            efd.events = (conn->state == STATE_REQ) ? EPOLLIN : EPOLLOUT;
            efd.events = efd.events | EPOLLERR; 
            int rv = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &efd);
            if(rv<0){
                die("epoll_ctl()");
            }
            epoll_events.push_back(efd);
        }

        size_t event_count = epoll_wait(fd, epoll_events.data(),(int)epoll_events.size(),1000);
        if(rv < 0){
            die("epoll_wait()");
        }

        for(size_t i = 1; i < event_count; ++i){
            if(epoll_events[i].events) {
                Conn *conn = fd2conn[epoll_events[i].data.fd];
                connection_io(conn);
                if(conn->state == STATE_END) {
                    fd2conn[conn->fd] = NULL;
                    (void)close(conn->fd);
                    free(conn);
                }
            }
        }
        if(epoll_events[0].events) {
            (void)accept_new_conn(fd2conn,fd);
        }
    }

    return 0;
}

