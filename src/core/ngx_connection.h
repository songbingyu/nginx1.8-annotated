
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_listening_s  ngx_listening_t;

// see http://www.tuicool.com/articles/QrIJ7j
struct ngx_listening_s {
    ngx_socket_t        fd;

    struct sockaddr    *sockaddr;
    socklen_t           socklen;    /* size of sockaddr */
    size_t              addr_text_max_len;
	// 以字符串形式存储ip地址
    ngx_str_t           addr_text;
	// 套接字类型。types是SOCK_STREAM时，表示是tcp
    int                 type;
	// TCP实现监听时的backlog队列，
	// 它表示允许正在通过三次握手建立tcp连接但还没有任何进程开始处理的连接最大个数
    int                 backlog;
	// buf
    int                 rcvbuf;
    int                 sndbuf;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                 keepidle;
    int                 keepintvl;
    int                 keepcnt;
#endif

    /* handler of accepted connection */
	// 当新的tcp连接成功建立后的处理方法
    ngx_connection_handler_pt   handler;
	// 目前主要用于HTTP或者mail等模块，用于保存当前监听端口对应着的所有主机名
    void               *servers;  /* array of ngx_http_in_addr_t, for example */

    ngx_log_t           log;
	// 日志指针
    ngx_log_t          *logp;
	// tcp连接创建内存池，则内存池的初始大小应该是pool_size。
    size_t              pool_size;
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;
    /* should be here because of the deferred accept */
	// n秒后仍然没有收到用户的数据，就丢弃该连接
    ngx_msec_t          post_accept_timeout;

    ngx_listening_t    *previous;
    ngx_connection_t   *connection;

	// 为1表示监听句柄有效，为0表示正常关闭
    unsigned            open:1;
	// 为1表示不关闭原先打开的监听端口，为0表示关闭曾经打开的监听端口
    unsigned            remain:1;
	// 为1表示跳过设置当前ngx_listening_t结构体中的套接字，为0时正常初始化套接字
    unsigned            ignore:1;

    unsigned            bound:1;       /* already bound */
    unsigned            inherited:1;   /* inherited from previous process */
    unsigned            nonblocking_accept:1;
    unsigned            listen:1;
    unsigned            nonblocking:1;
    unsigned            shared:1;    /* shared between threads or processes */
    unsigned            addr_ntop:1;

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned            ipv6only:1;
#endif
    unsigned            keepalive:2;

#if (NGX_HAVE_DEFERRED_ACCEPT)
    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#ifdef SO_ACCEPTFILTER
    char               *accept_filter;
#endif
#endif
#if (NGX_HAVE_SETFIB)
    int                 setfib;
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
    int                 fastopen;
#endif

};


typedef enum {
     NGX_ERROR_ALERT = 0,
     NGX_ERROR_ERR,
     NGX_ERROR_INFO,
     NGX_ERROR_IGNORE_ECONNRESET,
     NGX_ERROR_IGNORE_EINVAL
} ngx_connection_log_error_e;


typedef enum {
     NGX_TCP_NODELAY_UNSET = 0,
     NGX_TCP_NODELAY_SET,
     NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;


typedef enum {
     NGX_TCP_NOPUSH_UNSET = 0,
     NGX_TCP_NOPUSH_SET,
     NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;


#define NGX_LOWLEVEL_BUFFERED  0x0f
#define NGX_SSL_BUFFERED       0x01
#define NGX_SPDY_BUFFERED      0x02

// ref http://blog.csdn.net/xiaoliangsky/article/details/39831035
struct ngx_connection_s {
	// 连接未使用时，data用于充当连接池中空闲链表中的next指针。
	// 连接使用时由模块而定，HTTP中，data指向ngx_http_request_t  
    void               *data;
    ngx_event_t        *read;
    ngx_event_t        *write;

    ngx_socket_t        fd;

    ngx_recv_pt         recv; // 直接接收网络字符流的方法  
    ngx_send_pt         send; // 直接发送网络字符流的方法 
    ngx_recv_chain_pt   recv_chain; // 以链表来接收网络字符流的方法
    ngx_send_chain_pt   send_chain; // 以链表来发送网络字符流的方法

	// 这个连接对应的ngx_listening_t监听对象，此连接由listening监听端口的事件建立  
    ngx_listening_t    *listening;
	// 这个连接上已发送的字节数  
    off_t               sent;

    ngx_log_t          *log;
	// 内存池。一般在accept一个新的连接时，会创建一个内存池，
	// 而在这个连接结束时会销毁内存池。
	// 内存池大小是由上面listening成员的pool_size决定的*/
    ngx_pool_t         *pool;

    struct sockaddr    *sockaddr;
    socklen_t           socklen;
    ngx_str_t           addr_text; // 连接客户段字符串形式的IP地址  

    ngx_str_t           proxy_protocol_addr;

#if (NGX_SSL)
    ngx_ssl_connection_t  *ssl;
#endif

    struct sockaddr    *local_sockaddr;
    socklen_t           local_socklen;
	// 用户接受、缓存客户端发来的字符流，
	// buffer是由连接内存池分配的，大小自由决定  
    ngx_buf_t          *buffer;
	// 用来将当前连接以双向链表元素的形式添加到
	// ngx_cycle_t核心结构体的reuseable_connection_queue双向链表中，
	// 表示可以重用的连接
    ngx_queue_t         queue;
	// 连接使用次数。
	// ngx_connection_t结构体每次建立一条来自客户端的连接，
	// 或者主动向后端服务器发起连接时，number都会加1
    ngx_atomic_uint_t   number;

    ngx_uint_t          requests; // 处理的请求次数  

    unsigned            buffered:8;  // 缓存中的业务类型。
	// 本连接的日志级别，占用3位，取值范围为0～7，
	// 但实际只定义了5个值，由 ngx_connection_log_error_e 枚举表示。  
    unsigned            log_error:3;     /* ngx_connection_log_error_e */

    unsigned            unexpected_eof:1;
    unsigned            timedout:1;
    unsigned            error:1;
    unsigned            destroyed:1; // 为1表示连接已经销毁  
	// 为1表示连接处于空闲状态，如keepalive两次请求中间的状态
    unsigned            idle:1; 
	// 为1表示连接可重用，与上面的queue字段对应使用
    unsigned            reusable:1;
    unsigned            close:1;
	// 为1表示正在将文件中的数据发往连接的另一端 
    unsigned            sendfile:1;
	/* 
	  为1表示只有连接套接字对应的发送缓冲区必须满足最低设置的大小阀值时，
	  事件驱动模块才会分发该事件。
	  这与ngx_handle_write_event方法中的lowat参数是对应的
	*/
    unsigned            sndlowat:1;
    unsigned            tcp_nodelay:2;   /* ngx_connection_tcp_nodelay_e */
    unsigned            tcp_nopush:2;    /* ngx_connection_tcp_nopush_e */

    unsigned            need_last_buf:1;

#if (NGX_HAVE_IOCP)
    unsigned            accept_context_updated:1;
#endif

#if (NGX_HAVE_AIO_SENDFILE)
    unsigned            busy_count:2;
#endif

#if (NGX_THREADS)
    ngx_thread_task_t  *sendfile_task;
#endif
};


ngx_listening_t *ngx_create_listening(ngx_conf_t *cf, void *sockaddr,
    socklen_t socklen);
ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_configure_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,
    ngx_uint_t port);
ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);

ngx_connection_t *ngx_get_connection(ngx_socket_t s, ngx_log_t *log);
void ngx_free_connection(ngx_connection_t *c);

void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);

#endif /* _NGX_CONNECTION_H_INCLUDED_ */
