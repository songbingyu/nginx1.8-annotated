
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CHANNEL_H_INCLUDED_
#define _NGX_CHANNEL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

// ngx_channel_t频道是Nginx master进程与worker进程之间通信的常用工具，
// 它是使用本机套接字实现的。socketpair方法，用于创建父子进程间使用的套接字
typedef struct {
	 // 向worker进程发送的命令  
     ngx_uint_t  command;
	 /**
	 * 对应进程的id
	 */
     ngx_pid_t   pid;
	 /**
	 * 对应的进程在ngx_processes数组中的下标
	 */
     ngx_int_t   slot;
	 /**
	 * 文件描述符
	 */
     ngx_fd_t    fd;
} ngx_channel_t;


ngx_int_t ngx_write_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
    ngx_log_t *log);
ngx_int_t ngx_read_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
    ngx_log_t *log);
ngx_int_t ngx_add_channel_event(ngx_cycle_t *cycle, ngx_fd_t fd,
    ngx_int_t event, ngx_event_handler_pt handler);
void ngx_close_channel(ngx_fd_t *fd, ngx_log_t *log);


#endif /* _NGX_CHANNEL_H_INCLUDED_ */
