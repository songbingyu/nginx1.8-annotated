
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CHANNEL_H_INCLUDED_
#define _NGX_CHANNEL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

// ngx_channel_tƵ����Nginx master������worker����֮��ͨ�ŵĳ��ù��ߣ�
// ����ʹ�ñ����׽���ʵ�ֵġ�socketpair���������ڴ������ӽ��̼�ʹ�õ��׽���
typedef struct {
	 // ��worker���̷��͵�����  
     ngx_uint_t  command;
	 /**
	 * ��Ӧ���̵�id
	 */
     ngx_pid_t   pid;
	 /**
	 * ��Ӧ�Ľ�����ngx_processes�����е��±�
	 */
     ngx_int_t   slot;
	 /**
	 * �ļ�������
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
