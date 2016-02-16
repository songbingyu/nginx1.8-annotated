
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_PIPE_H_INCLUDED_
#define _NGX_EVENT_PIPE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct ngx_event_pipe_s  ngx_event_pipe_t;

typedef ngx_int_t (*ngx_event_pipe_input_filter_pt)(ngx_event_pipe_t *p,
                                                    ngx_buf_t *buf);
typedef ngx_int_t (*ngx_event_pipe_output_filter_pt)(void *data,
                                                     ngx_chain_t *chain);
// upstream
// http://www.codes51.com/article/detail_163904.html
struct ngx_event_pipe_s {
	// Nginx�����η�����֮�������
    ngx_connection_t  *upstream;
	// Nginx�����οͻ���֮�������
    ngx_connection_t  *downstream;
	/*
	   ֱ�ӽ��������η������Ļ����������������δ���κδ�������ݡ�
	   �������������ģ�����ܵ���Ӧ��������ͷ�� 
	 */
    ngx_chain_t       *free_raw_bufs;
	// ��ʾ���յ���������Ӧ���������������Ǿ���input_filter�����
    ngx_chain_t       *in;
	// ָ����յ���һ��������
    ngx_chain_t      **last_in;
	// �����Ž�Ҫ�����ͻ��˵Ļ���������
	// ��д����ʱ�ļ��ɹ�ʱ�����in�еĻ�������ӵ�out��
    ngx_chain_t       *out;
	// �ȴ��ͷŵĻ�����
    ngx_chain_t       *free;
	// ��ʾ�ϴε���ngx_http_output_filter����������Ӧʱû�з�����Ļ���������
    ngx_chain_t       *busy;

    /*
     * the input filter i.e. that moves HTTP/1.1 chunks
     * from the raw bufs to an incoming chain
     */
	// ������յ��ġ��������η�����������
    ngx_event_pipe_input_filter_pt    input_filter;
    void                             *input_ctx;
	// �����η�����Ӧ�ĺ���
    ngx_event_pipe_output_filter_pt   output_filter;
    void                             *output_ctx;
	// 1����ʾ��ǰ�Ѷ�ȡ�����ε���
    unsigned           read:1;
	// 1�������ļ�����
    unsigned           cacheable:1;
	// 1����ʾ����������Ӧʱ��һ��ֻ�ܽ���һ��ngx_buf_t������
	unsigned           single_buf : 1; 
	// 1��һ�����ٽ������ΰ��壬�������ܵ��ͷŻ�����
    unsigned           free_bufs:1;
	// 1����ʾNginx�����ν����Ѿ�����
    unsigned           upstream_done:1;
	// 1��Nginx�����η����������ӳ��ִ���
    unsigned           upstream_error:1;
	// 1����ʾ�����η������������ѹر�
    unsigned           upstream_eof:1;
	/* 
	   1����ʾ��ʱ������ȡ������Ӧ�ĵ����̡�
	   ��ʱ���ȵ���ngx_event_pipe_write_to_downstream
	   �������ͻ������е����ݸ����Σ��Ӷ��ڳ��������ռ䣬
	   �ٵ���ngx_event_pipe_read_upstream������ȡ������Ϣ 
	*/
    unsigned           upstream_blocked:1;
	// 1�������εĽ����ѽ���
    unsigned           downstream_done:1;
	// 1�������ε����ӳ��ִ���
    unsigned           downstream_error:1;
	// 1��������ʱ�ļ���������ngx_http_upstream_conf_t�е�ͬ����Ա��ֵ��
    unsigned           cyclic_temp_file:1;
	// �ѷ���Ļ���������
    ngx_int_t          allocated;
	// ��¼�˽���������Ӧ���ڴ滺������С��
	// bufs.size��ʾÿ���ڴ滺������С��bufs.num��ʾ��������num��������
    ngx_bufs_t         bufs;
	// �������á��Ƚϻ����������е�ngx_buf_t�ṹ���tag��־λ
    ngx_buf_tag_t      tag;
	/* 
	   busy�������д�������Ӧ���ȵ����ֵ��
	   ������busy_sizeʱ������ȴ�busy�������������㹻�����ݣ�
	   ���ܼ�������out��in�е����� 
	*/
    ssize_t            busy_size;
	// �Ѿ����յ�����������Ӧ����ĳ���
    off_t              read_length;
    off_t              length;
	// ��ʾ��ʱ�ļ�����󳤶�
    off_t              max_temp_file_size;
	// ��ʾһ��д���ļ�ʱ���ݵ���󳤶�
    ssize_t            temp_file_write_size;
	// ��ȡ������Ӧ�ĳ�ʱʱ��
    ngx_msec_t         read_timeout;
    ngx_msec_t         send_timeout;
	// �����η�����Ӧʱ��TCP���������õ�send_lowat��ˮλ��
    ssize_t            send_lowat;

    ngx_pool_t        *pool;
    ngx_log_t         *log;
	// ��ʾ�ڽ������η�������Ӧͷ���׶Σ��Ѿ���ȡ����Ӧ����
    ngx_chain_t       *preread_bufs;
	// ��ʾ�ڽ������η�������Ӧͷ���׶Σ��Ѿ���ȡ����Ӧ���峤��
    size_t             preread_size;
	// ���ڻ����ļ�
    ngx_buf_t         *buf_to_file;

    size_t             limit_rate;
    time_t             start_sec;
	// ���������Ӧ����ʱ�ļ�
    ngx_temp_file_t   *temp_file;
	// ��ʹ�õ�ngx_buf_t��������Ŀ/
    /* STUB */ int     num;
};


ngx_int_t ngx_event_pipe(ngx_event_pipe_t *p, ngx_int_t do_write);
ngx_int_t ngx_event_pipe_copy_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf);
ngx_int_t ngx_event_pipe_add_free_buf(ngx_event_pipe_t *p, ngx_buf_t *b);


#endif /* _NGX_EVENT_PIPE_H_INCLUDED_ */
