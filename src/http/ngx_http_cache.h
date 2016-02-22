
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_CACHE_H_INCLUDED_
#define _NGX_HTTP_CACHE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_CACHE_MISS          1
#define NGX_HTTP_CACHE_BYPASS        2
#define NGX_HTTP_CACHE_EXPIRED       3
#define NGX_HTTP_CACHE_STALE         4
#define NGX_HTTP_CACHE_UPDATING      5
#define NGX_HTTP_CACHE_REVALIDATED   6
#define NGX_HTTP_CACHE_HIT           7
#define NGX_HTTP_CACHE_SCARCE        8

#define NGX_HTTP_CACHE_KEY_LEN       16
#define NGX_HTTP_CACHE_ETAG_LEN      42
#define NGX_HTTP_CACHE_VARY_LEN      42

#define NGX_HTTP_CACHE_VERSION       3


typedef struct {
    ngx_uint_t                       status;
    time_t                           valid;
} ngx_http_cache_valid_t;


typedef struct {
	/* 缓存查询树的节点 */
    ngx_rbtree_node_t                node;
	/* LRU 队列中的节点 */
    ngx_queue_t                      queue;

    u_char                           key[NGX_HTTP_CACHE_KEY_LEN
                                         - sizeof(ngx_rbtree_key_t)];
	/* 引用计数 */
    unsigned                         count:20;
	/* 被请求查询到的次数 */
    unsigned                         uses:10;
    unsigned                         valid_msec:10;
	/*
	 当后端响应码 >= NGX_HTTP_SPECIAL_RESPONSE , 并且打开了
	 fastcgi_intercept_errors 配置，同时 fastcgi_cache_valid 配置指令和
	 error_page 配置指令也对该响应码做了设定 的情部下，该字段记录响应码，
	 并列的 valid_sec 字段记录该响应码的持续时间。这种 error 节点并不对
	 应实际的缓存文件。
	*/
    unsigned                         error:10;
	/*
	 该缓存节点是否有对应的缓存文件。新创建的缓存节点或者过期的
	 error 节点 (参见 error 字段，当 error 不等于 0 时，Nginx 随后也不
	 会再关心该节点的 exists 字段值) 该字段值为 0。当正常节点 ( error 等
	 于 0) 的 exists 为 0 时，进入 cache lock 模式。
	*/
    unsigned                         exists:1;
	// 缓存内容过期，某个请求正在获取有效的后端响应并更新此缓存
    unsigned                         updating:1;
	/* 正在被清理中 */
    unsigned                         deleting:1;
                                     /* 11 unused bits */

    ngx_file_uniq_t                  uniq;
	// 缓存节点的可回收时间 (附带缓存内容)。
    time_t                           expire;
	/*
	 valid_msec – 缓存内容的过期时间，缓存内容过期后被查询
	 时会由 ngx_http_file_cache_read 返回 NGX_HTTP_CACHE_STALE ，然后由
	 fastcgi_cache_use_stale 配置指令决定是否及何种情况下使用过期内容。
	*/
    time_t                           valid_sec;
    size_t                           body_start;
    off_t                            fs_size;
    ngx_msec_t                       lock_time;
} ngx_http_file_cache_node_t;

// http://www.tuicool.com/articles/QnMNr23
struct ngx_http_cache_s {
    ngx_file_t                       file;/* 缓存文件描述结构体 */
    ngx_array_t                      keys;
    uint32_t                         crc32/* crc32 of literal key */
    u_char                           key[NGX_HTTP_CACHE_KEY_LEN];
    u_char                           main[NGX_HTTP_CACHE_KEY_LEN];

    ngx_file_uniq_t                  uniq;
    time_t                           valid_sec;
    time_t                           last_modified;
    time_t                           date;

    ngx_str_t                        etag;
    ngx_str_t                        vary;
    u_char                           variant[NGX_HTTP_CACHE_KEY_LEN];

    size_t                           header_start;
    size_t                           body_start;
    off_t                            length;
    off_t                            fs_size;

    ngx_uint_t                       min_uses;
    ngx_uint_t                       error;
    ngx_uint_t                       valid_msec;

    ngx_buf_t                       *buf;

    ngx_http_file_cache_t           *file_cache;
    ngx_http_file_cache_node_t      *node;

#if (NGX_THREADS)
    ngx_thread_task_t               *thread_task;
#endif

    ngx_msec_t                       lock_timeout;
    ngx_msec_t                       lock_age;
    ngx_msec_t                       lock_time;
    ngx_msec_t                       wait_time;

    ngx_event_t                      wait_event;

    unsigned                         lock:1;
    unsigned                         waiting:1;

    unsigned                         updated:1;
    unsigned                         updating:1;
    unsigned                         exists:1;
    unsigned                         temp_file:1;
    unsigned                         reading:1;
    unsigned                         secondary:1;
};

/*
    包头结构，存储缓存文件的相关信息(修改时间、缓存 key 的 crc32 值、和用于指明
	HTTP 响应包头和包体在缓存文件中偏移位置的字段等)
	[ngx_http_file_cache_header_t]["\nKEY: "][orig_key]["\n"][header][body]
*/
typedef struct {
    ngx_uint_t                       version;
    time_t                           valid_sec;
    time_t                           last_modified;
    time_t                           date;
    uint32_t                         crc32;
    u_short                          valid_msec;
    u_short                          header_start;
    u_short                          body_start;
    u_char                           etag_len;
    u_char                           etag[NGX_HTTP_CACHE_ETAG_LEN];
    u_char                           vary_len;
    u_char                           vary[NGX_HTTP_CACHE_VARY_LEN];
    u_char                           variant[NGX_HTTP_CACHE_KEY_LEN];
} ngx_http_file_cache_header_t;


typedef struct {
    ngx_rbtree_t                     rbtree;
    ngx_rbtree_node_t                sentinel;
    ngx_queue_t                      queue;
    ngx_atomic_t                     cold;
    ngx_atomic_t                     loading;
    off_t                            size;
} ngx_http_file_cache_sh_t;


struct ngx_http_file_cache_s {
	// sh 维护 LRU 队列和红黑树，以及缓存文件的当前状态
    ngx_http_file_cache_sh_t        *sh;
    ngx_slab_pool_t                 *shpool;

    ngx_path_t                      *path;
    ngx_path_t                      *temp_path;

    off_t                            max_size;
    size_t                           bsize;

    time_t                           inactive;

    ngx_uint_t                       files;
    ngx_uint_t                       loader_files;
    ngx_msec_t                       last;
    ngx_msec_t                       loader_sleep;
    ngx_msec_t                       loader_threshold;

    ngx_shm_zone_t                  *shm_zone;
};


ngx_int_t ngx_http_file_cache_new(ngx_http_request_t *r);
ngx_int_t ngx_http_file_cache_create(ngx_http_request_t *r);
void ngx_http_file_cache_create_key(ngx_http_request_t *r);
ngx_int_t ngx_http_file_cache_open(ngx_http_request_t *r);
ngx_int_t ngx_http_file_cache_set_header(ngx_http_request_t *r, u_char *buf);
void ngx_http_file_cache_update(ngx_http_request_t *r, ngx_temp_file_t *tf);
void ngx_http_file_cache_update_header(ngx_http_request_t *r);
ngx_int_t ngx_http_cache_send(ngx_http_request_t *);
void ngx_http_file_cache_free(ngx_http_cache_t *c, ngx_temp_file_t *tf);
time_t ngx_http_file_cache_valid(ngx_array_t *cache_valid, ngx_uint_t status);

char *ngx_http_file_cache_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_file_cache_valid_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


extern ngx_str_t  ngx_http_cache_status[];


#endif /* _NGX_HTTP_CACHE_H_INCLUDED_ */
