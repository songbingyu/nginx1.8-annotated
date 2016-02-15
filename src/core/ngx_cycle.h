
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

struct ngx_shm_zone_s {
    void                     *data;
    ngx_shm_t                 shm;
    ngx_shm_zone_init_pt      init;
    void                     *tag;
};

// from http://www.jiancool.com/article/3132442090/
struct ngx_cycle_s {
	// 保存着所有模块配置项的结构体指针p,它首先是一个数组,
	// 该数组每个成员又是一个指针,这个指针又指向了存储着指针的数组
    void                  ****conf_ctx;
    ngx_pool_t               *pool;

	// log
    ngx_log_t                *log;

	// 由nginx.conf配置文件读取到日志路径后,将开始初始化error_log日志文件,
	// 由于log对象还在用于输出日志到屏幕,这时候new_log将暂时替代log,
	// 待初始化成功后,会用new_log的地址覆盖上面的指针
    ngx_log_t                 new_log;

    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */
	/*
	对于epoll,rtsig这样的事件模块,会以有效文件句柄树来预先建立
	这些ngx_connection_t结构体,以加速事件的收集,分发.这时files就会
	保存所有ngx_connection_t的指针组成的数组,而文件句柄的值用来访问
	files数组成员.
	*/
    ngx_connection_t        **files;

	// 连接pool
    ngx_connection_t         *free_connections;
    ngx_uint_t                free_connection_n;

	// 可复用连接队列
    ngx_queue_t               reusable_connections_queue;
	// 动态数组,每个成员存储ngx_listening_t成员,表示监听端口以及相关的参数 
    ngx_array_t               listening;
	// 存放缓存在磁盘上的路径的数组。元素的类型为ngx_path_t结构体
    ngx_array_t               paths; 
	// 存放所有打开的文件描述符的列表，files_n保存打开文件的个数
    ngx_list_t                open_files;
	// 使用的所有共享内存区域的列表
    ngx_list_t                shared_memory;

    ngx_uint_t                connection_n;
    ngx_uint_t                files_n;

	// all conn object
    ngx_connection_t         *connections;
	// 当前进程所有读事件
    ngx_event_t              *read_events;
	// 当前进程所有写事件
    ngx_event_t              *write_events;
	/* 
		旧的ngx_cycle_t对象,用于引用上一个ngx_cycle_t对象中的成员.
	    例如 ngx_init_cycle方法在启动初期,需要建立一个临时ngx_cycle_t
	    对象来保存一些变量,再调用ngx_init_cycle方法时,就可以把
	    旧的ngx_cycle_t对象传进去,而这时,这个old_cycle指针
	    就会保存这个前期的ngx_cycle_t对象 
	*/
    ngx_cycle_t              *old_cycle;

	// arg
    ngx_str_t                 conf_file;
    ngx_str_t                 conf_param;
    ngx_str_t                 conf_prefix;
    ngx_str_t                 prefix;
    ngx_str_t                 lock_file;
    ngx_str_t                 hostname;
};


typedef struct {
     ngx_flag_t               daemon;
     ngx_flag_t               master;

     ngx_msec_t               timer_resolution;

     ngx_int_t                worker_processes;
     ngx_int_t                debug_points;

     ngx_int_t                rlimit_nofile;
     ngx_int_t                rlimit_sigpending;
     off_t                    rlimit_core;

     int                      priority;

     ngx_uint_t               cpu_affinity_n;
     uint64_t                *cpu_affinity;

     char                    *username;
     ngx_uid_t                user;
     ngx_gid_t                group;

     ngx_str_t                working_directory;
     ngx_str_t                lock_file;

     ngx_str_t                pid;
     ngx_str_t                oldpid;

     ngx_array_t              env;
     char                   **environment;

#if (NGX_OLD_THREADS)
     ngx_int_t                worker_threads;
     size_t                   thread_stack_size;
#endif

} ngx_core_conf_t;


#if (NGX_OLD_THREADS)

typedef struct {
     ngx_pool_t              *pool;   /* pcre's malloc() pool */
} ngx_core_tls_t;

#endif


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
uint64_t ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_quiet_mode;
#if (NGX_OLD_THREADS)
extern ngx_tls_key_t          ngx_core_tls_key;
#endif


#endif /* _NGX_CYCLE_H_INCLUDED_ */
