/*
 * Copyright (C) 2008 Google, Inc.
 *
 * Based on, but no longer compatible with, the original
 * OpenBinder.org binder driver interface, which is:
 *
 * Copyright (c) 2005 Palmsource, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _LINUX_BINDER_H
#define _LINUX_BINDER_H
#include <stdio.h>
#include <fcntl.h>	// expected specifier-qualifier-list before 'size_t'
#include <stdlib.h>
#include "linuxx/ioctl.h"
#include "pthread.h"

#include "linuxx/errno-base.h"	// ENOMEM ...
#include "linuxx/list.h"
#include "linuxx/rbtree.h"

// for window
#ifdef _WIN32
typedef int uid_t;
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
#define __user
//typedef __typeof typeof;

// fcntl.h
#define O_NONBLOCK 4000
#endif




#define B_PACK_CHARS(c1, c2, c3, c4) \
	((((c1)<<24)) | (((c2)<<16)) | (((c3)<<8)) | (c4))
#define B_TYPE_LARGE 0x85

enum {
	BINDER_TYPE_BINDER	= B_PACK_CHARS('s', 'b', '*', B_TYPE_LARGE),
	BINDER_TYPE_WEAK_BINDER	= B_PACK_CHARS('w', 'b', '*', B_TYPE_LARGE),
	BINDER_TYPE_HANDLE	= B_PACK_CHARS('s', 'h', '*', B_TYPE_LARGE),
	BINDER_TYPE_WEAK_HANDLE	= B_PACK_CHARS('w', 'h', '*', B_TYPE_LARGE),
	BINDER_TYPE_FD		= B_PACK_CHARS('f', 'd', '*', B_TYPE_LARGE),
};

enum {
	FLAT_BINDER_FLAG_PRIORITY_MASK = 0xff,
	FLAT_BINDER_FLAG_ACCEPTS_FDS = 0x100,
};

/*
 * This is the flattened representation of a Binder object for transfer
 * between processes.  The 'offsets' supplied as part of a binder transaction
 * contains offsets into the data where these structures occur.  The Binder
 * driver takes care of re-writing the structure type and data as it moves
 * between processes.
 */
struct flat_binder_object {
	/* 8 bytes for large_flat_header. */
	unsigned long		type;
	unsigned long		flags;

	/* 8 bytes of data. */
	union {
		void		*binder;	/* local object */
		signed long	handle;		/* remote object */
	};

	/* extra data associated with local object */
	void			*cookie;
};

/*
 * On 64-bit platforms where user code may run in 32-bits the driver must
 * translate the buffer (and local binder) addresses apropriately.
 */

struct binder_write_read {
	signed long	write_size;	/* bytes to write */
	signed long	write_consumed;	/* bytes consumed by driver */
	unsigned long	write_buffer;
	signed long	read_size;	/* bytes to read */
	signed long	read_consumed;	/* bytes consumed by driver */
	unsigned long	read_buffer;
};

/* Use with BINDER_VERSION, driver fills in fields. */
struct binder_version {
	/* driver protocol version -- increment with incompatible change */
	signed long	protocol_version;
};

/* This is the current protocol version. */
#define BINDER_CURRENT_PROTOCOL_VERSION 7

#define BINDER_WRITE_READ   		_IOWR('b', 1, struct binder_write_read)
#define	BINDER_SET_IDLE_TIMEOUT		_IOW('b', 3, int64_t)
#define	BINDER_SET_MAX_THREADS		_IOW('b', 5, size_t)
#define	BINDER_SET_IDLE_PRIORITY	_IOW('b', 6, int)
#define	BINDER_SET_CONTEXT_MGR		_IOW('b', 7, int)
#define	BINDER_THREAD_EXIT		_IOW('b', 8, int)
#define BINDER_VERSION			_IOWR('b', 9, struct binder_version)

/*
 * NOTE: Two special error codes you should check for when calling
 * in to the driver are:
 *
 * EINTR -- The operation has been interupted.  This should be
 * handled by retrying the ioctl() until a different error code
 * is returned.
 *
 * ECONNREFUSED -- The driver is no longer accepting operations
 * from your process.  That is, the process is being destroyed.
 * You should handle this by exiting from your process.  Note
 * that once this error code is returned, all further calls to
 * the driver from any thread will return this same code.
 */

enum transaction_flags {
	TF_ONE_WAY	= 0x01,	/* this is a one-way call: async, no return */
	TF_ROOT_OBJECT	= 0x04,	/* contents are the component's root object */
	TF_STATUS_CODE	= 0x08,	/* contents are a 32-bit status code */
	TF_ACCEPT_FDS	= 0x10,	/* allow replies with file descriptors */
};

struct binder_transaction_data {
	/* The first two are only used for bcTRANSACTION and brTRANSACTION,
	 * identifying the target and contents of the transaction.
	 */
	union {
		size_t	handle;	/* target descriptor of command transaction */
		void	*ptr;	/* target descriptor of return transaction */
	} target;
#ifndef USE_COOKIE
	void		*cookie;	/* target object cookie */
#endif
	unsigned int	code;		/* transaction command */

	/* General information about the transaction. */
	unsigned int	flags;
	pid_t		sender_pid;
	uid_t		sender_euid;
	size_t		data_size;	/* number of bytes of data */
	size_t		offsets_size;	/* number of bytes of offsets */

	/* If this transaction is inline, the data immediately
	 * follows here; otherwise, it ends with a pointer to
	 * the data buffer.
	 */
	union {
		struct {
			/* transaction data */
			const void	*buffer;
			/* offsets from buffer to flat_binder_object structs */
			const void	*offsets;
		} ptr;
#ifndef USE_BINDER_TRANSACTION_DATA_BUF
		uint8_t	buf[8];
#endif
	} data;
};

struct binder_ptr_cookie {
	void *ptr;
	void *cookie;
};

struct binder_pri_desc {
	int priority;
	int desc;
};

struct binder_pri_ptr_cookie {
	int priority;
	void *ptr;
	void *cookie;
};

enum BinderDriverReturnProtocol {
	BR_ERROR = _IOR('r', 0, int),
	/*
	 * int: error code
	 */

	BR_OK = _IO('r', 1),
	/* No parameters! */

	BR_TRANSACTION = _IOR('r', 2, struct binder_transaction_data),
	BR_REPLY = _IOR('r', 3, struct binder_transaction_data),
	/*
	 * binder_transaction_data: the received command.
	 */

	BR_ACQUIRE_RESULT = _IOR('r', 4, int),
	/*
	 * not currently supported
	 * int: 0 if the last bcATTEMPT_ACQUIRE was not successful.
	 * Else the remote object has acquired a primary reference.
	 */

	BR_DEAD_REPLY = _IO('r', 5),
	/*
	 * The target of the last transaction (either a bcTRANSACTION or
	 * a bcATTEMPT_ACQUIRE) is no longer with us.  No parameters.
	 */

	BR_TRANSACTION_COMPLETE = _IO('r', 6),
	/*
	 * No parameters... always refers to the last transaction requested
	 * (including replies).  Note that this will be sent even for
	 * asynchronous transactions.
	 */

	BR_INCREFS = _IOR('r', 7, struct binder_ptr_cookie),
	BR_ACQUIRE = _IOR('r', 8, struct binder_ptr_cookie),
	BR_RELEASE = _IOR('r', 9, struct binder_ptr_cookie),
	BR_DECREFS = _IOR('r', 10, struct binder_ptr_cookie),
	/*
	 * void *:	ptr to binder
	 * void *: cookie for binder
	 */

	BR_ATTEMPT_ACQUIRE = _IOR('r', 11, struct binder_pri_ptr_cookie),
	/*
	 * not currently supported
	 * int:	priority
	 * void *: ptr to binder
	 * void *: cookie for binder
	 */

	BR_NOOP = _IO('r', 12),
	/*
	 * No parameters.  Do nothing and examine the next command.  It exists
	 * primarily so that we can replace it with a BR_SPAWN_LOOPER command.
	 */

	BR_SPAWN_LOOPER = _IO('r', 13),
	/*
	 * No parameters.  The driver has determined that a process has no
	 * threads waiting to service incomming transactions.  When a process
	 * receives this command, it must spawn a new service thread and
	 * register it via bcENTER_LOOPER.
	 */

	BR_FINISHED = _IO('r', 14),
	/*
	 * not currently supported
	 * stop threadpool thread
	 */

	BR_DEAD_BINDER = _IOR('r', 15, void *),
	/*
	 * void *: cookie
	 */
	BR_CLEAR_DEATH_NOTIFICATION_DONE = _IOR('r', 16, void *),
	/*
	 * void *: cookie
	 */

	BR_FAILED_REPLY = _IO('r', 17),
	/*
	 * The the last transaction (either a bcTRANSACTION or
	 * a bcATTEMPT_ACQUIRE) failed (e.g. out of memory).  No parameters.
	 */
};

enum BinderDriverCommandProtocol {
	BC_TRANSACTION = _IOW('c', 0, struct binder_transaction_data),
	BC_REPLY = _IOW('c', 1, struct binder_transaction_data),
	/*
	 * binder_transaction_data: the sent command.
	 */

	BC_ACQUIRE_RESULT = _IOW('c', 2, int),
	/*
	 * not currently supported
	 * int:  0 if the last BR_ATTEMPT_ACQUIRE was not successful.
	 * Else you have acquired a primary reference on the object.
	 */

	BC_FREE_BUFFER = _IOW('c', 3, int),
	/*
	 * void *: ptr to transaction data received on a read
	 */

	BC_INCREFS = _IOW('c', 4, int),
	BC_ACQUIRE = _IOW('c', 5, int),
	BC_RELEASE = _IOW('c', 6, int),
	BC_DECREFS = _IOW('c', 7, int),
	/*
	 * int:	descriptor
	 */

	BC_INCREFS_DONE = _IOW('c', 8, struct binder_ptr_cookie),
	BC_ACQUIRE_DONE = _IOW('c', 9, struct binder_ptr_cookie),
	/*
	 * void *: ptr to binder
	 * void *: cookie for binder
	 */

	BC_ATTEMPT_ACQUIRE = _IOW('c', 10, struct binder_pri_desc),
	/*
	 * not currently supported
	 * int: priority
	 * int: descriptor
	 */

	BC_REGISTER_LOOPER = _IO('c', 11),
	/*
	 * No parameters.
	 * Register a spawned looper thread with the device.
	 */

	BC_ENTER_LOOPER = _IO('c', 12),
	BC_EXIT_LOOPER = _IO('c', 13),
	/*
	 * No parameters.
	 * These two commands are sent as an application-level thread
	 * enters and exits the binder loop, respectively.  They are
	 * used so the binder can have an accurate count of the number
	 * of looping threads it has available.
	 */

	BC_REQUEST_DEATH_NOTIFICATION = _IOW('c', 14, struct binder_ptr_cookie),
	/*
	 * void *: ptr to binder
	 * void *: cookie
	 */

	BC_CLEAR_DEATH_NOTIFICATION = _IOW('c', 15, struct binder_ptr_cookie),
	/*
	 * void *: ptr to binder
	 * void *: cookie
	 */

	BC_DEAD_BINDER_DONE = _IOW('c', 16, void *),
	/*
	 * void *: cookie
	 */
};

#ifndef _SHENG_STRUCT
#define _SHENG_STRUCT
// struct define there

struct file {
	void *private_data;
	void *f_flags;
};

void *kzalloc(int Size, int nnn);

enum {
	BINDER_STAT_PROC,
	BINDER_STAT_THREAD,
	BINDER_STAT_NODE,
	BINDER_STAT_REF,
	BINDER_STAT_DEATH,
	BINDER_STAT_TRANSACTION,
	BINDER_STAT_TRANSACTION_COMPLETE,
	BINDER_STAT_COUNT
};

struct binder_stats {
	int br[_IOC_NR(BR_FAILED_REPLY) + 1];
	int bc[_IOC_NR(BC_DEAD_BINDER_DONE) + 1];
	int obj_created[BINDER_STAT_COUNT];
	int obj_deleted[BINDER_STAT_COUNT];
};


struct binder_transaction_log_entry {
	int debug_id;
	int call_type;
	int from_proc;
	int from_thread;
	int target_handle;
	int to_proc;
	int to_thread;
	int to_node;
	int data_size;
	int offsets_size;
};
struct binder_transaction_log {
	int next;
	int full;
	struct binder_transaction_log_entry entry[32];
};

struct binder_work {
	struct list_head entry;
	enum {
		BINDER_WORK_TRANSACTION = 1,
		BINDER_WORK_TRANSACTION_COMPLETE,
		BINDER_WORK_NODE,
		BINDER_WORK_DEAD_BINDER,
		BINDER_WORK_DEAD_BINDER_AND_CLEAR,
		BINDER_WORK_CLEAR_DEATH_NOTIFICATION,
	} type;
};

struct binder_node {
	int debug_id;
	struct binder_work work;
	union {
		struct rb_node rb_node;
		struct hlist_node dead_node;
	};
	struct binder_proc *proc;
	struct hlist_head refs;
	int internal_strong_refs;
	int local_weak_refs;
	int local_strong_refs;
	void __user *ptr;
	void __user *cookie;
	unsigned has_strong_ref : 1;
	unsigned pending_strong_ref : 1;
	unsigned has_weak_ref : 1;
	unsigned pending_weak_ref : 1;
	unsigned has_async_transaction : 1;
	unsigned accept_fds : 1;
	int min_priority : 8;
	struct list_head async_todo;
};

struct binder_ref_death {
	struct binder_work work;
	void __user *cookie;
};

struct binder_ref {
	/* Lookups needed: */
	/*   node + proc => ref (transaction) */
	/*   desc + proc => ref (transaction, inc/dec ref) */
	/*   node => refs + procs (proc exit) */
	int debug_id;
	struct rb_node rb_node_desc;
	struct rb_node rb_node_node;
	struct hlist_node node_entry;
	struct binder_proc *proc;
	struct binder_node *node;
	uint32_t desc;
	int strong;
	int weak;
	struct binder_ref_death *death;
};

struct binder_buffer {
	struct list_head entry; /* free and allocated entries by addesss */
	struct rb_node rb_node; /* free entry by size or allocated entry */
							/* by address */
	unsigned free : 1;
	unsigned allow_user_free : 1;
	unsigned async_transaction : 1;
	unsigned debug_id : 29;

	struct binder_transaction *transaction;

	struct binder_node *target_node;
	size_t data_size;
	size_t offsets_size;
	uint8_t data[0];
};

enum {
	BINDER_DEFERRED_PUT_FILES = 0x01,
	BINDER_DEFERRED_FLUSH = 0x02,
	BINDER_DEFERRED_RELEASE = 0x04,
};

struct binder_proc {
	struct hlist_node proc_node;
	struct rb_root threads;
	struct rb_root nodes;
	struct rb_root refs_by_desc;
	struct rb_root refs_by_node;
	int pid;
	int uid;
	int fd;
	//struct vm_area_struct *vma;
	//struct task_struct *tsk;
	//struct files_struct *files;
// 	struct hlist_node deferred_work_node;// cancel
// 	int deferred_work; // cancel
	void *buffer;
	ptrdiff_t user_buffer_offset;

	struct list_head buffers;
	struct rb_root free_buffers;
	struct rb_root allocated_buffers;
	size_t free_async_space;

// 	struct page **pages; //cancel
	size_t buffer_size;
	uint32_t buffer_free;
	struct list_head todo;
	pthread_cond_t wait;
	struct binder_stats stats;
	struct list_head delivered_death;
	int max_threads;
	int requested_threads;
	int requested_threads_started;
	int ready_threads;
	long default_priority;
};

enum {
	BINDER_LOOPER_STATE_REGISTERED = 0x01,
	BINDER_LOOPER_STATE_ENTERED = 0x02,
	BINDER_LOOPER_STATE_EXITED = 0x04,
	BINDER_LOOPER_STATE_INVALID = 0x08,
	BINDER_LOOPER_STATE_WAITING = 0x10,
	BINDER_LOOPER_STATE_NEED_RETURN = 0x20
};

struct binder_thread {
	struct binder_proc *proc;
	struct rb_node rb_node;
	int pid;
	int looper;
	struct binder_transaction *transaction_stack;
	struct list_head todo;
	uint32_t return_error; /* Write failed, return error code in read buf */
	uint32_t return_error2; /* Write failed, return error code in read */
							/* buffer. Used when sending a reply to a dead process that */
							/* we are also waiting on */
	pthread_cond_t wait;
	struct binder_stats stats;
};

struct binder_transaction {
	int debug_id;
	struct binder_work work;
	struct binder_thread *from;
	struct binder_transaction *from_parent;
	struct binder_proc *to_proc;
	struct binder_thread *to_thread;
	struct binder_transaction *to_parent;
	unsigned need_reply : 1;
	/*unsigned is_dead : 1;*/ /* not used at the moment */

	struct binder_buffer *buffer;
	unsigned int	code;
	unsigned int	flags;
	long	priority;
	long	saved_priority;
	uid_t	sender_euid;
};

enum {
	BINDER_DEBUG_USER_ERROR = 1U << 0,
	BINDER_DEBUG_FAILED_TRANSACTION = 1U << 1,
	BINDER_DEBUG_DEAD_TRANSACTION = 1U << 2,
	BINDER_DEBUG_OPEN_CLOSE = 1U << 3,
	BINDER_DEBUG_DEAD_BINDER = 1U << 4,
	BINDER_DEBUG_DEATH_NOTIFICATION = 1U << 5,
	BINDER_DEBUG_READ_WRITE = 1U << 6,
	BINDER_DEBUG_USER_REFS = 1U << 7,
	BINDER_DEBUG_THREADS = 1U << 8,
	BINDER_DEBUG_TRANSACTION = 1U << 9,
	BINDER_DEBUG_TRANSACTION_COMPLETE = 1U << 10,
	BINDER_DEBUG_FREE_BUFFER = 1U << 11,
	BINDER_DEBUG_INTERNAL_REFS = 1U << 12,
	BINDER_DEBUG_BUFFER_ALLOC = 1U << 13,
	BINDER_DEBUG_PRIORITY_CAP = 1U << 14,
	BINDER_DEBUG_BUFFER_ALLOC_ASYNC = 1U << 15,
};
#endif	// _SHENG_STRUCT

#ifndef _SHENG_DEFINE
#define _SHENG_DEFINE
// define threre
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#define PAGE_MASK (~(PAGE_SIZE-1))
#endif

#ifndef ALIGN	// linux/kernel.h
#if 0
#define ALIGN(x,a)		__ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)	(((x)+(mask))&~(mask))
#define IS_ALIGNED(x, a)		(((x) & ((typeof(x))(a) - 1)) == 0)
// linux/mm.h
#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)
#else
// fix
#define ALIGN(x,type,a)		__ALIGN_MASK(x,(type)(a)-1)
#define __ALIGN_MASK(x,mask)	(((x)+(mask))&~(mask))
#define IS_ALIGNED(x, type, a)		(((x) & ((type)(a) - 1)) == 0)
// linux/mm.h
#define PAGE_ALIGN(addr) ALIGN(addr, uintptr_t, PAGE_SIZE)
#endif
#endif


#define BUG() do{ \
	printf("BUG: failure at %s:%d/%s()!\n", __FILE__, __LINE__, __func__); \
	exit(0); \
} while(0)

#define BUG_ON(condition) do { if (condition) BUG(); } while(0)
#endif

struct remap_global_varable {
	uid_t* binder_context_mgr_uid;
	pthread_mutex_t* binder_lock;
	/*int br[_IOC_NR(BR_FAILED_REPLY) + 1];*/
	uint32_t* binder_stats_br;
	uint32_t* binder_stats_br_0;
	/*int bc[_IOC_NR(BC_DEAD_BINDER_DONE) + 1];*/
	uint32_t* binder_stats_bc;
	/*int obj_created[BINDER_STAT_COUNT];*/
	uint32_t* binder_stats_obj_created_BINDER_STAT_PROC;
	uint32_t* binder_stats_obj_created_BINDER_STAT_THREAD;
	uint32_t* binder_stats_obj_created_BINDER_STAT_NODE;
	uint32_t* binder_stats_obj_created_BINDER_STAT_REF;
	uint32_t* binder_stats_obj_created_BINDER_STAT_DEATH;
	uint32_t* binder_stats_obj_created_BINDER_STAT_TRANSACTION;
	uint32_t* binder_stats_obj_created_BINDER_STAT_TRANSACTION_COMPLETE;
	/*int obj_deleted[BINDER_STAT_COUNT];*/
	uint32_t* binder_stats_obj_deleted_BINDER_STAT_PROC;
	uint32_t* binder_stats_obj_deleted_BINDER_STAT_THREAD;
	uint32_t* binder_stats_obj_deleted_BINDER_STAT_NODE;
	uint32_t* binder_stats_obj_deleted_BINDER_STAT_REF;
	uint32_t* binder_stats_obj_deleted_BINDER_STAT_DEATH;
	uint32_t* binder_stats_obj_deleted_BINDER_STAT_TRANSACTION;
	uint32_t* binder_stats_obj_deleted_BINDER_STAT_TRANSACTION_COMPLETE;
	struct binder_node *binder_context_mgr_node;
	uint32_t* binder_last_id;
	struct hlist_head* binder_procs;
	struct hlist_head* binder_dead_nodes;
};

void InitReMapGlobalPointer();

extern int binder_stop_on_user_error;

void
binder_send_failed_reply(struct binder_transaction *t, uint32_t error_code);

struct binder_node *
binder_get_node(struct binder_proc *proc, void __user *ptr);
struct binder_ref *
binder_get_ref(struct binder_proc *proc, uint32_t desc);

int
binder_dec_ref(struct binder_ref *ref, int strong);

size_t binder_buffer_size(
	struct binder_proc *proc, struct binder_buffer *buffer);
	
int
binder_inc_node(struct binder_node *node, int strong, int internal,
		struct list_head *target_list);

struct binder_node *
binder_new_node(struct binder_proc *proc, void __user *ptr, void __user *cookie);	

struct binder_ref *
binder_get_ref_for_node(struct binder_proc *proc, struct binder_node *node);

int
binder_inc_ref(
	struct binder_ref *ref, int strong, struct list_head *target_list);
	
void
binder_pop_transaction(
	struct binder_thread *target_thread, struct binder_transaction *t);

void
binder_transaction_buffer_release(struct binder_proc *proc, struct binder_buffer *buffer, size_t *failed_at);

void binder_free_buf(
	struct binder_proc *proc, struct binder_buffer *buffer);

void binder_insert_free_buffer(
	struct binder_proc *proc, struct binder_buffer *new_buffer);

int binder_thread_read(struct binder_proc *proc, struct binder_thread *thread, void  __user *buffer, int size, signed long *consumed, int non_block);
int binder_thread_write(struct binder_proc *proc, struct binder_thread *thread, void __user *buffer, int size, signed long *consumed);
long binder_binder_version(unsigned int cmd, unsigned long arg, int f_flags, int pid, int tid);
long binder_set_max_threads(unsigned int cmd, unsigned long arg, int f_flags, int pid, int tid);
long binder_thread_exit(unsigned int cmd, unsigned long arg, int f_flags, int pid, int tid);
long binder_set_context_mgr(unsigned int cmd, unsigned long arg, int f_flags, int pid, int tid);
long binder_ioctl(unsigned int cmd, unsigned long arg, int f_flags, int pid, int tid);
int binder_open(int pid, int uid, int fd);
int binder_mmap(int pid, int map_size, void* old_map_addr);
int binder_release(int pid);
int binder_flush(int pid);


char *print_binder_transaction(char *buf, char *end, const char *prefix, struct binder_transaction *t);
char *print_binder_buffer(char *buf, char *end, const char *prefix, struct binder_buffer *buffer);
char *print_binder_work(char *buf, char *end, const char *prefix, const char *transaction_prefix, struct binder_work *w);
char *print_binder_thread(char *buf, char *end, struct binder_thread *thread, int print_always);
char *print_binder_node(char *buf, char *end, struct binder_node *node);
char *print_binder_ref(char *buf, char *end, struct binder_ref *ref);
char *print_binder_proc(char *buf, char *end, struct binder_proc *proc, int print_all);
char *print_binder_stats(char *buf, char *end, const char *prefix, struct binder_stats *stats);
char *print_binder_proc_stats(char *buf, char *end, struct binder_proc *proc);


#endif /* _LINUX_BINDER_H */

