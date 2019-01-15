/* binder.c
 *
 * Android IPC Subsystem
 *
 * Copyright (C) 2007-2008 Google, Inc.
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

#include <sys/types.h>
#include "stdio.h"
#ifdef _WIN32
#include <io.h>
#include <windows.h>
void WinPrintf(const char* fmt, ...) {
	char msg[0x1000] = {0};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	OutputDebugStringA(msg);
}
#else
void WinPrintf(const char* fmt, ...) {}
#endif
#include <stdint.h>

#include "base/base.h"
#include "binder.h"

#ifndef mutex_lock
static pthread_mutex_t binder_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t s_rlock = PTHREAD_MUTEX_INITIALIZER;
#define mutex_lock(x) BaseAPI::GetInstance()->StructAPI()->pthread_mutex_lock(x)
#define mutex_unlock(x) BaseAPI::GetInstance()->StructAPI()->pthread_mutex_unlock(x)
#define wait_event_interruptible(x,y) BaseAPI::GetInstance()->StructAPI()->pthread_cond_wait(x,y)
#define wake_up_interruptible(x) BaseAPI::GetInstance()->StructAPI()->pthread_cond_signal(x)
#define init_waitqueue_head(x) BaseAPI::GetInstance()->StructAPI()->pthread_cond_init(x, NULL)
#endif

//#include "BinderServer.h"
//#include "BinderThread.h"

#include <stdlib.h>
#pragma comment(lib, "pthreadVC1.lib")


// move 
// #include <pthread.h> // TODO: build-windows

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
// build log
// -----------------------
/*
wait_queue_head_t void*;
wait_event_interruptible  注释了
remove priority  移除了优先级

1. 获取当前进程任务结构体
get_task_struct(current); // TODO: task
proc->tsk = current;

2.映射文件句柄
file  fget
3.
wait_event_interruptible
//

*/

struct remap_global_varable s_ptr;



void InitReMapGlobalPointer() {
	(*(uint32_t*)&s_ptr.binder_lock) = 0x00409000;
	(*(uint32_t*)&s_ptr.binder_context_mgr_uid) = 0x00409004;
	(*(uint32_t*)&s_ptr.binder_stats_br) = 0x0040B020;
	(*(uint32_t*)&s_ptr.binder_stats_br_0) = 0x0040B038;
	(*(uint32_t*)&s_ptr.binder_stats_bc) = 0x0040B068;
	(*(uint32_t*)&s_ptr.binder_stats_obj_created_BINDER_STAT_PROC) = 0x0040B0AC;
	(*(uint32_t*)&s_ptr.binder_stats_obj_created_BINDER_STAT_THREAD) = 0x0040B0B0;
	(*(uint32_t*)&s_ptr.binder_stats_obj_created_BINDER_STAT_NODE) = 0x0040B0B4;
	(*(uint32_t*)&s_ptr.binder_stats_obj_created_BINDER_STAT_REF) = 0x0040B0B8;
	(*(uint32_t*)&s_ptr.binder_stats_obj_created_BINDER_STAT_DEATH) = 0x0040B0BC;
	(*(uint32_t*)&s_ptr.binder_stats_obj_created_BINDER_STAT_TRANSACTION) = 0x0040B0C0;
	(*(uint32_t*)&s_ptr.binder_stats_obj_created_BINDER_STAT_TRANSACTION_COMPLETE) = 0x0040B0C4;
	(*(uint32_t*)&s_ptr.binder_stats_obj_deleted_BINDER_STAT_PROC) = 0x0040B0C8;
	(*(uint32_t*)&s_ptr.binder_stats_obj_deleted_BINDER_STAT_THREAD) = 0x0040B0CC;
	(*(uint32_t*)&s_ptr.binder_stats_obj_deleted_BINDER_STAT_NODE) = 0x0040B0D0;
	(*(uint32_t*)&s_ptr.binder_stats_obj_deleted_BINDER_STAT_REF) = 0x0040B0D4;
	(*(uint32_t*)&s_ptr.binder_stats_obj_deleted_BINDER_STAT_DEATH) = 0x0040B0D8;
	(*(uint32_t*)&s_ptr.binder_stats_obj_deleted_BINDER_STAT_TRANSACTION) = 0x0040B0DC;
	(*(uint32_t*)&s_ptr.binder_stats_obj_deleted_BINDER_STAT_TRANSACTION_COMPLETE) = 0x0040B0E0;
	(*(uint32_t*)&s_ptr.binder_context_mgr_node) = 0x0040B0E4;
	(*(uint32_t*)&s_ptr.binder_last_id) = 0x0040B0E8;
	(*(uint32_t*)&s_ptr.binder_procs) = 0x0040B0EC;
	(*(uint32_t*)&s_ptr.binder_dead_nodes) = 0x0040B0F0;
}

template <class T1, class T2>
T1* Pointer_a(T2* ptr) {
	T1* xxx = reinterpret_cast<T1*>(*(uint32_t*)ptr);
	return xxx;
}

binder_node* Pointer(binder_node* ptr) {
	binder_node* xx = Pointer_a<binder_node>(ptr);
	return xx;
}
pthread_mutex_t* Pointer(pthread_mutex_t* ptr) {
	pthread_mutex_t* xx = Pointer_a<pthread_mutex_t>(ptr);
	return xx;
}

#define xmalloc(x) BaseAPI::GetInstance()->StructAPI()->malloc(x)
#define xfree(x) BaseAPI::GetInstance()->StructAPI()->free(x)



#define copy_from_user(x, y, z) memcpy(x, y, z)
#define copy_to_user(x, y, z) memcpy(x, y, z)
#define get_user(to, from) 	((to = *from) == 0)
#define put_user(from, to) 	((*to = from) == 0)

#if 0
static DEFINE_MUTEX(binder_lock);
static struct proc_dir_entry *binder_proc_dir_entry_root;
static struct proc_dir_entry *binder_proc_dir_entry_proc;
static struct hlist_head binder_dead_nodes;
static HLIST_HEAD(binder_deferred_list);
static DEFINE_MUTEX(binder_deferred_lock);
#endif







int binder_read_proc_proc(
	char *page, char **start, off_t off, int count, int *eof, void *data);

/* This is only defined in include/asm-arm/sizes.h */
#ifndef SZ_1K
#define SZ_1K                               0x400
#endif

#ifndef SZ_4M
#define SZ_4M                               0x400000
#endif

#define FORBIDDEN_MMAP_FLAGS                (VM_WRITE)

#define BINDER_SMALL_BUF_SIZE (PAGE_SIZE * 64)






// static struct pthread_cond_t binder_user_error_wait = PTHREAD_COND_INITIALIZER;

#if 0
//module_param_named(debug_mask, binder_debug_mask, uint, S_IWUSR | S_IRUGO);
static int binder_debug_no_lock;
//module_param_named(proc_no_lock, binder_debug_no_lock, bool, S_IWUSR | S_IRUGO);
static DECLARE_WAIT_QUEUE_HEAD(binder_user_error_wait);
static int binder_set_stop_on_user_error(
	const char *val, struct kernel_param *kp)
{
	int ret;
	ret = param_set_int(val, kp);
	if (binder_stop_on_user_error < 2)
		wake_up(&binder_user_error_wait);
	return ret;
}
module_param_call(stop_on_user_error, binder_set_stop_on_user_error,
	param_get_int, &binder_stop_on_user_error, S_IWUSR | S_IRUGO);

#endif


struct binder_stats binder_stats;
struct binder_transaction_log binder_transaction_log;
struct binder_transaction_log binder_transaction_log_failed;
static struct binder_transaction_log_entry *binder_transaction_log_add(struct binder_transaction_log *log)

{
	struct binder_transaction_log_entry *e;
	e = &log->entry[log->next];
	memset(e, 0, sizeof(*e));
	log->next++;
	if (log->next == ARRAY_SIZE(log->entry)) {
		log->next = 0;
		log->full = 1;
	}
	return e;
}

int binder_stop_on_user_error;
// TODO:注释了printf
#define binder_user_error(x, ...) \
	do { \
		if (binder_debug_mask & BINDER_DEBUG_USER_ERROR) \
			/*printf(x);*/ \
		if (binder_stop_on_user_error) \
			binder_stop_on_user_error = 2; \
	} while (0)

#ifndef kzalloc
void *kzalloc(int Size, int nnn)
{
	void *tmp = xmalloc(Size);
	memset(tmp, 0, Size);
	return tmp;
}
#define kfree(x) xfree(x)
#define GFP_KERNEL 0
#endif

uid_t binder_context_mgr_uid = -1;
int binder_last_id;

HLIST_HEAD(binder_procs);

struct binder_node *binder_context_mgr_node;

uint32_t binder_debug_mask = BINDER_DEBUG_USER_ERROR |
BINDER_DEBUG_FAILED_TRANSACTION | BINDER_DEBUG_DEAD_TRANSACTION | BINDER_DEBUG_READ_WRITE| BINDER_DEBUG_THREADS| BINDER_DEBUG_TRANSACTION| BINDER_DEBUG_TRANSACTION_COMPLETE;


static void *buffer_start_page(struct binder_buffer *buffer)
{
	return (void *)((uintptr_t)buffer & PAGE_MASK);
}

static void *buffer_end_page(struct binder_buffer *buffer)
{
	return (void *)(((uintptr_t)(buffer + 1) - 1) & PAGE_MASK);
}

static int
binder_has_proc_work(struct binder_proc *proc, struct binder_thread *thread)
{
	return !list_empty(&proc->todo) || (thread->looper & BINDER_LOOPER_STATE_NEED_RETURN);
}

static int
binder_has_thread_work(struct binder_thread *thread)
{
	return !list_empty(&thread->todo) || thread->return_error != BR_OK ||
		(thread->looper & BINDER_LOOPER_STATE_NEED_RETURN);
}

void
binder_stat_br(struct binder_proc *proc, struct binder_thread *thread, uint32_t cmd)
{
	if (_IOC_NR(cmd) < ARRAY_SIZE(binder_stats.br)) {
		{
			s_ptr.binder_stats_br[_IOC_NR(cmd)]++;
			/*binder_stats.br[_IOC_NR(cmd)]++;*/
		}
		proc->stats.br[_IOC_NR(cmd)]++;
		thread->stats.br[_IOC_NR(cmd)]++;
	}
}

/*
 * copied from sys_close
 */
static long task_close_fd(struct binder_proc *proc, unsigned int fd)
{
// TODO: deal with
#if 0
	struct file *filp;
	struct files_struct *files = proc->files;
	struct fdtable *fdt;
	int retval;

	if (files == NULL)
		return -ESRCH;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	if (fd >= fdt->max_fds)
		goto out_unlock;
	filp = fdt->fd[fd];
	if (!filp)
		goto out_unlock;
	rcu_assign_pointer(fdt->fd[fd], NULL);
	FD_CLR(fd, fdt->close_on_exec);
	__put_unused_fd(files, fd);
	spin_unlock(&files->file_lock);
	retval = filp_close(filp, files);

	/* can't restart close syscall because file table entry was cleared */
	if (unlikely(retval == -ERESTARTSYS ||
		     retval == -ERESTARTNOINTR ||
		     retval == -ERESTARTNOHAND ||
		     retval == -ERESTART_RESTARTBLOCK))
		retval = -EINTR;

	return retval;

out_unlock:
	spin_unlock(&files->file_lock);
	return -EBADF;
#endif
	return -1;	
}


static int binder_update_page_range(struct binder_proc *proc, int allocate,
	void *start, void *end, struct vm_area_struct *vma)
{
// TODO: 用户空间跟内核空间建立映射
#if 0
	void *page_addr;
	unsigned long user_page_addr;
	struct vm_struct tmp_area;
	struct page **page;
	struct mm_struct *mm;

	if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
		printf( "binder: %d: %s pages %p-%p\n",
		       proc->pid, allocate ? "allocate" : "free", start, end);

	if (end <= start)
		return 0;

	if (vma)
		mm = NULL;
	else
		mm = get_task_mm(proc->tsk);

	if (mm) {
		down_write(&mm->mmap_sem);
		vma = proc->vma;
	}

	if (allocate == 0)
		goto free_range;

	if (vma == NULL) {
		printf( "binder: %d: binder_alloc_buf failed to "
		       "map pages in userspace, no vma\n", proc->pid);
		goto err_no_vma;
	}

	for (page_addr = start; page_addr < end; page_addr += PAGE_SIZE) {
		int ret;
		struct page **page_array_ptr;
		page = &proc->pages[(page_addr - proc->buffer) / PAGE_SIZE];

		BUG_ON(*page);
		*page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (*page == NULL) {
			printf( "binder: %d: binder_alloc_buf failed "
			       "for page at %p\n", proc->pid, page_addr);
			goto err_alloc_page_failed;
		}
		tmp_area.addr = page_addr;
		tmp_area.size = PAGE_SIZE + PAGE_SIZE /* guard page? */;
		page_array_ptr = page;
		ret = map_vm_area(&tmp_area, PAGE_KERNEL, &page_array_ptr);
		if (ret) {
			printf( "binder: %d: binder_alloc_buf failed "
			       "to map page at %p in kernel\n",
			       proc->pid, page_addr);
			goto err_map_kernel_failed;
		}
		user_page_addr =
			(uintptr_t)page_addr + proc->user_buffer_offset;
		ret = vm_insert_page(vma, user_page_addr, page[0]);
		if (ret) {
			printf( "binder: %d: binder_alloc_buf failed "
			       "to map page at %lx in userspace\n",
			       proc->pid, user_page_addr);
			goto err_vm_insert_page_failed;
		}
		/* vm_insert_page does not seem to increment the refcount */
	}
	if (mm) {
		up_write(&mm->mmap_sem);
		mmput(mm);
	}
	return 0;

free_range:
	for (page_addr = end - PAGE_SIZE; page_addr >= start;
	     page_addr -= PAGE_SIZE) {
		page = &proc->pages[(page_addr - proc->buffer) / PAGE_SIZE];
		if (vma)
			zap_page_range(vma, (uintptr_t)page_addr +
				proc->user_buffer_offset, PAGE_SIZE, NULL);
err_vm_insert_page_failed:
		unmap_kernel_range((unsigned long)page_addr, PAGE_SIZE);
err_map_kernel_failed:
		__free_page(*page);
		*page = NULL;
err_alloc_page_failed:
		;
	}
err_no_vma:
	if (mm) {
		up_write(&mm->mmap_sem);
		mmput(mm);
	}
	return -ENOMEM;
#endif
	return -1;	
}

static void binder_set_nice(long nice)
{
// remove priority 任务结构体相关 
#if 0
	long min_nice;
	if (can_nice(current, nice)) {
		set_user_nice(current, nice);
		return;
	}
	min_nice = 20 - current->signal->rlim[RLIMIT_NICE].rlim_cur;
	if (binder_debug_mask & BINDER_DEBUG_PRIORITY_CAP)
		printf( "binder: %d: nice value %ld not allowed use "
		       "%ld instead\n", current->pid, nice, min_nice);
	set_user_nice(current, min_nice);	// kernel/sched.c
	if (min_nice < 20)
		return;
	binder_user_error("binder: %d RLIMIT_NICE not set\n", current->pid);
#endif	
}

struct binder_proc* GetBinderProc(size_t pid) {
	struct binder_proc *proc;
	struct hlist_node *pos;
	hlist_for_each_entry(proc, struct binder_proc, pos, &binder_procs, proc_node) {
		if (pid == proc->pid) {
			return proc;
		}
	}
	return nullptr;
}


static void binder_insert_allocated_buffer(
	struct binder_proc *proc, struct binder_buffer *new_buffer)
{
	struct rb_node **p = &proc->allocated_buffers.rb_node;
	struct rb_node *parent = NULL;
	struct binder_buffer *buffer;

	BUG_ON(new_buffer->free);

	while (*p) {
		parent = *p;
		buffer = rb_entry(parent, struct binder_buffer, rb_node);
		BUG_ON(buffer->free);

		if (new_buffer < buffer)
			p = &parent->rb_left;
		else if (new_buffer > buffer)
			p = &parent->rb_right;
		else
			BUG();
	}
	rb_link_node(&new_buffer->rb_node, parent, p);
	rb_insert_color(&new_buffer->rb_node, &proc->allocated_buffers);
}

inline struct binder_buffer *binder_alloc_buf(struct binder_proc *proc,
	size_t data_size, size_t offsets_size, int is_async)
{
	struct rb_node *n = proc->free_buffers.rb_node;
	struct binder_buffer *buffer;
	size_t buffer_size;
	struct rb_node *best_fit = NULL;
	void *has_page_addr;
	void *end_page_addr;
	size_t size;

#if 0
	if (proc->vma == NULL) {
		printf( "binder: %d: binder_alloc_buf, no vma\n",
		       proc->pid);
		return NULL;
	}
#endif

	size = ALIGN(data_size, size_t, sizeof(void *)) +
		ALIGN(offsets_size, size_t, sizeof(void *));

	if (size < data_size || size < offsets_size) {
		binder_user_error("binder: %d: got transaction with invalid "
			"size %zd-%zd\n", proc->pid, data_size, offsets_size);
		return NULL;
	}

	if (is_async &&
	    proc->free_async_space < size + sizeof(struct binder_buffer)) {
		if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
			printf( "binder: %d: binder_alloc_buf size %zd f"
			       "ailed, no async space left\n", proc->pid, size);
		return NULL;
	}

	while (n) {
		buffer = rb_entry(n, struct binder_buffer, rb_node);
		BUG_ON(!buffer->free);
		buffer_size = binder_buffer_size(proc, buffer);

		if (size < buffer_size) {
			best_fit = n;
			n = n->rb_left;
		} else if (size > buffer_size)
			n = n->rb_right;
		else {
			best_fit = n;
			break;
		}
	}
	if (best_fit == NULL) {
		printf( "binder: %d: binder_alloc_buf size %zd failed, "
		       "no address space\n", proc->pid, size);
		return NULL;
	}
	if (n == NULL) {
		buffer = rb_entry(best_fit, struct binder_buffer, rb_node);
		buffer_size = binder_buffer_size(proc, buffer);
	}
	if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
		printf( "binder: %d: binder_alloc_buf size %zd got buff"
		       "er %p size %zd\n", proc->pid, size, buffer, buffer_size);
	has_page_addr =
		(void *)(((uintptr_t)buffer->data + buffer_size) & PAGE_MASK);
	if (n == NULL) {
		if (size + sizeof(struct binder_buffer) + 4 >= buffer_size)
			buffer_size = size; /* no room for other buffers */
		else
			buffer_size = size + sizeof(struct binder_buffer);
	}
	end_page_addr =
		(void *)PAGE_ALIGN((uintptr_t)buffer->data + buffer_size);
	if (end_page_addr > has_page_addr)
		end_page_addr = has_page_addr;
#if 0
	if (binder_update_page_range(proc, 1,
	    (void *)PAGE_ALIGN((uintptr_t)buffer->data), end_page_addr, NULL))
		return NULL;
#endif
	rb_erase(best_fit, &proc->free_buffers);
	buffer->free = 0;
	binder_insert_allocated_buffer(proc, buffer);
	if (buffer_size != size) {
		struct binder_buffer *new_buffer = (binder_buffer *)((uintptr_t *)buffer->data + size);
		list_add(&new_buffer->entry, &buffer->entry);
		new_buffer->free = 1;
		binder_insert_free_buffer(proc, new_buffer);
	}
	if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
		printf( "binder: %d: binder_alloc_buf size %zd got "
		       "%p\n", proc->pid, size, buffer);
	buffer->data_size = data_size;
	buffer->offsets_size = offsets_size;
	buffer->async_transaction = is_async;
	if (is_async) {
		proc->free_async_space -= size + sizeof(struct binder_buffer);
		if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC_ASYNC)
			printf( "binder: %d: binder_alloc_buf size %zd "
			       "async free %zd\n", proc->pid, size,
			       proc->free_async_space);
	}

	return buffer;
}

static void binder_insert_free_buffer(
	struct binder_proc *proc, struct binder_buffer *new_buffer)
{
	struct rb_node **p = &proc->free_buffers.rb_node;
	struct rb_node *parent = NULL;
	struct binder_buffer *buffer;
	size_t buffer_size;
	size_t new_buffer_size;

	BUG_ON(!new_buffer->free);

	new_buffer_size = binder_buffer_size(proc, new_buffer);

	if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
		printf( "binder: %d: add free buffer, size %zd, "
		       "at %p\n", proc->pid, new_buffer_size, new_buffer);

	while (*p) {
		parent = *p;
		buffer = rb_entry(parent, struct binder_buffer, rb_node);
		BUG_ON(!buffer->free);

		buffer_size = binder_buffer_size(proc, buffer);

		if (new_buffer_size < buffer_size)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}
	rb_link_node(&new_buffer->rb_node, parent, p);
	rb_insert_color(&new_buffer->rb_node, &proc->free_buffers);
}

static void binder_delete_free_buffer(
	struct binder_proc *proc, struct binder_buffer *buffer)
{
	struct binder_buffer *prev, *next = NULL;
	int free_page_end = 1;
	int free_page_start = 1;

	BUG_ON(proc->buffers.next == &buffer->entry);
	prev = list_entry(buffer->entry.prev, struct binder_buffer, entry);
	BUG_ON(!prev->free);
	if (buffer_end_page(prev) == buffer_start_page(buffer)) {
		free_page_start = 0;
		if (buffer_end_page(prev) == buffer_end_page(buffer))
			free_page_end = 0;
		if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
			printf( "binder: %d: merge free, buffer %p "
			       "share page with %p\n", proc->pid, buffer, prev);
	}

	if (!list_is_last(&buffer->entry, &proc->buffers)) {
		next = list_entry(buffer->entry.next,
				  struct binder_buffer, entry);
		if (buffer_start_page(next) == buffer_end_page(buffer)) {
			free_page_end = 0;
			if (buffer_start_page(next) ==
			    buffer_start_page(buffer))
				free_page_start = 0;
			if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
				printf( "binder: %d: merge free, "
				       "buffer %p share page with %p\n",
				       proc->pid, buffer, prev);
		}
	}
	list_del(&buffer->entry);
	if (free_page_start || free_page_end) {
		if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
			printf( "binder: %d: merge free, buffer %p do "
			       "not share page%s%s with with %p or %p\n",
			       proc->pid, buffer, free_page_start ? "" : " end",
			       free_page_end ? "" : " start", prev, next);
		binder_update_page_range(proc, 0, free_page_start ?
			buffer_start_page(buffer) : buffer_end_page(buffer),
			(void*)((int)(free_page_end ? buffer_end_page(buffer) : buffer_start_page(buffer)) + PAGE_SIZE), NULL);
	}
}

int
binder_dec_node(struct binder_node *node, int strong, int internal)
{
	if (strong) {
		if (internal)
			node->internal_strong_refs--;
		else
			node->local_strong_refs--;
		if (node->local_strong_refs || node->internal_strong_refs)
			return 0;
	}
	else {
		if (!internal)
			node->local_weak_refs--;
		if (node->local_weak_refs || !hlist_empty(&node->refs))
			return 0;
	}
	if (node->proc && (node->has_strong_ref || node->has_weak_ref)) {
		if (list_empty(&node->work.entry)) {
			list_add_tail(&node->work.entry, &node->proc->todo);
			wake_up_interruptible(&node->proc->wait);
		}
	}
	else {
		if (hlist_empty(&node->refs) && !node->local_strong_refs &&
			!node->local_weak_refs) {
			list_del_init(&node->work.entry);
			if (node->proc) {
				rb_erase(&node->rb_node, &node->proc->nodes);
				if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
					printf("binder: refless node %d deleted\n", node->debug_id);
			}
			else {
				hlist_del(&node->dead_node);
				if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
					printf("binder: dead node %d deleted\n", node->debug_id);
			}
			kfree(node);
			binder_stats.obj_deleted[BINDER_STAT_NODE]++;
		}
	}
	return 0;
}

static void
binder_transaction(struct binder_proc *proc, struct binder_thread *thread,
	struct binder_transaction_data *tr,void* ptr, int reply)
{
#if 1
	struct binder_work *tcomplete = nullptr;
	uint32_t *offp, *off_end = nullptr;
	struct binder_proc *target_proc = nullptr;
	struct binder_thread *target_thread = NULL;
	struct binder_node *target_node = NULL;
	struct list_head *target_list = nullptr;
	pthread_cond_t *target_wait = nullptr;
	struct binder_transaction *in_reply_to = NULL;
// 	struct binder_transaction_log_entry *e;
	uint32_t return_error;

// 	e = binder_transaction_log_add(&binder_transaction_log);
// 	e->call_type = reply ? 2 : !!(tr->flags & TF_ONE_WAY);
// 	e->from_proc = proc->pid;
// 	e->from_thread = thread->pid;
// 	e->target_handle = tr->target.handle;
// 	e->data_size = tr->data_size;
// 	e->offsets_size = tr->offsets_size;

	if (reply) {
		in_reply_to = thread->transaction_stack;
		if (in_reply_to == NULL) {
			binder_user_error("binder: %d:%d got reply transaction with no transaction stack\n",proc->pid, thread->pid);
			return_error = BR_FAILED_REPLY;
			goto err_empty_call_stack;
		}
		//binder_set_nice(in_reply_to->saved_priority);
		if (in_reply_to->to_thread != thread) {
			binder_user_error("binder: %d:%d got reply transaction "
				"with bad transaction stack,"
				" transaction %d has target %d:%d\n",
				proc->pid, thread->pid, in_reply_to->debug_id,
				in_reply_to->to_proc ?
				in_reply_to->to_proc->pid : 0,
				in_reply_to->to_thread ?
				in_reply_to->to_thread->pid : 0);
			return_error = BR_FAILED_REPLY;
			in_reply_to = NULL;
			goto err_bad_call_stack;
		}
		{
			//FIX
// 			thread->transaction_stack = in_reply_to->to_parent;
			in_reply_to->to_thread->transaction_stack = in_reply_to->to_parent;
		}
		target_thread = in_reply_to->from;
		if (target_thread == NULL) {
			return_error = BR_DEAD_REPLY;
			goto err_dead_binder;
		}
		if (target_thread->transaction_stack != in_reply_to) {
			binder_user_error("binder: %d:%d got reply transaction "
				"with bad target transaction stack %d, "
				"expected %d\n",
				proc->pid, thread->pid,
				target_thread->transaction_stack ?
				target_thread->transaction_stack->debug_id : 0,
				in_reply_to->debug_id);
			return_error = BR_FAILED_REPLY;
			in_reply_to = NULL;
			target_thread = NULL;
			goto err_dead_binder;
		}
		target_proc = target_thread->proc;
	} else {
		if (tr->target.handle) {
			struct binder_ref *ref;
			ref = binder_get_ref(proc, tr->target.handle);
			if (ref == NULL) {
				binder_user_error("binder: %d:%d got "
					"transaction to invalid handle\n",
					proc->pid, thread->pid);
				return_error = BR_FAILED_REPLY;
				goto err_invalid_target_handle;
			}
			target_node = ref->node;
		} else {
			{
				target_node = Pointer(s_ptr.binder_context_mgr_node);
				/*target_node = binder_context_mgr_node;*/
			}
			if (target_node == NULL) {
				return_error = BR_DEAD_REPLY;
				goto err_no_context_mgr_node;
			}
		}
// 		e->to_node = target_node->debug_id;
		target_proc = target_node->proc;
		if (target_proc == NULL) {
			return_error = BR_DEAD_REPLY;
			goto err_dead_binder;
		}
		if (!(tr->flags & TF_ONE_WAY) && thread->transaction_stack) {
			struct binder_transaction *tmp;
			tmp = thread->transaction_stack;
			if (tmp->to_thread != thread) {
				binder_user_error("binder: %d:%d got new "
					"transaction with bad transaction stack"
					", transaction %d has target %d:%d\n",
					proc->pid, thread->pid, tmp->debug_id,
					tmp->to_proc ? tmp->to_proc->pid : 0,
					tmp->to_thread ?
					tmp->to_thread->pid : 0);
				return_error = BR_FAILED_REPLY;
				goto err_bad_call_stack;
			}
			while (tmp) {
				if (tmp->from && tmp->from->proc == target_proc)
					target_thread = tmp->from;
				tmp = tmp->from_parent;
			}
		}
	}
	if (target_thread) {
		target_list = &target_thread->todo;
		target_wait = &target_thread->wait;
	}
	else {
		target_list = &target_proc->todo;
		target_wait = &target_proc->wait;
	}

	/* TODO: reuse incoming transaction for reply */
	struct binder_transaction* tttttt = (struct binder_transaction*)kzalloc(sizeof(*tttttt), GFP_KERNEL);
	if (tttttt == NULL) {
		{
// 			return_error = BR_FAILED_REPLY;
// 			goto err_alloc_t_failed;
			if (in_reply_to)
			{
				return_error = BR_FAILED_REPLY;
				goto err_alloc_t_failed;
			}
			else {
				thread->return_error = BR_FAILED_REPLY;
				return;
			}
		}
	}
	{
		s_ptr.binder_stats_obj_created_BINDER_STAT_TRANSACTION[0]++;
		/*binder_stats.obj_created[BINDER_STAT_TRANSACTION]++;*/
	}
	tcomplete = (binder_work*)kzalloc(sizeof(*tcomplete), GFP_KERNEL);
	if (tcomplete == NULL) {
		return_error = BR_FAILED_REPLY;
		goto err_alloc_tcomplete_failed;
	}
	memset(tcomplete, 0, sizeof(*tcomplete));
	{
		s_ptr.binder_stats_obj_created_BINDER_STAT_TRANSACTION_COMPLETE[0]++;
		tttttt->debug_id = ++s_ptr.binder_last_id[0];
		/*binder_stats.obj_created[BINDER_STAT_TRANSACTION_COMPLETE]++;*/
		/*tttttt->debug_id = ++binder_last_id;*/
	}

	if (binder_debug_mask & BINDER_DEBUG_TRANSACTION) {
		if (reply)
			printf( "binder: %d:%d BC_REPLY %d -> %d:%d, "
			       "data %p-%p size %zd-%zd\n",
			       proc->pid, thread->pid, tttttt->debug_id,
			       target_proc->pid, target_thread->pid,
			       tr->data.ptr.buffer, tr->data.ptr.offsets,
			       tr->data_size, tr->offsets_size);
		else
			printf( "binder: %d:%d BC_TRANSACTION %d -> "
			       "%d - node %d, data %p-%p size %zd-%zd\n",
			       proc->pid, thread->pid, tttttt->debug_id,
			       target_proc->pid, target_node->debug_id,
			       tr->data.ptr.buffer, tr->data.ptr.offsets,
			       tr->data_size, tr->offsets_size);
	}

	if (!reply && !(tr->flags & TF_ONE_WAY))
		tttttt->from = thread;
	else
		tttttt->from = NULL;
	tttttt->sender_euid = target_proc->uid;	// TODO:
	tttttt->to_proc = target_proc;
	tttttt->to_thread = target_thread;
	tttttt->code = tr->code;
	tttttt->flags = tr->flags;
	//tttttt->priority = task_nice(current);	// remove priority
	tttttt->buffer = binder_alloc_buf(target_proc, tr->data_size,
		tr->offsets_size, !reply && (tttttt->flags & TF_ONE_WAY));
	if (tttttt->buffer == NULL) {
		return_error = BR_FAILED_REPLY;
		goto err_binder_alloc_buf_failed;
	}
	tttttt->buffer->allow_user_free = 0;
	tttttt->buffer->debug_id = tttttt->debug_id;
	tttttt->buffer->transaction = tttttt;
	tttttt->buffer->target_node = target_node;
	if (target_node) {
		binder_inc_node(target_node, 1, 0, NULL);
	}

	unsigned long* p1 = (unsigned long*)tttttt->buffer;
	{
		// 	offp = (uint32_t *)((unsigned long)tttttt->buffer->data + tr->data_size);
		offp = (uint32_t *)(tttttt->buffer->data + ALIGN(tr->data_size, uint32_t, sizeof(void *)));
	}
/*	WinPrintf("tttttt->buffer %p:tttttt->buffer->data %P", tttttt->buffer, tttttt->buffer->data);*/
#if 1
	copy_from_user(tttttt->buffer->data, ptr, tr->data_size);
	copy_from_user(offp, (char*)((unsigned long)ptr + tr->data_size), tr->offsets_size);
#else
	copy_from_user(tttttt->buffer->data, tr->data.ptr.buffer, tr->data_size);
	copy_from_user(offp, tr->data.ptr.offsets, tr->offsets_size);
#endif
	if (!IS_ALIGNED(tr->offsets_size, size_t, sizeof(size_t))) {
		binder_user_error("binder: %d:%d got transaction with "
			"invalid offsets size, %zd\n",
			proc->pid, thread->pid, tr->offsets_size);
		return_error = BR_FAILED_REPLY;
		goto err_bad_offset;
	}
	off_end = (size_t*)((size_t)offp + tr->offsets_size);
	for (; offp < off_end; offp++) {
		struct flat_binder_object *fp;
		if (*offp>tttttt->buffer->data_size - sizeof(*fp)){
		//if (*offp > tttttt->buffer->data_size - sizeof(*fp) ||
		//    tttttt->buffer->data_size < sizeof(*fp) ||
		//    !IS_ALIGNED(*offp, size_t, sizeof(void *))) {
			binder_user_error("binder: %d:%d got transaction with "
				"invalid offset, %zd\n",
				proc->pid, thread->pid, *offp);
			return_error = BR_FAILED_REPLY;
			goto err_bad_offset;
		}
		fp = (struct flat_binder_object *)(tttttt->buffer->data + *offp);
		switch (fp->type) {
		case BINDER_TYPE_BINDER:
		case BINDER_TYPE_WEAK_BINDER: {
			struct binder_ref *ref;
			struct binder_node *node = binder_get_node(proc, fp->binder);
			if (node == NULL) {
				node = binder_new_node(proc, fp->binder, fp->cookie);
				if (node == NULL) {
					return_error = BR_FAILED_REPLY;
					goto err_binder_new_node_failed;
				}
				node->min_priority = fp->flags & FLAT_BINDER_FLAG_PRIORITY_MASK;
				node->accept_fds = !!(fp->flags & FLAT_BINDER_FLAG_ACCEPTS_FDS);	
			}
			if (fp->cookie != node->cookie) {
				binder_user_error("binder: %d:%d sending u%p "
					"node %d, cookie mismatch %p != %p\n",
					proc->pid, thread->pid,
					fp->binder, node->debug_id,
					fp->cookie, node->cookie);
				goto err_binder_get_ref_for_node_failed;
			}
			ref = binder_get_ref_for_node(target_proc, node);
			if (ref == NULL) {
				return_error = BR_FAILED_REPLY;
				goto err_binder_get_ref_for_node_failed;
			}
			if (fp->type == BINDER_TYPE_BINDER)
				fp->type = BINDER_TYPE_HANDLE;
			else
				fp->type = BINDER_TYPE_WEAK_HANDLE;
			fp->handle = ref->desc;
			binder_inc_ref(ref, fp->type == BINDER_TYPE_HANDLE, &thread->todo);
			if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
				printf( "        node %d u%p -> ref %d desc %d\n",
				       node->debug_id, node->ptr, ref->debug_id, ref->desc);
		} break;
		case BINDER_TYPE_HANDLE:
		case BINDER_TYPE_WEAK_HANDLE: {
			struct binder_ref *ref = binder_get_ref(proc, fp->handle);
			if (ref == NULL) {
				binder_user_error("binder: %d:%d got "
					"transaction with invalid "
					"handle, %ld\n", proc->pid,
					thread->pid, fp->handle);
				return_error = BR_FAILED_REPLY;
				goto err_binder_get_ref_failed;
			}
			if (ref->node->proc == target_proc) {
				if (fp->type == BINDER_TYPE_HANDLE)
					fp->type = BINDER_TYPE_BINDER;
				else
					fp->type = BINDER_TYPE_WEAK_BINDER;
				fp->binder = ref->node->ptr;
				fp->cookie = ref->node->cookie;
				binder_inc_node(ref->node, fp->type == BINDER_TYPE_BINDER, 0, NULL);
				if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
					printf( "        ref %d desc %d -> node %d u%p\n",
					       ref->debug_id, ref->desc, ref->node->debug_id, ref->node->ptr);
			} else {
				struct binder_ref *new_ref;
				new_ref = binder_get_ref_for_node(target_proc, ref->node);
				if (new_ref == NULL) {
					return_error = BR_FAILED_REPLY;
					goto err_binder_get_ref_for_node_failed;
				}
				fp->handle = new_ref->desc;
				binder_inc_ref(new_ref, fp->type == BINDER_TYPE_HANDLE, NULL);
				if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
					printf( "        ref %d desc %d -> ref %d desc %d (node %d)\n",
					       ref->debug_id, ref->desc, new_ref->debug_id, new_ref->desc, ref->node->debug_id);
			}
		} break;

		case BINDER_TYPE_FD: {
			int target_fd;
			struct file *file;

			if (reply) {
				if (!(in_reply_to->flags & TF_ACCEPT_FDS)) {
					binder_user_error("binder: %d:%d got reply with fd, %ld, but target does not allow fds\n",
						proc->pid, thread->pid, fp->handle);
					return_error = BR_FAILED_REPLY;
					goto err_fd_not_allowed;
				}
			} else if (!target_node->accept_fds) {
				binder_user_error("binder: %d:%d got transaction with fd, %ld, but target does not allow fds\n",
					proc->pid, thread->pid, fp->handle);
				return_error = BR_FAILED_REPLY;
				goto err_fd_not_allowed;
			}
			#if 0 // dup
			// TODO: deal with
			file = fget(fp->handle);
			if (file == NULL) {
				binder_user_error("binder: %d:%d got transaction with invalid fd, %ld\n",
					proc->pid, thread->pid, fp->handle);
				return_error = BR_FAILED_REPLY;
				goto err_fget_failed;
			}
			target_fd = task_get_unused_fd_flags(target_proc, O_CLOEXEC);
			if (target_fd < 0) {
				fput(file);
				return_error = BR_FAILED_REPLY;
				goto err_get_unused_fd_failed;
			}
			task_fd_install(target_proc, target_fd, file);
			if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
				printf( "        fd %ld -> %d\n", fp->handle, target_fd);
			/* TODO: fput? */
			fp->handle = target_fd;
#else
			HANDLE target_hd = nullptr;
			HANDLE target_process = OpenProcess(PROCESS_ALL_ACCESS, TRUE, target_proc->pid);
			DuplicateHandle(GetCurrentProcess(), (HANDLE)fp->cookie, target_process, &target_hd, 0, 0, DUPLICATE_SAME_ACCESS);
			CloseHandle((HANDLE)fp->cookie);
			fp->cookie = target_hd;
			#endif
		} break;

		default:
			binder_user_error("binder: %d:%d got transactio"
				"n with invalid object type, %lx\n",
				proc->pid, thread->pid, fp->type);
			return_error = BR_FAILED_REPLY;
			goto err_bad_object_type;
		}
	}
	if (reply) {
/*		BUG_ON(tttttt->buffer->async_transaction != 0);*/
		binder_pop_transaction(target_thread, in_reply_to);
	} else if (!(tttttt->flags & TF_ONE_WAY)) {
/*		BUG_ON(tttttt->buffer->async_transaction != 0);*/
		tttttt->need_reply = 1;
		tttttt->from_parent = thread->transaction_stack;
		thread->transaction_stack = tttttt;
	} else {
// 		BUG_ON(target_node == NULL);
// 		BUG_ON(tttttt->buffer->async_transaction != 1);
		if (target_node->has_async_transaction) {
			target_list = &target_node->async_todo;
			target_wait = NULL;
		} else
			target_node->has_async_transaction = 1;
	}
	tttttt->work.type = binder_work::BINDER_WORK_TRANSACTION;
	list_add_tail(&tttttt->work.entry, target_list);
	tcomplete->type = binder_work::BINDER_WORK_TRANSACTION_COMPLETE;
	list_add_tail(&tcomplete->entry, &thread->todo);
	if (target_wait) {
		wake_up_interruptible(target_wait);
	}
	return;
#if 0
err_get_unused_fd_failed:
err_fget_failed:
#endif
err_fd_not_allowed:
err_binder_get_ref_for_node_failed:
err_binder_get_ref_failed:
err_binder_new_node_failed:
err_bad_object_type:
err_bad_offset:
err_copy_data_failed:
	binder_transaction_buffer_release(target_proc, tttttt->buffer, offp);
	tttttt->buffer->transaction = NULL;
	binder_free_buf(target_proc, tttttt->buffer);
err_binder_alloc_buf_failed:
	kfree(tcomplete);
	{
		s_ptr.binder_stats_obj_deleted_BINDER_STAT_TRANSACTION_COMPLETE[0]++;
		/*binder_stats.obj_deleted[BINDER_STAT_TRANSACTION_COMPLETE]++;*/
	}
err_alloc_tcomplete_failed:
	kfree(tttttt);
	{
		s_ptr.binder_stats_obj_deleted_BINDER_STAT_TRANSACTION[0]++;
		/*binder_stats.obj_deleted[BINDER_STAT_TRANSACTION]++;*/
	}
err_alloc_t_failed:
err_bad_call_stack:
err_empty_call_stack:
err_dead_binder:
err_invalid_target_handle:
err_no_context_mgr_node:
	if (binder_debug_mask & BINDER_DEBUG_FAILED_TRANSACTION)
		printf( "binder: %d:%d transaction failed %d, size"
				"%zd-%zd\n",
			   proc->pid, thread->pid, return_error,
			   tr->data_size, tr->offsets_size);

	{
// 		struct binder_transaction_log_entry *fe;
// 		fe = binder_transaction_log_add(&binder_transaction_log_failed);
// 		*fe = *e;
	}

// 	BUG_ON(thread->return_error != BR_OK);
	if (in_reply_to) {
		thread->return_error = BR_TRANSACTION_COMPLETE;
		binder_send_failed_reply(in_reply_to, return_error);
	} else
		thread->return_error = return_error;
#endif
}
static size_t binder_buffer_size(
	struct binder_proc *proc, struct binder_buffer *buffer)
{
	if (list_is_last(&buffer->entry, &proc->buffers))
		return (size_t)proc->buffer + (size_t)proc->buffer_size - (size_t)(void *)buffer->data;
	else
		return (size_t)list_entry(buffer->entry.next,
			struct binder_buffer, entry) - (size_t)buffer->data;
}

static void binder_free_buf(
	struct binder_proc *proc, struct binder_buffer *buffer)
{
	size_t size, buffer_size;

	buffer_size = binder_buffer_size(proc, buffer);

	size = ALIGN(buffer->data_size, size_t, sizeof(void *)) +
		ALIGN(buffer->offsets_size, size_t, sizeof(void *));
	if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
		printf( "binder: %d: binder_free_buf %p size %zd buffer"
		       "_size %zd\n", proc->pid, buffer, size, buffer_size);

	BUG_ON(buffer->free);
	BUG_ON(size > buffer_size);
	BUG_ON(buffer->transaction != NULL);
	BUG_ON((void *)buffer < proc->buffer);
	BUG_ON((size_t)buffer > (size_t)proc->buffer + proc->buffer_size);

	if (buffer->async_transaction) {
		proc->free_async_space += size + sizeof(struct binder_buffer);
		if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC_ASYNC)
			printf( "binder: %d: binder_free_buf size %zd "
			       "async free %zd\n", proc->pid, size,
			       proc->free_async_space);
	}

	binder_update_page_range(proc, 0,
		(void *)PAGE_ALIGN((uintptr_t)buffer->data),
		(void *)(((uintptr_t)buffer->data + buffer_size) & PAGE_MASK),
		NULL);
	rb_erase(&buffer->rb_node, &proc->allocated_buffers);
	buffer->free = 1;
	if (!list_is_last(&buffer->entry, &proc->buffers)) {
		struct binder_buffer *next = list_entry(buffer->entry.next, struct binder_buffer, entry);
		if (next&&next->free) {
			rb_erase(&next->rb_node, &proc->free_buffers);
			binder_delete_free_buffer(proc, next);
		}
	}
	if (proc->buffers.next != &buffer->entry) {
		struct binder_buffer *prev = list_entry(buffer->entry.prev, struct binder_buffer, entry);
		if (prev&&prev->free) {
			binder_delete_free_buffer(proc, buffer);
			rb_erase(&prev->rb_node, &proc->free_buffers);
			buffer = prev;
		}
	}
	binder_insert_free_buffer(proc, buffer);
}


static void
binder_transaction_buffer_release(struct binder_proc *proc, struct binder_buffer *buffer, size_t *failed_at)
{
	size_t *offp, *off_end;
	int debug_id = buffer->debug_id;

	if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
		printf( "binder: %d buffer release %d, size %zd-%zd, failed at %p\n",
			   proc->pid, buffer->debug_id,
			   buffer->data_size, buffer->offsets_size, failed_at);

	if (buffer->target_node)
		binder_dec_node(buffer->target_node, 1, 0);

	offp = (size_t *)(buffer->data + ALIGN(buffer->data_size, size_t, sizeof(void *)));
	if (failed_at)
		off_end = failed_at;
	else
		off_end = (size_t*)((size_t)offp + buffer->offsets_size);
	for (; offp < off_end; offp++) {
		struct flat_binder_object *fp;
		if (*offp > buffer->data_size - sizeof(*fp) ||
		    buffer->data_size < sizeof(*fp) ||
		    !IS_ALIGNED(*offp, size_t, sizeof(void *))) {
			printf( "binder: transaction release %d bad"
					"offset %zd, size %zd\n", debug_id, *offp, buffer->data_size);
			continue;
		}
		fp = (struct flat_binder_object *)(buffer->data + *offp);
		switch (fp->type) {
		case BINDER_TYPE_BINDER:
		case BINDER_TYPE_WEAK_BINDER: {
			struct binder_node *node = binder_get_node(proc, fp->binder);
			if (node == NULL) {
				printf( "binder: transaction release %d bad node %p\n", debug_id, fp->binder);
				break;
			}
			if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
				printf( "        node %d u%p\n",
				       node->debug_id, node->ptr);
			binder_dec_node(node, fp->type == BINDER_TYPE_BINDER, 0);
		} break;
		case BINDER_TYPE_HANDLE:
		case BINDER_TYPE_WEAK_HANDLE: {
			struct binder_ref *ref = binder_get_ref(proc, fp->handle);
			if (ref == NULL) {
				printf( "binder: transaction release %d bad handle %ld\n", debug_id, fp->handle);
				break;
			}
			if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
				printf( "        ref %d desc %d (node %d)\n",
				       ref->debug_id, ref->desc, ref->node->debug_id);
			binder_dec_ref(ref, fp->type == BINDER_TYPE_HANDLE);
		} break;

		case BINDER_TYPE_FD:
			if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
				printf( "        fd %ld\n", fp->handle);
			if (failed_at)
				task_close_fd(proc, fp->handle);
			break;

		default:
			printf( "binder: transaction release %d bad object type %lx\n", debug_id, fp->type);
			break;
		}
	}
}

static struct binder_buffer *binder_buffer_lookup(
	struct binder_proc *proc, void __user *user_ptr)
{
	struct rb_node *n = proc->allocated_buffers.rb_node;
	struct binder_buffer *buffer;
	struct binder_buffer *kern_ptr;

	kern_ptr = (struct binder_buffer*)((ptrdiff_t)user_ptr - proc->user_buffer_offset - offsetof(struct binder_buffer, data));

	while (n) {
		buffer = rb_entry(n, struct binder_buffer, rb_node);
		BUG_ON(buffer->free);

		if (kern_ptr < buffer)
			n = n->rb_left;
		else if (kern_ptr > buffer)
			n = n->rb_right;
		else
			return buffer;
	}
	return NULL;
}

static struct binder_node *
binder_get_node(struct binder_proc *proc, void __user *ptr)
{
	struct rb_node *n = proc->nodes.rb_node;
	struct binder_node *node;

	while (n) {
		node = rb_entry(n, struct binder_node, rb_node);

		if (ptr < node->ptr)
			n = n->rb_left;
		else if (ptr > node->ptr)
			n = n->rb_right;
		else
			return node;
	}
	return NULL;
}

static int
binder_inc_node(struct binder_node *node, int strong, int internal,
		struct list_head *target_list)
{
	if (strong) {
		if (internal) {
			if (target_list == NULL &&
			    node->internal_strong_refs == 0 &&
			    !(node == binder_context_mgr_node &&
			    node->has_strong_ref)) {
				printf( "binder: invalid inc strong "
					"node for %d\n", node->debug_id);
				return -EINVAL;
			}
			node->internal_strong_refs++;
		} else
			node->local_strong_refs++;
		if (!node->has_strong_ref && target_list) {
			list_del_init(&node->work.entry);
			list_add_tail(&node->work.entry, target_list);
		}
	} else {
		if (!internal)
			node->local_weak_refs++;
		if (!node->has_weak_ref && list_empty(&node->work.entry)) {
			if (target_list == NULL) {
				printf( "binder: invalid inc weak node "
					"for %d\n", node->debug_id);
				return -EINVAL;
			}
			list_add_tail(&node->work.entry, target_list);
		}
	}
	return 0;
}

static void
binder_delete_ref(struct binder_ref *ref)
{
	if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
		printf( "binder: %d delete ref %d desc %d for "
			"node %d\n", ref->proc->pid, ref->debug_id,
			ref->desc, ref->node->debug_id);
	rb_erase(&ref->rb_node_desc, &ref->proc->refs_by_desc);
	rb_erase(&ref->rb_node_node, &ref->proc->refs_by_node);
	if (ref->strong)
		binder_dec_node(ref->node, 1, 1);
	hlist_del(&ref->node_entry);
	binder_dec_node(ref->node, 0, 1);
	if (ref->death) {
		if (binder_debug_mask & BINDER_DEBUG_DEAD_BINDER)
			printf( "binder: %d delete ref %d desc %d "
				"has death notification\n", ref->proc->pid,
				ref->debug_id, ref->desc);
		list_del(&ref->death->work.entry);
		kfree(ref->death);
		binder_stats.obj_deleted[BINDER_STAT_DEATH]++;
	}
	kfree(ref);
	binder_stats.obj_deleted[BINDER_STAT_REF]++;
}

static int
binder_dec_ref(struct binder_ref *ref, int strong)
{
	if (strong) {
		if (ref->strong == 0) {
			binder_user_error("binder: %d invalid dec strong, ref %d desc %d s %d w %d\n",ref->proc->pid, ref->debug_id,ref->desc, ref->strong, ref->weak);
			return -EINVAL;
		}
		ref->strong--;
		if (ref->strong == 0) {
			int ret;
			ret = binder_dec_node(ref->node, strong, 1);
			if (ret)
				return ret;
		}
	} 
	else {
		if (ref->weak == 0) {
			binder_user_error("binder: %d invalid dec weak, ref %d desc %d s %d w %d\n",ref->proc->pid, ref->debug_id,ref->desc, ref->strong, ref->weak);
			return -EINVAL;
		}
		ref->weak--;
	}
	if (ref->strong == 0 && ref->weak == 0)
		binder_delete_ref(ref);
	return 0;
}

static int
binder_inc_ref(
	struct binder_ref *ref, int strong, struct list_head *target_list)
{
	int ret;
	if (strong) {
		if (ref->strong == 0) {
			ret = binder_inc_node(ref->node, 1, 1, target_list);
			if (ret)
				return ret;
		}
		ref->strong++;
	} else {
		if (ref->weak == 0) {
			ret = binder_inc_node(ref->node, 0, 1, target_list);
			if (ret)
				return ret;
		}
		ref->weak++;
	}
	return 0;
}

static struct binder_ref *
binder_get_ref(struct binder_proc *proc, uint32_t desc)
{
	struct rb_node *n = proc->refs_by_desc.rb_node;
	struct binder_ref *ref;

	while (n) {
		ref = rb_entry(n, struct binder_ref, rb_node_desc);

		if (desc < ref->desc)
			n = n->rb_left;
		else if (desc > ref->desc)
			n = n->rb_right;
		else
			return ref;
	}
	return NULL;
}

static struct binder_ref *
binder_get_ref_for_node(struct binder_proc *proc, struct binder_node *node)
{
	struct rb_node *n;
	struct rb_node **p = &proc->refs_by_node.rb_node;
	struct rb_node *parent = NULL;
	struct binder_ref *ref, *new_ref;

	while (*p) {
		parent = *p;
		ref = rb_entry(parent, struct binder_ref, rb_node_node);

		if (node < ref->node)
			p = &(*p)->rb_left;
		else if (node > ref->node)
			p = &(*p)->rb_right;
		else
			return ref;
	}
	new_ref = (struct binder_ref*)kzalloc(sizeof(*ref), GFP_KERNEL);
	if (new_ref == NULL)
		return NULL;
	{
		s_ptr.binder_stats_obj_created_BINDER_STAT_REF[0]++;
		new_ref->debug_id = ++s_ptr.binder_last_id[0];
		/*binder_stats.obj_created[BINDER_STAT_REF]++;*/
		/*new_ref->debug_id = ++binder_last_id;*/
	}
	new_ref->proc = proc;
	new_ref->node = node;
	rb_link_node(&new_ref->rb_node_node, parent, p);
	rb_insert_color(&new_ref->rb_node_node, &proc->refs_by_node);
	{
		new_ref->desc = (node == Pointer(s_ptr.binder_context_mgr_node)) ? 0 : 1;
		/*new_ref->desc = (node == binder_context_mgr_node) ? 0 : 1;*/
	}
	for (n = rb_first(&proc->refs_by_desc); n != NULL; n = rb_next(n)) {
		ref = rb_entry(n, struct binder_ref, rb_node_desc);
		if (ref->desc > new_ref->desc)
			break;
		new_ref->desc = ref->desc + 1;
	}

	p = &proc->refs_by_desc.rb_node;
	while (*p) {
		parent = *p;
		ref = rb_entry(parent, struct binder_ref, rb_node_desc);

		if (new_ref->desc < ref->desc)
			p = &(*p)->rb_left;
		else if (new_ref->desc > ref->desc)
			p = &(*p)->rb_right;
		else
			BUG();
	}
	rb_link_node(&new_ref->rb_node_desc, parent, p);
	rb_insert_color(&new_ref->rb_node_desc, &proc->refs_by_desc);
	if (node) {
		hlist_add_head(&new_ref->node_entry, &node->refs);
		if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
			printf( "binder: %d new ref %d desc %d for "
				"node %d\n", proc->pid, new_ref->debug_id,
				new_ref->desc, node->debug_id);
	} else {
		if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
			printf( "binder: %d new ref %d desc %d for "
				"dead node\n", proc->pid, new_ref->debug_id,
				new_ref->desc);
	}
	return new_ref;
}

static bool is_attach = false;

int binder_thread_write(struct binder_proc *proc, struct binder_thread *thread,
		    void __user *buffer, int size, signed long *consumed)
{
	/*if (!is_attach) {
		Sleep(10000);
		is_attach = true;
	}*/
	uint32_t cmd;
	void __user *ptr = (void*)((signed long)buffer + *consumed);
	void __user *end = (void*)((int)buffer + size);
	{
		if (ptr >= (unsigned __int8 *)buffer + size || thread->return_error != BR_OK) {
			return 0;
		}
	}

	while (ptr < end && thread->return_error == BR_OK) {
		get_user(cmd, (uint32_t __user *)ptr);
		ptr = (void*)((uint32_t)ptr + sizeof(uint32_t));
		if (_IOC_NR(cmd) < ARRAY_SIZE(binder_stats.bc)) {
			{
				++s_ptr.binder_stats_bc[_IOC_NR(cmd)];
				/*binder_stats.bc[_IOC_NR(cmd)]++;*/
			}
			proc->stats.bc[_IOC_NR(cmd)]++;
			thread->stats.bc[_IOC_NR(cmd)]++;
		}
		switch (cmd) {
		case BC_INCREFS:
		case BC_ACQUIRE:
		case BC_RELEASE:
		case BC_DECREFS: {
			uint32_t target;
			struct binder_ref *ref;
			const char *debug_string;

			get_user(target, (uint32_t __user *)ptr);
			ptr = (void*)((uint32_t)ptr + sizeof(uint32_t));
			if (target == 0 && Pointer(s_ptr.binder_context_mgr_node) &&
			    (cmd == BC_INCREFS || cmd == BC_ACQUIRE)) {
				{
					ref = binder_get_ref_for_node(proc, Pointer(s_ptr.binder_context_mgr_node));
					/*ref = binder_get_ref_for_node(proc, binder_context_mgr_node);*/
				}
				if (ref->desc != target) {
					binder_user_error("binder: %d:%d tried to acquire reference to desc 0, got %d instead\n",proc->pid, thread->pid,ref->desc);
				}
			}
			else {
				ref = binder_get_ref(proc, target);
			}
			if (ref == NULL) {
				binder_user_error("binder: %d:%d refcount change on invalid ref %d\n",proc->pid, thread->pid, target);
				break;
			}
			switch (cmd) {
			case BC_INCREFS:
				debug_string = "IncRefs";
				binder_inc_ref(ref, 0, NULL);
				break;
			case BC_ACQUIRE:
				debug_string = "Acquire";
				binder_inc_ref(ref, 1, NULL);
				break;
			case BC_RELEASE:
				debug_string = "Release";
				binder_dec_ref(ref, 1);
				break;
			case BC_DECREFS:
			default:
				debug_string = "DecRefs";
				binder_dec_ref(ref, 0);
				break;
			}
			if (binder_debug_mask & BINDER_DEBUG_USER_REFS)
				printf( "binder: %d:%d %s ref %d desc %d s %d w %d for node %d\n",
				       proc->pid, thread->pid, debug_string, ref->debug_id, ref->desc, ref->strong, ref->weak, ref->node->debug_id);
			break;
		}
		case BC_INCREFS_DONE:
		case BC_ACQUIRE_DONE: {
			void __user *node_ptr;
			void *cookie;
			struct binder_node *node;

			get_user(node_ptr, (void * __user *)ptr);
			ptr = (void*)((uint32_t)ptr + sizeof(void*));
			get_user(cookie, (void * __user *)ptr);
			ptr = (void*)((uint32_t)ptr + sizeof(void*));
			node = binder_get_node(proc, node_ptr);
			if (node == NULL) {
				binder_user_error("binder: %d:%d "
					"%s u%p no match\n",
					proc->pid, thread->pid,
					cmd == BC_INCREFS_DONE ?
					"BC_INCREFS_DONE" :
					"BC_ACQUIRE_DONE",
					node_ptr);
				break;
			}
			if (cookie != node->cookie) {
				binder_user_error("binder: %d:%d %s u%p node %d"
					" cookie mismatch %p != %p\n",
					proc->pid, thread->pid,
					cmd == BC_INCREFS_DONE ?
					"BC_INCREFS_DONE" : "BC_ACQUIRE_DONE",
					node_ptr, node->debug_id,
					cookie, node->cookie);
				break;
			}
			if (cmd == BC_ACQUIRE_DONE) {
				if (node->pending_strong_ref == 0) {
					binder_user_error("binder: %d:%d "
						"BC_ACQUIRE_DONE node %d has "
						"no pending acquire request\n",
						proc->pid, thread->pid,
						node->debug_id);
					break;
				}
				node->pending_strong_ref = 0;
			} else {
				if (node->pending_weak_ref == 0) {
					binder_user_error("binder: %d:%d "
						"BC_INCREFS_DONE node %d has "
						"no pending increfs request\n",
						proc->pid, thread->pid,
						node->debug_id);
					break;
				}
				node->pending_weak_ref = 0;
			}
			binder_dec_node(node, cmd == BC_ACQUIRE_DONE, 0);
			if (binder_debug_mask & BINDER_DEBUG_USER_REFS)
				printf( "binder: %d:%d %s node %d ls %d lw %d\n",
				       proc->pid, thread->pid, cmd == BC_INCREFS_DONE ? "BC_INCREFS_DONE" : "BC_ACQUIRE_DONE", node->debug_id, node->local_strong_refs, node->local_weak_refs);
			break;
		}
		case BC_ATTEMPT_ACQUIRE:
			printf( "binder: BC_ATTEMPT_ACQUIRE not supported\n");
			return -EINVAL;
		case BC_ACQUIRE_RESULT:
			printf( "binder: BC_ACQUIRE_RESULT not supported\n");
			return -EINVAL;

		case BC_FREE_BUFFER: {
			void __user *data_ptr;
			struct binder_buffer *buffer;

			get_user(data_ptr, (void * __user *)ptr);
			ptr = (void*)((uint32_t)ptr + sizeof(void*));

			buffer = binder_buffer_lookup(proc, data_ptr);
			if (buffer == NULL) {
				binder_user_error("binder: %d:%d "
					"BC_FREE_BUFFER u%p no match\n",
					proc->pid, thread->pid, data_ptr);
				break;
			}
			if (!buffer->allow_user_free) {
				binder_user_error("binder: %d:%d "
					"BC_FREE_BUFFER u%p matched "
					"unreturned buffer\n",
					proc->pid, thread->pid, data_ptr);
				break;
			}
			if (binder_debug_mask & BINDER_DEBUG_FREE_BUFFER)
				printf( "binder: %d:%d BC_FREE_BUFFER u%p found buffer %d for %s transaction\n",
				       proc->pid, thread->pid, data_ptr, buffer->debug_id,
				       buffer->transaction ? "active" : "finished");

			if (buffer->transaction) {
				buffer->transaction->buffer = NULL;
				buffer->transaction = NULL;
			}
			if (buffer->async_transaction && buffer->target_node) {
				BUG_ON(!buffer->target_node->has_async_transaction);
				if (list_empty(&buffer->target_node->async_todo))
					buffer->target_node->has_async_transaction = 0;
				else
					list_move_tail(buffer->target_node->async_todo.next, &thread->todo);
			}
			binder_transaction_buffer_release(proc, buffer, NULL);
			binder_free_buf(proc, buffer);
			break;
		}

		case BC_TRANSACTION:
		case BC_REPLY: {
			//CHECK OK
			struct binder_transaction_data tr;
			memmove(&tr, ptr, sizeof(tr));
			ptr = (void*)((uint32_t)ptr + sizeof(tr));
			binder_transaction(proc, thread, &tr, ptr, cmd == BC_REPLY);
			ptr = (void*)((unsigned long)ptr + tr.data_size);
			ptr = (void*)((unsigned long)ptr + tr.offsets_size);
			break;
		}

		case BC_REGISTER_LOOPER:
			//CHECK OK
			if (binder_debug_mask & BINDER_DEBUG_THREADS)
				printf( "binder: %d:%d BC_REGISTER_LOOPER\n",
				       proc->pid, thread->pid);
			if (thread->looper & BINDER_LOOPER_STATE_ENTERED) {
				thread->looper |= BINDER_LOOPER_STATE_INVALID;
				binder_user_error("binder: %d:%d ERROR:"
					" BC_REGISTER_LOOPER called "
					"after BC_ENTER_LOOPER\n",
					proc->pid, thread->pid);
			} else if (proc->requested_threads == 0) {
				thread->looper |= BINDER_LOOPER_STATE_INVALID;
				binder_user_error("binder: %d:%d ERROR:"
					" BC_REGISTER_LOOPER called "
					"without request\n",
					proc->pid, thread->pid);
			} else {
				proc->requested_threads--;
				proc->requested_threads_started++;
			}
			thread->looper |= BINDER_LOOPER_STATE_REGISTERED;
			break;
		case BC_ENTER_LOOPER:
			//CHECK OK
			if (binder_debug_mask & BINDER_DEBUG_THREADS)
				printf( "binder: %d:%d BC_ENTER_LOOPER\n",
				       proc->pid, thread->pid);
			if (thread->looper & BINDER_LOOPER_STATE_REGISTERED) {
				thread->looper |= BINDER_LOOPER_STATE_INVALID;
				binder_user_error("binder: %d:%d ERROR:"
					" BC_ENTER_LOOPER called after "
					"BC_REGISTER_LOOPER\n",
					proc->pid, thread->pid);
			}
			thread->looper |= BINDER_LOOPER_STATE_ENTERED;
			break;
		case BC_EXIT_LOOPER:
			//CHECK OK
			if (binder_debug_mask & BINDER_DEBUG_THREADS)
				printf( "binder: %d:%d BC_EXIT_LOOPER\n",
				       proc->pid, thread->pid);
			thread->looper |= BINDER_LOOPER_STATE_EXITED;
			break;

		case BC_REQUEST_DEATH_NOTIFICATION:
		case BC_CLEAR_DEATH_NOTIFICATION: {
			uint32_t target;
			void __user *cookie;
			struct binder_ref *ref;
			struct binder_ref_death *death;

			get_user(target, (uint32_t __user *)ptr);
			ptr = (void*)((uint32_t)ptr + sizeof(uint32_t));
			get_user(cookie, (void __user * __user *)ptr);
			ptr = (void*)((uint32_t)ptr + sizeof(void*));
			ref = binder_get_ref(proc, target);
			if (ref == NULL) {
				binder_user_error("binder: %d:%d %s "
					"invalid ref %d\n",
					proc->pid, thread->pid,
					cmd == BC_REQUEST_DEATH_NOTIFICATION ?
					"BC_REQUEST_DEATH_NOTIFICATION" :
					"BC_CLEAR_DEATH_NOTIFICATION",
					target);
				break;
			}

			if (binder_debug_mask & BINDER_DEBUG_DEATH_NOTIFICATION)
				printf( "binder: %d:%d %s %p ref %d desc %d s %d w %d for node %d\n",
				       proc->pid, thread->pid,
				       cmd == BC_REQUEST_DEATH_NOTIFICATION ?
				       "BC_REQUEST_DEATH_NOTIFICATION" :
				       "BC_CLEAR_DEATH_NOTIFICATION",
				       cookie, ref->debug_id, ref->desc,
				       ref->strong, ref->weak, ref->node->debug_id);

			if (cmd == BC_REQUEST_DEATH_NOTIFICATION) {
				if (ref->death) {
					binder_user_error("binder: %d:%"
						"d BC_REQUEST_DEATH_NOTI"
						"FICATION death notific"
						"ation already set\n",
						proc->pid, thread->pid);
					break;
				}
				death = (struct binder_ref_death*)kzalloc(sizeof(*death), GFP_KERNEL);
				if (death == NULL) {
					thread->return_error = BR_ERROR;
					if (binder_debug_mask & BINDER_DEBUG_FAILED_TRANSACTION)
						printf("binder: %d:%d "
							"BC_REQUEST_DEATH_NOTIFICATION failed\n",
							proc->pid, thread->pid);
					break;
				}
				{
					++s_ptr.binder_stats_obj_deleted_BINDER_STAT_DEATH[0];
					/*binder_stats.obj_created[BINDER_STAT_DEATH]++;*/
				}
				INIT_LIST_HEAD(&death->work.entry);
				death->cookie = cookie;
				ref->death = death;
				if (ref->node->proc == NULL) {
					ref->death->work.type = binder_work::BINDER_WORK_DEAD_BINDER;
					if (thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED)) {
						list_add_tail(&ref->death->work.entry, &thread->todo);
					}
					else {
						list_add_tail(&ref->death->work.entry, &proc->todo);
						wake_up_interruptible(&proc->wait);
					}
				}
			}
 else {
	 if (ref->death == NULL) {
		 binder_user_error("binder: %d:%"
			 "d BC_CLEAR_DEATH_NOTIFI"
			 "CATION death notificat"
			 "ion not active\n",
			 proc->pid, thread->pid);
		 break;
	 }
	 death = ref->death;
	 if (death->cookie != cookie) {
		 binder_user_error("binder: %d:%"
			 "d BC_CLEAR_DEATH_NOTIFI"
			 "CATION death notificat"
			 "ion cookie mismatch "
			 "%p != %p\n",
			 proc->pid, thread->pid,
			 death->cookie, cookie);
		 break;
	 }
	 ref->death = NULL;
	 if (list_empty(&death->work.entry)) {
		 death->work.type = binder_work::BINDER_WORK_CLEAR_DEATH_NOTIFICATION;
		 if (thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED)) {
			 list_add_tail(&death->work.entry, &thread->todo);
		 }
		 else {
			 list_add_tail(&death->work.entry, &proc->todo);
			 wake_up_interruptible(&proc->wait);
		 }
	 }
	 else {
		 BUG_ON(death->work.type != binder_work::BINDER_WORK_DEAD_BINDER);
		 death->work.type = binder_work::BINDER_WORK_DEAD_BINDER_AND_CLEAR;
	 }
 }
		} break;
		case BC_DEAD_BINDER_DONE: {
			struct binder_work *w;
			void __user *cookie;
			struct binder_ref_death *death = NULL;
			get_user(cookie, (void __user * __user *)ptr);
			ptr = (void*)((uint32_t)ptr + sizeof(void*));
			list_for_each_entry(w, struct binder_work, &proc->delivered_death, entry) {
				struct binder_ref_death *tmp_death = container_of(w, struct binder_ref_death, work);
				if (tmp_death->cookie == cookie) {
					death = tmp_death;
					break;
				}
			}
			if (binder_debug_mask & BINDER_DEBUG_DEAD_BINDER)
				printf("binder: %d:%d BC_DEAD_BINDER_DONE %p found %p\n",
					proc->pid, thread->pid, cookie, death);
			if (death == NULL) {
				binder_user_error("binder: %d:%d BC_DEAD"
					"_BINDER_DONE %p not found\n",
					proc->pid, thread->pid, cookie);
				break;
			}

			list_del_init(&death->work.entry);
			if (death->work.type == binder_work::BINDER_WORK_DEAD_BINDER_AND_CLEAR) {
				death->work.type = binder_work::BINDER_WORK_CLEAR_DEATH_NOTIFICATION;
				if (thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED)) {
					list_add_tail(&death->work.entry, &thread->todo);
				}
				else {
					list_add_tail(&death->work.entry, &proc->todo);
					wake_up_interruptible(&proc->wait);
				}
			}
		} break;

		default:
			printf("binder: %d:%d unknown command %d\n", proc->pid, thread->pid, cmd);
			return -EINVAL;
		}
		*consumed = ((signed long)ptr - (signed long)buffer);
		{
			if (ptr >= (unsigned __int8 *)buffer + size || thread->return_error != BR_OK) {
				return 0;
			}
		}
	}
	return -EINVAL;
}
#include <time.h>
#ifdef WIN32
#   include <windows.h>
#else
#   include <sys/time.h>
#endif

#ifdef WIN32
int
gettimeofday(struct timeval *tp, void *tzp)
{
	time_t clock;
	struct tm tm;
	SYSTEMTIME wtm;

	GetLocalTime(&wtm);
	tm.tm_year = wtm.wYear - 1900;
	tm.tm_mon = wtm.wMonth - 1;
	tm.tm_mday = wtm.wDay;
	tm.tm_hour = wtm.wHour;
	tm.tm_min = wtm.wMinute;
	tm.tm_sec = wtm.wSecond;
	tm.tm_isdst = -1;
	clock = mktime(&tm);
	tp->tv_sec = clock;
	tp->tv_usec = wtm.wMilliseconds * 1000;

	return (0);
}
#endif

int
binder_thread_read(struct binder_proc *proc, struct binder_thread *thread,
	void  __user *buffer, int size, signed long *consumed, int non_block)
{
	/*
	if (!is_attach) {
		Sleep(10000);
		is_attach = true;
	}
	*/
	void __user *ptr = (void*)((signed long)buffer + *consumed);
	void __user *end = (void*)((int)buffer + size);

	int ret = 0;
	int wait_for_proc_work;

	if (*consumed == 0) {
		put_user(BR_NOOP, (uint32_t __user *)ptr);
		ptr = (void*)((uint32_t)ptr + sizeof(uint32_t));
	}

retry:
	wait_for_proc_work = thread->transaction_stack == NULL && list_empty(&thread->todo);

	if (thread->return_error != BR_OK && ptr < end) {
		if (thread->return_error2 != BR_OK) {
			put_user(thread->return_error2, (uint32_t __user *)ptr);
			ptr = (void*)((uint32_t)ptr + sizeof(uint32_t));
			if (ptr == end)
				goto done;
			thread->return_error2 = BR_OK;
		}
		put_user(thread->return_error, (uint32_t __user *)ptr);
		ptr = (void*)((uint32_t)ptr + sizeof(uint32_t));
		thread->return_error = BR_OK;
		goto done;
	}
	thread->looper |= BINDER_LOOPER_STATE_WAITING;
	if (wait_for_proc_work) {
		proc->ready_threads++;
		{
			BaseAPI::GetInstance()->StructAPI()->pthread_mutex_unlock(s_ptr.binder_lock);
		}
		if (!(thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED))) {
			binder_user_error("binder: %d:%d ERROR: Thread waiting "
				"for process work before calling BC_REGISTER_"
				"LOOPER or BC_ENTER_LOOPER (state %x)\n",
				proc->pid, thread->pid, thread->looper);
			WinPrintf("1111111111111111111111111");
			// wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
		}
		if (non_block) {
			if (!binder_has_proc_work(proc, thread))
				ret = -EAGAIN;
		} else{
			{
				BaseAPI::GetInstance()->StructAPI()->pthread_mutex_lock(s_ptr.binder_lock);
			}
			while (!binder_has_proc_work(proc, thread)){
				BaseAPI::GetInstance()->StructAPI()->pthread_cond_wait(&proc->wait, s_ptr.binder_lock);
			}
			ret = 0;
			{
				BaseAPI::GetInstance()->StructAPI()->pthread_mutex_unlock(s_ptr.binder_lock);
			}
		}
		{
			BaseAPI::GetInstance()->StructAPI()->pthread_mutex_lock(s_ptr.binder_lock);
		}
		proc->ready_threads--;
	} else {
		{
			BaseAPI::GetInstance()->StructAPI()->pthread_mutex_unlock(s_ptr.binder_lock);
		}
		if (non_block) {
			if (!binder_has_thread_work(thread))
				ret = -EAGAIN;
		} 
		else {
			ret = 0;
			{
				BaseAPI::GetInstance()->StructAPI()->pthread_mutex_lock(s_ptr.binder_lock);
			}
			while (!binder_has_thread_work(thread)) {
				BaseAPI::GetInstance()->StructAPI()->pthread_cond_wait(&thread->wait, s_ptr.binder_lock);
			}
			{
				BaseAPI::GetInstance()->StructAPI()->pthread_mutex_unlock(s_ptr.binder_lock);
			}
		}
		{
			BaseAPI::GetInstance()->StructAPI()->pthread_mutex_lock(s_ptr.binder_lock);
		}
	}

	thread->looper &= ~BINDER_LOOPER_STATE_WAITING;

	if (ret) {
		return ret;
	}

	while (1) {
		uint32_t cmd;
		struct binder_transaction_data tr;
		struct binder_work *w;
		struct binder_transaction *t = NULL;
		if (!list_empty(&thread->todo))
			w = list_first_entry(&thread->todo, struct binder_work, entry);
		else if (!list_empty(&proc->todo) && wait_for_proc_work)
			w = list_first_entry(&proc->todo, struct binder_work, entry);
		else {
			if ((uintptr_t)ptr - (uintptr_t)buffer == 4 && !(thread->looper & BINDER_LOOPER_STATE_NEED_RETURN)) /* no data added */
				goto retry;
			break;
		}

		if ((unsigned long)end - (unsigned long)ptr < (sizeof(tr) + 4))
			break;

		switch (w->type) {
		case binder_work::BINDER_WORK_TRANSACTION: {
			t = container_of(w, struct binder_transaction, work);
			break;
		} 
		case binder_work::BINDER_WORK_TRANSACTION_COMPLETE: {
			cmd = BR_TRANSACTION_COMPLETE;
			put_user(cmd, (uint32_t __user *)ptr);
			ptr = (void*)((uint32_t)ptr + sizeof(uint32_t));

			binder_stat_br(proc, thread, cmd);
			if (binder_debug_mask & BINDER_DEBUG_TRANSACTION_COMPLETE)
				printf("binder: %d:%d BR_TRANSACTION_COMPLETE\n",
					proc->pid, thread->pid);

			list_del(&w->entry);
			kfree(w);
			{
				++s_ptr.binder_stats_obj_deleted_BINDER_STAT_TRANSACTION_COMPLETE[0];
				/*binder_stats.obj_deleted[BINDER_STAT_TRANSACTION_COMPLETE]++;*/
			}
			break;
		}
		case binder_work::BINDER_WORK_NODE: {
			struct binder_node *node = container_of(w, struct binder_node, work);
			uint32_t cmd = BR_NOOP;
			const char *cmd_name;
			int strong = node->internal_strong_refs || node->local_strong_refs;
			int weak = !hlist_empty(&node->refs) || node->local_weak_refs || strong;
			if (weak && !node->has_weak_ref) {
				cmd = BR_INCREFS;
				cmd_name = "BR_INCREFS";
				node->has_weak_ref = 1;
				node->pending_weak_ref = 1;
				node->local_weak_refs++;
			}
			else if (strong && !node->has_strong_ref) {
				cmd = BR_ACQUIRE;
				cmd_name = "BR_ACQUIRE";
				node->has_strong_ref = 1;
				node->pending_strong_ref = 1;
				node->local_strong_refs++;
			}
			else if (!strong && node->has_strong_ref) {
				cmd = BR_RELEASE;
				cmd_name = "BR_RELEASE";
				node->has_strong_ref = 0;
			}
			else if (!weak && node->has_weak_ref) {
				cmd = BR_DECREFS;
				cmd_name = "BR_DECREFS";
				node->has_weak_ref = 0;
			}
			if (cmd != BR_NOOP) {
				put_user(cmd, (uint32_t __user *)ptr);
				ptr = (void*)((uint32_t)ptr + sizeof(uint32_t));
				put_user(node->ptr, (void * __user *)ptr);
				ptr = (void*)((uint32_t)ptr + sizeof(void*));
				put_user(node->cookie, (void * __user *)ptr);
				ptr = (void*)((uint32_t)ptr + sizeof(void*));

				binder_stat_br(proc, thread, cmd);
				if (binder_debug_mask & BINDER_DEBUG_USER_REFS)
					printf("binder: %d:%d %s %d u%p c%p\n",
						proc->pid, thread->pid, cmd_name, node->debug_id, node->ptr, node->cookie);
			}
			else {
				list_del_init(&w->entry);
				if (!weak && !strong) {
					if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
						printf("binder: %d:%d node %d u%p c%p deleted\n",
							proc->pid, thread->pid, node->debug_id, node->ptr, node->cookie);
					rb_erase(&node->rb_node, &proc->nodes);
					kfree(node);
					{
						s_ptr.binder_stats_obj_deleted_BINDER_STAT_NODE[0]++;
						/*binder_stats.obj_deleted[BINDER_STAT_NODE]++;*/
					}
				}
				else {
					if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
						printf("binder: %d:%d node %d u%p c%p state unchanged\n",
							proc->pid, thread->pid, node->debug_id, node->ptr, node->cookie);
				}
			}
			break;
		}
		case binder_work::BINDER_WORK_DEAD_BINDER:
		case binder_work::BINDER_WORK_DEAD_BINDER_AND_CLEAR:
		case binder_work::BINDER_WORK_CLEAR_DEATH_NOTIFICATION: {
			struct binder_ref_death *death = container_of(w, struct binder_ref_death, work);
			uint32_t cmd;
			if (w->type == binder_work::BINDER_WORK_CLEAR_DEATH_NOTIFICATION)
				cmd = BR_CLEAR_DEATH_NOTIFICATION_DONE;
			else
				cmd = BR_DEAD_BINDER;
			put_user(cmd, (uint32_t __user *)ptr);
			ptr = (void*)((uint32_t)ptr + sizeof(uint32_t));
			put_user(death->cookie, (void * __user *)ptr);
			ptr = (void*)((uint32_t)ptr + sizeof(void*));
			if (binder_debug_mask & BINDER_DEBUG_DEATH_NOTIFICATION)
				printf("binder: %d:%d %s %p\n",
					proc->pid, thread->pid,
					cmd == BR_DEAD_BINDER ?
					"BR_DEAD_BINDER" :
					"BR_CLEAR_DEATH_NOTIFICATION_DONE",
					death->cookie);

			if (w->type == binder_work::BINDER_WORK_CLEAR_DEATH_NOTIFICATION) {
				list_del(&w->entry);
				kfree(death);
				{
					++s_ptr.binder_stats_obj_deleted_BINDER_STAT_DEATH[0];
					/*binder_stats.obj_deleted[BINDER_STAT_DEATH]++;*/
				}
			}
			else {
				list_move(&w->entry, &proc->delivered_death);
			}
			if (cmd == BR_DEAD_BINDER)
				goto done; /* DEAD_BINDER notifications can cause transactions */
			break;
		}
		default:
			continue;
		}

		if (!t)
			continue;

		BUG_ON(t->buffer == NULL);
		if (t->buffer->target_node) {
			struct binder_node *target_node = t->buffer->target_node;
			tr.target.ptr = target_node->ptr;
			tr.cookie =  target_node->cookie;
			cmd = BR_TRANSACTION;
		}
		else {
			tr.target.ptr = NULL;
			tr.cookie = NULL;
			cmd = BR_REPLY;
		}
		tr.code = t->code;
		tr.flags = t->flags;
		tr.sender_euid = t->sender_euid;

		if (t->from) {
			/*tr.sender_pid = proc->pid;*/
			tr.sender_pid = t->from->proc->pid;
		}
		else {
			tr.sender_pid = 0;
		}

		tr.data_size = t->buffer->data_size;
		tr.offsets_size = t->buffer->offsets_size;
		tr.data.ptr.buffer = (void *)((ptrdiff_t)t->buffer->data + proc->user_buffer_offset);
		tr.data.ptr.offsets = (void*)((size_t)tr.data.ptr.buffer + ALIGN(t->buffer->data_size, size_t, sizeof(void *)));
		
		put_user(cmd, (uint32_t __user *)ptr);
		ptr = (void*)((uint32_t)ptr + sizeof(uint32_t));
		copy_to_user(ptr, &tr, sizeof(tr));
		ptr = (void*)((uint32_t)ptr + sizeof(tr));

		binder_stat_br(proc, thread, cmd);
		list_del(&t->work.entry);
		t->buffer->allow_user_free = 1;
		if (cmd == BR_TRANSACTION && !(t->flags & TF_ONE_WAY)) {
			t->to_parent = thread->transaction_stack;
			t->to_thread = thread;
			thread->transaction_stack = t;
		}
		else {
			t->buffer->transaction = NULL;
			kfree(t);
			{
				++s_ptr.binder_stats_obj_deleted_BINDER_STAT_TRANSACTION[0];
				/*binder_stats.obj_deleted[BINDER_STAT_TRANSACTION]++;*/
			}
		}
		break;
	}

done:

	*consumed = (signed long)ptr - (signed long)buffer;
	if (proc->requested_threads + proc->ready_threads == 0 &&
	    proc->requested_threads_started < proc->max_threads &&
	    (thread->looper & (BINDER_LOOPER_STATE_REGISTERED |
	     BINDER_LOOPER_STATE_ENTERED)) /* the user-space code fails to */
	     /*spawn a new thread if we leave this out */) {
		proc->requested_threads++;
		put_user(BR_SPAWN_LOOPER, (uint32_t __user *)buffer);
	}
	return 0;
}

static void binder_release_work(struct list_head *list)
{
	struct binder_work *w;
	while (!list_empty(list)) {
		w = list_first_entry(list, struct binder_work, entry);
		list_del_init(&w->entry);
		switch (w->type) {
		case binder_work::BINDER_WORK_TRANSACTION: {
			struct binder_transaction *t = container_of(w, struct binder_transaction, work);
			if (t->buffer->target_node && !(t->flags & TF_ONE_WAY))
				binder_send_failed_reply(t, BR_DEAD_REPLY);
		} break;
		case binder_work::BINDER_WORK_TRANSACTION_COMPLETE: {
			kfree(w);
			binder_stats.obj_deleted[BINDER_STAT_TRANSACTION_COMPLETE]++;
		} break;
		default:
			break;
		}
	}
}

static void
binder_pop_transaction(
	struct binder_thread *target_thread, struct binder_transaction *t)
{
	if (target_thread) {
// 		BUG_ON(target_thread->transaction_stack != t);
// 		BUG_ON(target_thread->transaction_stack->from != target_thread);
		target_thread->transaction_stack =
			target_thread->transaction_stack->from_parent;
		t->from = NULL;
	}
	t->need_reply = 0;
	if (t->buffer)
		t->buffer->transaction = NULL;
	kfree(t);
	{
		s_ptr.binder_stats_obj_deleted_BINDER_STAT_TRANSACTION[0]++;
		/*binder_stats.obj_deleted[BINDER_STAT_TRANSACTION]++;*/
	}
}

static void
binder_send_failed_reply(struct binder_transaction *t, uint32_t error_code)
{
	struct binder_thread *target_thread;
// 	BUG_ON(t->flags & TF_ONE_WAY);
	while (1) {
		target_thread = t->from;
		if (target_thread) {
			if (target_thread->return_error != BR_OK &&
			   target_thread->return_error2 == BR_OK) {
				target_thread->return_error2 =
					target_thread->return_error;
				target_thread->return_error = BR_OK;
			}
			if (target_thread->return_error == BR_OK) {
				if (binder_debug_mask & BINDER_DEBUG_FAILED_TRANSACTION)
					printf( "binder: send failed reply for transaction %d to %d:%d\n",
					       t->debug_id, target_thread->proc->pid, target_thread->pid);
				binder_pop_transaction(target_thread, t);
				target_thread->return_error = error_code;
				wake_up_interruptible(&target_thread->wait);
			} else {
				printf( "binder: reply failed, target "
					"thread, %d:%d, has error code %d "
					"already\n", target_thread->proc->pid,
					target_thread->pid,
					target_thread->return_error);
			}
			return;
		} else {
			struct binder_transaction *next = t->from_parent;
			if (binder_debug_mask & BINDER_DEBUG_FAILED_TRANSACTION)
				printf( "binder: send failed reply "
					"for transaction %d, target dead\n",
					t->debug_id);
			binder_pop_transaction(target_thread, t);
			if (next == NULL) {
				if (binder_debug_mask & BINDER_DEBUG_DEAD_BINDER)
					printf( "binder: reply failed,"
						" no target thread at root\n");
				return;
			}
			t = next;
			if (binder_debug_mask & BINDER_DEBUG_DEAD_BINDER)
				printf( "binder: reply failed, no targ"
					"et thread -- retry %d\n", t->debug_id);
		}
	}
}

static int binder_free_thread(struct binder_proc *proc, struct binder_thread *thread)
{
	struct binder_transaction *t;
	struct binder_transaction *send_reply = NULL;
	int active_transactions = 0;

	rb_erase(&thread->rb_node, &proc->threads);
	t = thread->transaction_stack;
	if (t && t->to_thread == thread)
		send_reply = t;
	while (t) {
		active_transactions++;
		if (binder_debug_mask & BINDER_DEBUG_DEAD_TRANSACTION)
			printf( "binder: release %d:%d transaction %d %s, still active\n",
			       proc->pid, thread->pid, t->debug_id, (t->to_thread == thread) ? "in" : "out");
		if (t->to_thread == thread) {
			t->to_proc = NULL;
			t->to_thread = NULL;
			if (t->buffer) {
				t->buffer->transaction = NULL;
				t->buffer = NULL;
			}
			t = t->to_parent;
		} else if (t->from == thread) {
			t->from = NULL;
			t = t->from_parent;
		} else
			BUG();
	}
	if (send_reply)
		binder_send_failed_reply(send_reply, BR_DEAD_REPLY);
	binder_release_work(&thread->todo);
	kfree(thread);
	binder_stats.obj_deleted[BINDER_STAT_THREAD]++;
	return active_transactions;
}

static struct binder_node *
binder_new_node(struct binder_proc *proc, void __user *ptr, void __user *cookie)
{
	struct rb_node **p = &proc->nodes.rb_node;
	struct rb_node *parent = NULL;
	struct binder_node *node;

	while (*p) {
		parent = *p;
		node = rb_entry(parent, struct binder_node, rb_node);

		if (ptr < node->ptr)
			p = &(*p)->rb_left;
		else if (ptr > node->ptr)
			p = &(*p)->rb_right;
		else
			return NULL;
	}

	node = (struct binder_node*)kzalloc(sizeof(*node), GFP_KERNEL);
	if (node == NULL)
		return NULL;
	{
		s_ptr.binder_stats_obj_created_BINDER_STAT_NODE[0]++;
		/*binder_stats.obj_created[BINDER_STAT_NODE]++;*/
	}
	rb_link_node(&node->rb_node, parent, p);
	rb_insert_color(&node->rb_node, &proc->nodes);
	node->debug_id = ++binder_last_id;
	node->proc = proc;
	node->ptr = ptr;
	node->cookie = cookie;
	node->work.type = binder_work::BINDER_WORK_NODE;
	INIT_LIST_HEAD(&node->work.entry);
	INIT_LIST_HEAD(&node->async_todo);
	#if 0
	if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
		printf( "binder: %d:%d node %d u%p c%p created\n",
		       proc->pid, current->pid, node->debug_id,
		       node->ptr, node->cookie);
	#endif
	return node;
}

static struct binder_thread *binder_get_thread(struct binder_proc *proc, int pid)
{
	struct binder_thread *thread = NULL;
	struct rb_node *parent = NULL;
	
	struct rb_node **p = &proc->threads.rb_node;

	while (*p) {
		parent = *p;
		// LOGD("xxxxxxxxxxxxxxxxxxx1:%p\n",parent);
		thread = rb_entry(parent, struct binder_thread, rb_node);
		// LOGD("xxxxxxxxxxxxxxxxxxx2x:%p\n",binder_has_thread_work(thread));
		// LOGD("xxxxxxxxxxxxxxxxxxx2:%p\n",thread->pid);
		if (thread && pid < thread->pid){
			// LOGD("xxxxxxxxxxxxxxxxxxx3:%p\n",p);
			p = &(*p)->rb_left;
		}
		else if (thread && pid > thread->pid){
			// LOGD("xxxxxxxxxxxxxxxxxxx4:%p\n",p);
			p = &(*p)->rb_right;
		}
		else{
			// LOGD("xxxxxxxxxxxxxxxxxxx5:%p\n",thread);
			break;
		}
	}
	if (*p == NULL) {
		thread = (struct binder_thread*)kzalloc(sizeof(*thread), GFP_KERNEL);
		
		if (thread == NULL)
			return NULL;
		binder_stats.obj_created[BINDER_STAT_THREAD]++;
		thread->proc = proc;
		thread->pid = pid;
		init_waitqueue_head(&thread->wait);
		INIT_LIST_HEAD(&thread->todo);
		rb_link_node(&thread->rb_node, parent, p);
		rb_insert_color(&thread->rb_node, &proc->threads);
		thread->looper |= BINDER_LOOPER_STATE_NEED_RETURN;
		thread->return_error = BR_OK;
		thread->return_error2 = BR_OK;
	}
	return thread;
}
long binder_thread_exit(unsigned int cmd, unsigned long arg, int f_flags, int pid, int tid) {
	int ret;
	struct binder_thread *thread = nullptr;
	unsigned int size = _IOC_SIZE(cmd);
	void __user *ubuf = (void __user *)arg;

	mutex_lock(&binder_lock);
	struct binder_proc *proc = GetBinderProc(pid);
	if (proc == NULL) {
		ret = -ENOMEM;
		goto err;
	}
	thread = binder_get_thread(proc, tid);
	if (thread == NULL) {
		ret = -ENOMEM;
		goto err;
	}
	binder_free_thread(proc, thread);
	thread = NULL;
	ret = 0;
err:
	if (thread)
		thread->looper &= ~BINDER_LOOPER_STATE_NEED_RETURN;
	mutex_unlock(&binder_lock);
	return ret;
}
long binder_set_context_mgr(unsigned int cmd, unsigned long arg, int f_flags, int pid, int tid) {
	int ret;
	struct binder_thread *thread = nullptr;
	unsigned int size = _IOC_SIZE(cmd);
	void __user *ubuf = (void __user *)arg;

	mutex_lock(&binder_lock);
	struct binder_proc *proc = GetBinderProc(pid);
	if (proc == NULL) {
		ret = -ENOMEM;
		goto err;
	}
	thread = binder_get_thread(proc, tid);
	if (thread == NULL) {
		ret = -ENOMEM;
		goto err;
	}
	if (binder_context_mgr_node != NULL) {
		printf("binder: BINDER_SET_CONTEXT_MGR already set\n");
		ret = -EBUSY;
		goto err;
	}
	if (binder_context_mgr_uid != -1) {
		if (binder_context_mgr_uid != proc->uid) {// current->cred->euid) {
			printf("binder: BINDER_SET_"
				"CONTEXT_MGR bad uid %d != %d\n",
				proc->uid, // current->cred->euid,
				binder_context_mgr_uid);
			ret = -EPERM;
			goto err;
		}
	}
	else
		binder_context_mgr_uid = proc->uid; // current->cred->euid;
	binder_context_mgr_node = binder_new_node(proc, NULL, NULL);
	if (binder_context_mgr_node == NULL) {
		ret = -ENOMEM;
		goto err;
	}
	binder_context_mgr_node->local_weak_refs++;
	binder_context_mgr_node->local_strong_refs++;
	binder_context_mgr_node->has_strong_ref = 1;
	binder_context_mgr_node->has_weak_ref = 1;
	ret = 0;
err:
	if (thread)
		thread->looper &= ~BINDER_LOOPER_STATE_NEED_RETURN;
	mutex_unlock(&binder_lock);
	return ret;
}
long binder_set_max_threads(unsigned int cmd, unsigned long arg, int f_flags, int pid, int tid) {
	int ret;
	struct binder_thread *thread = nullptr;
	unsigned int size = _IOC_SIZE(cmd);
	void __user *ubuf = (void __user *)arg;

	mutex_lock(&binder_lock);
	struct binder_proc *proc = GetBinderProc(pid);
	if (proc == NULL) {
		ret = -ENOMEM;
		goto err;
	}
	thread = binder_get_thread(proc, tid);
	if (thread == NULL) {
		ret = -ENOMEM;
		goto err;
	}
	copy_from_user(&proc->max_threads, ubuf, sizeof(proc->max_threads));
	ret = 0;
err:
	if (thread)
		thread->looper &= ~BINDER_LOOPER_STATE_NEED_RETURN;
	mutex_unlock(&binder_lock);
	return ret;
}
long binder_binder_version(unsigned int cmd, unsigned long arg, int f_flags, int pid, int tid) {
	int ret;
	struct binder_thread *thread = nullptr;
	unsigned int size = _IOC_SIZE(cmd);
	void __user *ubuf = (void __user *)arg;

	mutex_lock(&binder_lock);
	struct binder_proc *proc = GetBinderProc(pid);
	if (proc == NULL) {
		ret = -ENOMEM;
		goto err;
	}
	thread = binder_get_thread(proc, tid);
	if (thread == NULL) {
		ret = -ENOMEM;
		goto err;
	}
	if (size != sizeof(struct binder_version)) {
		ret = -EINVAL;
		goto err;
	}
	put_user(BINDER_CURRENT_PROTOCOL_VERSION, &((struct binder_version *)ubuf)->protocol_version);
	ret = 0;
err:
	if (thread)
		thread->looper &= ~BINDER_LOOPER_STATE_NEED_RETURN;
	mutex_unlock(&binder_lock);
	return ret;
}
//static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
long binder_ioctl(unsigned int cmd, unsigned long arg, int f_flags, int pid, int tid)
{
	int ret;
	// struct binder_proc *proc = (struct binder_proc *)filp->private_data;
	struct binder_thread *thread = nullptr;
	unsigned int size = _IOC_SIZE(cmd);
	void __user *ubuf = (void __user *)arg;

	mutex_lock(&binder_lock);
	struct binder_proc *proc = GetBinderProc(pid);
	if (proc == NULL) {
		ret = -ENOMEM;
		goto err;
	}
	thread = binder_get_thread(proc, tid);
	if (thread == NULL) {
		ret = -ENOMEM;
		goto err;
	}
// 	char* ssss = new char[102400];
// 	print_binder_proc(ssss, ssss + 102400,proc,1);
// 	printf("%s", ssss);
// 	delete[] ssss;
// 	ssss = new char[102400];
// 	print_binder_thread(ssss, ssss + 102400, thread, 1);
// 	printf("-------%s", ssss);
// 	delete[] ssss;
#if 1
	switch (cmd) {
	case BINDER_WRITE_READ: {
		struct binder_write_read bwr;
		if (size != sizeof(struct binder_write_read)) {
			ret = -EINVAL;
			goto err;
		}
		memmove(&bwr, ubuf, sizeof(bwr));
// 		if (binder_debug_mask & BINDER_DEBUG_READ_WRITE)
// 			WinPrintf("binder: %d:%d write %ld at %08lx, read %ld at %08lx\n",
// 			       proc->pid, thread->pid, bwr.write_size, bwr.write_buffer, bwr.read_size, bwr.read_buffer);
		if (bwr.write_size > 0) {
			ret = binder_thread_write(proc, thread, (void __user *)bwr.write_buffer, bwr.write_size, &bwr.write_consumed);
			if (ret < 0) {
				ret = -EFAULT;
				bwr.read_consumed = 0;
				memmove(ubuf, &bwr, sizeof(bwr));
				goto err;
			}
		}
		if (bwr.read_size > 0) {
			ret = binder_thread_read(proc, thread, (void __user *)bwr.read_buffer, bwr.read_size, &bwr.read_consumed, f_flags & O_NONBLOCK);
			if (!list_empty(&proc->todo))
				wake_up_interruptible(&proc->wait);
			if (ret < 0) {
				ret = -EFAULT;
				memmove(ubuf, &bwr, sizeof(bwr));
				goto err;
			}
		}
// 		if (binder_debug_mask & BINDER_DEBUG_READ_WRITE)
// 			WinPrintf( "binder: %d:%d wrote %ld of %ld, read return %ld of %ld\n",
// 			       proc->pid, thread->pid, bwr.write_consumed, bwr.write_size, bwr.read_consumed, bwr.read_size);
		memmove(ubuf, &bwr, sizeof(bwr));
		break;
	}
	#if 1
	case BINDER_SET_MAX_THREADS:
		copy_from_user(&proc->max_threads, ubuf, sizeof(proc->max_threads));
		break;
	case BINDER_SET_CONTEXT_MGR:
		if (binder_context_mgr_node != NULL) {
			printf( "binder: BINDER_SET_CONTEXT_MGR already set\n");
			ret = -EBUSY;
			goto err;
		}
		if (binder_context_mgr_uid != -1) {
			if (binder_context_mgr_uid != proc->uid) {// current->cred->euid) {
				printf( "binder: BINDER_SET_"
				       "CONTEXT_MGR bad uid %d != %d\n",
				       proc->uid, // current->cred->euid,
				       binder_context_mgr_uid);
				ret = -EPERM;
				goto err;
			}
		} else
			binder_context_mgr_uid = proc->uid; // current->cred->euid;
		binder_context_mgr_node = binder_new_node(proc, NULL, NULL);
		if (binder_context_mgr_node == NULL) {
			ret = -ENOMEM;
			goto err;
		}
		binder_context_mgr_node->local_weak_refs++;
		binder_context_mgr_node->local_strong_refs++;
		binder_context_mgr_node->has_strong_ref = 1;
		binder_context_mgr_node->has_weak_ref = 1;
		break;
	case BINDER_THREAD_EXIT:
		if (binder_debug_mask & BINDER_DEBUG_THREADS)
			printf( "binder: %d:%d exit\n",
			       proc->pid, thread->pid);
		binder_free_thread(proc, thread);
		thread = NULL;
		break;
	case BINDER_VERSION:
		if (size != sizeof(struct binder_version)) {
			ret = -EINVAL;
			goto err;
		}
		put_user(BINDER_CURRENT_PROTOCOL_VERSION, &((struct binder_version *)ubuf)->protocol_version);
		break;
		#endif
	default:
		ret = -EINVAL;
		goto err;
	}
#endif	
	ret = 0;
err:
	if (thread)
		thread->looper &= ~BINDER_LOOPER_STATE_NEED_RETURN;
	mutex_unlock(&binder_lock);
	//wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
	//if (ret && ret != -ERESTARTSYS)
	//	printf( "binder: %d:%d ioctl %x %lx returned %d\n", proc->pid, current->pid, cmd, arg, ret);

	return ret;
}
int binder_mmap(int pid,int map_size,void* old_map_addr)
{
	int ret;
	pthread_mutex_lock(&binder_lock);
	struct binder_proc *proc = GetBinderProc(pid);
	pthread_mutex_unlock(&binder_lock);
	if (!proc) {
		ret = -ENOMEM;
		goto err_bad_arg;
	}
	if (!binder_procs.first){
		return 0;
	}
	const char *failure_string;
	struct binder_buffer *buffer;
	if (proc->buffer) {
		ret = -EBUSY;
		failure_string = "already mapped";
		goto err_already_mapped;
	}
#ifdef _WIN32
	typedef void* (__cdecl *mmap_fn)(void* start, size_t length, int prot, int flags, int fd, uint64_t);
	mmap_fn mmap = (mmap_fn)GetProcAddress(LoadLibraryA("C:\\Users\\Administrator\\Desktop\\xxx\\libosal"), "mmap");
#endif
	proc->buffer = mmap(0, map_size, 3, 1, proc->fd, 0);
	if (proc->buffer == (void *)-1){
		OutputDebugStringA("111111111111111111111111111xxx");
	}
	else {
		memset(proc->buffer, 0, map_size);
		OutputDebugStringA("mmap ok");
	}
/*	WinPrintf("pid %d:mmap %p:client_mmap %p", pid, proc->buffer, old_map_addr);*/
	proc->user_buffer_offset = (uintptr_t)old_map_addr - (uintptr_t)proc->buffer;
	proc->buffer_size = map_size;

#if 0
	if (binder_update_page_range(proc, 1, proc->buffer, proc->buffer + PAGE_SIZE, vma)) {
		ret = -ENOMEM;
		failure_string = "alloc small buf";
		goto err_alloc_small_buf_failed;
	}
#endif
	
	buffer = (struct binder_buffer *)proc->buffer;
	INIT_LIST_HEAD(&proc->buffers);
	list_add(&buffer->entry, &proc->buffers);
	buffer->free = 1;
	binder_insert_free_buffer(proc, buffer);
	proc->free_async_space = proc->buffer_size / 2;
	return 0;

err_alloc_small_buf_failed:
err_alloc_pages_failed:
	proc->buffer = NULL;
err_get_vm_area_failed:
err_already_mapped:
err_bad_arg:
	return ret;
}
/// binder_open
//////////////////
int binder_open(int pid, int uid, int fd)
{
	struct binder_proc *proc;

//	if (binder_debug_mask & BINDER_DEBUG_OPEN_CLOSE)
//		printf( "binder_open: %d:%d\n", current->group_leader->pid, current->pid);

	proc = (struct binder_proc *)kzalloc(sizeof(*proc), GFP_KERNEL);
	if (proc == NULL)
		return -ENOMEM;
	// get_task_struct(current); // TODO: task
	// proc->tsk = current;
	INIT_LIST_HEAD(&proc->todo);
	init_waitqueue_head(&proc->wait);
	// proc->default_priority = task_nice(current);	// remove priority
	mutex_lock(&binder_lock);
	binder_stats.obj_created[BINDER_STAT_PROC]++;
	hlist_add_head(&proc->proc_node, &binder_procs);
	// proc->pid = current->group_leader->pid;	// TODO: pid
	proc->pid = pid;
	proc->uid = uid;

#ifdef _WIN32
	int (__cdecl *_open_osfhandle_xx)(intptr_t, int);
	_open_osfhandle_xx = (int(__cdecl*)(intptr_t, int))GetProcAddress(GetModuleHandleW(L"msvcrt.dll"), "_open_osfhandle");
	proc->fd = _open_osfhandle_xx(fd, 0x8008);
#else
	proc->fd = _open_osfhandle(fd, 0x8008);
#endif
	if (proc->fd==-1){
		OutputDebugStringA("111111111111111111111111111xxx");
	}
	else {
		OutputDebugStringA("DuplicateHandle OK");
	}
	INIT_LIST_HEAD(&proc->delivered_death);
	
	mutex_unlock(&binder_lock);

#if 0
	if (binder_proc_dir_entry_proc) {
		char strbuf[11];
		snprintf(strbuf, sizeof(strbuf), "%u", proc->pid);
		remove_proc_entry(strbuf, binder_proc_dir_entry_proc);
		create_proc_read_entry(strbuf, S_IRUGO, binder_proc_dir_entry_proc, binder_read_proc_proc, proc);
	}
#endif
	return 0;
}

static pthread_mutex_t binder_deferred_lock = PTHREAD_MUTEX_INITIALIZER;
static HLIST_HEAD(binder_deferred_list);
static struct hlist_head binder_dead_nodes;


static void binder_deferred_flush(struct binder_proc *proc)
{
	struct rb_node *n;
	int wake_count = 0;
	for (n = rb_first(&proc->threads); n != NULL; n = rb_next(n)) {
		struct binder_thread *thread = rb_entry(n, struct binder_thread, rb_node);
		thread->looper |= BINDER_LOOPER_STATE_NEED_RETURN;
		if (thread->looper & BINDER_LOOPER_STATE_WAITING) {
			wake_up_interruptible(&thread->wait);
			wake_count++;
		}
	}
	// TODO: pthread ??
	// wake_up_interruptible_all(&proc->wait);

	if (binder_debug_mask & BINDER_DEBUG_OPEN_CLOSE)
		printf("binder_flush: %d woke %d threads\n", proc->pid, wake_count);
}


static void binder_deferred_release(struct binder_proc *proc)
{
#if 1
	struct hlist_node *pos;
	struct binder_transaction *t;
	struct rb_node *n;
	int threads, nodes, incoming_refs, outgoing_refs, buffers, active_transactions, page_count;

// 	BUG_ON(proc->vma);
// 	BUG_ON(proc->files);

	hlist_del(&proc->proc_node);
	if (binder_context_mgr_node && binder_context_mgr_node->proc == proc) {
		if (binder_debug_mask & BINDER_DEBUG_DEAD_BINDER)
			printf("binder_release: %d context_mgr_node gone\n", proc->pid);
		binder_context_mgr_node = NULL;
	}

	threads = 0;
	active_transactions = 0;
	while ((n = rb_first(&proc->threads))) {
		struct binder_thread *thread = rb_entry(n, struct binder_thread, rb_node);
		threads++;
		active_transactions += binder_free_thread(proc, thread);
	}
	nodes = 0;
	incoming_refs = 0;
	while ((n = rb_first(&proc->nodes))) {
		struct binder_node *node = rb_entry(n, struct binder_node, rb_node);

		nodes++;
		rb_erase(&node->rb_node, &proc->nodes);
		list_del_init(&node->work.entry);
		if (hlist_empty(&node->refs)) {
			kfree(node);
			binder_stats.obj_deleted[BINDER_STAT_NODE]++;
		}
		else {
			struct binder_ref *ref;
			int death = 0;

			node->proc = NULL;
			node->local_strong_refs = 0;
			node->local_weak_refs = 0;
			hlist_add_head(&node->dead_node, &binder_dead_nodes);

			hlist_for_each_entry(ref, struct binder_ref, pos, &node->refs, node_entry) {
				incoming_refs++;
				if (ref->death) {
					death++;
					if (list_empty(&ref->death->work.entry)) {
						ref->death->work.type = binder_work::BINDER_WORK_DEAD_BINDER;
						list_add_tail(&ref->death->work.entry, &ref->proc->todo);
						wake_up_interruptible(&ref->proc->wait);
					}
					else
						BUG();
				}
			}
			if (binder_debug_mask & BINDER_DEBUG_DEAD_BINDER)
				printf("binder: node %d now dead, refs %d, death %d\n", node->debug_id, incoming_refs, death);
		}
	}
	outgoing_refs = 0;
	while ((n = rb_first(&proc->refs_by_desc))) {
		struct binder_ref *ref = rb_entry(n, struct binder_ref, rb_node_desc);
		outgoing_refs++;
		binder_delete_ref(ref);
	}
	binder_release_work(&proc->todo);
	buffers = 0;

	while ((n = rb_first(&proc->allocated_buffers))) {
		struct binder_buffer *buffer = rb_entry(n, struct binder_buffer, rb_node);
		t = buffer->transaction;
		if (t) {
			t->buffer = NULL;
			buffer->transaction = NULL;
			printf("binder: release proc %d, transaction %d, not freed\n", proc->pid, t->debug_id);
			/*BUG();*/
		}
		binder_free_buf(proc, buffer);
		buffers++;
	}

	binder_stats.obj_deleted[BINDER_STAT_PROC]++;

	page_count = 0;
// 	if (proc->pages) {
// 		int i;
// 		for (i = 0; i < proc->buffer_size / PAGE_SIZE; i++) {
// 			if (proc->pages[i]) {
// 				if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
// 					printf("binder_release: %d: page %d at %p not freed\n", proc->pid, i, (uint32_t)proc->buffer + i * PAGE_SIZE);
// 				// __free_page(proc->pages[i]);
// 				// TODO: 释放物理内存页
// 				page_count++;
// 			}
// 		}
// 		kfree(proc->pages);
// 		// vfree(proc->buffer);	// TODO: ...
// 	}

	// put_task_struct(proc->tsk); // TODO: 释放任务结构体

	if (binder_debug_mask & BINDER_DEBUG_OPEN_CLOSE)
		printf("binder_release: %d threads %d, nodes %d (ref %d), refs %d, active transactions %d, buffers %d, pages %d\n",
			proc->pid, threads, nodes, incoming_refs, outgoing_refs, active_transactions, buffers, page_count);

	kfree(proc);
#endif
}

static void binder_deferred_func()
{
	struct binder_proc *proc;
	struct files_struct *files;

	int defer;
	do {
		mutex_lock(&binder_lock);
 		mutex_lock(&binder_deferred_lock);
		if (!hlist_empty(&binder_deferred_list)) {
// 			proc = hlist_entry(binder_deferred_list.first,
// 				struct binder_proc, deferred_work_node);
// 			hlist_del_init(&proc->deferred_work_node);
// 			defer = proc->deferred_work;
// 			proc->deferred_work = 0;
		}
		else {
			proc = NULL;
			defer = 0;
		}
 		mutex_unlock(&binder_deferred_lock);

		files = NULL;
		if (defer & BINDER_DEFERRED_PUT_FILES)
// 			if ((files = proc->files))
// 				proc->files = NULL;

		if (defer & BINDER_DEFERRED_FLUSH)
			binder_deferred_flush(proc);

		if (defer & BINDER_DEFERRED_RELEASE)
			binder_deferred_release(proc); /* frees proc */

		mutex_unlock(&binder_lock);
#if 0	// TODO:　释放文件结构体
		if (files)
			put_files_struct(files);
#endif	
	} while (proc);
}

static void binder_defer_work(struct binder_proc *proc, int defer)
{
	mutex_lock(&binder_deferred_lock);
	binder_deferred_func();
	mutex_unlock(&binder_deferred_lock);
}
int binder_flush(int pid)
{
	pthread_mutex_lock(&binder_lock);
	struct binder_proc *proc = GetBinderProc(pid);
	pthread_mutex_unlock(&binder_lock);
	if (!proc){
		return -1;
	}
	binder_defer_work(proc, BINDER_DEFERRED_FLUSH);

	return 0;
}
/// binder_release
//////////////////
int binder_release(int pid)
{
	pthread_mutex_lock(&binder_lock);
	struct binder_proc *proc = GetBinderProc(pid);
	pthread_mutex_unlock(&binder_lock);
	if (!proc) {
		return -1;
	}
#if 0
	if (binder_proc_dir_entry_proc) {
		char strbuf[11];
		snprintf(strbuf, sizeof(strbuf), "%u", proc->pid);
		remove_proc_entry(strbuf, binder_proc_dir_entry_proc);
	}
#endif

	binder_defer_work(proc, BINDER_DEFERRED_RELEASE);

	return 0;
}


char *print_binder_transaction(char *buf, char *end, const char *prefix, struct binder_transaction *t)
{
	buf += snprintf(buf, end - buf, "%s %d: %p from %d:%d to %d:%d code %x flags %x pri %ld r%d",
		prefix, t->debug_id, t, t->from ? t->from->proc->pid : 0,
		t->from ? t->from->pid : 0,
		t->to_proc ? t->to_proc->pid : 0,
		t->to_thread ? t->to_thread->pid : 0,
		t->code, t->flags, t->priority, t->need_reply);
	if (buf >= end)
		return buf;
	if (t->buffer == NULL) {
		buf += snprintf(buf, end - buf, " buffer free\n");
		return buf;
	}
	if (t->buffer->target_node) {
		buf += snprintf(buf, end - buf, " node %d",
			t->buffer->target_node->debug_id);
		if (buf >= end)
			return buf;
	}
	buf += snprintf(buf, end - buf, " size %zd:%zd data %p\n",
		t->buffer->data_size, t->buffer->offsets_size,
		t->buffer->data);
	return buf;
}

char *print_binder_buffer(char *buf, char *end, const char *prefix, struct binder_buffer *buffer)
{
	buf += snprintf(buf, end - buf, "%s %d: %p size %zd:%zd %s\n",
		prefix, buffer->debug_id, buffer->data,
		buffer->data_size, buffer->offsets_size,
		buffer->transaction ? "active" : "delivered");
	return buf;
}

char *print_binder_work(char *buf, char *end, const char *prefix,
	const char *transaction_prefix, struct binder_work *w)
{
	struct binder_node *node;
	struct binder_transaction *t;

	switch (w->type) {
	case binder_work::BINDER_WORK_TRANSACTION:
		t = container_of(w, struct binder_transaction, work);
		buf = print_binder_transaction(buf, end, transaction_prefix, t);
		break;
	case binder_work::BINDER_WORK_TRANSACTION_COMPLETE:
		buf += snprintf(buf, end - buf,
			"%stransaction complete\n", prefix);
		break;
	case binder_work::BINDER_WORK_NODE:
		node = container_of(w, struct binder_node, work);
		buf += snprintf(buf, end - buf, "%snode work %d: u%p c%p\n",
			prefix, node->debug_id, node->ptr, node->cookie);
		break;
	case binder_work::BINDER_WORK_DEAD_BINDER:
		buf += snprintf(buf, end - buf, "%shas dead binder\n", prefix);
		break;
	case binder_work::BINDER_WORK_DEAD_BINDER_AND_CLEAR:
		buf += snprintf(buf, end - buf,
			"%shas cleared dead binder\n", prefix);
		break;
	case binder_work::BINDER_WORK_CLEAR_DEATH_NOTIFICATION:
		buf += snprintf(buf, end - buf,
			"%shas cleared death notification\n", prefix);
		break;
	default:
		buf += snprintf(buf, end - buf, "%sunknown work: type %d\n",
			prefix, w->type);
		break;
	}
	return buf;
}

char *print_binder_thread(char *buf, char *end, struct binder_thread *thread, int print_always)
{
	struct binder_transaction *t;
	struct binder_work *w;
	char *start_buf = buf;
	char *header_buf;

	buf += snprintf(buf, end - buf, "  thread %d: l %02x\n", thread->pid, thread->looper);
	header_buf = buf;
	t = thread->transaction_stack;
	while (t) {
		if (buf >= end)
			break;
		if (t->from == thread) {
			buf = print_binder_transaction(buf, end, "    outgoing transaction", t);
			t = t->from_parent;
		}
		else if (t->to_thread == thread) {
			buf = print_binder_transaction(buf, end, "    incoming transaction", t);
			t = t->to_parent;
		}
		else {
			buf = print_binder_transaction(buf, end, "    bad transaction", t);
			t = NULL;
		}
	}
	list_for_each_entry(w, struct binder_work, &thread->todo, entry) {
		if (buf >= end)
			break;
		buf = print_binder_work(buf, end, "    ",
			"    pending transaction", w);
	}
	if (!print_always && buf == header_buf)
		buf = start_buf;
	return buf;
}

char *print_binder_node(char *buf, char *end, struct binder_node *node)
{
	struct binder_ref *ref;
	struct hlist_node *pos;
	struct binder_work *w;
	int count;
	count = 0;
	hlist_for_each_entry(ref, struct binder_ref, pos, &node->refs, node_entry)
		count++;

	buf += snprintf(buf, end - buf, "  node %d: u%p c%p hs %d hw %d ls %d lw %d is %d iw %d",
		node->debug_id, node->ptr, node->cookie,
		node->has_strong_ref, node->has_weak_ref,
		node->local_strong_refs, node->local_weak_refs,
		node->internal_strong_refs, count);
	if (buf >= end)
		return buf;
	if (count) {
		buf += snprintf(buf, end - buf, " proc");
		if (buf >= end)
			return buf;
		hlist_for_each_entry(ref, struct binder_ref, pos, &node->refs, node_entry) {
			buf += snprintf(buf, end - buf, " %d", ref->proc->pid);
			if (buf >= end)
				return buf;
		}
	}
	buf += snprintf(buf, end - buf, "\n");
	list_for_each_entry(w, struct binder_work, &node->async_todo, entry) {
		if (buf >= end)
			break;
		buf = print_binder_work(buf, end, "    ",
			"    pending async transaction", w);
	}
	return buf;
}

char *print_binder_ref(char *buf, char *end, struct binder_ref *ref)
{
	buf += snprintf(buf, end - buf, "  ref %d: desc %d %snode %d s %d w %d d %p\n",
		ref->debug_id, ref->desc, ref->node->proc ? "" : "dead ",
		ref->node->debug_id, ref->strong, ref->weak, ref->death);
	return buf;
}

char *print_binder_proc(char *buf, char *end, struct binder_proc *proc, int print_all)
{
	struct binder_work *w;
	struct rb_node *n;
	char *start_buf = buf;
	char *header_buf;

	buf += snprintf(buf, end - buf, "proc %d\n", proc->pid);
	header_buf = buf;

	for (n = rb_first(&proc->threads); n != NULL && buf < end; n = rb_next(n))
		buf = print_binder_thread(buf, end, rb_entry(n, struct binder_thread, rb_node), print_all);
	for (n = rb_first(&proc->nodes); n != NULL && buf < end; n = rb_next(n)) {
		struct binder_node *node = rb_entry(n, struct binder_node, rb_node);
		if (print_all || node->has_async_transaction)
			buf = print_binder_node(buf, end, node);
	}
	if (print_all) {
		for (n = rb_first(&proc->refs_by_desc); n != NULL && buf < end; n = rb_next(n))
			buf = print_binder_ref(buf, end, rb_entry(n, struct binder_ref, rb_node_desc));
	}
	for (n = rb_first(&proc->allocated_buffers); n != NULL && buf < end; n = rb_next(n))
		buf = print_binder_buffer(buf, end, "  buffer", rb_entry(n, struct binder_buffer, rb_node));
	list_for_each_entry(w, struct binder_work, &proc->todo, entry) {
		if (buf >= end)
			break;
		buf = print_binder_work(buf, end, "  ",
			"  pending transaction", w);
	}
	list_for_each_entry(w, struct binder_work, &proc->delivered_death, entry) {
		if (buf >= end)
			break;
		buf += snprintf(buf, end - buf, "  has delivered dead binder\n");
		break;
	}
	if (!print_all && buf == header_buf)
		buf = start_buf;
	return buf;
}

static const char *binder_return_strings[] = {
	"BR_ERROR",
	"BR_OK",
	"BR_TRANSACTION",
	"BR_REPLY",
	"BR_ACQUIRE_RESULT",
	"BR_DEAD_REPLY",
	"BR_TRANSACTION_COMPLETE",
	"BR_INCREFS",
	"BR_ACQUIRE",
	"BR_RELEASE",
	"BR_DECREFS",
	"BR_ATTEMPT_ACQUIRE",
	"BR_NOOP",
	"BR_SPAWN_LOOPER",
	"BR_FINISHED",
	"BR_DEAD_BINDER",
	"BR_CLEAR_DEATH_NOTIFICATION_DONE",
	"BR_FAILED_REPLY"
};

static const char *binder_command_strings[] = {
	"BC_TRANSACTION",
	"BC_REPLY",
	"BC_ACQUIRE_RESULT",
	"BC_FREE_BUFFER",
	"BC_INCREFS",
	"BC_ACQUIRE",
	"BC_RELEASE",
	"BC_DECREFS",
	"BC_INCREFS_DONE",
	"BC_ACQUIRE_DONE",
	"BC_ATTEMPT_ACQUIRE",
	"BC_REGISTER_LOOPER",
	"BC_ENTER_LOOPER",
	"BC_EXIT_LOOPER",
	"BC_REQUEST_DEATH_NOTIFICATION",
	"BC_CLEAR_DEATH_NOTIFICATION",
	"BC_DEAD_BINDER_DONE"
};

static const char *binder_objstat_strings[] = {
	"proc",
	"thread",
	"node",
	"ref",
	"death",
	"transaction",
	"transaction_complete"
};

char *print_binder_stats(char *buf, char *end, const char *prefix, struct binder_stats *stats)
{
	int i;

/*	BUILD_BUG_ON(ARRAY_SIZE(stats->bc) != ARRAY_SIZE(binder_command_strings));*/
	for (i = 0; i < ARRAY_SIZE(stats->bc); i++) {
		if (stats->bc[i])
			buf += snprintf(buf, end - buf, "%s%s: %d\n", prefix,
				binder_command_strings[i], stats->bc[i]);
		if (buf >= end)
			return buf;
	}

/*	BUILD_BUG_ON(ARRAY_SIZE(stats->br) != ARRAY_SIZE(binder_return_strings));*/
	for (i = 0; i < ARRAY_SIZE(stats->br); i++) {
		if (stats->br[i])
			buf += snprintf(buf, end - buf, "%s%s: %d\n", prefix,
				binder_return_strings[i], stats->br[i]);
		if (buf >= end)
			return buf;
	}

// 	BUILD_BUG_ON(ARRAY_SIZE(stats->obj_created) != ARRAY_SIZE(binder_objstat_strings));
// 	BUILD_BUG_ON(ARRAY_SIZE(stats->obj_created) != ARRAY_SIZE(stats->obj_deleted));
	for (i = 0; i < ARRAY_SIZE(stats->obj_created); i++) {
		if (stats->obj_created[i] || stats->obj_deleted[i])
			buf += snprintf(buf, end - buf, "%s%s: active %d total %d\n", prefix,
				binder_objstat_strings[i],
				stats->obj_created[i] - stats->obj_deleted[i],
				stats->obj_created[i]);
		if (buf >= end)
			return buf;
	}
	return buf;
}

char *print_binder_proc_stats(char *buf, char *end, struct binder_proc *proc)
{
	struct binder_work *w;
	struct rb_node *n;
	int count, strong, weak;

	buf += snprintf(buf, end - buf, "proc %d\n", proc->pid);
	if (buf >= end)
		return buf;
	count = 0;
	for (n = rb_first(&proc->threads); n != NULL; n = rb_next(n))
		count++;
	buf += snprintf(buf, end - buf, "  threads: %d\n", count);
	if (buf >= end)
		return buf;
	buf += snprintf(buf, end - buf, "  requested threads: %d+%d/%d\n"
		"  ready threads %d\n"
		"  free async space %zd\n", proc->requested_threads,
		proc->requested_threads_started, proc->max_threads,
		proc->ready_threads, proc->free_async_space);
	if (buf >= end)
		return buf;
	count = 0;
	for (n = rb_first(&proc->nodes); n != NULL; n = rb_next(n))
		count++;
	buf += snprintf(buf, end - buf, "  nodes: %d\n", count);
	if (buf >= end)
		return buf;
	count = 0;
	strong = 0;
	weak = 0;
	for (n = rb_first(&proc->refs_by_desc); n != NULL; n = rb_next(n)) {
		struct binder_ref *ref = rb_entry(n, struct binder_ref, rb_node_desc);
		count++;
		strong += ref->strong;
		weak += ref->weak;
	}
	buf += snprintf(buf, end - buf, "  refs: %d s %d w %d\n", count, strong, weak);
	if (buf >= end)
		return buf;

	count = 0;
	for (n = rb_first(&proc->allocated_buffers); n != NULL; n = rb_next(n))
		count++;
	buf += snprintf(buf, end - buf, "  buffers: %d\n", count);
	if (buf >= end)
		return buf;

	count = 0;
	list_for_each_entry(w, struct binder_work, &proc->todo, entry) {
		switch (w->type) {
		case binder_work::BINDER_WORK_TRANSACTION:
			count++;
			break;
		default:
			break;
		}
	}
	buf += snprintf(buf, end - buf, "  pending transactions: %d\n", count);
	if (buf >= end)
		return buf;

	buf = print_binder_stats(buf, end, "  ", &proc->stats);

	return buf;
}