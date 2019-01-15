#ifndef _SOCKETBINDER_PIPE_PROTOCOL_H
#define _SOCKETBINDER_PIPE_PROTOCOL_H

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <cctype>

namespace ArmVM {

	const size_t kBINDER_VM_SIZE = ((1 * 1024 * 1024) - (4096 * 2));

	enum ENUM_CALL_TYPE
	{
		kSockBinderInit = -1,
		kSockBinderClose = 3,
		kSockBinderKill = 3,
		kSockBinderIoctl = 2,
		kSockBinderMMap = 1,
		kSockBinderMunmap,
		kSockBinderOpen = 0
	};
	enum ENUM_BINDER_TABLE
	{
		kBINDER_WRITE_READ = 0xC0186201,
		kBINDER_SET_IDLE_TIMEOUT = 0x40046203,
		kBINDER_SET_MAX_THREADS = 0x40046205,
		kBINDER_SET_IDLE_PRIORITY = 0x40046206,
		kBINDER_SET_CONTEXT_MGR = 0x40046207,
		kBINDER_SET_CONTEXT_MGR_1 = 0x80046207,
		kBINDER_THREAD_EXIT = 0x40046208,
		kBINDER_VERSION = 0xC0046209,
	};
	struct binder_write_read {
		signed long write_size;
		signed long write_consumed;
		unsigned long write_buffer;
		signed long read_size;
		signed long read_consumed;
		unsigned long read_buffer;
	};
	struct base_msg
	{
		ENUM_CALL_TYPE call_type;
		uint32_t pid;
		uint32_t tid;
		uint32_t uid;
		uint32_t ext_len;
	};
	struct base_struct_msg
	{
		uint32_t pid;
		uint32_t tid;
		uint32_t uid;
		uint32_t ext_len;
	};
	struct struct_mmap_info {
		uint32_t map_size;
		void* map_addr;
	};
	struct struct_mmap_msg
	{
		base_msg msg;
		struct_mmap_info map_info;
	};
	struct struct_kill_msg
	{
		base_msg msg;
	};
	struct struct_ioctl_info
	{
		uint32_t ioctl_code;
		uint32_t arg;
	};
	struct struct_ioctl_msg
	{
		base_msg msg;
		struct_ioctl_info ioctl_info;
		binder_write_read bwr;
	};
	struct struct_ioctl_msg_parse
	{
		struct_ioctl_info ioctl_info;
		binder_write_read bwr;
	};
	struct struct_open_msg
	{
		base_msg msg;
		uint32_t fd;
	};
	struct struct_close_msg
	{
		base_msg msg;
	};
}

#endif
