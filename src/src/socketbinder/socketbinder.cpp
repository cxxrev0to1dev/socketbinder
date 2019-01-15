// socketbinder.cpp : Defines the entry point for the console application.
//

#include <cstdint>
#include "stdafx.h"
#pragma comment(lib,"pthreadVC1.lib")
#pragma comment(lib,"ws2_32.lib")

#include <windows.h>  
#include <conio.h>
#include "PipeServer.h"
#include <io.h>
#include <cstdio>
#include <fcntl.h>
#include <iostream>
#include <string>
#include "glog/logging.h"
#include "base/commandlineflags.h"
#include "config.h"
DECLARE_bool(logtostderr);
#include "PipeStream.h"
#include "PipeProtocol.h"
#include "binder.h"
#include "glog/logging.h"
#pragma comment(lib,"base.lib")

int(__cdecl *osal_sockmap_add)(const char*, int, int);
int(__stdcall *osal_winsockInit)();
uint32_t(__cdecl* readPipe)(HANDLE hFile, void *buf, int len);
uint32_t(__cdecl* writePipe)(HANDLE hFile, const void* buf, int len);
BOOL (__cdecl* closePipe)(HANDLE hObject);

static HANDLE s_semaphore[500] = {nullptr};
static HANDLE s_pipe_handle[500] = {nullptr};
static uint32_t s_client_count = 0;


void* DynamicMallocRead(HANDLE hfile,const uint32_t len) {

	{
		uint32_t v7 = (uint32_t)((char *)len + 0xFF);
		if ((uint32_t)len >= 0)
			v7 = len;
		uint32_t v26 = len;
		uint32_t v27 = (signed int)v7 >> 8;// NOTE:It must be like this
		if ((signed int)v7 >> 8 > 0) {// NOTE:It must be like this
									  //OutputDebugStringA("1111111111111111");
		}
		else {
			//OutputDebugStringA("1111111111111111");
		}
	}
	{
		signed int ext_len = len;
		signed int* v1 = (signed int *)malloc(len + 0x10);
		memset(v1, 0, len + 0x10);
		int v2 = ext_len + 0xFF;
		if (ext_len >= 0)
			v2 = ext_len;
		signed int *v28 = v1;
		uint32_t v3 = (signed int)v2 >> 8;// NOTE:It must be like this
		if ((signed int)v2 >> 8 > 0)// NOTE:It must be like this
		{
			unsigned __int8 *v4 = (unsigned __int8 *)v1;
			int v5 = 0;
			while (1)
			{
				size_t lllll1 = 0x100;
				if (readPipe(hfile,v4, 0x100) != 0x100)
					break;
				v4 += 256;
				if (++v5 == v3)
					break;
			}
		}
		unsigned __int8 *v4 = (unsigned __int8 *)v1;
		unsigned int v8 = (unsigned int)(ext_len >> 31) >> 0x18;
		int v9 = (unsigned __int8)(v8 + ext_len) - v8;
		size_t v10 = v9;
		if (v9 > 0 && (readPipe(hfile,v4, v10) == v9)) {
			return v1;
		}
		return v1;
	}
}
int msg_handler(HANDLE pipe) {
	int result = 0;
	ArmVM::ENUM_CALL_TYPE call_type;
	struct ArmVM::base_struct_msg base_struct;
	const unsigned char* null_check = nullptr;
	CHECK_EQ(readPipe(pipe, &call_type, sizeof(uint32_t)), sizeof(uint32_t));
	CHECK_EQ(readPipe(pipe, &base_struct, sizeof(struct ArmVM::base_struct_msg)), sizeof(struct ArmVM::base_struct_msg));

	if (call_type == ArmVM::kSockBinderOpen) {
		uint32_t fd = 0;
		CHECK_EQ(readPipe(pipe, &fd, sizeof(uint32_t)), sizeof(uint32_t));
		struct ArmVM::struct_open_msg open_msg = { { call_type,base_struct.pid,base_struct.tid,base_struct.uid,base_struct.ext_len }, fd };
		static int once = 1;
		if (once)
		{
			//Sleep(10000);
			once = 0;
		}
		result = binder_open(open_msg.msg.pid, open_msg.msg.uid, open_msg.fd);
		CHECK_GE(result, 0);
		CHECK_EQ(writePipe(pipe, &result, sizeof(uint32_t)), sizeof(uint32_t));
	}
	else if (call_type == ArmVM::kSockBinderClose) {
		struct ArmVM::struct_close_msg close_msg = { { call_type,base_struct.pid,base_struct.tid,base_struct.uid,base_struct.ext_len } };
		OutputDebugStringA("33333333333333333333333");
	}
	else if (call_type == ArmVM::kSockBinderMMap) {
		struct ArmVM::struct_mmap_info map_info = { 0, nullptr };
		CHECK_EQ(readPipe(pipe, &map_info, sizeof(struct ArmVM::struct_mmap_info)), sizeof(struct ArmVM::struct_mmap_info));
		struct ArmVM::struct_mmap_msg mmap_msg = { { call_type,base_struct.pid,base_struct.tid,base_struct.uid,base_struct.ext_len }, map_info };
		result = binder_mmap(base_struct.pid, map_info.map_size, map_info.map_addr);
		CHECK_GE(result, 0);
		CHECK_EQ(writePipe(pipe, &result, sizeof(uint32_t)), sizeof(uint32_t));
	}
	else if (call_type == ArmVM::kSockBinderIoctl) {
		ArmVM::struct_ioctl_info ioctl_info;
		int bytes_available = base_struct.ext_len;
		uint8_t* xxxx = (uint8_t*)DynamicMallocRead(pipe,bytes_available);
/*		CHECK_EQ(readPipe(pipe, &xxxx[0], bytes_available), bytes_available);*/
		memmove(&ioctl_info, &xxxx[0], sizeof(struct ArmVM::struct_ioctl_info));
		bytes_available -= sizeof(struct ArmVM::struct_ioctl_info);
		struct ArmVM::struct_ioctl_msg ioctl_msg = { { call_type,base_struct.pid,base_struct.tid,base_struct.uid,base_struct.ext_len }, ioctl_info,{ 0 } };
		if (ioctl_info.ioctl_code == ArmVM::kBINDER_WRITE_READ) {
			ArmVM::binder_write_read bwr = { 0 };
			memmove(&bwr, &xxxx[sizeof(struct ArmVM::struct_ioctl_info)], sizeof(struct binder_write_read));
			bytes_available -= sizeof(struct binder_write_read);
			bwr.write_buffer = (unsigned long)malloc(bwr.write_size);
			bwr.read_buffer = (unsigned long)malloc(bwr.read_size);
			if (bwr.write_buffer && bwr.write_size) {
				memset((void*)bwr.write_buffer, 0, bwr.write_size);
				memmove((void*)bwr.write_buffer, &xxxx[base_struct.ext_len - bytes_available], bytes_available);
			}
			if (bwr.read_buffer && bwr.read_size) {
				memset((void*)bwr.read_buffer, 0, bwr.read_size);
			}
			static int count = 0;
			result = binder_ioctl(ioctl_info.ioctl_code, (unsigned long)&bwr, ioctl_info.arg, base_struct.pid, base_struct.tid);
			if (result != 0) {
				LOG(ERROR) << "xxxxxxxxxxxxxxxxxxxxxx";
				Sleep(10000);
			}
			else {
				LOG(INFO) << "ok:" << count;
			}
			CHECK_EQ(result, 0);
			CHECK_EQ(writePipe(pipe, &result, sizeof(uint32_t)), sizeof(uint32_t));
			CHECK_EQ(writePipe(pipe, &bwr, sizeof(ArmVM::binder_write_read)), sizeof(ArmVM::binder_write_read));
			if (bwr.read_consumed > 0 && !result) {
				CHECK_EQ(writePipe(pipe, (void*)(void*)bwr.read_buffer, bwr.read_consumed), bwr.read_consumed);
			}
			free((void*)bwr.write_buffer);
			free((void*)bwr.read_buffer);
		}
		else if (ioctl_info.ioctl_code == ArmVM::kBINDER_SET_MAX_THREADS) {
			uint32_t max_threads = 0;
			if (bytes_available == sizeof(uint32_t))
				memmove(&max_threads, &xxxx[sizeof(struct ArmVM::struct_ioctl_info)], sizeof(uint32_t));
			result = binder_set_max_threads(BINDER_SET_MAX_THREADS, (unsigned long)&max_threads, 0, base_struct.pid, base_struct.tid);
			CHECK_GE(result, 0);
			CHECK_EQ(writePipe(pipe, &result, sizeof(uint32_t)), sizeof(uint32_t));
			CHECK_EQ(writePipe(pipe, &max_threads, sizeof(uint32_t)), sizeof(uint32_t));
		}
		else if (ioctl_info.ioctl_code == ArmVM::kBINDER_THREAD_EXIT) {
			uint32_t exit_threads = 0;
			if (bytes_available == sizeof(uint32_t))
				memmove(&exit_threads, &xxxx[sizeof(struct ArmVM::struct_ioctl_info)], sizeof(uint32_t));
			result = binder_thread_exit(BINDER_THREAD_EXIT, 0, 0, base_struct.pid, base_struct.tid);
			CHECK_GE(result, 0);
			CHECK_EQ(writePipe(pipe, &result, sizeof(uint32_t)), sizeof(uint32_t));
		}
		else if (ioctl_info.ioctl_code == ArmVM::kBINDER_SET_CONTEXT_MGR)
		{
			uint32_t exit_threads = 0;
			if (bytes_available == sizeof(uint32_t))
				memmove(&exit_threads, &xxxx[sizeof(struct ArmVM::struct_ioctl_info)], sizeof(uint32_t));
			result = binder_set_context_mgr(ArmVM::kBINDER_SET_CONTEXT_MGR_1, (unsigned long)&exit_threads, 0, base_struct.pid, base_struct.tid);
			CHECK_GE(result, 0);
			CHECK_EQ(writePipe(pipe, &result, sizeof(uint32_t)), sizeof(uint32_t));
			CHECK_EQ(writePipe(pipe, &exit_threads, sizeof(uint32_t)), sizeof(uint32_t));
		}
		else {
			uint32_t version_data = 0;
			if (bytes_available == sizeof(uint32_t))
				memmove(&version_data, &xxxx[sizeof(struct ArmVM::struct_ioctl_info)], sizeof(uint32_t));
			result = binder_binder_version(ArmVM::kBINDER_VERSION, (unsigned long)&version_data, 0, base_struct.pid, base_struct.tid);
			CHECK_GE(result, 0);
			CHECK_EQ(writePipe(pipe, &result, sizeof(uint32_t)), sizeof(uint32_t));
			CHECK_EQ(writePipe(pipe, &version_data, sizeof(uint32_t)), sizeof(uint32_t));
		}
		if (xxxx){
			free(xxxx);
		}
	}
	return result;
}
void *dword_40B4E0[500]; // idb
int PIPE_HANDLE_ARRAY[500]; // idb
int dword_40C480[500]; // idb


void* thread_main(void *p_arg) {
// 	HANDLE pipe_handle = s_pipe_handle[(uint32_t)p_arg];
// 	HANDLE semaphore_handle = s_pipe_handle[(uint32_t)p_arg];
	int i;
	uint32_t i1 = (uint32_t)p_arg;
	//Sleep(10000);
	for (i = (i1 - (uint32_t)dword_40B4E0) >> 2; ; dword_40B4E0[i + 0x3E8] = 0)
	{
		WaitForSingleObject((HANDLE)dword_40B4E0[i], INFINITE);
		void* v2 = (void **)dword_40B4E0[i + 500];
		HANDLE pipe_handle = (HANDLE)*(uint32_t*)v2;
		ULONG client_pid;
		GetNamedPipeClientProcessId(pipe_handle, &client_pid);
		while (!msg_handler(pipe_handle));
		DisconnectNamedPipe(pipe_handle);
		CloseHandle(pipe_handle);
	}
	return nullptr;
}
static void InitAddress() {
	osal_sockmap_add = (int(__cdecl*)(const char*, int, int))GetProcAddress(LoadLibraryA("C:\\Windroy\\windroy_root\\system\\lib\\libosal_hal"), "osal_sockmap_add");
	osal_winsockInit = (int(__stdcall*)())GetProcAddress(LoadLibraryA("C:\\Windroy\\windroy_root\\system\\lib\\libosal_hal"), "osal_winsockInit");
	readPipe = (uint32_t(__cdecl*)(HANDLE, void*, int))GetProcAddress(LoadLibraryA("C:\\Windroy\\windroy_root\\system\\lib\\libsbutils.dll"), "readPipe");
	writePipe = (uint32_t(__cdecl*)(HANDLE, const void*, int))GetProcAddress(LoadLibraryA("C:\\Windroy\\windroy_root\\system\\lib\\libsbutils.dll"), "writePipe");
	closePipe = (BOOL(__cdecl*)(HANDLE))GetProcAddress(LoadLibraryA("C:\\Windroy\\windroy_root\\system\\lib\\libsbutils.dll"), "closePipe");
}
int main(int argc, char **argv)
{
	int index = 0,state = 0;
	InitAddress();
	osal_winsockInit();
	if (osal_sockmap_add("socketbinder", 0, GetCurrentProcessId()))
		return -1;
/*
	while (true) {
		HANDLE clientPipe = CreateNamedPipeA(ArmVM::kPipeServerName,
			PIPE_ACCESS_DUPLEX, PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES,
			ArmVM::kPipeMaxBufferSize,
			ArmVM::kPipeMaxBufferSize,
			NMPWAIT_WAIT_FOREVER, 0);
		static bool t1 = false;
		if (!t1) {
			Sleep(10000);
			t1 = true;
		}
		if (clientPipe == INVALID_HANDLE_VALUE) {
			break;
		}
		if (ConnectNamedPipe((HANDLE)clientPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
			void* v6 = (void*)malloc(4u);
			*(uint32_t*)v6 = (uint32_t)clientPipe;
			if (s_client_count <= 0)
			{
			LABEL_12:
				s_client_count = index + 1;
				HANDLE Semaphore_handle = (void *)CreateSemaphore(0, 0, 1, 0);
				dword_40B4E0[index] = Semaphore_handle;
				dword_40B4E0[index + 1000] = 0;
				pthread_t thread;
				pthread_create(&thread, nullptr, thread_main, (int *)(4 * index + (uint32_t)dword_40B4E0));
				state = index + 1000;
			}
			else
			{
				while (dword_40C480[0])
				{
					int v9 = 0;
					while (++v9 != index)
					{
						if (!dword_40C480[v9])
						{
							if (v9 >= 0)
							{
								index = v9;
								state = v9 + 1000;
								goto LABEL_13;
							}
							break;
						}
					}
					if (index > 0x1F3)
					{
						Sleep(1000);
						index = s_client_count;
						if (s_client_count > 0)
							continue;
					}
					goto LABEL_12;
				}
				index = 0;
				state = 0x3E8;
			}
		LABEL_13:
			PIPE_HANDLE_ARRAY[index] = (int)v6;
			dword_40B4E0[state] = (void *)1;
			ReleaseSemaphore((HANDLE)dword_40B4E0[index], 1, 0);
		}
		else {
			CloseHandle((HANDLE)clientPipe);
			clientPipe = nullptr;
		}
	}
*/
	ArmVM::PipeServer* server = ArmVM::PipeServer::create();
	server->Main();
    return (!server->isExiting());
}

