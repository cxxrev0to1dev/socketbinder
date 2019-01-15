#include <process.h>
#include <Windows.h>
#pragma comment(lib,"base.lib")
#pragma comment(lib,"pthreadVC1.lib")
#include <pthread.h>
#pragma comment(lib,"user32.lib")
#pragma comment(lib,"ws2_32.lib")
#include "glog/logging.h"
#include "base/commandlineflags.h"
#include "config.h"
DECLARE_bool(logtostderr);
#include "base/base.h"
#include "socketbinder/PipeProtocol.h"
#include "binder.h"
#include <iomanip>
#include <sstream>
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma comment(linker, "/EXPORT:create_binder_ioctl_int_message=_AheadLib_create_binder_ioctl_int_message,@1")
#pragma comment(linker, "/EXPORT:socketeq_clear_used_share_file=_AheadLib_socketeq_clear_used_share_file,@3")
#pragma comment(linker, "/EXPORT:socketeq_get_file_name=_AheadLib_socketeq_get_file_name,@5")
#pragma comment(linker, "/EXPORT:socketeq_install_share_file=_AheadLib_socketeq_install_share_file,@6")

// #pragma comment(linker, "/EXPORT:send_message=_AheadLib_send_message,@2")
// #pragma comment(linker, "/EXPORT:socketeq_close=_AheadLib_socketeq_close,@4")
// #pragma comment(linker, "/EXPORT:socketeq_ioctl=_AheadLib_socketeq_ioctl,@7")
// #pragma comment(linker, "/EXPORT:socketeq_kill=_AheadLib_socketeq_kill,@8")
// #pragma comment(linker, "/EXPORT:socketeq_mmap=_AheadLib_socketeq_mmap,@9")
// #pragma comment(linker, "/EXPORT:socketeq_munmap=_AheadLib_socketeq_munmap,@10")
// #pragma comment(linker, "/EXPORT:socketeq_open=_AheadLib_socketeq_open,@11")

// #pragma comment(linker, "/EXPORT:socketeq_open=_socketeq_open,@11")
// #pragma comment(linker, "/EXPORT:socketeq_munmap=_socketeq_munmap,@10")
// #pragma comment(linker, "/EXPORT:socketeq_mmap=_socketeq_mmap,@9")
// #pragma comment(linker, "/EXPORT:socketeq_kill=_socketeq_kill,@8")
// #pragma comment(linker, "/EXPORT:send_message=_send_message,@2")
// #pragma comment(linker, "/EXPORT:socketeq_close=_socketeq_close,@4")
// #pragma comment(linker, "/EXPORT:socketeq_ioctl=_socketeq_ioctl,@7")
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define EXTERNC extern "C"
#define NAKED __declspec(naked)
#define EXPORT __declspec(dllexport)

#define ALCPP EXPORT NAKED
#define ALSTD EXTERNC EXPORT NAKED void __stdcall
#define ALCFAST EXTERNC EXPORT NAKED void __fastcall
#define ALCDECL EXTERNC NAKED void __cdecl
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static BaseAPI s_base_api;
static pthread_once_t s_once = PTHREAD_ONCE_INIT;
static pthread_key_t s_pipe_key;
static int s_tid = 0;
static uint32_t s_mmap_end_addr = 0;
void __cdecl DestrctorClosePipe(void *a1)
{
	if (a1)
	{
		if (!s_base_api.StructAPI()->closePipe){
			s_base_api.Load();
		}
		s_base_api.StructAPI()->closePipe((void*)*(uint32_t*)a1);
		free(a1);
	}
	pthread_setspecific(s_pipe_key, 0);
}
static void once_run(void)
{
	pthread_key_create(&s_pipe_key, DestrctorClosePipe);
}
EXTERNC EXPORT int __cdecl socketeq_munmap(void *start, size_t length) {
	return s_base_api.StructAPI()->munmap(start, length);
}
void WinPrintf(const char* fmt, ...) {
	char msg[0x800] = { 0 };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	OutputDebugStringA(msg);
}
EXTERNC EXPORT int __cdecl send_message(const void* proto, uint32_t proto_len, bool initia, int ioctl_code, void* out) {
	void* cur_pipe = pthread_getspecific(s_pipe_key);
	if (cur_pipe) {
		cur_pipe = reinterpret_cast<void*>(*(uint32_t*)cur_pipe);
	}
	else {
		void* handle = s_base_api.StructAPI()->connectPipe("\\\\.\\pipe\\socketbinderpipe");
		if (handle ==INVALID_HANDLE_VALUE){
			return -1;
		}
		cur_pipe = malloc(sizeof(void*));
		*(uint32_t*)cur_pipe = reinterpret_cast<uint32_t>(handle);
		pthread_setspecific(s_pipe_key, cur_pipe);
		cur_pipe = handle;
	}
	if (ioctl_code!=BINDER_WRITE_READ&&
		initia&&
		ioctl_code!=BINDER_SET_CONTEXT_MGR&&
		ioctl_code!=BINDER_SET_MAX_THREADS&&
		ioctl_code!=BINDER_THREAD_EXIT&&
		ioctl_code!=BINDER_VERSION){
		OutputDebugStringA("111111111111111111");
		return -1;
	}
	struct ArmVM::base_msg* x1 = (struct ArmVM::base_msg*)proto;
	if (s_base_api.StructAPI()->writePipe(cur_pipe,&x1->call_type,sizeof(uint32_t))<0){
		if (GetLastError() != 6 && GetLastError() - 0xE8 > 1)
			return -1;
		s_base_api.StructAPI()->closePipe(cur_pipe);
		void* handle = s_base_api.StructAPI()->connectPipe("\\\\.\\pipe\\socketbinderpipe");
		if (handle == INVALID_HANDLE_VALUE) {
			return -1;
		}
		void* pp_pipe = pthread_getspecific(s_pipe_key);
		*(uint32_t*)pp_pipe = reinterpret_cast<uint32_t>(handle);
		pthread_setspecific(s_pipe_key, pp_pipe);
		cur_pipe = handle;
		CHECK_GE(s_base_api.StructAPI()->writePipe(cur_pipe, &x1->call_type, sizeof(uint32_t)), 0);
// 		if (s_base_api.StructAPI()->writePipe(cur_pipe, &x1->call_type, sizeof(uint32_t)) < 0) {
// 			OutputDebugStringA("11111111111111111111111");
// 			return -1;
// 		}
	}
	CHECK_GE(s_base_api.StructAPI()->writePipe(cur_pipe, &x1->pid, sizeof(struct ArmVM::base_struct_msg)), 0);
// 	if (s_base_api.StructAPI()->writePipe(cur_pipe, &x1->pid, sizeof(struct ArmVM::base_struct_msg)) < 0) {
// 		OutputDebugStringA("22222222222222222222222");
// 		return -1;
// 	}
	const uint8_t* x2 = (const uint8_t*)&((uint8_t*)proto)[sizeof(struct ArmVM::base_msg)];
// 	{
// 		uint32_t v7 = (x1->ext_len + 0xFF);
// 		if (x1->ext_len >= 0)
// 			v7 = x1->ext_len;
// 		uint32_t v8 = (signed int)v7 >> 8;
// 		if (v8 > 0) {
// 			uint8_t* x3 = const_cast<uint8_t*>(x2);
// 			uint32_t v9 = 0;
// 			uint32_t v24 = 0;
// 			do
// 			{
// 				uint8_t b1[0x200] = { 0 };
// 				memcpy(b1, x3, 0x100u);
// 				v24 = v9;
// 				if (s_base_api.StructAPI()->writePipe(cur_pipe, b1, 0x100) != 0x100)
// 				{
// 					OutputDebugStringA("111111111111111211");
// 					return -1;
// 				}
// 				x3 += 0x100;
// 				v9 = v24 + 1;
// 			} while (v24 + 1 != v8);
// 		}
// 		uint32_t v13 = (unsigned int)((signed int)x1->ext_len >> 31) >> 24;
// 		uint8_t v14 = (unsigned __int8)(v13 + (uint8_t)x1->ext_len) - v13;
// 		if (v14 > 0)
// 		{
// 			uint8_t b1[0x200] = { 0 };
// 			memcpy(b1, x2, (unsigned __int8)(v13 + (uint8_t)x1->ext_len) - v13);
// 			CHECK_EQ(s_base_api.StructAPI()->writePipe(cur_pipe, b1, v14), v14);
// 		}
// 	} 
	{
		uint32_t v7 = (uint32_t)((char *)x1->ext_len + 0xFF);
		if ((uint32_t)x1->ext_len >= 0)
			v7 = x1->ext_len;
		uint8_t* v8 = (uint8_t *)x2;
		uint32_t v26 = x1->ext_len;
		uint32_t v27 = (signed int)v7 >> 8;
		if ((signed int)v7 >> 8 > 0)
		{
			uint32_t v9 = 0;
			uint32_t v24 = 0;
			do
			{
				char v29[0x200] = {0};
				memcpy(v29, v8, 0x100u);
				v24 = v9;
				if (s_base_api.StructAPI()->writePipe(cur_pipe, v29, 0x100) != 0x100)
				{
					OutputDebugStringA("111111111111111211");
					return -1;
				}
				v8 += 0x100;
				v9 = v24 + 1;
			} while (v24 + 1 != v27);
		}
		uint32_t v13 = (unsigned int)((signed int)v26 >> 31) >> 24;
		uint8_t v14 = (unsigned __int8)(v13 + (uint8_t)v26) - v13;
		if (v14 > 0)
		{
			char v29[0x200] = { 0 };
			memcpy(v29, v8, (unsigned __int8)(v13 + (uint8_t)v26) - v13);
			if (s_base_api.StructAPI()->writePipe(cur_pipe, v29, v14) != v14)
			{
				OutputDebugStringA("111111111111111211");
				return -1;
			}
		}
		// SOME
		// 		uint32_t v13 = 0; 
		// 		uint8_t v14 = (uint8_t)v26;
		// 		if (v14 > 0)
		// 		{
		// 			char v29[0x200] = { 0 };
		// 			memcpy(v29, v8, (uint8_t)v26);
		// 			if (s_base_api.StructAPI()->writePipe(cur_pipe, v29, v14) != v14)
		// 			{
		// 				OutputDebugStringA("111111111111111211");
		// 				return -1;
		// 			}
		// 		}
	}
//	CHECK_GE(s_base_api.StructAPI()->writePipe(cur_pipe, x2, x1->ext_len), 0);
// 	if (s_base_api.StructAPI()->writePipe(cur_pipe, x2, x1->ext_len) < 0){
// 		OutputDebugStringA("333333333333333333333333");
// 		return -1;
// 	}
	uint32_t result = -1;
	if (s_base_api.StructAPI()->readPipe(cur_pipe, &result, sizeof(uint32_t)) < 0){
		if (s_base_api.StructAPI()->readPipe(cur_pipe, &result, sizeof(uint32_t)) < 0) {
			LOG(INFO) << "readPipe result failed.";
			return -1;
		}
	}
// 	if(s_base_api.StructAPI()->readPipe(cur_pipe, &result, sizeof(uint32_t)) < 0){
// 		OutputDebugStringA("4444444444444444444444444");
// 		return -1;
// 	}
	if (!initia){
		return result;
	}
	if(ioctl_code==ArmVM::kBINDER_WRITE_READ){
		if (!result){
			struct ArmVM::binder_write_read* bwr = reinterpret_cast<struct ArmVM::binder_write_read*>(out);
			unsigned long wb_addr = bwr->write_buffer;
			unsigned long rb_addr = bwr->read_buffer;
			CHECK_GE(s_base_api.StructAPI()->readPipe(cur_pipe, out, sizeof(struct ArmVM::binder_write_read)), 0);
// 			if (s_base_api.StructAPI()->readPipe(cur_pipe, out, sizeof(struct ArmVM::binder_write_read)) < 0) {
// 				OutputDebugStringA("555555555555555555555555555");
// 				return -1;
// 			}
			bwr->read_buffer = rb_addr;
			bwr->write_buffer = wb_addr;
			if (bwr->read_consumed <= 0 || s_base_api.StructAPI()->readPipe(cur_pipe,(void*)rb_addr, bwr->read_consumed) == bwr->read_consumed)
				return result;
			return -1;
		}
	}
	else{
		uint32_t x3 = 0;
// 		if (s_base_api.StructAPI()->readPipe(cur_pipe, &x3, sizeof(uint32_t)) < 0) {
// 			return -1;
// 		}
		CHECK_GE(s_base_api.StructAPI()->readPipe(cur_pipe, &x3, sizeof(uint32_t)), 0);
		if (out) {
			memmove(out, &x3, sizeof(uint32_t));
		}
		return result;
	}
	return -1;
}
EXTERNC EXPORT int __cdecl socketeq_open(const char* pathname, int flags) {
	uint32_t ftmp = s_base_api.StructAPI()->osal_openTempFile("socketeq-binder", 0x64000, 0);
	if (ftmp < 0) {
		s_base_api.StructAPI()->Perror("get_shmm_fd");
		return -1;
	}
	pthread_once(&s_once, once_run);
	int fd = 0;
	s_tid = s_base_api.StructAPI()->gettid();
	uint32_t pid = s_base_api.StructAPI()->pid2handle(s_base_api.StructAPI()->osal_sockmap_getPid("socketbinder"));
	DuplicateHandle(GetCurrentProcess(), (HANDLE)s_base_api.StructAPI()->_get_osfhandle(ftmp), (HANDLE)pid, (LPHANDLE)&fd, 0, 0, DUPLICATE_SAME_ACCESS);
	ArmVM::struct_open_msg open_msg = { { ArmVM::kSockBinderOpen, _getpid(), s_base_api.StructAPI()->gettid(), s_base_api.StructAPI()->getuid(), sizeof(uint32_t) }, fd };
	if (send_message(&open_msg, sizeof(ArmVM::struct_open_msg), false, 0, nullptr)) {
		s_base_api.StructAPI()->osal_close((void*)ftmp);
		return -1;
	}
	return ftmp;
}
EXTERNC EXPORT int __cdecl socketeq_close(int fd) {
	static bool close_state = false;
	int result = 0;
	if (!close_state){
		struct ArmVM::struct_close_msg close_msg = { { ArmVM::kSockBinderClose, _getpid(), s_base_api.StructAPI()->gettid(), s_base_api.StructAPI()->getuid(), 0 } };
		result = send_message(&close_msg, sizeof(ArmVM::struct_close_msg), false, 0, nullptr);
		s_base_api.StructAPI()->osal_close((void*)fd);
		close_state = true;
	}
	return result;
}
EXTERNC EXPORT int __cdecl socketeq_kill(int pid) {
	struct ArmVM::struct_close_msg kill_msg = { { ArmVM::kSockBinderKill, pid, pid, 0, 0 } };
	return send_message(&kill_msg, sizeof(struct ArmVM::struct_kill_msg), false, 0, nullptr);
}
EXTERNC EXPORT void* __cdecl socketeq_mmap(void *start, size_t length, int prot, int flags, int fd, uint64_t offset) {
	if (length > 0x64000) {
		return (void*)-1;
	}
	void* mmap_addr = s_base_api.StructAPI()->mmap(0, length, 3, 1, fd, 0);
	int pid = _getpid();
	int tid = s_base_api.StructAPI()->gettid();
	if (s_tid== tid){
		tid = pid;
	}
	struct ArmVM::struct_mmap_msg mmap_msg = { { ArmVM::kSockBinderMMap, pid, tid, s_base_api.StructAPI()->getuid(), sizeof(struct ArmVM::struct_mmap_info) },{ length, mmap_addr } };
	if (send_message(&mmap_msg, sizeof(struct ArmVM::struct_mmap_msg), false, 0, nullptr) < 0){
		s_base_api.StructAPI()->munmap(mmap_addr, length);
		return (void*)-1;
	}
	s_mmap_end_addr = (uint32_t)mmap_addr + 0x64000;
	return mmap_addr;
}
std::string hexStr(unsigned char *data, int len)
{
	std::stringstream ss;
	ss << std::hex;
	for (int i = 0; i < len; ++i)
		ss << std::setw(2) << std::setfill('0') << (int)data[i];
	return ss.str();
}
EXTERNC EXPORT int socketeq_ioctl(int fd, int request, void* out) {
	int result = -1;
	size_t binder_msg_size = sizeof(struct ArmVM::struct_ioctl_msg);
	struct ArmVM::binder_write_read* bwr = (struct ArmVM::binder_write_read*)out;
	if (request == ArmVM::kBINDER_WRITE_READ) {
		binder_msg_size += bwr->write_size;
	}
	else {
		binder_msg_size = sizeof(struct ArmVM::base_msg);
		binder_msg_size += sizeof(struct ArmVM::struct_ioctl_info);
		binder_msg_size += sizeof(uint32_t);
	}
	struct ArmVM::struct_ioctl_msg* binder_msg = (struct ArmVM::struct_ioctl_msg*)malloc(binder_msg_size);
	int pid = _getpid();
	int tid = s_base_api.StructAPI()->gettid();
	if (s_tid == tid) {
		tid = pid;
	}
	memset(binder_msg, 0, binder_msg_size);
	binder_msg->msg.call_type = ArmVM::kSockBinderIoctl;
	binder_msg->msg.pid = pid;
	binder_msg->msg.tid = tid;
	binder_msg->msg.uid = s_base_api.StructAPI()->getuid();
	binder_msg->ioctl_info.ioctl_code = request;
	if (request == BINDER_SET_MAX_THREADS ||
		request == BINDER_SET_CONTEXT_MGR ||
		request == BINDER_THREAD_EXIT ||
		request == BINDER_VERSION) {
		binder_msg->msg.ext_len = (sizeof(uint32_t) * 3);
		if (out) {
			binder_msg->bwr.write_size = *(uint32_t*)out;
		}
		result = send_message(binder_msg, binder_msg_size, true, request, out);
	}
	else {
		binder_msg->bwr.write_size = bwr->write_size;
		binder_msg->bwr.write_consumed = bwr->write_consumed;
		binder_msg->bwr.write_buffer = bwr->write_buffer;
		binder_msg->bwr.read_size = bwr->read_size;
		binder_msg->bwr.read_consumed = bwr->read_consumed;
		binder_msg->bwr.read_buffer = bwr->read_buffer;
		binder_msg->msg.ext_len = (sizeof(uint32_t) * 2) + sizeof(struct ArmVM::binder_write_read) + bwr->write_size;
		char* data = (char*)((unsigned long)binder_msg + sizeof(struct ArmVM::struct_ioctl_msg));
		memcpy(data, (const void*)bwr->write_buffer, bwr->write_size);
		if (bwr->write_size>0){
			LOG(INFO) << "write:" << hexStr((unsigned char*)data, bwr->write_size);
			google::FlushLogFiles(google::GLOG_INFO);
		}
		result = send_message(binder_msg, binder_msg_size, true, BINDER_WRITE_READ, (unsigned int*)out);
	}
	if (binder_msg){
		free(binder_msg);
		binder_msg = nullptr;
	}
	return result;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Hook 命名空间
namespace Hook
{
	HHOOK m_hHook;
			// HOOK 句柄


	// HOOK 函数
	LRESULT CALLBACK HookProc(INT iCode, WPARAM wParam, LPARAM lParam)
	{
		if (iCode > 0)
		{
			;
		}

		return CallNextHookEx(m_hHook, iCode, wParam, lParam);
	}

	// Hook
	inline BOOL WINAPI Hook(INT iHookId = WH_CALLWNDPROC)
	{
		m_hHook = SetWindowsHookEx(iHookId, HookProc, NULL, GetCurrentThreadId());
		return (m_hHook != NULL);
	}

	// Unhook
	inline VOID WINAPI Unhook()
	{
		if (m_hHook)
		{
			UnhookWindowsHookEx(m_hHook);
		}
	}
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AheadLib 命名空间
namespace AheadLib
{
	HMODULE m_hModule = NULL;	// 原始模块句柄
	DWORD m_dwReturn[11] = {0};	// 原始函数返回地址


	// 加载原始模块
	inline BOOL WINAPI Load()
	{
		TCHAR tzPath[MAX_PATH];
		TCHAR tzTemp[MAX_PATH * 2];

		lstrcpy(tzPath, TEXT("libsbinderOrg.dll"));
		m_hModule = LoadLibrary(tzPath);
		if (m_hModule == NULL)
		{
			wsprintf(tzTemp, TEXT("无法加载 %s，程序无法正常运行。"), tzPath);
			MessageBox(NULL, tzTemp, TEXT("AheadLib"), MB_ICONSTOP);
		}
		else
		{
			//InitializeAddresses();
		}

		return (m_hModule != NULL);	
	}
		
	// 获取原始函数地址
	FARPROC WINAPI GetAddress(PCSTR pszProcName)
	{
		FARPROC fpAddress;
		CHAR szProcName[16];
		TCHAR tzTemp[MAX_PATH];

		if (m_hModule == NULL)
		{
			if (Load() == FALSE)
			{
				ExitProcess(-1);
			}
		}

		fpAddress = GetProcAddress(m_hModule, pszProcName);
		if (fpAddress == NULL)
		{
			if (HIWORD(pszProcName) == 0)
			{
				wsprintfA(szProcName, "%d", pszProcName);
				pszProcName = szProcName;
			}

			wsprintf(tzTemp, TEXT("无法找到函数 %hs，程序无法正常运行。"), pszProcName);
			MessageBox(NULL, tzTemp, TEXT("AheadLib"), MB_ICONSTOP);
			ExitProcess(-2);
		}

		return fpAddress;
	}

	// 释放原始模块
	inline VOID WINAPI Free()
	{
		if (m_hModule)
		{
			FreeLibrary(m_hModule);
		}
	}
}
using namespace AheadLib;
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 入口函数
BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, PVOID pvReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hModule);
		for (INT i = 0; i < sizeof(m_dwReturn) / sizeof(DWORD); i++)
		{
			m_dwReturn[i] = TlsAlloc();
		}

		Hook::Hook();
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		for (INT i = 0; i < sizeof(m_dwReturn) / sizeof(DWORD); i++)
		{
			TlsFree(m_dwReturn[i]);
		}

		Free();
		Hook::Unhook();

	}

	return TRUE;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ALCDECL AheadLib_create_binder_ioctl_int_message(void)
{
	__asm int 3
	// 保存返回地址到 TLS
	__asm PUSH m_dwReturn[0 * TYPE long];
	__asm CALL DWORD PTR [TlsSetValue];

	// 调用原始函数
	GetAddress("create_binder_ioctl_int_message")();

	// 获取返回地址并返回
	__asm PUSH EAX;
	__asm PUSH m_dwReturn[0 * TYPE long];
	__asm CALL DWORD PTR [TlsGetValue];
	__asm XCHG EAX, [ESP];
	__asm RET;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ALCDECL AheadLib_socketeq_clear_used_share_file(void)
{
	__asm int 3
	// 保存返回地址到 TLS
	__asm PUSH m_dwReturn[2 * TYPE long];
	__asm CALL DWORD PTR [TlsSetValue];

	// 调用原始函数
	GetAddress("socketeq_clear_used_share_file")();

	// 获取返回地址并返回
	__asm PUSH EAX;
	__asm PUSH m_dwReturn[2 * TYPE long];
	__asm CALL DWORD PTR [TlsGetValue];
	__asm XCHG EAX, [ESP];
	__asm RET;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ALCDECL AheadLib_socketeq_get_file_name(void)
{
	// 保存返回地址到 TLS
	__asm PUSH m_dwReturn[4 * TYPE long];
	__asm CALL DWORD PTR[TlsSetValue];

	// 调用原始函数
	GetAddress("socketeq_get_file_name")();

	// 获取返回地址并返回
	__asm PUSH EAX;
	__asm PUSH m_dwReturn[4 * TYPE long];
	__asm CALL DWORD PTR[TlsGetValue];
	__asm XCHG EAX, [ESP];
	__asm RET;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ALCDECL AheadLib_socketeq_install_share_file(void)
{
	__asm int 3
	// 保存返回地址到 TLS
	__asm PUSH m_dwReturn[5 * TYPE long];
	__asm CALL DWORD PTR[TlsSetValue];

	// 调用原始函数
	GetAddress("socketeq_install_share_file")();

	// 获取返回地址并返回
	__asm PUSH EAX;
	__asm PUSH m_dwReturn[5 * TYPE long];
	__asm CALL DWORD PTR[TlsGetValue];
	__asm XCHG EAX, [ESP];
	__asm RET;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// ALCDECL AheadLib_send_message(void)
// {
// 	// 保存返回地址到 TLS
// 	__asm PUSH m_dwReturn[1 * TYPE long];
// 	__asm CALL DWORD PTR[TlsSetValue];
// 
// 	// 调用原始函数
// 	GetAddress("send_message")();
// 
// 	// 获取返回地址并返回
// 	__asm PUSH EAX;
// 	__asm PUSH m_dwReturn[1 * TYPE long];
// 	__asm CALL DWORD PTR[TlsGetValue];
// 	__asm XCHG EAX, [ESP];
// 	__asm RET;
// }
// 
// ALCDECL AheadLib_socketeq_close(void)
// {
// 	// 保存返回地址到 TLS
// 	__asm PUSH m_dwReturn[3 * TYPE long];
// 	__asm CALL DWORD PTR [TlsSetValue];
// 
// 	// 调用原始函数
// 	GetAddress("socketeq_close")();
// 
// 	// 获取返回地址并返回
// 	__asm PUSH EAX;
// 	__asm PUSH m_dwReturn[3 * TYPE long];
// 	__asm CALL DWORD PTR [TlsGetValue];
// 	__asm XCHG EAX, [ESP];
// 	__asm RET;
// }
// 
// ALCDECL AheadLib_socketeq_ioctl(void)
// {
// 	// 保存返回地址到 TLS
// 	__asm PUSH m_dwReturn[6 * TYPE long];
// 	__asm CALL DWORD PTR [TlsSetValue];
// 
// 	// 调用原始函数
// 	GetAddress("socketeq_ioctl")();
// 
// 	// 获取返回地址并返回
// 	__asm PUSH EAX;
// 	__asm PUSH m_dwReturn[6 * TYPE long];
// 	__asm CALL DWORD PTR [TlsGetValue];
// 	__asm XCHG EAX, [ESP];
// 	__asm RET;
// }
// 
// ALCDECL AheadLib_socketeq_kill(void)
// {
// 	// 保存返回地址到 TLS
// 	__asm PUSH m_dwReturn[7 * TYPE long];
// 	__asm CALL DWORD PTR [TlsSetValue];
// 
// 	// 调用原始函数
// 	GetAddress("socketeq_kill")();
// 
// 	// 获取返回地址并返回
// 	__asm PUSH EAX;
// 	__asm PUSH m_dwReturn[7 * TYPE long];
// 	__asm CALL DWORD PTR [TlsGetValue];
// 	__asm XCHG EAX, [ESP];
// 	__asm RET;
// }
// 
// ALCDECL AheadLib_socketeq_mmap(void)
// {
// 	// 保存返回地址到 TLS
// 	__asm PUSH m_dwReturn[8 * TYPE long];
// 	__asm CALL DWORD PTR [TlsSetValue];
// 
// 	// 调用原始函数
// 	GetAddress("socketeq_mmap")();
// 
// 	// 获取返回地址并返回
// 	__asm PUSH EAX;
// 	__asm PUSH m_dwReturn[8 * TYPE long];
// 	__asm CALL DWORD PTR [TlsGetValue];
// 	__asm XCHG EAX, [ESP];
// 	__asm RET;
// }
// 
// ALCDECL AheadLib_socketeq_munmap(void)
// {
// 	// 保存返回地址到 TLS
// 	__asm PUSH m_dwReturn[9 * TYPE long];
// 	__asm CALL DWORD PTR [TlsSetValue];
// 
// 	// 调用原始函数
// 	GetAddress("socketeq_munmap")();
// 
// 	// 获取返回地址并返回
// 	__asm PUSH EAX;
// 	__asm PUSH m_dwReturn[9 * TYPE long];
// 	__asm CALL DWORD PTR [TlsGetValue];
// 	__asm XCHG EAX, [ESP];
// 	__asm RET;
// }
// 
// ALCDECL AheadLib_socketeq_open(void)
// {
// 	// 保存返回地址到 TLS
// 	__asm PUSH m_dwReturn[10 * TYPE long];
// 	__asm CALL DWORD PTR [TlsSetValue];
// 
// 	// 调用原始函数
// 	GetAddress("socketeq_open")();
// 
// 	// 获取返回地址并返回
// 	__asm PUSH EAX;
// 	__asm PUSH m_dwReturn[10 * TYPE long];
// 	__asm CALL DWORD PTR [TlsGetValue];
// 	__asm XCHG EAX, [ESP];
// 	__asm RET;
// }
