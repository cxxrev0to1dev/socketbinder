// base.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "base.h"

BaseAPI* BaseAPI::GetInstance() {
	static BaseAPI* xxxx = nullptr;
	if (!xxxx){
		xxxx = new BaseAPI;
	}
	return xxxx;
}
BaseAPI::BaseAPI(){
	memset(&struct_api_, 0, sizeof(struct struct_api));
	Load();
	FindFunc find_func("msvcrt.dll");
	struct_api_._open_osfhandle = reinterpret_cast<_open_osfhandle_func>(find_func.GetAddress("_open_osfhandle"));
	struct_api_._get_osfhandle = reinterpret_cast<_get_osfhandle_func>(find_func.GetAddress("_get_osfhandle"));
	struct_api_.malloc = reinterpret_cast<malloc_func>(find_func.GetAddress("malloc"));
	struct_api_.free = reinterpret_cast<free_func>(find_func.GetAddress("free"));
	FindFunc find_func_a("libpthread.dll");
	struct_api_.pthread_mutex_lock = reinterpret_cast<pthread_mutex_lock_func>(find_func_a.GetAddress("pthread_mutex_lock"));
	struct_api_.pthread_mutex_unlock = reinterpret_cast<pthread_mutex_unlock_func>(find_func_a.GetAddress("pthread_mutex_unlock"));
	struct_api_.pthread_cond_wait = reinterpret_cast<pthread_cond_wait_func>(find_func_a.GetAddress("pthread_cond_wait"));
	struct_api_.pthread_cond_init = reinterpret_cast<pthread_cond_init_func>(find_func_a.GetAddress("pthread_cond_init"));
	struct_api_.pthread_cond_signal = reinterpret_cast<pthread_cond_signal_func>(find_func_a.GetAddress("pthread_cond_signal"));
    return;
}
BaseAPI::~BaseAPI() {
	memset(&struct_api_, 0, sizeof(struct struct_api));
}
struct struct_api* BaseAPI::StructAPI() {
	return &struct_api_;
}
void BaseAPI::Load() {
	libsbutils();
	libsbinder();
	libosal_hal();
	libosal();
}
void BaseAPI::libosal_hal() {
	FindFunc find_func("libosal_hal.dll");
	struct_api_.get_file_name = reinterpret_cast<get_file_name_func>(find_func.GetAddress("get_file_name"));
	struct_api_.osal_close = reinterpret_cast<osal_close_func>(find_func.GetAddress("osal_close"));
	struct_api_.osal_openTempFile = reinterpret_cast<osal_openTempFile_func>(find_func.GetAddress("osal_openTempFile"));
	struct_api_.osal_sockmap_getPid = reinterpret_cast<osal_sockmap_getPid_func>(find_func.GetAddress("osal_sockmap_getPid"));
}
void BaseAPI::libosal() {
	FindFunc find_func("libosal.dll");
	//struct_api_.getpid = reinterpret_cast<getpid_func>(find_func.GetAddress("getpid"));
	struct_api_.gettid = reinterpret_cast<gettid_func>(find_func.GetAddress("gettid"));
	struct_api_.getuid = reinterpret_cast<getuid_func>(find_func.GetAddress("getuid"));
	struct_api_.mmap = reinterpret_cast<mmap_func>(find_func.GetAddress("mmap"));
	struct_api_.munmap = reinterpret_cast<munmap_func>(find_func.GetAddress("munmap"));
	struct_api_.pid2handle = reinterpret_cast<pid2handle_func>(find_func.GetAddress("pid2handle"));
}
void BaseAPI::libsbutils(){
	FindFunc find_func("libsbutils.dll");
	struct_api_.writePipe = reinterpret_cast<writePipe_func>(find_func.GetAddress("writePipe"));
	struct_api_.readPipe = reinterpret_cast<readPipe_func>(find_func.GetAddress("readPipe"));
	struct_api_.connectPipe = reinterpret_cast<connectPipe_func>(find_func.GetAddress("connectPipe"));
	struct_api_.closePipe = reinterpret_cast<closePipe_func>(find_func.GetAddress("closePipe"));
	struct_api_.Perror = reinterpret_cast<Perror_func>(find_func.GetAddress("Perror"));
}
void BaseAPI::libsbinder() {
	FindFunc find_func("libsbinderOrg.dll");
	struct_api_.socketeq_open = reinterpret_cast<socketeq_open_func>(find_func.GetAddress("socketeq_open"));
	struct_api_.send_message = reinterpret_cast<send_message_func>(find_func.GetAddress("send_message"));
}

FindFunc::FindFunc(const char* module_name):module_handle_(nullptr){
	CHAR tzTemp[MAX_PATH * 2];
	module_handle_ = LoadLibraryA(module_name);
	if (module_handle_ == NULL){
		wsprintfA(tzTemp, "load %s failed!", module_name);
		MessageBoxA(NULL, tzTemp, __FUNCTION__, MB_ICONSTOP);
	}
}

FindFunc::~FindFunc()
{
// 	if (module_handle_)
// 	{
// 		FreeLibrary(module_handle_);
// 		module_handle_ = nullptr;
// 	}
}

FARPROC FindFunc::GetAddress(const char* func_name) {
	FARPROC fpAddress;
	CHAR szProcName[16];
	CHAR tzTemp[MAX_PATH];

	fpAddress = GetProcAddress(module_handle_, func_name);
	if (fpAddress == NULL)
	{
		if (HIWORD(func_name) == 0)
		{
			wsprintfA(szProcName, "%d", func_name);
		}

		wsprintfA(tzTemp, "find %s function failed!", func_name);
		MessageBoxA(NULL, tzTemp, __FUNCTION__, MB_ICONSTOP);
		ExitProcess(-2);
	}

	return fpAddress;
}