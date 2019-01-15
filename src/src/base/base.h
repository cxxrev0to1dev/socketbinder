// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the BASE_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// BASE_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef BASE_EXPORTS
#define BASE_API __declspec(dllexport)
#else
#define BASE_API __declspec(dllimport)
#endif

#include <cstdint>
#include <pthread.h>

using get_file_name_func = int(__cdecl*)(void* file, char *name_buf, int length);
using osal_close_func = int(__cdecl*)(void* handle);
using osal_openTempFile_func = int(__cdecl*)(const char *a1, int file_size, int access);
using osal_sockmap_getPid_func = int(__cdecl*)(const char *process_name);
using Perror_func = int(__cdecl*)(const char *str);
using getpid_func = int(__cdecl*)();
using gettid_func = int(__cdecl*)();
using getuid_func = int(__cdecl*)();
using mmap_func = void* (__cdecl *)(void* start, size_t length, int prot, int flags, int fd, uint64_t offset);
using munmap_func = int(__cdecl*)(void *start, size_t length);
using pid2handle_func = int(__cdecl*)(int pid);
using writePipe_func = int(__cdecl*)(void* file, const void *buf, int len);
using readPipe_func = int(__cdecl*)(void* file, void *buf, size_t length);
using connectPipe_func = void*(__cdecl*)(const char *name);
using closePipe_func = int(__cdecl*)(void* file);
using socketeq_open_func = int(__cdecl*)(const char* pathname, int flags);
using send_message_func = int(__cdecl*)(const void* proto, uint32_t proto_len, bool initia, int ioctl_code, void* out);
using _open_osfhandle_func = int(__cdecl*)(intptr_t, int);
using _get_osfhandle_func = intptr_t(__cdecl*)(int);
using malloc_func = void*(__cdecl*)(size_t);
using free_func = void (__cdecl*)(void *);

using pthread_mutex_lock_func = int(PTW32_CDECL*)(pthread_mutex_t * mutex);
using pthread_mutex_unlock_func = int(PTW32_CDECL*)(pthread_mutex_t * mutex);
using pthread_cond_wait_func = int(PTW32_CDECL*)(pthread_cond_t * cond, pthread_mutex_t * mutex);
using pthread_cond_init_func = int(PTW32_CDECL*)(pthread_cond_t * cond, const pthread_condattr_t * attr);
using pthread_cond_signal_func = int(PTW32_CDECL*)(pthread_cond_t * cond);


struct struct_api
{
	get_file_name_func get_file_name;
	osal_close_func osal_close;
	osal_openTempFile_func osal_openTempFile;
	osal_sockmap_getPid_func osal_sockmap_getPid;
	Perror_func Perror;
	getpid_func getpid;
	gettid_func gettid;
	getuid_func getuid;
	mmap_func mmap;
	munmap_func munmap;
	pid2handle_func pid2handle;
	writePipe_func writePipe;
	readPipe_func readPipe;
	connectPipe_func connectPipe;
	closePipe_func closePipe;
	socketeq_open_func socketeq_open;
	send_message_func send_message;
	_open_osfhandle_func _open_osfhandle;
	_get_osfhandle_func _get_osfhandle;
	malloc_func malloc;
	free_func free;
	pthread_mutex_lock_func pthread_mutex_lock;
	pthread_mutex_unlock_func pthread_mutex_unlock;
	pthread_cond_wait_func pthread_cond_wait;
	pthread_cond_init_func pthread_cond_init;
	pthread_cond_signal_func pthread_cond_signal;
};
class BaseAPI {
public:
	BASE_API static BaseAPI* GetInstance();
	BASE_API BaseAPI(void);
	BASE_API virtual ~BaseAPI();
	BASE_API struct struct_api* StructAPI();
	BASE_API void Load();
private:
	BaseAPI(const BaseAPI&) = delete;
	BaseAPI& operator=(const BaseAPI&) = delete;
	void libosal_hal();
	void libosal();
	void libsbutils();
	void libsbinder();
	struct struct_api struct_api_;
};

class FindFunc
{
public:
	BASE_API explicit FindFunc(const char* module_name);
	BASE_API virtual ~FindFunc();
	BASE_API FARPROC GetAddress(const char* func_name);
private:
	FindFunc(const FindFunc&) = delete;
	FindFunc& operator=(const FindFunc&) = delete;
	HMODULE module_handle_;
};
