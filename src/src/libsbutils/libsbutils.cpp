


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 头文件
#include <cstdint>
#include <Windows.h>
#include <tlhelp32.h>
#include "glog/logging.h"
#include "base/commandlineflags.h"
#include "config.h"
DECLARE_bool(logtostderr);
#pragma comment(lib,"user32.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"base.lib")
#include "detours.h"
#include "binder.h"
#include "binder.h"
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma comment(linker, "/EXPORT:Perror=_AheadLib_Perror,@1")
#pragma comment(linker, "/EXPORT:Recv=_AheadLib_Recv,@2")
#pragma comment(linker, "/EXPORT:Send=_AheadLib_Send,@3")
#pragma comment(linker, "/EXPORT:Signal=_AheadLib_Signal,@4")
#pragma comment(linker, "/EXPORT:binder_clear_used_share_file=_AheadLib_binder_clear_used_share_file,@5")
#pragma comment(linker, "/EXPORT:binder_install_share_file=_AheadLib_binder_install_share_file,@6")
#pragma comment(linker, "/EXPORT:closePipe=_AheadLib_closePipe,@7")
#pragma comment(linker, "/EXPORT:connectPipe=_AheadLib_connectPipe,@8")
#pragma comment(linker, "/EXPORT:debug_info=_AheadLib_debug_info,@9")
#pragma comment(linker, "/EXPORT:get_shmm_fd=_AheadLib_get_shmm_fd,@10")
#pragma comment(linker, "/EXPORT:readPipe=_AheadLib_readPipe,@11")
#pragma comment(linker, "/EXPORT:writePipe=_AheadLib_writePipe,@12")
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 宏定义
#define EXTERNC extern "C"
#define NAKED __declspec(naked)
#define EXPORT __declspec(dllexport)

#define ALCPP EXPORT NAKED
#define ALSTD EXTERNC EXPORT NAKED void __stdcall
#define ALCFAST EXTERNC EXPORT NAKED void __fastcall
#define ALCDECL EXTERNC NAKED void __cdecl



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
	DWORD m_dwReturn[12] = {0};	// 原始函数返回地址


	// 加载原始模块
	inline BOOL WINAPI Load()
	{
		TCHAR tzPath[MAX_PATH];
		TCHAR tzTemp[MAX_PATH * 2];

		lstrcpy(tzPath, TEXT("libsbutilsOrg.dll"));
		m_hModule = LoadLibrary(tzPath);
		if (m_hModule == NULL)
		{
			wsprintf(tzTemp, TEXT("无法加载 %s，程序无法正常运行。"), tzPath);
			MessageBox(NULL, tzTemp, TEXT("AheadLib"), MB_ICONSTOP);
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
				wsprintf(szProcName, "%d", pszProcName);
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


std::string s_process_name;
static std::string GetProcName(DWORD aPid)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);
	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}
	for (BOOL bok = Process32First(processesSnapshot, &processInfo); bok; bok = Process32Next(processesSnapshot, &processInfo)) {
		if (aPid == processInfo.th32ProcessID) {
			CloseHandle(processesSnapshot);
			return processInfo.szExeFile;
		}

	}
	CloseHandle(processesSnapshot);
	return std::string("");
}

typedef int(*binder_thread_read_proc)(uint32_t* proc, uint32_t* thread, uint8_t* buffer, uint32_t size, uint32_t *consumed, int non_block);
typedef int(__cdecl* binder_thread_write_proc)(uint32_t *proc, uint32_t *thread, uint8_t* buffer, uint32_t size, uint32_t *consumed);
binder_thread_read_proc binder_read = (binder_thread_read_proc)0x00404950;
binder_thread_write_proc binder_write = (binder_thread_write_proc)0x00405050;
int NAKED binder_thread_read_naked(uint32_t* proc, uint32_t* thread, uint8_t* buffer , uint32_t size, uint32_t *consumed, int non_block){
	__asm pushad
	__asm mov edi,esp
	__asm push [edi + 0x2C]
	__asm push [edi + 0x28]
	__asm push [edi + 0x24]
	__asm push ecx
	__asm push edx
	__asm push eax
	__asm call binder_thread_read
	__asm add esp,0x18
	__asm popad
	__asm ret
}
static void hook() {
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)binder_read, binder_thread_read_naked);
	DetourAttach(&(PVOID&)binder_write, binder_thread_write);
	DetourTransactionCommit();
}
static void unhook() {
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)binder_read, binder_thread_read_naked);
	DetourDetach(&(PVOID&)binder_write, binder_thread_write);
	DetourTransactionCommit();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, PVOID pvReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hModule);
		s_process_name = GetProcName(GetCurrentProcessId());
		if (s_process_name == "socketbinder.exe") {
			LOG(INFO) << "ProcessName:" << s_process_name;
			InitReMapGlobalPointer();
			hook();
		}
		for (INT i = 0; i < sizeof(m_dwReturn) / sizeof(DWORD); i++){
			m_dwReturn[i] = TlsAlloc();
		}
		Hook::Hook();
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		if (s_process_name == "socketbinder.exe"){
			unhook();
		}
		for (INT i = 0; i < sizeof(m_dwReturn) / sizeof(DWORD); i++)
		{
			TlsFree(m_dwReturn[i]);
		}
		Hook::Unhook();

	}

	return TRUE;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ALCDECL AheadLib_Perror(void)
{
	
	__asm PUSH m_dwReturn[0 * TYPE long];
	__asm CALL DWORD PTR [TlsSetValue];

	
	GetAddress("Perror")();

	
	__asm PUSH EAX;
	__asm PUSH m_dwReturn[0 * TYPE long];
	__asm CALL DWORD PTR [TlsGetValue];
	__asm XCHG EAX, [ESP];
	__asm RET;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ALCDECL AheadLib_Recv(void)
{
	
	__asm PUSH m_dwReturn[1 * TYPE long];
	__asm CALL DWORD PTR [TlsSetValue];

	
	GetAddress("Recv")();

	
	__asm PUSH EAX;
	__asm PUSH m_dwReturn[1 * TYPE long];
	__asm CALL DWORD PTR [TlsGetValue];
	__asm XCHG EAX, [ESP];
	__asm RET;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ALCDECL AheadLib_Send(void)
{
	
	__asm PUSH m_dwReturn[2 * TYPE long];
	__asm CALL DWORD PTR [TlsSetValue];

	
	GetAddress("Send")();

	
	__asm PUSH EAX;
	__asm PUSH m_dwReturn[2 * TYPE long];
	__asm CALL DWORD PTR [TlsGetValue];
	__asm XCHG EAX, [ESP];
	__asm RET;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ALCDECL AheadLib_Signal(void)
{
	
	__asm PUSH m_dwReturn[3 * TYPE long];
	__asm CALL DWORD PTR [TlsSetValue];

	
	GetAddress("Signal")();

	
	__asm PUSH EAX;
	__asm PUSH m_dwReturn[3 * TYPE long];
	__asm CALL DWORD PTR [TlsGetValue];
	__asm XCHG EAX, [ESP];
	__asm RET;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ALCDECL AheadLib_binder_clear_used_share_file(void)
{
	
	__asm PUSH m_dwReturn[4 * TYPE long];
	__asm CALL DWORD PTR [TlsSetValue];

	
	GetAddress("binder_clear_used_share_file")();

	
	__asm PUSH EAX;
	__asm PUSH m_dwReturn[4 * TYPE long];
	__asm CALL DWORD PTR [TlsGetValue];
	__asm XCHG EAX, [ESP];
	__asm RET;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ALCDECL AheadLib_binder_install_share_file(void)
{
	
	__asm PUSH m_dwReturn[5 * TYPE long];
	__asm CALL DWORD PTR [TlsSetValue];

	
	GetAddress("binder_install_share_file")();

	
	__asm PUSH EAX;
	__asm PUSH m_dwReturn[5 * TYPE long];
	__asm CALL DWORD PTR [TlsGetValue];
	__asm XCHG EAX, [ESP];
	__asm RET;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ALCDECL AheadLib_closePipe(void)
{
	
	__asm PUSH m_dwReturn[6 * TYPE long];
	__asm CALL DWORD PTR [TlsSetValue];

	
	GetAddress("closePipe")();

	
	__asm PUSH EAX;
	__asm PUSH m_dwReturn[6 * TYPE long];
	__asm CALL DWORD PTR [TlsGetValue];
	__asm XCHG EAX, [ESP];
	__asm RET;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ALCDECL AheadLib_connectPipe(void)
{
	
	__asm PUSH m_dwReturn[7 * TYPE long];
	__asm CALL DWORD PTR [TlsSetValue];

	
	GetAddress("connectPipe")();

	
	__asm PUSH EAX;
	__asm PUSH m_dwReturn[7 * TYPE long];
	__asm CALL DWORD PTR [TlsGetValue];
	__asm XCHG EAX, [ESP];
	__asm RET;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ALCDECL AheadLib_debug_info(void)
{
	
	__asm PUSH m_dwReturn[8 * TYPE long];
	__asm CALL DWORD PTR [TlsSetValue];

	
	GetAddress("debug_info")();

	
	__asm PUSH EAX;
	__asm PUSH m_dwReturn[8 * TYPE long];
	__asm CALL DWORD PTR [TlsGetValue];
	__asm XCHG EAX, [ESP];
	__asm RET;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ALCDECL AheadLib_get_shmm_fd(void)
{
	
	__asm PUSH m_dwReturn[9 * TYPE long];
	__asm CALL DWORD PTR [TlsSetValue];

	
	GetAddress("get_shmm_fd")();

	
	__asm PUSH EAX;
	__asm PUSH m_dwReturn[9 * TYPE long];
	__asm CALL DWORD PTR [TlsGetValue];
	__asm XCHG EAX, [ESP];
	__asm RET;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ALCDECL AheadLib_readPipe(void)
{
	
	__asm PUSH m_dwReturn[10 * TYPE long];
	__asm CALL DWORD PTR [TlsSetValue];

	
	GetAddress("readPipe")();

	
	__asm PUSH EAX;
	__asm PUSH m_dwReturn[10 * TYPE long];
	__asm CALL DWORD PTR [TlsGetValue];
	__asm XCHG EAX, [ESP];
	__asm RET;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ALCDECL AheadLib_writePipe(void)
{
	
	__asm PUSH m_dwReturn[11 * TYPE long];
	__asm CALL DWORD PTR [TlsSetValue];

	
	GetAddress("writePipe")();

	
	__asm PUSH EAX;
	__asm PUSH m_dwReturn[11 * TYPE long];
	__asm CALL DWORD PTR [TlsGetValue];
	__asm XCHG EAX, [ESP];
	__asm RET;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
