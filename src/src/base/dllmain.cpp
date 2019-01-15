// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#pragma comment(lib,"user32.lib")
#pragma comment(lib,"ws2_32.lib")
#include "glog/logging.h"
#include "base/commandlineflags.h"
#include "config.h"
DECLARE_bool(logtostderr);
#include <tlhelp32.h>
#include "base.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	if (ul_reason_for_call==DLL_PROCESS_ATTACH){
		DisableThreadLibraryCalls(hModule);
		GOOGLE_NAMESPACE::InitGoogleLogging("debug");
		char buffer[MAX_PATH] = { 0 };
		GetModuleFileNameA(nullptr, buffer, MAX_PATH);
		LOG(INFO) << "GetModuleFileNameA:" << buffer;
		google::FlushLogFiles(google::GLOG_INFO);
		BaseAPI::GetInstance();
	}
	return TRUE;
}

