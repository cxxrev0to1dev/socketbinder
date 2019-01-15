#ifndef _SOCKETBINDER_OS_EXECUTE_WINDROY_H
#define _SOCKETBINDER_OS_EXECUTE_WINDROY_H

namespace ArmVM {
	namespace internal{
		void ExecuteWindroySocketBinder();
		void ExecuteWindroy();
	}
}
//size_t ExecuteProcess(std::wstring FullPathToExe, std::wstring Parameters, size_t SecondsToWait)
//{
//	size_t iMyCounter = 0, iReturnVal = 0, iPos = 0;
//	DWORD dwExitCode = 0;
//	std::wstring sTempStr = L"";
//	if (Parameters.size() != 0){
//		if (Parameters[0] != L' '){
//			Parameters.insert(0, L" ");
//		}
//	}
//	sTempStr = FullPathToExe;
//	iPos = sTempStr.find_last_of(L"\\");
//	sTempStr.erase(0, iPos + 1);
//	Parameters = sTempStr.append(Parameters);
//	wchar_t * pwszParam = new wchar_t[Parameters.size() + 1];
//	if (pwszParam == 0){
//		return 1;
//	}
//	const wchar_t* pchrTemp = Parameters.c_str();
//	wcscpy_s(pwszParam, Parameters.size() + 1, pchrTemp);
//	STARTUPINFOW siStartupInfo;
//	PROCESS_INFORMATION piProcessInfo;
//	memset(&siStartupInfo, 0, sizeof(siStartupInfo));
//	memset(&piProcessInfo, 0, sizeof(piProcessInfo));
//	siStartupInfo.cb = sizeof(siStartupInfo);
//	if (CreateProcessW(const_cast<LPCWSTR>(FullPathToExe.c_str()),
//		pwszParam, 0, 0, false,
//		CREATE_DEFAULT_ERROR_MODE, 0, 0,
//		&siStartupInfo, &piProcessInfo) != false){
//		dwExitCode = WaitForSingleObject(piProcessInfo.hProcess, (SecondsToWait * 1000));
//	}
//	else{
//		iReturnVal = GetLastError();
//	}
//	delete[]pwszParam;
//	pwszParam = 0;
//	CloseHandle(piProcessInfo.hProcess);
//	CloseHandle(piProcessInfo.hThread);
//
//	return iReturnVal;
//}
//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nShowCmd){
//	SetEnvironmentVariableA("WINDROY_ROOT", "C:\\Windroy\\windroy_root\\");
//	SetEnvironmentVariableA("PATH", "C:\\Windroy\\windroy_root\\system\\lib;C:\\Windroy\\windroy_root\\system\\bin");
//	ExecuteProcess(L"C:\\Windroy\\windroy_root\\system\\bin\\android-start.exe", L"", 10);
//	return 0;
//}

#endif