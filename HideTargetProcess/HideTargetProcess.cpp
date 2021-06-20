#include <iostream>
#include <tchar.h>
#include <Windows.h>
#include <TlHelp32.h>

#define INJECTION_MODE	0
#define EJECTION_MODE	1	

typedef void(*PFN_SetProcName)(const TCHAR* szProcName);

DWORD convert_ansi_to_unicode_string(
	__out std::wstring& unicode,
	__in const char* ansi,
	__in const size_t ansi_size
) {
	DWORD error = 0;
	do {
		if ((nullptr == ansi) || (0 == ansi_size)) {
			error = ERROR_INVALID_PARAMETER;
			break;
		}
		unicode.clear();
		//
		// getting required cch.
		//
		int required_cch = ::MultiByteToWideChar(
			CP_ACP,
			0,
			ansi, static_cast<int>(ansi_size),
			nullptr, 0
		);
		if (0 == required_cch) {
			error = ::GetLastError();
			break;
		}
		unicode.resize(required_cch);
		//
		// convert.
		//
		if (0 == ::MultiByteToWideChar(
			CP_ACP,
			0,
			ansi, static_cast<int>(ansi_size),
			const_cast<wchar_t*>(unicode.c_str()), static_cast<int>(unicode.size())
		)) {
			error = ::GetLastError();
			break;
		}
	} while (false);

	return error;
}

DWORD convert_unicode_to_ansi_string(
	__out std::string& ansi,
	__in const wchar_t* unicode,
	__in const size_t unicode_size
) {
	DWORD error = 0;
	do {
		if ((nullptr == unicode) || (0 == unicode_size)) {
			error = ERROR_INVALID_PARAMETER;
			break;
		}
		ansi.clear();
		//
		// getting required cch.
		//
		int required_cch = ::WideCharToMultiByte(
			CP_ACP,
			0,
			unicode, static_cast<int>(unicode_size),
			nullptr, 0,
			nullptr, nullptr
		);
		if (0 == required_cch) {
			error = ::GetLastError();
			break;
		}
		//
		// allocate.
		//
		ansi.resize(required_cch);
		//
		// convert.
		//
		if (0 == ::WideCharToMultiByte(
			CP_ACP,
			0,
			unicode, static_cast<int>(unicode_size),
			const_cast<char*>(ansi.c_str()), static_cast<int>(ansi.size()),
			nullptr, nullptr
		)) {
			error = ::GetLastError();
			break;
		}
	} while (false);
	return error;
}

DWORD convert_unicode_to_utf8_string(
	__out std::string& utf8,
	__in const wchar_t* unicode,
	__in const size_t unicode_size
) {
	DWORD error = 0;
	do {
		if ((nullptr == unicode) || (0 == unicode_size)) {
			error = ERROR_INVALID_PARAMETER;
			break;
		}
		utf8.clear();
		//
		// getting required cch.
		//
		int required_cch = ::WideCharToMultiByte(
			CP_UTF8,
			WC_ERR_INVALID_CHARS,
			unicode, static_cast<int>(unicode_size),
			nullptr, 0,
			nullptr, nullptr
		);
		if (0 == required_cch) {
			error = ::GetLastError();
			break;
		}
		//
		// allocate.
		//
		utf8.resize(required_cch);
		//
		// convert.
		//
		if (0 == ::WideCharToMultiByte(
			CP_UTF8,
			WC_ERR_INVALID_CHARS,
			unicode, static_cast<int>(unicode_size),
			const_cast<char*>(utf8.c_str()), static_cast<int>(utf8.size()),
			nullptr, nullptr
		)) {
			error = ::GetLastError();
			break;
		}
	} while (false);
	return error;
}

WORD convert_utf8_to_unicode_string(
	__out std::wstring& unicode,
	__in const char* utf8,
	__in const size_t utf8_size
) {
	DWORD error = 0;
	do {
		if ((nullptr == utf8) || (0 == utf8_size)) {
			error = ERROR_INVALID_PARAMETER;
			break;
		}
		unicode.clear();
		//
		// getting required cch.
		//
		int required_cch = ::MultiByteToWideChar(
			CP_UTF8,
			MB_ERR_INVALID_CHARS,
			utf8, static_cast<int>(utf8_size),
			nullptr, 0
		);
		if (0 == required_cch) {
			error = ::GetLastError();
			break;
		}
		//
		// allocate.
		//
		unicode.resize(required_cch);
		//
		// convert.
		//
		if (0 == ::MultiByteToWideChar(
			CP_UTF8,
			MB_ERR_INVALID_CHARS,
			utf8, static_cast<int>(utf8_size),
			const_cast<wchar_t*>(unicode.c_str()), static_cast<int>(unicode.size())
		)) {
			error = ::GetLastError();
			break;
		}
	} while (false);
	return error;
}

bool 
SetPrivilege(
	_In_ LPCTSTR lpszPrivilege, 
	_In_ bool bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(),
						  TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
						  &hToken))
	{
		printf("OpenProcessToken error: %u\n", GetLastError());
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL,            // lookup privilege on local system
							  lpszPrivilege,   // privilege to lookup 
							  &luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(hToken,
							   FALSE,
							   &tp,
							   sizeof(TOKEN_PRIVILEGES),
							   (PTOKEN_PRIVILEGES)NULL,
							   (PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

bool 
InjectDll(
	_In_ DWORD dwPID, 
	_In_ const char* szDllPath)
{
	HANDLE                  hProcess, hThread;
	LPVOID                  pRemoteBuf;
	DWORD                   dwBufSize = strlen(szDllPath) + 1;
	LPTHREAD_START_ROUTINE  pThreadProc;

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
	{
		printf("OpenProcess(%d) failed!!!\n", dwPID);
		return false;
	}

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize,
								MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(hProcess, pRemoteBuf,
		(LPVOID)szDllPath, dwBufSize, NULL);

	pThreadProc = (LPTHREAD_START_ROUTINE)
		GetProcAddress(GetModuleHandle(_T("kernel32.dll")),
					   "LoadLibraryA");
	hThread = CreateRemoteThread(hProcess, NULL, 0,
								 pThreadProc, pRemoteBuf, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return true;
}

bool 
EjectDll(
	_In_ DWORD dwPID, 
	_In_ const char* szDllPath)
{
	BOOL                    bMore = FALSE, bFound = FALSE;
	HANDLE                  hSnapshot, hProcess, hThread;
	MODULEENTRY32           me = { sizeof(me) };
	LPTHREAD_START_ROUTINE  pThreadProc;

	if (INVALID_HANDLE_VALUE ==
		(hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID)))
		return false;

	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
		std::wstring unicode_path;
		if (ERROR_SUCCESS != convert_ansi_to_unicode_string(unicode_path,
															szDllPath,
															strlen(szDllPath)))
		{
			printf("convert_ansi_to_unicode_string failed.");
			break;
		}

		if (0 != _tcsicmp(me.szModule, unicode_path.c_str()) ||
			0 != _tcsicmp(me.szExePath, unicode_path.c_str()))
		{
			bFound = false;
			break;
		}
	}

	if (!bFound)
	{
		CloseHandle(hSnapshot);
		return false;
	}

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
	{
		printf("OpenProcess(%d) failed!!!\n", dwPID);
		CloseHandle(hSnapshot);
		return FALSE;
	}

	pThreadProc = (LPTHREAD_START_ROUTINE)
		GetProcAddress(GetModuleHandle(_T("kernel32.dll")),
					   "FreeLibrary");
	hThread = CreateRemoteThread(hProcess, NULL, 0,
								 pThreadProc, me.modBaseAddr, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);
	CloseHandle(hSnapshot);

	return true;
}

bool 
InjectAllProcess(
	_In_ int mode, 
	_In_ const char* szDllPath)
{
	DWORD                   dwPID = 0;
	HANDLE                  hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32          pe;

	// Get the snapshot of the system
	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

	// find process
	Process32First(hSnapShot, &pe);
	do
	{
		dwPID = pe.th32ProcessID;

		// 시스템의 안정성을 위해서
		// PID 가 100 보다 작은 시스템 프로세스에 대해서는
		// DLL Injection 을 수행하지 않는다.
		if (dwPID < 100)
			continue;

		if (mode == INJECTION_MODE)
			InjectDll(dwPID, szDllPath);
		else
			EjectDll(dwPID, szDllPath);
	} while (Process32Next(hSnapShot, &pe));

	CloseHandle(hSnapShot);

	return true;
}

int 
_tmain(int argc, TCHAR* argv[])
{
	int mode = INJECTION_MODE;
	HMODULE                 lib = nullptr;
	PFN_SetProcName         setprocname = nullptr;

	if (argc != 4)
	{
		std::cout << "\n Usage : HideTargetProcess.exe <-hide|-show> <process name> <dll path>\n\n";
		return 1;
	}
	
	//
	//	사실 Win7, Win10에서 실패할 수 있다.
	//	그래서 성공여부를 확인하지 않는다.
	//
	SetPrivilege(SE_DEBUG_NAME,
				 TRUE);

	if (0 != _tcsicmp(argv[1], _T("-show")))
	{
		mode = EJECTION_MODE;
	}

	lib = LoadLibrary(argv[3]);
	setprocname = (PFN_SetProcName)GetProcAddress(lib, "SetProcName");
	setprocname(argv[2]);

	std::string dll_path;
	if (ERROR_SUCCESS != convert_unicode_to_ansi_string(dll_path,
														argv[3],
														_tcslen(argv[3])))
	{
		_tprintf(_T("convert_unicode_to_ansi_string failed. argv[3]:%s", argv[3]));
		return 1;
	}

	if (true != InjectAllProcess(mode, dll_path.c_str()))
	{
		_tprintf(_T("InjectAllProcess failed. mode:%s, dll_path:%s\n"),
			(mode == INJECTION_MODE) ? _T("INJECTION_MODE") : _T("EJECTION_MODE"),
				 dll_path.c_str());
		return 1;
	}

	FreeLibrary(lib);

	return 0;
}