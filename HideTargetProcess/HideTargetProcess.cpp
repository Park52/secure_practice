#include <iostream>
#include <tchar.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>

#define INJECTION_MODE	0
#define EJECTION_MODE	1	

typedef void(*PFN_SetProcName)(const char* szProcName);
typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)
(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer);

typedef NTSTATUS(NTAPI* pfnRtlCreateUserThread)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL,
	IN PTHREAD_START_ROUTINE StartAddress,
	IN PVOID Parameter OPTIONAL,
	OUT PHANDLE ThreadHandle OPTIONAL,
	OUT CLIENT_ID* ClientId OPTIONAL);

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
			unicode, 
			-1,
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
			unicode, 
			-1,
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
	HANDLE                  hProcess = NULL, hThread = NULL;
	HMODULE					hModule = NULL;
	LPVOID                  pRemoteBuf = nullptr;
	LPTHREAD_START_ROUTINE  pThreadProc = nullptr;
	DWORD                   dwBufSize = strlen(szDllPath) + 1;
	DWORD					err_num = ERROR_SUCCESS;
	do
	{
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
		if (NULL == hProcess)
		{
			printf("OpenProcess(%d) failed!!!\n", dwPID);
			break;
		}

		pRemoteBuf = VirtualAllocEx(hProcess, 
									NULL, 
									dwBufSize,
									MEM_COMMIT, 
									PAGE_READWRITE);
		if (nullptr == pRemoteBuf)
		{
			printf("VirtualAllocEx failed!!!\n");
			break;
		}

		if (TRUE != WriteProcessMemory(hProcess, 
									   pRemoteBuf,
									   (LPVOID)szDllPath, 
									   dwBufSize, 
									   NULL))
		{
			printf("WriteProcessMemory failed!!!\n");
			break;
		}

		hModule = GetModuleHandle(_T("kernel32.dll"));
		if (NULL == hModule)
		{
			printf("GetModuleHandle failed!!!\n");
			break;
		}

		pThreadProc = (LPTHREAD_START_ROUTINE)
			GetProcAddress(hModule,
						   "LoadLibraryW");
		if (NULL == pThreadProc)
		{
			printf("GetProcAddress failed!!! Gle:%u\n", GetLastError());
			break;
		}
		hThread = CreateRemoteThread(hProcess, NULL, 0,
									 pThreadProc, pRemoteBuf, 0, NULL);
		if (NULL == hThread)
		{
			err_num = GetLastError();
			_tprintf(_T("CreateRemoteThread failed. GetLastError:%u\n"), err_num);
			do
			{
				if (err_num == ERROR_ACCESS_DENIED)
				{
					if (nullptr != pRemoteBuf)
					{
						VirtualFreeEx(hProcess,
									  pRemoteBuf,
									  dwBufSize,
									  MEM_RELEASE);
						pRemoteBuf = nullptr;
					}

					if (NULL != hProcess)
					{
						CloseHandle(hProcess);
						hProcess = NULL;
					}

					break;
				}

				if (err_num == ERROR_NOT_ENOUGH_MEMORY)
				{
					HMODULE hntdll = LoadLibrary(_T("ntdll.dll"));
					if (NULL == hntdll)
					{
						err_num = GetLastError();
						_tprintf(_T("LoadLibrary ntdll.dll failed. GetLastError:%u\n"), err_num);
						break;
					}

					CLIENT_ID cid;
					pfnRtlCreateUserThread RtlCreateUserThread = (pfnRtlCreateUserThread)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "RtlCreateUserThread");
					if (nullptr == RtlCreateUserThread)
					{
						err_num = GetLastError();
						_tprintf(_T("GetProcAddress failed. GetLastError:%u\n"), err_num);
						break;
					}
					else
					{
						NTSTATUS status = 0;
						status = RtlCreateUserThread(hProcess,
													 NULL,
													 FALSE,
													 0, 0, 0,
													 (LPTHREAD_START_ROUTINE)pThreadProc,
													 pRemoteBuf,
													 &hThread,
													 &cid);

						if (!NT_SUCCESS(status) || NULL == hThread)
						{
							_tprintf(_T("RtlCreateUserThread failed.\n"));
							break;
						}
					}
				}
			} while (false);
		}

		WaitForSingleObject(hThread, INFINITE);
	} while (false);

	if (nullptr != pRemoteBuf && NULL != hProcess)
	{
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		pRemoteBuf = nullptr;
	}
	
	if (NULL != hThread)
	{
		CloseHandle(hThread);
		hThread = NULL;
	}
	if (NULL != hProcess)
	{
		CloseHandle(hProcess);
		hProcess = NULL;
	}

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
		if (dwPID < 1000 || dwPID == GetCurrentProcessId())
			continue;

		if (mode == INJECTION_MODE)
		{
			InjectDll(dwPID, szDllPath);
		}		
		else
		{
			EjectDll(dwPID, szDllPath);
		}
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

	if (0 == _tcsicmp(argv[1], _T("-show")))
	{
		mode = EJECTION_MODE;
	}

	lib = LoadLibrary(argv[3]);
	setprocname = (PFN_SetProcName)GetProcAddress(lib, "SetProcName");
	std::string proc_name;
	if (ERROR_SUCCESS != convert_unicode_to_ansi_string(proc_name,
														argv[2],
														sizeof(argv[2])))
	{
		_tprintf(_T("convert_unicode_to_ansi_string failed. argv[2]:%s", argv[2]));
		return 1;
	}

	setprocname(proc_name.c_str());

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