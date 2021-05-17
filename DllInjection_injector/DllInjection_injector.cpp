#include <iostream>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <winternl.h>

#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
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
bool
print_process_list()
{
	HANDLE _process_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (_process_snap == INVALID_HANDLE_VALUE)
	{
		std::wcout << L"CreateToolhelp32Snapshot failed." << std::endl;
		return false;
	}

	PROCESSENTRY32W _pe;
	_pe.dwSize = sizeof(PROCESSENTRY32W);

	if (TRUE != Process32FirstW(_process_snap, &_pe))
	{
		std::wcout << L"Process32FirstW failed." << std::endl;
		CloseHandle(_process_snap);
		return false;
	}

	_tprintf(_T("\t[Process name] \t[PID]\t\n"));

	do
	{
		_tprintf(_T("%25s %8d\n"), _pe.szExeFile, _pe.th32ProcessID);
	} while (Process32Next(_process_snap, &_pe));

	if (nullptr != _process_snap)
	{
		CloseHandle(_process_snap);
		_process_snap = nullptr;
	}

	return true;
}

bool 
inject_dll_to_target(
	_In_ const DWORD pid,
	_In_ const wchar_t* dll_path
)
{
	DWORD err_num = NULL;
	HANDLE hProcess = NULL, hThread = NULL;
	HMODULE hModule = NULL;
	TCHAR* pRemotebuffer = nullptr;
	SIZE_T buf_size = _tcslen(dll_path) * sizeof(TCHAR) + 1;
	LPTHREAD_START_ROUTINE pThreadProc;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		err_num = GetLastError();
		_tprintf(_T("OpenProcess failed. GetLastError:%u\n"), err_num);
		return false;
	}

	pRemotebuffer = (TCHAR*)VirtualAllocEx(hProcess,
										   nullptr,
										   buf_size,
										   MEM_COMMIT,
										   PAGE_READWRITE);
	if (pRemotebuffer == nullptr)
	{
		err_num = GetLastError();
		_tprintf(_T("VirtualAllocEx failed. GetLastError:%u\n"), err_num);
		if (NULL != hProcess)
		{
			CloseHandle(hProcess);
			hProcess = NULL;
		}
		return false;
	}

	_ASSERTE(NULL != hProcess);
	_ASSERTE(nullptr != pRemotebuffer);

	if (TRUE != WriteProcessMemory(hProcess,
								   pRemotebuffer,
								   (LPVOID)dll_path,
								   buf_size,
								   nullptr))
	{
		_tprintf(_T("WriteProcessMemory failed. GetLastError:%u"), GetLastError());
		if (nullptr != pRemotebuffer)
		{
			VirtualFreeEx(hProcess,
						  pRemotebuffer,
						  buf_size,
						  MEM_RELEASE);
			pRemotebuffer = nullptr;
		}
		if (NULL != hProcess)
		{
			CloseHandle(hProcess);
			hProcess = NULL;
		}
		return false;
	}

	hModule = GetModuleHandle(_T("kernel32.dll"));
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "LoadLibraryW");

	hThread = CreateRemoteThread(hProcess,
								 NULL,
								 0,
								 pThreadProc,
								 pRemotebuffer,
								 0,
								 NULL);
	if (NULL == hThread)
	{
		err_num = GetLastError();
		_tprintf(_T("CreateRemoteThread failed. GetLastError:%u\n"), err_num);
		do
		{
			if (err_num == ERROR_ACCESS_DENIED)
			{
				if (nullptr != pRemotebuffer)
				{
					VirtualFreeEx(hProcess,
								  pRemotebuffer,
								  buf_size,
								  MEM_RELEASE);
					pRemotebuffer = nullptr;
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
					_tprintf(_T("LoadLibrary ntdll.dll failed. GetLastError:%u\n"),err_num);
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
												 pRemotebuffer, 
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

	if (NULL != hThread)
	{
		WaitForSingleObject(hThread, INFINITE);
	}

	if (nullptr != pRemotebuffer)
	{
		VirtualFreeEx(hProcess,
					  pRemotebuffer,
					  buf_size,
					  MEM_RELEASE);
		pRemotebuffer = nullptr;
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

int main()
{
	_tprintf(_T("Inject dll path: "));
	std::wstring _dll_path;
	std::getline(std::wcin, _dll_path);
	if (TRUE != PathFileExists(_dll_path.c_str()))
	{
		_tprintf(_T("file is not exist. file_path:%ws"), _dll_path.c_str());
		return -1;
	}

	if (true != print_process_list())
	{
		_tprintf(_T("print_process_list failed."));
		return -1;
	}

	DWORD _target_pid = 0xffffff;
	_tprintf(_T("Select Inject target process ID : "));
	std::wcin >> _target_pid;

	if (true != inject_dll_to_target(_target_pid,
									 _dll_path.c_str()))
	{
		_tprintf(_T("inject_dll_to_target failed."));
		return -1;
	}

	return 0;
}