/*
	부모 프로세스를 지정해 프로그램을 실행시켜주는 프로그램이다.
	주의사항) 권한에 따라 프로그램 목적대로 실행되지 않을 수 있다.
	example)
		1) 실행
		2) 실행시키고 싶은 exe 경로 및 실행인자를 입력
		3) 출력된 프로세스들을 보고, 부모 프로세스로 지정할 PID를 입력하면 실행된다.
*/
#include <iostream>
#include <string>
#include <tchar.h>
#include <Windows.h>
#include <TlHelp32.h>

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
create_process_under_selected_process(_In_ const DWORD parent_pid,
									  _In_ const wchar_t* exec_path)
{
	if (nullptr == exec_path)
	{
		_tprintf(_T("Invalid Parameter\n"));
		return false;
	}
	STARTUPINFOEX _si;
	SIZE_T _attr_size;

	ZeroMemory(&_si, sizeof(STARTUPINFOEX));

	HANDLE _parent_process_handle = OpenProcess(MAXIMUM_ALLOWED, false, parent_pid);
	if (NULL == _parent_process_handle)
	{
		_tprintf(_T("OpenProcess failed. GetLastError:%u\n"), GetLastError());
		return false;
	}

	InitializeProcThreadAttributeList(NULL, 1, 0, &_attr_size);
	_si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, _attr_size);
	InitializeProcThreadAttributeList(_si.lpAttributeList, 1, 0, &_attr_size);
	UpdateProcThreadAttribute(_si.lpAttributeList,
							  0,
							  PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
							  &_parent_process_handle,
							  sizeof(HANDLE),
							  NULL, NULL);
	_si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	PROCESS_INFORMATION _pi;
	size_t buf_size = ((wcslen(exec_path) + 1) * sizeof(wchar_t));
	wchar_t* buf = (wchar_t*)malloc(buf_size);

	if (nullptr == buf)
	{
		_tprintf(_T("Memory alloc failed."));
		{
			CloseHandle(_parent_process_handle);
			_parent_process_handle = nullptr;
		}
		return false;
	}

	RtlCopyMemory(buf,
				  exec_path,
				  wcslen(exec_path) * sizeof(wchar_t));
	buf[wcslen(exec_path)] = 0x0000;

	if (TRUE != CreateProcess(NULL,
							  buf,
							  NULL,
							  NULL,
							  FALSE,
							  EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
							  NULL,
							  NULL,
							  &_si.StartupInfo,
							  &_pi))
	{
		_tprintf(_T("CreatePrcess Failed. GetLasteError:%u\n "), GetLastError());
		{
			CloseHandle(_parent_process_handle);
			_parent_process_handle = nullptr;

			free(buf);
			buf = nullptr;
		}
		return false;
	}

	CloseHandle(_pi.hThread);
	CloseHandle(_pi.hProcess);

	if (nullptr != _parent_process_handle)
	{
		CloseHandle(_parent_process_handle);
		_parent_process_handle = nullptr;
	}

	if (nullptr != buf)
	{
		free(buf);
		buf = nullptr;
	}

	if (nullptr != _si.lpAttributeList)
	{
		DeleteProcThreadAttributeList(_si.lpAttributeList);
		_si.lpAttributeList = nullptr;
	}

	HeapFree(GetProcessHeap(), NULL, _si.lpAttributeList);
	return true;
}

int main()
{
	_tprintf(_T("Execute Path(Include Command): "));
	std::wstring _execute_path;
	std::getline(std::wcin, _execute_path);

	if (true != print_process_list())
	{
		_tprintf(_T("print_process_list failed."));
		return -1;
	}

	_tprintf(_T("Select your parent process ID : "));
	DWORD _parent_process_id = 0;
	std::wcin >> _parent_process_id;

	if (true != create_process_under_selected_process(_parent_process_id,
													  _execute_path.c_str()))
	{
		_tprintf(_T("create_process_under_selected_process failed."));
		return -1;
	}

	return 0;
}