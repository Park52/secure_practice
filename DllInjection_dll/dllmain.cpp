#include "pch.h"

#include <iostream>
#include <sstream>
#include <Windows.h>

#define _select_my_parent_process L"C:\\work.secure_practice\\out\\x64_debug\\SelectMyParentProcess.exe"

BOOL
APIENTRY DllMain(HMODULE hModule,
				 DWORD  ul_reason_for_call,
				 LPVOID lpReserved
)
{
	HANDLE hProcess = nullptr;
	wchar_t _program_path[MAX_PATH] = _select_my_parent_process;
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		CreateProcess(nullptr,
					  _program_path,
					  nullptr,
					  nullptr,
					  FALSE,
					  0,
					  nullptr,
					  nullptr,
					  &si,
					  &pi);

		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

