#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

const char* dll_name = "Sauerbraten.dll";

BYTE* ShellCode(
	DWORD_PTR loadLibraryAddress,
    const char* dllPath,
	DWORD_PTR originalRipAddress) {
    // Allocate memory for the entire shellcode
    static BYTE ShellCodeBuffer[12 + 27 + 26 + MAX_PATH + 1];

    BYTE StartSubroutine[12] = {
        // push rax
        0x50,
        // push rcx
        0x51,
        // push rdx
        0x52,
        // push r8
        0x41, 0x50,
        // push r9
        0x41, 0x51,
        // push r10
        0x41, 0x52,
        // push r11
        0x41, 0x53,
        // pushfq
        0x9C,
    };

    BYTE Loadlib[27] = {
        // lea rcx, [RIP + address]
        0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
        // mov rdx, [LoadLibraryA address]
        0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // sub rsp, 40
        0x48, 0x83, 0xEC, 0x28,
        // call rdx (call LoadLibraryA)
        0xFF, 0xD2,
        // add rsp, 40
        0x48, 0x83, 0xC4, 0x28
    };

    BYTE EndSubroutine[26 + MAX_PATH + 1] = {
        // popfq
        0x9D,
        // pop r11
        0x41, 0x5B,
        // pop r10
        0x41, 0x5A,
        // pop r9
        0x41, 0x59,
        // pop r8
        0x41, 0x58,
        // pop rdx
        0x5A,
        // pop rcx
        0x59,
        // pop rax
        0x58,
        // push low word of address
        0x68, 0x00, 0x00, 0x00, 0x00,
		// push high word of address
        0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,
        // ret
        0xC3,
        // Dll path (null-terminated)
        0x00
    };

    DWORD offsetsToModule = 46;
    DWORD low = (DWORD)originalRipAddress;
	DWORD high = (DWORD)(originalRipAddress >> 32);

	// Copy the addresses into the Loadlib
	memcpy(&Loadlib[3], &offsetsToModule, sizeof(DWORD));
	memcpy(&Loadlib[9], &loadLibraryAddress, sizeof(DWORD_PTR));

	// Copy the addresses into the EndSubroutine
	memcpy(&EndSubroutine[13], &low, sizeof(DWORD));
	memcpy(&EndSubroutine[21], &high, sizeof(DWORD));
    memcpy(&EndSubroutine[26], dllPath, MAX_PATH);

    // Copy the parts into the shellcode buffer
    memcpy(&ShellCodeBuffer, &StartSubroutine, sizeof(StartSubroutine));
    memcpy(&ShellCodeBuffer[12], &Loadlib, sizeof(Loadlib));
    memcpy(&ShellCodeBuffer[39], &EndSubroutine, sizeof(EndSubroutine));

    return ShellCodeBuffer;
}

HANDLE GetTargetProcessHandle(DWORD &pid)
{
    return OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, pid);
}

bool CompareModuleName(const WCHAR* moduleName, const WCHAR* wModuleName) {
    std::wstring lowerModuleName;

    for (const WCHAR* p = moduleName; *p; ++p)
    {
        lowerModuleName.push_back(towlower(*p));
    }

    return _wcsicmp(lowerModuleName.c_str(), wModuleName) == 0;
}

DWORD_PTR GetFunctionAddress(const wchar_t* moduleName, const char* functionName, DWORD &processId)
{
    HMODULE module = GetModuleHandle(moduleName);
    FARPROC procAddress = GetProcAddress(module, functionName);
	DWORD_PTR offset = (DWORD_PTR)procAddress - (DWORD_PTR)module;

	MODULEENTRY32 moduleEntry;
	moduleEntry.dwSize = sizeof(MODULEENTRY32);

	HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);
	while (Module32Next(snapshotHandle, &moduleEntry))
    {
        if (CompareModuleName(moduleEntry.szModule, moduleName)) {
            CloseHandle(snapshotHandle);
            return (DWORD_PTR)(moduleEntry.modBaseAddr + offset);
        }
	}
	CloseHandle(snapshotHandle);
	return 0;
}

DWORD GetTargetProcessThreadID(DWORD processID) {
    HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    while (Thread32Next(snapshotHandle, &threadEntry)) {
            if (threadEntry.th32OwnerProcessID == processID) {
                CloseHandle(snapshotHandle);
                return threadEntry.th32ThreadID;
            }

    }
    CloseHandle(snapshotHandle);
	return 0;
}

CONTEXT GteTargetProcessThreadContext(DWORD threadID) {
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;

    HANDLE threadHandle = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, threadID);
    SuspendThread(threadHandle);
    GetThreadContext(threadHandle, &context);
    CloseHandle(threadHandle);

    return context;
}

void SetRemoteThreadContext(DWORD &threadId, DWORD_PTR &RipAddress, CONTEXT &context)
{
	HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
	context.Rip = RipAddress;
	SetThreadContext(hThread, &context);
	CloseHandle(hThread);
}

int main(int argc, char* argv[])
{
    BYTE shellcode[326];
	char dll_path[MAX_PATH];
	GetFullPathNameA(dll_name, MAX_PATH, dll_path, nullptr);

	DWORD pid;
	HWND hwnd = FindWindowA(NULL, "Cube 2: Sauerbraten");
	GetWindowThreadProcessId(hwnd, &pid);

	HANDLE process = GetTargetProcessHandle(pid);
	DWORD tid = GetTargetProcessThreadID(pid);
	CONTEXT threadContext = GteTargetProcessThreadContext(tid);

    DWORD_PTR remoteLoadLibraryAddress = GetFunctionAddress(L"kernel32.dll", "LoadLibraryA", pid);

    DWORD_PTR remoteFullModulePathAddress = (DWORD_PTR)VirtualAllocEx(process, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(process, (LPVOID)remoteFullModulePathAddress, dll_path, MAX_PATH, NULL);

    memcpy(shellcode, ShellCode(remoteLoadLibraryAddress, dll_path, threadContext.Rip), 326);

    DWORD_PTR remoteHijackAddress = (DWORD_PTR)VirtualAllocEx(process, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(process, (LPVOID)remoteHijackAddress, shellcode, sizeof(shellcode), NULL);

	SetRemoteThreadContext(tid, remoteHijackAddress, threadContext);
	CloseHandle(process);

    HANDLE hThreadHadnle = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
	VirtualFreeEx(process, (LPVOID)remoteFullModulePathAddress, 0, MEM_RELEASE);
	VirtualFreeEx(process, (LPVOID)remoteHijackAddress, 0, MEM_RELEASE);
    ResumeThread(hThreadHadnle);
	CloseHandle(hThreadHadnle);
}