#include <iostream>
#include <Windows.h>

const char* dll_name = "Sauerbraten.dll";

int main(int argc, char* argv[])
{
	char dll_path[MAX_PATH];
	GetFullPathNameA(dll_name, MAX_PATH, dll_path, nullptr);

	DWORD pid;
	HWND hwnd = FindWindowA(NULL, "Cube 2: Sauerbraten");
	GetWindowThreadProcessId(hwnd, &pid);
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	LPVOID address = VirtualAllocEx(process, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(process, address, dll_path, MAX_PATH, NULL);
	CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, address, 0, NULL);
	
	CloseHandle(process);
	VirtualFreeEx(process, address, 0, MEM_RELEASE);
	getchar();
}