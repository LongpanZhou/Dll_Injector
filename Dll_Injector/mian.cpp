#include <iostream>
#include <Windows.h>
#include <string>
#include <libloaderapi.h>
#include <thread>

void get_proc_id(const char* proc_name, DWORD& proc_id)
{
	std::wstring wide_proc_name = std::wstring(proc_name, proc_name + strlen(proc_name));
	GetWindowThreadProcessId(FindWindow(NULL, wide_proc_name.c_str()), &proc_id);
}

void error(const char* msg)
{
	std::cout << msg << std::endl;
	getchar();
	exit(-1);
}

bool file_exists(std::string file_name)
{
	struct stat buffer;
	return (stat(file_name.c_str(), &buffer) == 0);
}

int main()
{
	DWORD proc_id = 0;
	char dll_path[MAX_PATH];
	const char* dll_name = "tut_internal.dll";
	const char* window_name = "AssaultCube";

	if (!file_exists(dll_name))
		error("Dll not found");
	
	if (!GetFullPathNameA(dll_name, MAX_PATH, dll_path, nullptr))
		error("GetFullPathNameA failed");

	get_proc_id(window_name, proc_id);
	if (!proc_id)
		error("Process not found");

	HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, false, proc_id);
	if (!h_process)
		error("OpenProcess failed");

	LPVOID alloc_mem = VirtualAllocEx(h_process, nullptr, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!alloc_mem)
		error("VirtualAllocEx failed");

	if (!WriteProcessMemory(h_process, alloc_mem, dll_path, MAX_PATH, nullptr))
		error("WriteProcessMemory failed");

	HANDLE h_thread = CreateRemoteThread(h_process, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, alloc_mem, 0, nullptr);
	if (!h_thread)
		error("CreateRemoteThread failed");

	std::this_thread::sleep_for(std::chrono::seconds(1));
	CloseHandle(h_process);
	VirtualFreeEx(h_process, alloc_mem, 0, MEM_RELEASE);
	std::cout << "Dll injected" << std::endl;
	getchar();
	return 0;
}