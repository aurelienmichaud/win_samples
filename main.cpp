#include <windows.h>
#include <psapi.h>
#include <tchar.h>
#include <stdio.h>

#define ABORT(msg)	\
	do {printf("ABORT : %s\n", msg); exit(EXIT_FAILURE);} while(0)

#define PROCESS_ARRAY_SIZE		2048
#define PROCESS_FILENAME_SIZE	512
#define MODULE_ARRAY_SIZE		256
#define MODULE_FILENAME_SIZE	512

void print_process_cmdline(DWORD process_id)
{
	char powershell_cmd[1024];
	snprintf(powershell_cmd, 1024, "PowerShell -Command \"& {Get-WmiObject win32_Process | Where-Object {$_.ProcessId -eq '%d'} | Format-List -Property CommandLine}\"", process_id);
	system(powershell_cmd);
}

void print_process_properties(DWORD process_id)
{
	HANDLE hp;
	unsigned int i;
	HMODULE process_module_array[MODULE_ARRAY_SIZE];
	DWORD process_module_array_size;
	TCHAR process_name[PROCESS_FILENAME_SIZE];
	TCHAR module_name[MODULE_FILENAME_SIZE];
	
	if (NULL == (hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process_id))) {
		/*printf("[!] Failed to open a handle on the process (id:%d)\n", process_id);*/
		return;
	}

	/* Fetch all the process's DLLs */
	if (EnumProcessModules(hp, process_module_array, sizeof(process_module_array), &process_module_array_size) == 0) {
		/*printf("[!] Failed to fetch modules of the process (id:%d)\n", process_id);*/
		return;
	}

	/* Get the process's name */
	if (GetProcessImageFileName(hp, process_name, PROCESS_FILENAME_SIZE / sizeof(TCHAR)) == 0) {
		printf("[!] Failed to fetch the name of the process (id:%d)\n", process_id);
		return;
	} else {
		_tprintf(TEXT("Process '%s' :\n"), process_name);
	}

	print_process_cmdline(process_id);

	for (i = 0; i < (process_module_array_size / sizeof(*process_module_array)); i++) {
		/* Get the DLL's name */
		if (GetModuleFileName(process_module_array[i], module_name, MODULE_FILENAME_SIZE / sizeof(TCHAR)) == 0) {
			/*printf("\tFailed to fetch the DLL(%3d)'s name of process (id:%d)\n", i, process_id);*/
			continue;
		}

		_tprintf(TEXT("\t'%s'\n"), module_name);
	}

	CloseHandle(hp);
}

int main(int ac, char** av)
{
	unsigned int i;
	DWORD process_id_array[PROCESS_ARRAY_SIZE];
	DWORD process_id_array_size;

	if (EnumProcesses(process_id_array, sizeof(process_id_array), &process_id_array_size) == 0)
		ABORT("Could not fetch the list of processes (EnumProcesses)");

	for (i = 0; i < (process_id_array_size / sizeof(*process_id_array)); i++) {
		print_process_properties(process_id_array[i]);
	}

	return EXIT_SUCCESS;
}
