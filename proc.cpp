#include <windows.h>
#include <psapi.h>
#include <processthreadsapi.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>

#include "Winternl.h"

#define ABORT(msg)	\
	do {printf("ABORT : %s\n", msg); exit(EXIT_FAILURE);} while(0)

#define PROCESS_ARRAY_SIZE	2048
#define PROCESS_FILENAME_SIZE	512
#define MODULE_ARRAY_SIZE	256
#define MODULE_FILENAME_SIZE	512

#define ERRO_OPEN_PROCESS	(-1)
#define ERRO_MALLOC		(-2)

#define WARN_NO_PROCESS_NAME	(1 << 0)
#define WARN_NO_MODULE_ARRAY	(1 << 1)
#define WARN_NO_COMMAND_LINE	(1 << 2)

struct process_properties {
	DWORD		pid;
	HANDLE		handle;
	TCHAR*		name;
	TCHAR*		command_line;
	HMODULE*	process_module_array;
	DWORD		process_module_array_size;
};

TCHAR* fetch_cmd_line(HANDLE hp)
{
	TCHAR* tchar_cmdline;
	PROCESS_BASIC_INFORMATION pbi;
	RTL_USER_PROCESS_PARAMETERS* params_structure_addr;
	UNICODE_STRING cmdline;

	if (NULL == hp)
		return NULL;

	/* In order to fetch the command line string, we first need to fetch the Process Basic Information
	 * structure (PBI), located inside the process inside the process' memory. The command line string pointer
	 * is well hidden and we need to go through a couple of structures inside the process' memory to get to it.
	 * We follow this scheme :
	 *
	 *		PBI -> PEB -> Process Parameters -> CommandLine
	 */

	/* Load ntdll in order to use NtQueryInformationProcess function, since it should not be called directly. */
	{
		/* Only for the following instruction */
		typedef NTSTATUS (NTAPI* _NtQueryInformationProcess)(
			HANDLE ProcessHandle,
			DWORD ProcessInformationClass,
			PVOID ProcessInformation,
			DWORD ProcessInformationLength,
			PDWORD ReturnLength
		);

		_NtQueryInformationProcess NtQueryInformationProcess =
			(_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

		/* Fetch the process' Process Basic Information (pbi) structure. */
		NtQueryInformationProcess(	hp,
						ProcessBasicInformation,
						&pbi,
						sizeof(pbi),
						NULL);
	}

	/* The PBI contains the address of a PEB structure which in turn,
	 * containes the address of the Process Parameters structure. */
	if (0 == ReadProcessMemory(	hp,
					&(pbi.PebBaseAddress->ProcessParameters),
					&params_structure_addr,
					sizeof(params_structure_addr),
					NULL))
	{
		return NULL;
	}

	/* The Process Parameters structure contains the address of the command line string. */
	if (0 == ReadProcessMemory(	hp,
					&(params_structure_addr->CommandLine),
					&cmdline,
					sizeof(cmdline),
					NULL))
	{
		return NULL;
	}

	tchar_cmdline = (TCHAR*)malloc(cmdline.Length);

	if (NULL == tchar_cmdline)
		return NULL;

	/* Eventually, we are able to copy the command line string from the process' memory inside
	 * our own buffer. */
	if (0 == ReadProcessMemory(hp, cmdline.Buffer, tchar_cmdline, cmdline.Length, NULL))
		return NULL;

	return tchar_cmdline;
}

int get_process_properties(DWORD process_id, struct process_properties *pp)
{
	int ret_value;
	int length;

	HMODULE process_module_array[MODULE_ARRAY_SIZE];
	DWORD process_module_array_size;
	TCHAR process_name[PROCESS_FILENAME_SIZE];

	if (NULL == pp)
		return NULL;


	ret_value = 0;

	pp->pid = process_id;

	if (pp->handle != NULL) {
		CloseHandle(pp->handle);
		pp->handle = NULL;
	}

	if (NULL == (pp->handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process_id))) {
		/*printf("[!] Failed to open a handle on the process (id:%d)\n", process_id);*/
		return ERRO_OPEN_PROCESS;
	}


	if (pp->process_module_array != NULL) {
		free(pp->process_module_array);
		pp->process_module_array = NULL;
	}

	/* Fetch all the process's DLLs */
	if (EnumProcessModules(pp->handle, process_module_array, sizeof(process_module_array), &process_module_array_size) == 0) {
		/*printf("[!] Failed to fetch modules of the process (id:%d)\n", process_id);*/
		ret_value |= WARN_NO_MODULE_ARRAY;
	}
	else {
		pp->process_module_array_size = process_module_array_size;
		pp->process_module_array = (HMODULE *) malloc(pp->process_module_array_size);
		if (NULL != pp->process_module_array) {
			memcpy(pp->process_module_array, process_module_array, pp->process_module_array_size);
		} else {
			return ERRO_MALLOC;
		}
	}

	if (pp->name != NULL) {
		free(pp->name);
		pp->name = NULL;
	}

	/* Get the process's name */
	if (0 == (length = GetProcessImageFileName(pp->handle, process_name, PROCESS_FILENAME_SIZE / sizeof(TCHAR)))) {
		ret_value |= WARN_NO_PROCESS_NAME;
	}
	else {
		pp->name = (TCHAR*)malloc((length + 1) * sizeof(*(pp->name)));
		if (NULL != pp->name)
			memcpy(pp->name, process_name, (length + 1) * sizeof(*(pp->name)));
		else
			return ERRO_MALLOC;
	}

	if (pp->command_line != NULL) {
		free(pp->command_line);
		pp->command_line = NULL;
	}

	if (NULL == (pp->command_line = fetch_cmd_line(pp->handle)))
		ret_value |= WARN_NO_COMMAND_LINE;

	return ret_value;
}

void print_module_array(HMODULE *module_array, DWORD length)
{
	unsigned int i;
	TCHAR module_name[MODULE_FILENAME_SIZE];

	if (NULL == module_array)
		return;

	for (i = 0; i < length; i++) {
		/* Get the DLL's name */
		if (GetModuleFileName(module_array[i], module_name, MODULE_FILENAME_SIZE / sizeof(TCHAR)) != 0) {
			_tprintf(TEXT("\t'%s'\n"), module_name);
		}
		else {
			/*printf("\tFailed to fetch the DLL(%3d)'s name of process (id:%d)\n", i, process_id);*/
		}
	}
}

void print_process_properties(struct process_properties *pp)
{
	if (NULL == pp)
		return;

	if (pp->name != NULL)
		_tprintf(TEXT("Process '%s' :\n"), pp->name);

	if (pp->command_line != NULL)
		_tprintf(TEXT("\tCOMMAND LINE : '%s'\n\n"), pp->command_line);

	print_module_array(pp->process_module_array, pp->process_module_array_size / sizeof(*(pp->process_module_array)));

}

void display_all_processes()
{
	unsigned int i;
	DWORD process_id_array[PROCESS_ARRAY_SIZE];
	DWORD process_id_array_size;
	struct process_properties pp = { 0 };

	if (EnumProcesses(process_id_array, sizeof(process_id_array), &process_id_array_size) == 0)
		ABORT("Could not fetch the list of processes (EnumProcesses)");

	printf("%d processes detected.\n\n", (process_id_array_size / sizeof(*process_id_array)));

	for (i = 0; i < (process_id_array_size / sizeof(*process_id_array)); i++) {
		switch (get_process_properties(process_id_array[i], &pp)) {
			case ERRO_OPEN_PROCESS:
				break;
			case ERRO_MALLOC:
			default:
				print_process_properties(&pp);
				printf("\n\n");
				CloseHandle(pp.handle);
		}
	}
}

int main(int ac, char** av)
{
	display_all_processes();

	return EXIT_SUCCESS;
}
