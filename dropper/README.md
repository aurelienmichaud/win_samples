# Dropper

## How to

In order to make a final EXE, you need :
* To compile the downloader.cpp into Malware1.exe
* Launch the Python script make_dropper.py in order to store a xored version of the Malware1.exe into a new source code (dropper.cpp)
* Compile the dropper.cpp
* The final executable (compiled version of dropper.cpp) can be executed independantly

## dowloader.cpp
This is the final source code that we want to be executed. This source code :
* Downloads a remote file
* Stores that file as a binary dump inside a Registry Key (HKEY_CURRENT_USER\SORTWARE\Malware)

## Malware1.exe
It's the compiled version of the dowloader.cpp file

## make_dropper.py
This is a Python script that generates the dropper.cpp source code. The way Malware1.exe is stored inside dropper.cpp is that it is stored into multiple ```unsigned char``` buffers.

Why ?

Because when the compiler of Visual Studio sees a table initialization that looks like the following :

```
unsigned char buf[] = "...................." \
	".............................."\
	
	...

	"..............................." \
```

it stops initializing the table once it reaches a maximum size which seems to be 0xC00. After that, all the remaining bytes that will be NULL bytes. And the trick of separating the dump into
multiple smaller (less than 0xC00) tables seems to be working fine.

So, this script :
* Xors the Malware1.exe file with a key (0x35 for example).
* Generates the dropper.cpp source file.

## dropper.cpp

This is the file generated by the Python script make_dropper.py. This source code :
* contains Malware1.exe dump xored with a one-byte key
* un-xors that Malware1.exe dump stored into multiple buffers
* Writes this un-xored EXE dump into a file
* Installs some persistence features (HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run)
* Launches the newly-created EXE file
	


