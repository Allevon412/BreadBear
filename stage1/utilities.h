#pragma once
#include "definitions.h"
#include "DynamicFunctionResolvers.h"

HMODULE customLoadLibrary(LPCWSTR library);

PIMAGE_NT_HEADERS getNtHeaders(DWORD_PTR imageBase);
SIZE_T getImageSize(DWORD_PTR imageBase);

void selfDelete();


typedef HANDLE (WINAPI* t_CreateFileW)(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
);

typedef BOOL (WINAPI* t_SetFileInformationByHandle)(
	HANDLE                    hFile,
	FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
	LPVOID                    lpFileInformation,
	DWORD                     dwBufferSize
);

typedef DWORD (WINAPI* t_GetModuleFileNameW)(
	HMODULE hModule,
	LPWSTR  lpFilename,
	DWORD   nSize
);