#pragma once
#include "definitions.h"
#include "DynamicFunctionResolvers.h"

typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL (WINAPI* t_FlushInstructionCache)(
	HANDLE  hProcess,
	LPCVOID lpBaseAddress,
	SIZE_T  dwSize
);

int DisableETW(void);