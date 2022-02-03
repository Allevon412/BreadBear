#pragma once
#include "definitions.h"
#include <stdio.h>

HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName);
FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char* sProcName);