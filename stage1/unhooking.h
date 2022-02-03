#pragma once
#include "definitions.h"
#include "DynamicFunctionResolvers.h"
#include <stdio.h>

static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pMapping);
BOOL unHookLibrary(WCHAR sNtdllPath[], unsigned char sdll[], PVX_TABLE table);
void UnhookStart(PVX_TABLE table);


