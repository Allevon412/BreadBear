#pragma once


#include "definitions.h"
#include "peb_structs.h"
#include <string.h>
#include <stdio.h>

PTEB RtlGetThreadEnvironmentBlock();
DWORD64 djb2(PBYTE str);
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);
BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry);
PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len);
