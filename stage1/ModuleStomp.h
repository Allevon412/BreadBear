#include "definitions.h"
#include "DynamicFunctionResolvers.h"
#include "utilities.h"
#include "ReflectiveLoader.h"

BOOL InjectSCModuleStomp(DWORD_PTR baseAddr, SIZE_T imageSize, DWORD_PTR* outPtr);

//typedef BOOL (WINAPI* t_VirtualProtect)(
//	LPVOID lpAddress,
//	SIZE_T dwSize,
//	DWORD  flNewProtect,
//	PDWORD lpflOldProtect
//);