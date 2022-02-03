#pragma once
#include "definitions.h"
#include "utilities.h"
#include <heapapi.h>


#define WIN32_LEAN_AND_MEAN

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI* VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef DWORD(NTAPI* NTFLUSHINSTRUCTIONCACHE)(HANDLE, PVOID, ULONG);

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

#define KERNEL32DLL_HASH				0x6A4ABC5B
#define NTDLLDLL_HASH					0x3CFA685D

#define LOADLIBRARYA_HASH				0xEC0E4E8E
#define GETPROCADDRESS_HASH				0x7C0DFCAA
#define VIRTUALALLOC_HASH				0x91AFCA54
#define NTFLUSHINSTRUCTIONCACHE_HASH	0x534C0AB8

#define IMAGE_REL_BASED_ARM_MOV32A		5
#define IMAGE_REL_BASED_ARM_MOV32T		7

#define ARM_MOV_MASK					(DWORD)(0xFBF08000)
#define ARM_MOV_MASK2					(DWORD)(0xFBF08F00)
#define ARM_MOVW						0xF2400000
#define ARM_MOVT						0xF2C00000

#define HASH_KEY						13
//===============================================================================================//
#pragma intrinsic( _rotr )

__forceinline DWORD ror(DWORD d)
{
	return _rotr(d, HASH_KEY);
}

__forceinline DWORD hash(char* c)
{
	register DWORD h = 0;
	do
	{
		h = ror(h);
		h += *c;
	} while (*++c);

	return h;
}


// WinDbg> dt -v ntdll!_PEB_FREE_BLOCK
typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
	struct _PEB_FREE_BLOCK* pNext;
	DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;


typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

ULONG_PTR WINAPI reflectiveLoader(DWORD_PTR baseAddr);

typedef BOOL (WINAPI* t_ReadProcessMemory)(
	HANDLE  hProcess,
	LPCVOID lpBaseAddress,
	LPVOID  lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesRead
);

typedef HANDLE (WINAPI * t_CreateThread)(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
);

typedef LPVOID (WINAPI * t_VirtualAlloc)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);

typedef DWORD  (WINAPI* t_WaitForSingleObject)(
	HANDLE hHandle,
	DWORD  dwMilliseconds
);