
//
// support by KsaHijack
// github:https://github.com/KsaNL/Hijacker_x96
//

#include <Windows.h>

#pragma comment(linker, "/EXPORT:GetFileVersionInfoA=HJ_GetFileVersionInfoA,@1")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoByHandle=HJ_GetFileVersionInfoByHandle,@2")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoExA=HJ_GetFileVersionInfoExA,@3")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoExW=HJ_GetFileVersionInfoExW,@4")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeA=HJ_GetFileVersionInfoSizeA,@5")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExA=HJ_GetFileVersionInfoSizeExA,@6")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExW=HJ_GetFileVersionInfoSizeExW,@7")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeW=HJ_GetFileVersionInfoSizeW,@8")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoW=HJ_GetFileVersionInfoW,@9")
#pragma comment(linker, "/EXPORT:VerFindFileA=HJ_VerFindFileA,@10")
#pragma comment(linker, "/EXPORT:VerFindFileW=HJ_VerFindFileW,@11")
#pragma comment(linker, "/EXPORT:VerInstallFileA=HJ_VerInstallFileA,@12")
#pragma comment(linker, "/EXPORT:VerInstallFileW=HJ_VerInstallFileW,@13")
#pragma comment(linker, "/EXPORT:VerLanguageNameA=KERNEL32.VerLanguageNameA,@14")
#pragma comment(linker, "/EXPORT:VerLanguageNameW=KERNEL32.VerLanguageNameW,@15")
#pragma comment(linker, "/EXPORT:VerQueryValueA=HJ_VerQueryValueA,@16")
#pragma comment(linker, "/EXPORT:VerQueryValueW=HJ_VerQueryValueW,@17")

static INT g_hj = 3001; // v3.0.0.1 KsaHijack
static HMODULE g_Module, g_ModuleProxy;

extern "C" {
	int HJ_GetFileVersionInfoA() { return g_hj + 1; }
	int HJ_GetFileVersionInfoByHandle() { return g_hj + 2; }
	int HJ_GetFileVersionInfoExA() { return g_hj + 3; }
	int HJ_GetFileVersionInfoExW() { return g_hj + 4; }
	int HJ_GetFileVersionInfoSizeA() { return g_hj + 5; }
	int HJ_GetFileVersionInfoSizeExA() { return g_hj + 6; }
	int HJ_GetFileVersionInfoSizeExW() { return g_hj + 7; }
	int HJ_GetFileVersionInfoSizeW() { return g_hj + 8; }
	int HJ_GetFileVersionInfoW() { return g_hj + 9; }
	int HJ_VerFindFileA() { return g_hj + 10; }
	int HJ_VerFindFileW() { return g_hj + 11; }
	int HJ_VerInstallFileA() { return g_hj + 12; }
	int HJ_VerInstallFileW() { return g_hj + 13; }
	int HJ_VerQueryValueA() { return g_hj + 16; }
	int HJ_VerQueryValueW() { return g_hj + 17; }
}

#define MACROPROXY(x) \
		Jmper = GetAddress(#x); \
		::WriteProcessMemory(INVALID_HANDLE_VALUE, &HJ_ ##x, Shells, sizeof Shells, NULL);
INT64 WINAPI GetAddress(PCSTR pszProcName);
BOOL WINAPI DllFill()
{
	// x32Mode
	// 
	// static BYTE Shells[7] = { 0xB8,0x00,0x00,0x00,0x00,0xFF,0xE0 };
	// INT& Jmper = *(PINT)(Shells + 1);

	// x64Mode
	//
	static BYTE Shells[12] = { 0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xE0 };
	INT64& Jmper = *(PINT64)(Shells + 2);

	MACROPROXY(GetFileVersionInfoA);
	MACROPROXY(GetFileVersionInfoByHandle);
	MACROPROXY(GetFileVersionInfoExA);
	MACROPROXY(GetFileVersionInfoExW);
	MACROPROXY(GetFileVersionInfoSizeA);
	MACROPROXY(GetFileVersionInfoSizeExA);
	MACROPROXY(GetFileVersionInfoSizeExW);
	MACROPROXY(GetFileVersionInfoSizeW);
	MACROPROXY(GetFileVersionInfoW);
	MACROPROXY(VerFindFileA);
	MACROPROXY(VerFindFileW);
	MACROPROXY(VerInstallFileA);
	MACROPROXY(VerInstallFileW);
	MACROPROXY(VerQueryValueA);
	MACROPROXY(VerQueryValueW);

	return TRUE; // Always
}
#undef MACROPROXY

BOOL WINAPI DllLoad()
{
	WCHAR tzPath[MAX_PATH];
	WCHAR tzTemp[MAX_PATH * 2];

	//GetModuleFileName(NULL,tzPath,MAX_PATH); // Use CurrentConetent
	//PathRemoveFileSpec(tzPath);

	::GetSystemDirectoryW(tzPath, MAX_PATH); // Default Systeam
	lstrcatW(tzPath, L"\\version.dll");

	g_ModuleProxy = LoadLibraryW(tzPath);
	if (g_ModuleProxy == NULL)
	{
		wsprintfW(tzTemp, L"无法找到模块 %s,程序无法正常运行", tzPath);
		::MessageBoxW(NULL, tzTemp, L"ERROR", MB_ICONSTOP);
	}

	return (g_ModuleProxy != NULL);
}

INT64 WINAPI GetAddress(PCSTR pszProcName)
{
	FARPROC fpAddress;
	CHAR szProcName[16];
	WCHAR tzTemp[MAX_PATH];

	fpAddress = ::GetProcAddress(g_ModuleProxy, pszProcName);
	if (fpAddress == NULL)
	{
		if (HIWORD(pszProcName) == 0)
		{
			wsprintfA(szProcName, "#%d", *(PDWORD)pszProcName);
			pszProcName = szProcName;
		}

		wsprintf(tzTemp, L"无法找到函数 %hs , 程序无法正常运行", pszProcName);
		::MessageBoxW(NULL, tzTemp, L"ERROR", MB_ICONSTOP);
		::ExitProcess(-2);
	}
	return (INT64)fpAddress;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, PVOID lpReserved)
{
	UNREFERENCED_PARAMETER(lpReserved);
	static BOOL scModuleInited = FALSE;
	
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		if (!scModuleInited) {

			if (DllLoad() && DllFill())
			{
				g_Module = hModule; // Self
				// g_ModuleProxy = g_ModuleProxy;
				// ToDo: Input your sync codes here

				printf(
					"ModuleProxy 0x%llX\n",
					(INT_PTR)g_ModuleProxy
				);

				::DisableThreadLibraryCalls(hModule);
				scModuleInited = TRUE;
			}

		}
		return TRUE;
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		if (g_ModuleProxy) {
			::FreeLibrary(g_ModuleProxy);
			g_ModuleProxy = NULL;
		}
	}
	return FALSE;
}
