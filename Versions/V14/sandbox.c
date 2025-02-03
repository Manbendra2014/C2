#include "sandbox.h"

#pragma comment(lib, "Netapi32.lib")
#define BUFFER_SIZE 256

void ToLowerCase(TCHAR *str) {
    for (int i = 0; str[i]; i++) {
        str[i] = (TCHAR)tolower((unsigned char)str[i]);
    }
}

BOOL IsMachineInDomain() {
    PDSROLE_PRIMARY_DOMAIN_INFO_BASIC pDomainInfo = NULL;
    DWORD status;
    status = DsRoleGetPrimaryDomainInformation(NULL, DsRolePrimaryDomainInfoBasic, (PBYTE*)&pDomainInfo);
    if (status != ERROR_SUCCESS) {
        // printf("Failed to retrieve domain information. Error: %lu\n", status);
        return FALSE;
    }
    BOOL isInDomain = FALSE;
    if (pDomainInfo->MachineRole == DsRole_RoleMemberWorkstation ||
        pDomainInfo->MachineRole == DsRole_RoleMemberServer ||
        pDomainInfo->MachineRole == DsRole_RoleBackupDomainController ||
        pDomainInfo->MachineRole == DsRole_RolePrimaryDomainController) {
        isInDomain = TRUE;
    }
    // printf("Machine Role: %u\n", pDomainInfo->MachineRole);
    DsRoleFreeMemory(pDomainInfo);
    return isInDomain;
}

BOOL IsInsideVM() {
    HKEY hKey;
    TCHAR szManufacturer[256], szModel[256];
    DWORD dwSize;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Control\\SystemInformation"), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        dwSize = sizeof(szManufacturer);
        if (RegQueryValueEx(hKey, TEXT("SystemManufacturer"), NULL, NULL, (LPBYTE)szManufacturer, &dwSize) == ERROR_SUCCESS) {
            ToLowerCase(szManufacturer);
        } else {
            // printf("Failed to read SystemManufacturer value. Error: %d\n", GetLastError());
            RegCloseKey(hKey);
            return FALSE;
        }
        dwSize = sizeof(szModel);
        if (RegQueryValueEx(hKey, TEXT("SystemProductName"), NULL, NULL, (LPBYTE)szModel, &dwSize) == ERROR_SUCCESS) {
            ToLowerCase(szModel);
        } else {
            // printf("Failed to read SystemProductName value. Error: %d\n", GetLastError());
            RegCloseKey(hKey);
            return 0;
        }
        RegCloseKey(hKey);
        if (strstr(szManufacturer, "vmware") != NULL || strstr(szModel, "vmware") != NULL) {
            return TRUE;
        }
        if (strstr(szManufacturer, "virtualbox") != NULL || strstr(szModel, "virtualbox") != NULL) {
            return TRUE;
        }
        if (strstr(szManufacturer, "xen") != NULL || strstr(szModel, "xen") != NULL) {
            return TRUE;
        }
        if (strstr(szManufacturer, "microsoft") != NULL && strstr(szModel, "hyperv") != NULL) {
            return TRUE;
        }
        return FALSE;
    } else {
        // printf("Failed to read registry key. Error: %d\n", GetLastError());
        return FALSE;
    }
}

BOOL memoryCheck() {
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&statex)) {
        if (statex.ullTotalPhys < 4LL * 1024 * 1024 * 1024) {
            return TRUE;
        } else {
            return FALSE;
        }
    } else {
        // printf("Failed to get memory status. Error: %ld\n", GetLastError());
        return TRUE;
    }
}

BOOL screenResolution() {
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    // printf("Screen Resolution: %d x %d\n", width, height);
    if (width < 1024 || height < 768)
        return TRUE;
    else
        return FALSE;
}

BOOL detectUserInactivity(DWORD thresholdMs) {
    LASTINPUTINFO lii = {0};
    lii.cbSize = sizeof(LASTINPUTINFO);
    if (GetLastInputInfo(&lii)) {
        DWORD currentTime = GetTickCount();
        DWORD idleTime = currentTime - lii.dwTime;
        return idleTime > thresholdMs;
    }
    return TRUE; 
}

BOOL sandboxCheck() {
    DWORD inactivityThreshold = 10000;
    if (IsMachineInDomain()) {
        return FALSE;
    }
    else {
        if (IsInsideVM() || screenResolution() || memoryCheck()) {
            return TRUE;
        }
        else if (detectUserInactivity(inactivityThreshold)) {
            return TRUE;
        }
        else {
            return FALSE;
        }
    }
}