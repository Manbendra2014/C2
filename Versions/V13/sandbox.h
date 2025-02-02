#ifndef SANDBOX_H    // Include guard to prevent double inclusion
#define SANDBOX_H

#include <windows.h>
#include <dsrole.h>
#include <stdio.h>

void ToLowerCase(TCHAR *str);

BOOL IsMachineInDomain();
BOOL IsInsideVM();
BOOL memoryCheck();
BOOL screenResolution();
BOOL detectUserInactivity(DWORD thresholdMs);
BOOL sandboxCheck();

#endif // SANDBOX_H