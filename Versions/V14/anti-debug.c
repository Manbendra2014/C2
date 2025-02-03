#include "anti-debug.h"
#include <setjmp.h>
#include <stdio.h>

// Global variable to store debugger detection result
static bool debuggerDetected = false;
static jmp_buf jumpBuffer;

// Custom exception handler
LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS *ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        debuggerDetected = false; // No debugger detected
        longjmp(jumpBuffer, 1);  // Return control to the setjmp location
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

bool IsDebugged()
{
    // Set the unhandled exception filter
    SetUnhandledExceptionFilter(ExceptionHandler);
    if (setjmp(jumpBuffer) == 0)
    {
        // Inline assembly to set the Trap Flag
        asm volatile(
            "pushfq;"                  // Push the RFLAGS register onto the stack
            "orl $0x100, (%%rsp);"     // Set the Trap Flag (TF) in the RFLAGS
            "popfq;"                   // Pop the modified value back into RFLAGS
            "nop;"                     // Execute a harmless instruction to trigger SINGLE_STEP
            :
            :
            : "memory"
        );
        debuggerDetected = true;
    }
    else
    {
        // Exception was caught: no debugger detected
        debuggerDetected = false;
    }
    // Reset the unhandled exception filter
    SetUnhandledExceptionFilter(NULL);
    return debuggerDetected;
}