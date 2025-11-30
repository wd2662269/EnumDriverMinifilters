/*
 * Driver.c
 * 
 * Main driver entry point for EnumerateDriverMinifilters
 * This minifilter driver automatically finds OperationsOffset from FileInfo.sys
 * Compatible with Windows 10 to Windows 11 25H2
 */

#include "EnumerateDriverMinifilters.h"

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

// Global filter handle
PFLT_FILTER g_FilterHandle = NULL;

// FLT_OPERATION_REGISTRATION - Define the operations we care about
const FLT_OPERATION_REGISTRATION g_OperationRegistration[] = {
    { IRP_MJ_CREATE,
      0,
      NULL,  // PreOperation
      NULL   // PostOperation
    },
    { IRP_MJ_OPERATION_END }
};

// FLT_REGISTRATION - Filter registration structure
const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),           // Size
    FLT_REGISTRATION_VERSION,           // Version
    0,                                  // Flags
    NULL,                               // Context registration
    g_OperationRegistration,            // Operation callbacks
    DriverUnload,                       // FilterUnload
    NULL,                               // InstanceSetup
    NULL,                               // InstanceQueryTeardown
    NULL,                               // InstanceTeardownStart
    NULL,                               // InstanceTeardownComplete
    NULL,                               // GenerateFileName
    NULL,                               // NormalizeNameComponent
    NULL                                // NormalizeContextCleanup
#if FLT_MGR_LONGHORN
    , NULL                              // TransactionNotification (Vista+)
    , NULL                              // NormalizeNameComponentEx (Vista+)
#endif
#if FLT_MGR_WIN8
    , NULL                              // SectionNotification (Win8+)
#endif
};

// Filter unload callback
NTSTATUS DriverUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    
    DbgPrint("[EnumerateMinifilters] Driver unloading...\n");
    
    if (g_FilterHandle != NULL) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }
    
    return STATUS_SUCCESS;
}

// Driver entry point
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    ULONG operationsOffset = 0;
    
    UNREFERENCED_PARAMETER(RegistryPath);
    
    DbgPrint("[EnumerateMinifilters] Driver loading...\n");
    DbgPrint("[EnumerateMinifilters] Build: %s %s\n", __DATE__, __TIME__);
    
    // Log Windows version information
    DbgPrint("[EnumerateMinifilters] Windows Build: %lu\n", GetWindowsBuildNumber());
    DbgPrint("[EnumerateMinifilters] Is Windows 10 or later: %s\n", 
             IsWindows10OrLater() ? "Yes" : "No");
    DbgPrint("[EnumerateMinifilters] Is Windows 11: %s\n", 
             IsWindows11() ? "Yes" : "No");
    
    // Auto-find Operations offset from FileInfo.sys
    status = AutoFindOperationsOffsetFromFileInfo(&operationsOffset);
    if (NT_SUCCESS(status)) {
        DbgPrint("[EnumerateMinifilters] Auto-detected OperationsOffset: 0x%X\n", 
                 operationsOffset);
    } else {
        DbgPrint("[EnumerateMinifilters] Failed to auto-detect OperationsOffset: 0x%X\n", 
                 status);
    }
    
    // Register the minifilter
    status = FltRegisterFilter(
        DriverObject,
        &g_FilterRegistration,
        &g_FilterHandle
    );
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EnumerateMinifilters] FltRegisterFilter failed: 0x%X\n", status);
        return status;
    }
    
    // Enumerate all loaded minifilters
    status = EnumerateMinifilters();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EnumerateMinifilters] EnumerateMinifilters failed: 0x%X\n", status);
        // Continue anyway, enumeration is not critical for driver operation
    }
    
    // Start filtering
    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EnumerateMinifilters] FltStartFiltering failed: 0x%X\n", status);
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        return status;
    }
    
    DbgPrint("[EnumerateMinifilters] Driver loaded successfully\n");
    
    return STATUS_SUCCESS;
}
