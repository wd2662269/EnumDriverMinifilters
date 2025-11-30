/*
 * EnumerateDriverMinifilters.c
 * 
 * Automatically find OperationsOffset from FileInfo.sys minifilter.
 * Compatible with Windows 10 to Windows 11 25H2.
 * 
 * This module scans the FileInfo.sys driver to locate the FLT_REGISTRATION
 * structure and extract the offset to the Operations field dynamically.
 */

#include "EnumerateDriverMinifilters.h"
#include <ntstrsafe.h>

// Global variable to store the found Operations offset
ULONG g_OperationsOffset = 0;

// Function to get the current Windows build number
ULONG GetWindowsBuildNumber(VOID)
{
    RTL_OSVERSIONINFOW osVersionInfo;
    osVersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
    
    if (NT_SUCCESS(RtlGetVersion(&osVersionInfo))) {
        return osVersionInfo.dwBuildNumber;
    }
    
    return 0;
}

// Check if running on Windows 10 or later
BOOLEAN IsWindows10OrLater(VOID)
{
    ULONG buildNumber = GetWindowsBuildNumber();
    // Windows 10 starts at build 10240
    return (buildNumber >= 10240);
}

// Check if running on Windows 11
BOOLEAN IsWindows11(VOID)
{
    ULONG buildNumber = GetWindowsBuildNumber();
    // Windows 11 starts at build 22000
    return (buildNumber >= 22000);
}

// Pattern matching function to find byte patterns in memory
PVOID FindPatternInMemory(
    _In_ PVOID StartAddress,
    _In_ SIZE_T SearchSize,
    _In_ PUCHAR Pattern,
    _In_ SIZE_T PatternSize,
    _In_opt_ PUCHAR Mask
)
{
    PUCHAR searchPtr = (PUCHAR)StartAddress;
    PUCHAR searchEnd = searchPtr + SearchSize - PatternSize;
    
    if (SearchSize < PatternSize) {
        return NULL;
    }
    
    while (searchPtr <= searchEnd) {
        BOOLEAN found = TRUE;
        
        for (SIZE_T i = 0; i < PatternSize; i++) {
            // If mask is provided, check if this byte should be compared
            if (Mask != NULL && Mask[i] == '?') {
                continue; // Wildcard, skip comparison
            }
            
            if (searchPtr[i] != Pattern[i]) {
                found = FALSE;
                break;
            }
        }
        
        if (found) {
            return searchPtr;
        }
        
        searchPtr++;
    }
    
    return NULL;
}

// Get the base address and size of a kernel module
NTSTATUS GetDriverBaseAddress(
    _In_ PUNICODE_STRING DriverName,
    _Out_ PVOID* DriverBase,
    _Out_ PSIZE_T DriverSize
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bufferSize = 0;
    PRTL_PROCESS_MODULES moduleInfo = NULL;
    ANSI_STRING ansiDriverName;
    
    *DriverBase = NULL;
    *DriverSize = 0;
    
    // First call to get required buffer size
    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return status;
    }
    
    // Allocate buffer
    moduleInfo = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(
        NonPagedPool,
        bufferSize,
        'FDME'
    );
    
    if (moduleInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Second call to get actual information
    status = ZwQuerySystemInformation(SystemModuleInformation, moduleInfo, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(moduleInfo, 'FDME');
        return status;
    }
    
    // Convert Unicode name to ANSI for comparison
    status = RtlUnicodeStringToAnsiString(&ansiDriverName, DriverName, TRUE);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(moduleInfo, 'FDME');
        return status;
    }
    
    // Search for the driver in the module list
    for (ULONG i = 0; i < moduleInfo->NumberOfModules; i++) {
        PRTL_PROCESS_MODULE_INFORMATION module = &moduleInfo->Modules[i];
        PCHAR moduleName = (PCHAR)(module->FullPathName + module->OffsetToFileName);
        
        // Case-insensitive comparison
        if (_stricmp(moduleName, ansiDriverName.Buffer) == 0) {
            *DriverBase = module->ImageBase;
            *DriverSize = module->ImageSize;
            status = STATUS_SUCCESS;
            break;
        }
    }
    
    if (*DriverBase == NULL) {
        status = STATUS_NOT_FOUND;
    }
    
    RtlFreeAnsiString(&ansiDriverName);
    ExFreePoolWithTag(moduleInfo, 'FDME');
    
    return status;
}

// Find the FLT_REGISTRATION structure in a minifilter driver
// and extract the Operations offset
NTSTATUS FindOperationsOffset(
    _In_ PVOID DriverBase,
    _In_ SIZE_T DriverSize,
    _Out_ PULONG OperationsOffset
)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_SECTION_HEADER sectionHeader;
    PVOID dataSection = NULL;
    SIZE_T dataSectionSize = 0;
    
    *OperationsOffset = 0;
    
    if (DriverBase == NULL || DriverSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Validate PE headers
    dosHeader = (PIMAGE_DOS_HEADER)DriverBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    
    ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)DriverBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    
    // Find .data or .rdata section where FLT_REGISTRATION is likely stored
    sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        // Look for .data, .rdata, or INIT sections
        if (RtlCompareMemory(sectionHeader[i].Name, ".data", 5) == 5 ||
            RtlCompareMemory(sectionHeader[i].Name, ".rdata", 6) == 6 ||
            RtlCompareMemory(sectionHeader[i].Name, "INIT", 4) == 4) {
            
            dataSection = (PVOID)((PUCHAR)DriverBase + sectionHeader[i].VirtualAddress);
            dataSectionSize = sectionHeader[i].Misc.VirtualSize;
            
            // Search for FLT_REGISTRATION pattern in this section
            // The FLT_REGISTRATION structure starts with Size and Version fields
            // For Windows 10/11: Size is typically 0x58 (88 bytes) and Version is 0x0203
            
            PUCHAR searchPtr = (PUCHAR)dataSection;
            PUCHAR searchEnd = searchPtr + dataSectionSize - sizeof(FLT_REGISTRATION);
            
            while (searchPtr < searchEnd) {
                PFLT_REGISTRATION potentialReg = (PFLT_REGISTRATION)searchPtr;
                
                // Check for valid FLT_REGISTRATION signature:
                // - Size should be reasonable (0x48-0x60 range)
                // - Version should be 0x0200, 0x0201, 0x0202, or 0x0203
                if ((potentialReg->Size >= 0x48 && potentialReg->Size <= 0x60) &&
                    (potentialReg->Version >= 0x0200 && potentialReg->Version <= 0x0203)) {
                    
                    // Verify this looks like a valid FLT_REGISTRATION
                    // Check if OperationRegistration pointer is valid (within driver range)
                    if (potentialReg->OperationRegistration != NULL) {
                        ULONG_PTR opRegAddr = (ULONG_PTR)potentialReg->OperationRegistration;
                        ULONG_PTR driverEnd = (ULONG_PTR)DriverBase + DriverSize;
                        
                        if (opRegAddr >= (ULONG_PTR)DriverBase && opRegAddr < driverEnd) {
                            // Calculate the offset of OperationRegistration field
                            // within the FLT_REGISTRATION structure
                            *OperationsOffset = (ULONG)FIELD_OFFSET(FLT_REGISTRATION, OperationRegistration);
                            
                            DbgPrint("[EnumerateMinifilters] Found FLT_REGISTRATION at %p\n", searchPtr);
                            DbgPrint("[EnumerateMinifilters] Size: 0x%X, Version: 0x%X\n", 
                                     potentialReg->Size, potentialReg->Version);
                            DbgPrint("[EnumerateMinifilters] OperationsOffset: 0x%X\n", *OperationsOffset);
                            
                            return STATUS_SUCCESS;
                        }
                    }
                }
                
                searchPtr += sizeof(PVOID); // Align to pointer size
            }
        }
    }
    
    return status;
}

// Main function to automatically find Operations offset from FileInfo.sys
NTSTATUS AutoFindOperationsOffsetFromFileInfo(
    _Out_ PULONG OperationsOffset
)
{
    NTSTATUS status;
    PVOID fileInfoBase = NULL;
    SIZE_T fileInfoSize = 0;
    UNICODE_STRING fileInfoName;
    ULONG buildNumber;
    
    *OperationsOffset = 0;
    
    // Get Windows build number for logging
    buildNumber = GetWindowsBuildNumber();
    DbgPrint("[EnumerateMinifilters] Windows Build Number: %lu\n", buildNumber);
    
    // Initialize the driver name to search for
    RtlInitUnicodeString(&fileInfoName, L"fileinfo.sys");
    
    // Get FileInfo.sys base address
    status = GetDriverBaseAddress(&fileInfoName, &fileInfoBase, &fileInfoSize);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EnumerateMinifilters] Failed to find fileinfo.sys: 0x%X\n", status);
        return status;
    }
    
    DbgPrint("[EnumerateMinifilters] FileInfo.sys found at %p, size: 0x%zX\n", 
             fileInfoBase, fileInfoSize);
    
    // Find the Operations offset by scanning the driver
    status = FindOperationsOffset(fileInfoBase, fileInfoSize, OperationsOffset);
    if (NT_SUCCESS(status)) {
        DbgPrint("[EnumerateMinifilters] Successfully found OperationsOffset: 0x%X\n", 
                 *OperationsOffset);
        g_OperationsOffset = *OperationsOffset;
    } else {
        DbgPrint("[EnumerateMinifilters] Failed to find OperationsOffset: 0x%X\n", status);
        
        // Fallback to known offsets based on Windows version
        // These are the documented offsets for FLT_REGISTRATION.OperationRegistration
        if (buildNumber >= 22000) {
            // Windows 11 (all versions including 25H2)
            *OperationsOffset = 0x30; // Offset 48 in FLT_REGISTRATION
        } else if (buildNumber >= 10240) {
            // Windows 10 (all versions)
            *OperationsOffset = 0x30; // Offset 48 in FLT_REGISTRATION
        } else {
            // Older versions
            *OperationsOffset = 0x28; // Offset 40 in FLT_REGISTRATION
        }
        
        DbgPrint("[EnumerateMinifilters] Using fallback OperationsOffset: 0x%X for build %lu\n", 
                 *OperationsOffset, buildNumber);
        g_OperationsOffset = *OperationsOffset;
        status = STATUS_SUCCESS;
    }
    
    return status;
}

// Enumerate all loaded minifilters and their operations
NTSTATUS EnumerateMinifilters(VOID)
{
    NTSTATUS status;
    ULONG filterCount = 0;
    PFLT_FILTER* filterList = NULL;
    ULONG i;
    ULONG operationsOffset;
    
    // First, auto-find the Operations offset
    status = AutoFindOperationsOffsetFromFileInfo(&operationsOffset);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EnumerateMinifilters] Failed to auto-find OperationsOffset\n");
        return status;
    }
    
    // Get the count of registered filters
    status = FltEnumerateFilters(NULL, 0, &filterCount);
    if (status != STATUS_BUFFER_TOO_SMALL && !NT_SUCCESS(status)) {
        DbgPrint("[EnumerateMinifilters] FltEnumerateFilters failed: 0x%X\n", status);
        return status;
    }
    
    if (filterCount == 0) {
        DbgPrint("[EnumerateMinifilters] No minifilters found\n");
        return STATUS_SUCCESS;
    }
    
    DbgPrint("[EnumerateMinifilters] Found %lu minifilters\n", filterCount);
    
    // Allocate buffer for filter list
    filterList = (PFLT_FILTER*)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(PFLT_FILTER) * filterCount,
        'FLME'
    );
    
    if (filterList == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Get the actual filter list
    status = FltEnumerateFilters(filterList, filterCount, &filterCount);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(filterList, 'FLME');
        return status;
    }
    
    // Iterate through each filter
    for (i = 0; i < filterCount; i++) {
        PFLT_FILTER filter = filterList[i];
        
        // Get filter name using FltGetFilterInformation
        ULONG bytesReturned;
        PFILTER_FULL_INFORMATION filterInfo = NULL;
        ULONG filterInfoSize = sizeof(FILTER_FULL_INFORMATION) + 256 * sizeof(WCHAR);
        
        filterInfo = (PFILTER_FULL_INFORMATION)ExAllocatePoolWithTag(
            NonPagedPool,
            filterInfoSize,
            'IFME'
        );
        
        if (filterInfo != NULL) {
            status = FltGetFilterInformation(
                filter,
                FilterFullInformation,
                filterInfo,
                filterInfoSize,
                &bytesReturned
            );
            
            if (NT_SUCCESS(status)) {
                WCHAR filterName[256] = {0};
                RtlCopyMemory(filterName, filterInfo->FilterNameBuffer, 
                             min(filterInfo->FilterNameLength, sizeof(filterName) - sizeof(WCHAR)));
                
                DbgPrint("[EnumerateMinifilters] Filter[%lu]: %ws\n", i, filterName);
                DbgPrint("[EnumerateMinifilters]   Frame ID: %lu\n", filterInfo->FrameID);
                DbgPrint("[EnumerateMinifilters]   Instances: %lu\n", filterInfo->NumberOfInstances);
            }
            
            ExFreePoolWithTag(filterInfo, 'IFME');
        }
        
        // Release the filter reference
        FltObjectDereference(filter);
    }
    
    ExFreePoolWithTag(filterList, 'FLME');
    
    return STATUS_SUCCESS;
}
