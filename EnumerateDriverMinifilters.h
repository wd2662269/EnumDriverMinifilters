#ifndef _ENUMERATE_DRIVER_MINIFILTERS_H_
#define _ENUMERATE_DRIVER_MINIFILTERS_H_

#include <ntifs.h>
#include <fltKernel.h>
#include <windef.h>

// Structures for Minifilter internal enumeration
// These structures are reverse-engineered and may vary by Windows version

#pragma pack(push, 1)

// FLT_FILTER internal structure
typedef struct _FLT_FILTER_INTERNAL {
    ULONG Flags;
    ULONG FrameID;
    PFLT_FILTER FilterLink;
    UNICODE_STRING Name;
    PUNICODE_STRING DefaultAltitude;
    // ... more fields depending on Windows version
} FLT_FILTER_INTERNAL, *PFLT_FILTER_INTERNAL;

// FLT_OPERATION_REGISTRATION structure
typedef struct _FLT_OPERATION_REGISTRATION_INTERNAL {
    UCHAR MajorFunction;
    FLT_OPERATION_REGISTRATION_FLAGS Flags;
    PFLT_PRE_OPERATION_CALLBACK PreOperation;
    PFLT_POST_OPERATION_CALLBACK PostOperation;
    PVOID Reserved1;
} FLT_OPERATION_REGISTRATION_INTERNAL, *PFLT_OPERATION_REGISTRATION_INTERNAL;

#pragma pack(pop)

// Function prototypes
NTSTATUS FindOperationsOffset(
    _In_ PVOID DriverBase,
    _In_ SIZE_T DriverSize,
    _Out_ PULONG OperationsOffset
);

NTSTATUS GetDriverBaseAddress(
    _In_ PUNICODE_STRING DriverName,
    _Out_ PVOID* DriverBase,
    _Out_ PSIZE_T DriverSize
);

NTSTATUS EnumerateMinifilters(VOID);

NTSTATUS AutoFindOperationsOffsetFromFileInfo(
    _Out_ PULONG OperationsOffset
);

// Pattern matching for finding Operations field offset
PVOID FindPatternInMemory(
    _In_ PVOID StartAddress,
    _In_ SIZE_T SearchSize,
    _In_ PUCHAR Pattern,
    _In_ SIZE_T PatternSize,
    _In_ PUCHAR Mask
);

// Version detection
BOOLEAN IsWindows10OrLater(VOID);
BOOLEAN IsWindows11(VOID);
ULONG GetWindowsBuildNumber(VOID);

#endif // _ENUMERATE_DRIVER_MINIFILTERS_H_
