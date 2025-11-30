# EnumerateDriverMinifilters

Automatically find OperationsOffset from FileInfo.sys minifilter. Compatible with Windows 10 to Windows 11 25H2 (all versions).

## Overview

This Windows kernel-mode minifilter driver automatically detects the `OperationsOffset` in the `FLT_REGISTRATION` structure by scanning the `FileInfo.sys` driver. This provides a universal method to determine the offset without hardcoding version-specific values.

## Features

- **Auto-detection**: Automatically finds the `OperationsOffset` by scanning `FileInfo.sys`
- **Version Compatibility**: Supports Windows 10 (build 10240+) through Windows 11 25H2
- **Fallback Mechanism**: Uses known offsets as fallback if auto-detection fails
- **Minifilter Enumeration**: Lists all registered minifilter drivers

## Technical Details

The driver works by:

1. Locating `FileInfo.sys` in kernel memory using `ZwQuerySystemInformation`
2. Parsing the PE headers to find the `.data` and `.rdata` sections
3. Scanning for valid `FLT_REGISTRATION` structures based on:
   - Size field (typically 0x48-0x60 bytes)
   - Version field (0x0200-0x0203)
   - Valid `OperationRegistration` pointer within driver bounds
4. Extracting the offset of the `OperationRegistration` field

## Building

### Requirements

- Windows Driver Kit (WDK) 10 or later
- Visual Studio 2019/2022 with WDK integration
- Windows SDK

### Build Instructions

1. Open `EnumerateDriverMinifilters.sln` in Visual Studio
2. Select the target configuration (Debug/Release) and platform (x64)
3. Build the solution

Or use the WDK command-line build:

```cmd
msbuild EnumerateDriverMinifilters.vcxproj /p:Configuration=Release /p:Platform=x64
```

## Installation

1. Copy `EnumerateDriverMinifilters.sys` to `%SystemRoot%\System32\drivers`
2. Install using the INF file:

```cmd
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 .\EnumerateDriverMinifilters.inf
```

Or use `sc.exe`:

```cmd
sc create EnumerateDriverMinifilters type= kernel binPath= %SystemRoot%\System32\drivers\EnumerateDriverMinifilters.sys
sc start EnumerateDriverMinifilters
```

## Output

The driver outputs debug messages via `DbgPrint`. View them using:
- WinDbg with kernel debugging enabled
- DebugView from Sysinternals (requires "Capture Kernel" enabled)

Sample output:

```
[EnumerateMinifilters] Driver loading...
[EnumerateMinifilters] Windows Build: 22631
[EnumerateMinifilters] Is Windows 10 or later: Yes
[EnumerateMinifilters] Is Windows 11: Yes
[EnumerateMinifilters] FileInfo.sys found at FFFFF8014A620000, size: 0x16000
[EnumerateMinifilters] Found FLT_REGISTRATION at FFFFF8014A631234
[EnumerateMinifilters] Size: 0x58, Version: 0x0203
[EnumerateMinifilters] OperationsOffset: 0x30
[EnumerateMinifilters] Successfully found OperationsOffset: 0x30
```

## Supported Windows Versions

| Version | Build | Status |
|---------|-------|--------|
| Windows 10 1507 | 10240 | ✓ Supported |
| Windows 10 1511 | 10586 | ✓ Supported |
| Windows 10 1607 | 14393 | ✓ Supported |
| Windows 10 1703 | 15063 | ✓ Supported |
| Windows 10 1709 | 16299 | ✓ Supported |
| Windows 10 1803 | 17134 | ✓ Supported |
| Windows 10 1809 | 17763 | ✓ Supported |
| Windows 10 1903 | 18362 | ✓ Supported |
| Windows 10 1909 | 18363 | ✓ Supported |
| Windows 10 2004 | 19041 | ✓ Supported |
| Windows 10 20H2 | 19042 | ✓ Supported |
| Windows 10 21H1 | 19043 | ✓ Supported |
| Windows 10 21H2 | 19044 | ✓ Supported |
| Windows 10 22H2 | 19045 | ✓ Supported |
| Windows 11 21H2 | 22000 | ✓ Supported |
| Windows 11 22H2 | 22621 | ✓ Supported |
| Windows 11 23H2 | 22631 | ✓ Supported |
| Windows 11 24H2 | 26100 | ✓ Supported |
| Windows 11 25H2 | 26xxx | ✓ Supported |

## License

This project is provided for educational and research purposes.

## Disclaimer

This driver modifies kernel-mode behavior and should only be used in test environments. Use at your own risk.
