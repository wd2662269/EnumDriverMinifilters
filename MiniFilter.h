#include <fltkernel.h>
 

LONG lOperationsOffset = 0;
PVOID   FilterAddr = 0;

extern "C" PVOID NTAPI RtlPcToFileHeader(
	_In_  PVOID PcValue,
	_Out_ PVOID* BaseOfImage
);


extern "C" DECLSPEC_IMPORT PERESOURCE PsLoadedModuleResource;
extern "C" DECLSPEC_IMPORT PLIST_ENTRY PsLoadedModuleList;

#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (PCHAR)(address) - \
                                                  (ULONG_PTR)(&((type *)0)->field)));
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, KLDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

PKLDR_DATA_TABLE_ENTRY GetKernelModuleForAddress(PVOID Address)
{
	for (PLIST_ENTRY Entry = PsLoadedModuleList; Entry != PsLoadedModuleList->Blink; Entry = Entry->Flink)
	{
		PLDR_DATA_TABLE_ENTRY DataTableEntry = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if ((ULONG_PTR)Address > (ULONG_PTR)DataTableEntry->DllBase &&
			(ULONG_PTR)Address < (ULONG_PTR)DataTableEntry->DllBase + DataTableEntry->SizeOfImage)
		{
			return DataTableEntry;
		}
	}
	return NULL;
}

 
static inline BOOLEAN GetKernelModuleRangeByName(PCWSTR moduleName, PVOID* outBase, PVOID* outEnd)
{
	if (!moduleName || !outBase || !outEnd) return FALSE;
	*outBase = nullptr;
	*outEnd = nullptr;

	 
	for (PLIST_ENTRY entry = PsLoadedModuleList->Flink;
		entry && entry != PsLoadedModuleList;
		entry = entry->Flink)
	{
		PLDR_DATA_TABLE_ENTRY dte =
			CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (!MmIsAddressValid(dte)) continue;

		 
		if (MmIsAddressValid(dte->BaseDllName.Buffer) && dte->BaseDllName.Length)
		{
			UNICODE_STRING target{};
			RtlInitUnicodeString(&target, moduleName);
			if (RtlEqualUnicodeString(&dte->BaseDllName, &target, TRUE))
			{
				*outBase = dte->DllBase;
				*outEnd = (PVOID)((ULONG_PTR)dte->DllBase + dte->SizeOfImage);
				return TRUE;
			}
		}

		 
		if (MmIsAddressValid(dte->FullDllName.Buffer) && dte->FullDllName.Length)
		{
			UNICODE_STRING target{};
			RtlInitUnicodeString(&target, moduleName);
			if (RtlEqualUnicodeString(&dte->FullDllName, &target, TRUE))
			{
				*outBase = dte->DllBase;
				*outEnd = (PVOID)((ULONG_PTR)dte->DllBase + dte->SizeOfImage);
				return TRUE;
			}
		}
	}

	 
	if (*outBase == nullptr)
	{
		 
		WCHAR full1[260] = { 0 };
		NTSTATUS st = RtlStringCchPrintfW(full1, ARRAYSIZE(full1), L"\\SystemRoot\\System32\\drivers\\%ws", moduleName);
		if (NT_SUCCESS(st))
		{
			for (PLIST_ENTRY entry = PsLoadedModuleList->Flink;
				entry && entry != PsLoadedModuleList;
				entry = entry->Flink)
			{
				PLDR_DATA_TABLE_ENTRY dte =
					CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				if (!MmIsAddressValid(dte)) continue;

				if (MmIsAddressValid(dte->FullDllName.Buffer) && dte->FullDllName.Length)
				{
					UNICODE_STRING target{};
					RtlInitUnicodeString(&target, full1);
					if (RtlEqualUnicodeString(&dte->FullDllName, &target, TRUE))
					{
						*outBase = dte->DllBase;
						*outEnd = (PVOID)((ULONG_PTR)dte->DllBase + dte->SizeOfImage);
						return TRUE;
					}
				}
			}
		}
	}

	return FALSE;
}


 
#ifndef PT_VERBOSE_MINIFLT
#define PT_VERBOSE_MINIFLT 1
#endif

 
static inline BOOLEAN IsValidMajor(UCHAR mj) {
    return mj <= 0x1B;  
}

BOOLEAN FindOperationsOffsetForFileInfo(PVOID FileInfoImageBase, ULONG FileInfoImageSize)
{
	if (!FileInfoImageBase || !FileInfoImageSize) {
		DbgPrint("[PT][FO] 参数无效 FileInfoImageBase=0x%p Size=0x%X\n", FileInfoImageBase, FileInfoImageSize);
		return FALSE;
	}

	NTSTATUS status;
	ULONG filterCount = 0;
	PFLT_FILTER* filterArray = nullptr;

	// 预枚举数量
	FltEnumerateFilters(nullptr, 0, &filterCount);
	if (filterCount == 0) {
		DbgPrint("[PT][FO] 枚举过滤器数量为 0\n");
		return FALSE;
	}

	filterArray = (PFLT_FILTER*)ExAllocatePoolWithTag(NonPagedPoolNx, filterCount * sizeof(PFLT_FILTER), 'foFF');
	if (!filterArray) {
		DbgPrint("[PT][FO] 分配过滤器数组失败 size=%zu\n", filterCount * sizeof(PFLT_FILTER));
		return FALSE;
	}

	status = FltEnumerateFilters(filterArray, filterCount, &filterCount);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[PT][FO] FltEnumerateFilters 失败 status=0x%X\n", status);
		ExFreePoolWithTag(filterArray, 'foFF');
		return FALSE;
	}

#if PT_VERBOSE_MINIFLT
	DbgPrint("[PT][FO] 成功枚举过滤器数量=%lu, sizeof(FLT_OPERATION_REGISTRATION)=0x%X\n",
		filterCount, (ULONG)sizeof(FLT_OPERATION_REGISTRATION));
#endif

	 
	const LONG kStart = 0x100;
	const LONG kEnd = 0x300;
	const LONG kStep = 8;                  
	const int  kNeedConfirmFilters = 1;   
	const int  kMinEntries = 6;            
	const int  kMaxEntries = 64;           
	const int  kMinPrologHit = 8;         // 至少命中这么多来自 FileInfo.sys 的回调

	int confirmedFilters = 0;
	LONG foundOffset = 0;

	for (LONG off = kStart; off <= kEnd && !foundOffset; off += kStep)
	{
		confirmedFilters = 0;

#if PT_VERBOSE_MINIFLT
		DbgPrint("[PT][FO] 尝试偏移 off=0x%X\n", off);
#endif

		for (ULONG i = 0; i < filterCount; i++)
		{
			PFLT_FILTER f = filterArray[i];
			if (!MmIsAddressValid(f)) {
#if PT_VERBOSE_MINIFLT
				DbgPrint("[PT][FO] 过滤器[%lu] 指针无效 f=0x%p\n", i, f);
#endif
				continue;
			}

			PVOID pOpsPtr = *(PVOID*)((PUCHAR)f + off);
			if (!pOpsPtr || !MmIsAddressValid(pOpsPtr)) {
#if PT_VERBOSE_MINIFLT
				DbgPrint("[PT][FO] 过滤器[%lu] 偏移处疑似操作表指针无效 pOpsPtr=0x%p\n", i, pOpsPtr);
#endif
				continue;
			}

			PFLT_OPERATION_REGISTRATION pCur = (PFLT_OPERATION_REGISTRATION)pOpsPtr;

#if PT_VERBOSE_MINIFLT
			DbgPrint("[PT][FO] 过滤器[%lu] 检查候选操作表地址=0x%p\n", i, pCur);
#endif

			int entryCount = 0;
			int prologHit = 0;
			int inImageCount = 0;
			int invalidStreak = 0;
			const int kMaxInvalidStreak = 3;
			BOOLEAN terminatorReached = FALSE;

			while (MmIsAddressValid(pCur) &&
				entryCount < kMaxEntries)
			{
				UCHAR mj = pCur->MajorFunction;

				if (mj > 0x2F) {
					 
#if PT_VERBOSE_MINIFLT
					DbgPrint("[PT][FO] 过滤器[%lu] mj=0x%X 超范围，停止扫描\n", i, mj);
#endif
					break;
				}
				if (mj == IRP_MJ_OPERATION_END) {
					terminatorReached = TRUE;
					entryCount++;
					break;
				}

				 
				BOOLEAN thisInImage = FALSE;
				BOOLEAN hasCallback = FALSE;

				if (pCur->PreOperation && MmIsAddressValid(pCur->PreOperation)) {
					hasCallback = TRUE;
					PVOID basePre = nullptr;
					if (RtlPcToFileHeader(pCur->PreOperation, &basePre) && basePre == FileInfoImageBase) {
						thisInImage = TRUE;
						UCHAR b0 = *(volatile UCHAR*)pCur->PreOperation;
						if (b0 == 0x40 || b0 == 0x48 || b0 == 0x4C || b0 == 0xF0) prologHit++;
					}
				}
				if (pCur->PostOperation && MmIsAddressValid(pCur->PostOperation)) {
					hasCallback = TRUE;
					PVOID basePost = nullptr;
					if (RtlPcToFileHeader(pCur->PostOperation, &basePost) && basePost == FileInfoImageBase) {
						thisInImage = TRUE;
					}
				}
				if (thisInImage) {
					inImageCount++;
					invalidStreak = 0;
				} else {
					 
					if (!IsValidMajor(mj) || !hasCallback) {
						invalidStreak++;
					} else {
						 
						invalidStreak++;
					}
					if (invalidStreak >= kMaxInvalidStreak) {
#if PT_VERBOSE_MINIFLT
						DbgPrint("[PT][FO] 过滤器[%lu] 连续非候选条目达到 %d，停止扫描\n", i, invalidStreak);
#endif
						break;
					}
				}

				entryCount++;
				pCur = (PFLT_OPERATION_REGISTRATION)((PUCHAR)pCur + sizeof(FLT_OPERATION_REGISTRATION));
			}

#if PT_VERBOSE_MINIFLT
			DbgPrint("[PT][FO] 过滤器[%lu] 结果 entryCount=%d inImage=%d prologHit=%d terminator=%d\n",
				i, entryCount, inImageCount, prologHit, terminatorReached);
#endif

			 
			if (entryCount >= kMinEntries &&
				(inImageCount >= kMinPrologHit || prologHit >= kMinPrologHit))
			{
				confirmedFilters++;

#if PT_VERBOSE_MINIFLT
				 
				DbgPrint("[PT][FO] 过滤器[%lu] 命中候选 off=0x%X，预览所有条目数量： \n", i, off);
				PFLT_OPERATION_REGISTRATION pDump = (PFLT_OPERATION_REGISTRATION)pOpsPtr;
				int streak = 0;
				for (int k = 0; 100 && MmIsAddressValid(pDump); k++) {
					UCHAR mj = pDump->MajorFunction;
					if (mj > 0x2F) {
						DbgPrint("  停止：mj=0x%02X 超范围\n", mj);
						break;
					}
					if (mj == IRP_MJ_OPERATION_END) {
						DbgPrint("  [%2d] mj=END\n", k);
						break;
					}

					PVOID pre = pDump->PreOperation;
					PVOID post = pDump->PostOperation;

					PVOID basePre = nullptr, basePost = nullptr;
					BOOLEAN preInImg = FALSE, postInImg = FALSE;

					if (pre && MmIsAddressValid(pre)) {
						PVOID outBase = nullptr;
						PVOID retBase = RtlPcToFileHeader(pre, &outBase);
						basePre = retBase ? retBase : outBase;
						preInImg = (basePre == FileInfoImageBase);
					}
					if (post && MmIsAddressValid(post)) {
						PVOID outBase = nullptr;
						PVOID retBase = RtlPcToFileHeader(post, &outBase);
						basePost = retBase ? retBase : outBase;
						postInImg = (basePost == FileInfoImageBase);
					}

					DbgPrint("  [%2d] mj=0x%02X pre=0x%p post=0x%p preInImg=%d postInImg=%d\n",
							 k, mj, pre, post, preInImg, postInImg);

					BOOLEAN hasCb = (pre && MmIsAddressValid(pre)) || (post && MmIsAddressValid(post));
					BOOLEAN inImg = (preInImg || postInImg);

					if (!IsValidMajor(mj) || !hasCb || !inImg) {
						streak++;
						if (streak >= kMaxInvalidStreak) {
							DbgPrint("  连续非候选条目达到 %d，停止预览\n", streak);
							break;
						}
					} else {
						streak = 0;
					}

					pDump = (PFLT_OPERATION_REGISTRATION)((PUCHAR)pDump + sizeof(FLT_OPERATION_REGISTRATION));
				}
#endif
				if (confirmedFilters >= kNeedConfirmFilters) {
					foundOffset = off;
					break;
				}
			}
		}

#if PT_VERBOSE_MINIFLT
		if (!foundOffset) {
			DbgPrint("[PT][FO] 偏移 0x%X 未通过验证 confirmedFilters=%d\n", off, confirmedFilters);
		}
#endif
	}

	for (ULONG i = 0; i < filterCount; i++) {
		if (filterArray[i]) FltObjectDereference(filterArray[i]);
	}
	ExFreePoolWithTag(filterArray, 'foFF');

	if (foundOffset) {
		lOperationsOffset = foundOffset;
		DbgPrint("[PT] lOperationsOffset found: 0x%X\n", lOperationsOffset);
		return TRUE;
	}

	DbgPrint("[PT] lOperationsOffset not found. 尝试范围 0x%X - 0x%X step=%d（阈值已放宽仍未命中）\n", kStart, kEnd, kStep);
	return FALSE;
}
 
BOOLEAN InitMiniFilter()
{
	PVOID fileInfoBase = nullptr;
	PVOID fileInfoEnd = nullptr;
	if (!GetKernelModuleRangeByName(L"FileInfo.sys", &fileInfoBase, &fileInfoEnd))
	{
		DbgPrint("[PT] Get FileInfo.sys range failed.\n");
		return FALSE;
	}
	ULONG fileInfoSize = (ULONG)((ULONG_PTR)fileInfoEnd - (ULONG_PTR)fileInfoBase);
	DbgPrint("[PT] FileInfo.sys base: 0x%llX, size: 0x%X\n", (ULONG64)fileInfoBase, fileInfoSize);
	if (!FindOperationsOffsetForFileInfo(fileInfoBase, fileInfoSize))
	{
		DbgPrint("[PT] FindOperationsOffsetForFileInfo failed.\n");
		return FALSE;
	}
	return TRUE;
}

BOOLEAN EnumerateDriverMinifilters()
{

	PVOID drvModuleBase = nullptr;
	PVOID drvModuleEnd = nullptr;
	if (!GetKernelModuleRangeByName(L"process.sys", &drvModuleBase, &drvModuleEnd))
	{
		return FALSE;
	}
  
	NTSTATUS status = STATUS_SUCCESS;
	ULONG ulFilterListSize = 0;
	PFLT_FILTER* ppFilterList = NULL;
	ULONG i = 0;
	PFLT_OPERATION_REGISTRATION pFltOperationRegistration = NULL;
	FltEnumerateFilters(NULL, 0, &ulFilterListSize);
	ppFilterList = (PFLT_FILTER*)ExAllocatePool(NonPagedPool, ulFilterListSize * sizeof(PFLT_FILTER));
	if (NULL == ppFilterList)
	{
		DbgPrint("[PT] ExAllocatePool Error!\n");
		return FALSE;
	}
	status = FltEnumerateFilters(ppFilterList, ulFilterListSize, &ulFilterListSize);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[PT] FltEnumerateFilters Error![0x%X]\n", status);
		return FALSE;
	}
	DbgPrint("[PT] ulFilterListSize=%d\n", ulFilterListSize);
	if (lOperationsOffset == 0)
	{
		DbgPrint("[PT] GetOperationsOffset Error\n");
		return FALSE;
	}
	 
	for (i = 0; i < ulFilterListSize; i++)
	{
		pFltOperationRegistration = (PFLT_OPERATION_REGISTRATION)(*(PVOID*)((PUCHAR)ppFilterList[i] + lOperationsOffset));
			 
			while (IRP_MJ_OPERATION_END != pFltOperationRegistration->MajorFunction)
			{
				if (MmIsAddressValid(pFltOperationRegistration->PreOperation) && pFltOperationRegistration->PreOperation >= drvModuleBase && pFltOperationRegistration->PreOperation<= drvModuleEnd) 
				{
					FilterAddr = pFltOperationRegistration->PreOperation;
					 
					if (FilterAddr)
						DbgPrint("[PT] BE Filter PreOperation found 0x%llX", FilterAddr);

					FilterAddr = pFltOperationRegistration->PostOperation;
					 
					if(FilterAddr)
						DbgPrint("[PT] BE Filter PostOperation found 0x%llX", FilterAddr);
					
				}
				pFltOperationRegistration = (PFLT_OPERATION_REGISTRATION)((PUCHAR)pFltOperationRegistration + sizeof(FLT_OPERATION_REGISTRATION));
			}
			 
 
		FltObjectDereference(ppFilterList[i]);
	}
	 
	DbgPrint("[PT] BE Filter Done");
 
	ExFreePool(ppFilterList);
	ppFilterList = NULL;
 
	return TRUE;
}

 