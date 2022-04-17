#pragma once
#include <fltKernel.h>
#include <ntimage.h>
#include "CommonSetting.h"

#define ALIGN_SIZE(size, alignment) (((size) + (alignment - 1)) & ~((alignment - 1)))

extern NTSYSAPI PVOID NTAPI RtlImageDirectoryEntryToData(
	IN	PVOID			Base,
	IN	BOOLEAN			MappedAsImage,
	IN	USHORT			DirectoryEntry,
	OUT PULONG			Size
);
PVOID LoadLibrary(PCWSTR FileFullPath, PVOID ModuleBase);
PVOID LoadLibraryInternal(PUCHAR VirtualAddress, PVOID ModuleBase);
VOID FixImportTable(IN PVOID VirtualAddress);
PVOID FindExportedRoutineByName(IN PVOID ModuleBase, IN PANSI_STRING FunctionName);
VOID FixBaseRelocTable(IN PVOID VirtualAddress, IN PVOID ModuleBase);
NTSTATUS GetKernelModuleInfo(PCHAR ModuleName, PVOID ModuleBase, SIZE_T* ModuleSize);
