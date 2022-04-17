#pragma once
#include <fltKernel.h>
#include <wdm.h>
#include <ntddk.h>
#include "CommonSetting.h"

typedef NTSTATUS(NTAPI* LPFN_TERMINATEPROCESS)(IN HANDLE ProcessHandle, IN NTSTATUS ExitStatus);

typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE
{
	PVOID  				ServiceTableBase;
	PVOID  				ServiceCounterTableBase;
	ULONG_PTR			NumberOfServices;
	PVOID  				ParameterTableBase;
}SYSTEM_SERVICE_DESCRIPTOR_TABLE, * PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

typedef struct _SYSTEM_MODULE_ENTRY
{
	UINT32				Unknow0[2];
	PVOID				ModuleBase;
	UINT32				ModuleSize;
	UINT32				Flags;
	UINT64				Unknow1;
	CHAR				ModuleName[256];
}SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG				NumberOfModules;
	SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,                         // 0x00 SYSTEM_BASIC_INFORMATION
	SystemProcessorInformation,                     // 0x01 SYSTEM_PROCESSOR_INFORMATION
	SystemPerformanceInformation,                   // 0x02
	SystemTimeOfDayInformation,                     // 0x03
	SystemPathInformation,                          // 0x04
	SystemProcessInformation,                       // 0x05 SYSTEM_PROCESS_INFORMATION
	SystemCallCountInformation,                     // 0x06
	SystemDeviceInformation,                        // 0x07
	SystemProcessorPerformanceInformation,          // 0x08
	SystemFlagsInformation,                         // 0x09
	SystemCallTimeInformation,                      // 0x0A
	SystemModuleInformation,                        // 0x0B SYSTEM_MODULE_INFORMATION
	SystemLocksInformation,                         // 0x0C
	SystemStackTraceInformation,                    // 0x0D
	SystemPagedPoolInformation,                     // 0x0E
	SystemNonPagedPoolInformation,                  // 0x0F
	SystemHandleInformation,                        // 0x10 SYSTEM_HANDLE_INFORMATION
	SystemObjectInformation,                        // 0x11 SYSTEM_OBJECT_INFORMATION
	SystemPageFileInformation,                      // 0x12
	SystemVdmInstemulInformation,                   // 0x13
	SystemVdmBopInformation,                        // 0x14
	SystemFileCacheInformation,                     // 0x15
	SystemPoolTagInformation,                       // 0x16
	SystemInterruptInformation,                     // 0x17
	SystemDpcBehaviorInformation,                   // 0x18
	SystemFullMemoryInformation,                    // 0x19
	SystemLoadGdiDriverInformation,                 // 0x1A
	SystemUnloadGdiDriverInformation,               // 0x1B
	SystemTimeAdjustmentInformation,                // 0x1C
	SystemSummaryMemoryInformation,                 // 0x1D
	SystemMirrorMemoryInformation,                  // 0x1E
	SystemPerformanceTraceInformation,              // 0x1F
	SystemObsolete0,                                // 0x20
	SystemExceptionInformation,                     // 0x21
	SystemCrashDumpStateInformation,                // 0x22
	SystemKernelDebuggerInformation,                // 0x23
	SystemContextSwitchInformation,                 // 0x24
	SystemRegistryQuotaInformation,                 // 0x25
	SystemExtendServiceTableInformation,            // 0x26
	SystemPrioritySeperation,                       // 0x27
	SystemPlugPlayBusInformation,                   // 0x28
	SystemDockInformation,                          // 0x29
	SystemPowerInformationNative,                   // 0x2A
	SystemProcessorSpeedInformation,                // 0x2B
	SystemCurrentTimeZoneInformation,               // 0x2C
	SystemLookasideInformation,                     // 0x2D
	SystemTimeSlipNotification,                     // 0x2E
	SystemSessionCreate,                            // 0x2F
	SystemSessionDetach,                            // 0x30
	SystemSessionInformation,                       // 0x31
	SystemRangeStartInformation,                    // 0x32
	SystemVerifierInformation,                      // 0x33
	SystemAddVerifier,                              // 0x34
	SystemSessionProcessesInformation,              // 0x35
	SystemLoadGdiDriverInSystemSpaceInformation,    // 0x36
	SystemNumaProcessorMap,                         // 0x37
	SystemPrefetcherInformation,                    // 0x38
	SystemExtendedProcessInformation,               // 0x39
	SystemRecommendedSharedDataAlignment,           // 0x3A
	SystemComPlusPackage,                           // 0x3B
	SystemNumaAvailableMemory,                      // 0x3C
	SystemProcessorPowerInformation,                // 0x3D
	SystemEmulationBasicInformation,                // 0x3E
	SystemEmulationProcessorInformation,            // 0x3F
	SystemExtendedHanfleInformation,                // 0x40
	SystemLostDelayedWriteInformation,              // 0x41
	SystemBigPoolInformation,                       // 0x42
	SystemSessionPoolTagInformation,                // 0x43
	SystemSessionMappedViewInformation,             // 0x44
	SystemHotpatchInformation,                      // 0x45
	SystemObjectSecurityMode,                       // 0x46
	SystemWatchDogTimerHandler,                     // 0x47
	SystemWatchDogTimerInformation,                 // 0x48
	SystemLogicalProcessorInformation,              // 0x49
	SystemWo64SharedInformationObosolete,           // 0x4A
	SystemRegisterFirmwareTableInformationHandler,  // 0x4B
	SystemFirmwareTableInformation,                 // 0x4C
	SystemModuleInformationEx,                      // 0x4D
	SystemVerifierTriageInformation,                // 0x4E
	SystemSuperfetchInformation,                    // 0x4F
	SystemMemoryListInformation,                    // 0x50
	SystemFileCacheInformationEx,                   // 0x51
	SystemThreadPriorityClientIdInformation,        // 0x52
	SystemProcessorIdleCycleTimeInformation,        // 0x53
	SystemVerifierCancellationInformation,          // 0x54
	SystemProcessorPowerInformationEx,              // 0x55
	SystemRefTraceInformation,                      // 0x56
	SystemSpecialPoolInformation,                   // 0x57
	SystemProcessIdInformation,                     // 0x58
	SystemErrorPortInformation,                     // 0x59
	SystemBootEnvironmentInformation,               // 0x5A SYSTEM_BOOT_ENVIRONMENT_INFORMATION
	SystemHypervisorInformation,                    // 0x5B
	SystemVerifierInformationEx,                    // 0x5C
	SystemTimeZoneInformation,                      // 0x5D
	SystemImageFileExecutionOptionsInformation,     // 0x5E
	SystemCoverageInformation,                      // 0x5F
	SystemPrefetchPathInformation,                  // 0x60
	SystemVerifierFaultsInformation,                // 0x61
	MaxSystemInfoClass                              // 0x67

} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

#define WPOFF() \
		_asm{cli}\
		_asm{mov eax, cr0}\
		_asm{and eax, ~0x10000}\
		_asm{mov cr0, eax}

#define WPON() \
		_asm{mov eax, cr0}\
		_asm{or eax, 0x10000}\
		_asm{mov cr0, eax}\
		_asm{sti}

typedef NTSTATUS(NTAPI* LPFN_TERMINATEPROCESS)(IN HANDLE ProcessHandle, IN NTSTATUS ExitStatus);

extern NTSTATUS ZwQuerySystemInformation(
	IN	ULONG		SystemInformationClass,
	IN	PVOID		SystemInformation,
	IN	ULONG		SystemInformationLength,
	OUT PULONG		ReturnLength
);
//extern NTSTATUS GetKernelModuleInfo(PCHAR ModuleName, PVOID ModuleBase, SIZE_T* ModuleSize);
UCHAR* PsGetProcessImageFileName(PEPROCESS EProcess);
NTSTATUS NTAPI FakeNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);
PVOID CreateFakeKiServiceTable(IN PVOID VirtualAddress, IN PVOID ModuleBase);
int FindKey(PUCHAR KeyVaule, ULONG KeyLength, PUCHAR VirtualAddress, ULONG ViewSize);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);

VOID HookKiFastCall();
VOID UnhookKiFastCall();
VOID HookKiFastCallInternal(ULONG CurrentAddress, ULONG TargetAddress);
VOID UnhookKiFastCallInternal(PUCHAR CodeData, ULONG CodeLength, PVOID CurrentAddress);
ULONG __stdcall FackFunction(ULONG ServiceTableBase, ULONG FunctionService, ULONG FunctionAddress);