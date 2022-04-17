#include "HookKiFastCallEntry.h"
#include "LoadLibrary.h"

PVOID						__ModuleBase;
SIZE_T						__ModuleSize;
ULONG						__FakeModuleBase;
ULONG						__HookKiFastCallEntry = 0;
LPFN_TERMINATEPROCESS		__OringinalNtTerminateProcess;

SYSTEM_SERVICE_DESCRIPTOR_TABLE			__FakeKeServiceDescriptorTable;
PSYSTEM_SERVICE_DESCRIPTOR_TABLE		KeServiceDescriptorTable;

ULONG __stdcall FackFunction(ULONG ServiceTableBase, ULONG FunctionService, ULONG FunctionAddress)
{
	if (ServiceTableBase == (ULONG)KeServiceDescriptorTable->ServiceTableBase)
	{
		return ((PULONG)(__FakeKeServiceDescriptorTable.ServiceTableBase))[FunctionService];      //Overload SSDT
	}
	return FunctionAddress;   //eax
}

VOID __declspec(naked) FakeKiFastCallEntry()
{
	__asm
	{
		pushad      //PUSHAD指令压入32位寄存器，其入栈顺序是:EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI
		pushfd
		push  edx
		push  eax
		push  edi
		call  FackFunction

		mov[esp + 0x18], eax
		popfd
		popad

		sub     esp, ecx
		shr     ecx, 2
		jmp __HookKiFastCallEntry
	}
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath)
{
	NTSTATUS Status = STATUS_SUCCESS;
	char  ModuleName[] = "ntoskrnl.exe";

	DriverObject->DriverUnload = DriverUnload;

	if (NT_SUCCESS(GetKernelModuleInfo(ModuleName, __ModuleBase, &__ModuleSize)))    //获得系统第一模块的基本信息
	{
		if (NULL != __ModuleBase)
		{
			__FakeModuleBase = LoadLibrary(L"\\SystemRoot\\System32\\ntoskrnl.exe", __ModuleBase);          //关闭PAE Page Address Extension
		}
	}
	else 
	{
		if (NT_SUCCESS(GetKernelModuleInfo((PUCHAR)"ntkrnlpa.exe", __ModuleBase, &__ModuleSize)))    //获得系统第一模块的基本信息
		{
			__FakeModuleBase = LoadLibrary(L"\\SystemRoot\\System32\\ntkrnlpa.exe", __ModuleBase);        //开启PAE
		}
	}

	if (__FakeModuleBase != NULL && __ModuleBase != NULL)
	{
		CreateFakeKiServiceTable((PVOID)__FakeModuleBase, __ModuleBase);
		HookKiFastCall();
	}

	return Status;
}

VOID HookKiFastCall()
{
	LONG KiFastCallEntry;
	_asm
	{
		mov ecx, 0x176
		rdmsr
		mov KiFastCallEntry, eax 
	}
	KdPrint(("KiFastCallEntry:%08X", KiFastCallEntry));
	__HookKiFastCallEntry = FindKey("\x2B\xE1\xC1\xE9\x02\x8B\xFC", 7, (PCHAR)KiFastCallEntry, 1000);   //硬编码搜索
	if (0 == __HookKiFastCallEntry)
		return;

	KdPrint(("Hook 位置%08X", __HookKiFastCallEntry));
	HookKiFastCallInternal(__HookKiFastCallEntry, (ULONG)(FakeKiFastCallEntry));
	__HookKiFastCallEntry += 5;
}

VOID UnhookKiFastCall()
{
	if (__HookKiFastCallEntry == 0)
	{
		return;
	}
	UnhookKiFastCallInternal((PUCHAR)"\x2B\xE1\xC1\xE9\x02\x8B\xFC", 7, (PVOID)(__HookKiFastCallEntry - 5));

	if (__FakeModuleBase != NULL)
	{
		ExFreePool((PVOID)__FakeModuleBase);
		__FakeModuleBase = NULL;
	}
}

VOID HookKiFastCallInternal(ULONG CurrentAddress, ULONG TargetAddress)
{
	WPOFF();
	*(PUCHAR)CurrentAddress = 0xE9;
	*(PULONG)(CurrentAddress + 1) = TargetAddress - CurrentAddress - 5;
	WPON();
}

VOID UnhookKiFastCallInternal(PUCHAR CodeData, ULONG CodeLength, PVOID CurrentAddress)
{
	WPOFF();
	memcpy(CurrentAddress, CodeData, CodeLength);
	WPON();
}

NTSTATUS FakeNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
	PEPROCESS EProcess;
	NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, KernelMode, &EProcess, NULL); //通过句柄获取对象
	if (NT_SUCCESS(Status))
	{
		ObDereferenceObject(EProcess);

	}
	return __OringinalNtTerminateProcess(ProcessHandle, ExitStatus);
}

PVOID CreateFakeKiServiceTable(IN PVOID VirtualAddress, IN PVOID ModuleBase)
{
	ULONG ViewSize;
	PIMAGE_BASE_RELOCATION ImageBaseRelocation = RtlImageDirectoryEntryToData(VirtualAddress, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &ViewSize);
	if (NULL == ImageBaseRelocation)
	{
		return NULL;
	}
	do
	{
		ULONG ItemCount = (ImageBaseRelocation->SizeOfBlock - 8) / 2;
		for (ULONG i = 0; i < ItemCount; i++)
		{
			ULONG TypeOffset = ((PULONG)((ULONG)ImageBaseRelocation + 8))[i]; //
			if (TypeOffset >> 12 == IMAGE_REL_BASED_HIGHLOW)
			{
				PULONG TempAddress = ImageBaseRelocation->VirtualAddress + (TypeOffset & 0x0FFF) + (ULONG)VirtualAddress;
				if (*TempAddress == (ULONG)(KeServiceDescriptorTable))
				{
					// mov ds:_KeServiceDescriptorTable, offset _KiServiceTable
					if (*(PUSHORT)(TempAddress - 2) == 0x05C7)
					{
						PULONG FakeServiceTableBase = (PULONG)(*(PULONG)(TempAddress + 4) - (ULONG)ModuleBase + (ULONG)VirtualAddress);
						for (ULONG j = 0; j < KeServiceDescriptorTable->NumberOfServices; j++)
						{
							FakeServiceTableBase[j] =  (ULONG)(((PULONG)(KeServiceDescriptorTable->ServiceTableBase))[j]) - (ULONG)ModuleBase + (ULONG)VirtualAddress;
							if (j == 370)
							{
								__OringinalNtTerminateProcess = FakeServiceTableBase[j];
								FakeServiceTableBase[j] = (ULONG32)FakeNtTerminateProcess;
							}
							else if (0)    //加强处理
							{
							}
							else if (0)
							{
							}
							else if (0)
							{
							}

						}
						__FakeKeServiceDescriptorTable.ServiceTableBase = FakeServiceTableBase;
						__FakeKeServiceDescriptorTable.ServiceCounterTableBase = KeServiceDescriptorTable->ServiceCounterTableBase;
						__FakeKeServiceDescriptorTable.NumberOfServices = KeServiceDescriptorTable->NumberOfServices;
						__FakeKeServiceDescriptorTable.ParameterTableBase = KeServiceDescriptorTable->ParameterTableBase;
						return NULL;
					}
				}
			}
		}
		ImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG)ImageBaseRelocation + ImageBaseRelocation->SizeOfBlock);
	} while (ImageBaseRelocation->VirtualAddress);
	return NULL;
}

int FindKey(PUCHAR KeyVaule, ULONG KeyLength, PUCHAR VirtualAddress, ULONG ViewSize)
{
	if (ViewSize <= 0)
		return -1;

	UCHAR TempArray[0x100];
	memset(TempArray, KeyLength + 1, 0x100);
	for (ULONG i = 0; i < KeyLength; i++)
	{
		TempArray[KeyVaule[i]] = (UCHAR)(KeyLength - i);
	}

	PUCHAR Travel = VirtualAddress;
	while (Travel + KeyLength <= VirtualAddress + ViewSize)
	{
		UCHAR* m = KeyVaule, * n = Travel;
		ULONG i;
		for (i = 0; i < KeyLength; i++)
		{
			if (m[i] != n[i])
				break;
		}
		if (i == KeyLength)
			return (ULONG)Travel;
		if (Travel + KeyLength == VirtualAddress + ViewSize)
			return -1;
		Travel += TempArray[Travel[KeyLength]];
	}
	return -1;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UnhookKiFastCall();
}

