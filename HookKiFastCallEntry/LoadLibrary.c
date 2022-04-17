#include "LoadLibrary.h"
#include "HookKiFastCallEntry.h"

PVOID LoadLibrary(PCWSTR FileFullPath, PVOID ModuleBase)
{
	UNICODE_STRING unstFileFullPath;
	RtlInitUnicodeString(&unstFileFullPath, FileFullPath);
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, &unstFileFullPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	HANDLE FileHandle;
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS Status = ZwCreateFile(&FileHandle, FILE_READ_DATA, &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE |FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("���ļ�ʧ��%ws", FileFullPath));
		ZwClose(FileHandle);
		return NULL;
	}

	FILE_STANDARD_INFORMATION FileStandardInfo;
	Status = ZwQueryInformationFile(FileHandle, &IoStatusBlock, &FileStandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("��ѯ�ļ���Ϣʧ��%ws", FileFullPath));
		ZwClose(FileHandle);
		return NULL;
	}

	PVOID Buffer = ExAllocatePool(PagedPool, FileStandardInfo.EndOfFile.LowPart);
	if (NULL == Buffer)
	{
		KdPrint(("�����ļ��ڴ�ʧ��%ws", FileFullPath));
		ZwClose(FileHandle);
		return NULL;
	}

	LARGE_INTEGER ReturnLength;
	Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, Buffer, FileStandardInfo.EndOfFile.LowPart, &ReturnLength, NULL);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("��ȡ�ļ����ڴ�ʧ��%ws", FileFullPath));
		ExFreePool(Buffer);
		ZwClose(FileHandle);
		return NULL;
	}
	ZwClose(FileHandle);

	//�ļ����ȶ���
	PVOID ImageMapBaseAddress = LoadLibraryInternal(Buffer, ModuleBase);
	if (NULL == ImageMapBaseAddress)
	{
		KdPrint(("ӳ���ļ�ʧ��!"));
		ExFreePool(Buffer);
		return NULL;
	}
	ExFreePool(Buffer);

	return ImageMapBaseAddress;
}

PVOID LoadLibraryInternal(PUCHAR VirtualAddress, PVOID ModuleBase)
{
	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)VirtualAddress;   //�ļ����ȶ���
	if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}
	PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)(VirtualAddress + ImageDosHeader->e_lfanew); //exe long file address new exe header
	if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}

	ULONG SectionAligment = ALIGN_SIZE(ImageNtHeaders->OptionalHeader.SizeOfImage, ImageNtHeaders->OptionalHeader.SectionAlignment);

	PVOID Buffer = ExAllocatePool(NonPagedPool, SectionAligment);
	if (NULL == Buffer)
	{
		return NULL;
	}
	RtlZeroMemory(Buffer, SectionAligment);
	RtlCopyMemory(Buffer, VirtualAddress, ImageNtHeaders->OptionalHeader.SizeOfHeaders);   //��������ͷ��

	PIMAGE_SECTION_HEADER ImageSectionHeader = (PIMAGE_SECTION_HEADER)((UINT8*)ImageNtHeaders + sizeof(ImageNtHeaders->Signature) + sizeof(ImageNtHeaders->FileHeader) + ImageNtHeaders->FileHeader.SizeOfOptionalHeader);

	for (int i = 0; i < ImageNtHeaders->FileHeader.NumberOfSections; i++)
	{
		RtlCopyMemory((PULONG)((ULONG)Buffer + ImageSectionHeader[i].VirtualAddress), VirtualAddress + ImageSectionHeader[i].PointerToRawData, ImageSectionHeader[i].Misc.VirtualSize);
	}
	KdPrint(("FakeModuleBase:%08X, FakeModuleSize:%08X  MoudleBase:%08X", Buffer, SectionAligment, ModuleBase));
	FixImportTable(Buffer);
	FixBaseRelocTable(Buffer, ModuleBase);
	return Buffer;
}

VOID FixImportTable(IN PVOID VirtualAddress)
{
	ULONG ViewSize;
	PIMAGE_IMPORT_DESCRIPTOR ImpageImportDescriptor = RtlImageDirectoryEntryToData(VirtualAddress, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ViewSize);
	while (ImpageImportDescriptor->OriginalFirstThunk && ImpageImportDescriptor->Name)
	{
		PVOID  ModuleBase = NULL;
		SIZE_T ModuleSize = 0;

		NTSTATUS status = GetKernelModuleInfo((PCHAR)VirtualAddress + ImpageImportDescriptor->Name, ModuleBase, &ModuleSize);   //Ntos.exe
		if (ModuleBase == NULL && !NT_SUCCESS(status))
		{
			KdPrint(("û�ҵ�ģ��!"));
			break;
		}

		PIMAGE_THUNK_DATA OriginalFirstThunk = (PIMAGE_THUNK_DATA)((ULONG)VirtualAddress + ImpageImportDescriptor->OriginalFirstThunk); //Function Odinal AddressOfData(IMAGE_IMPORT_BY_NAME)
		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((ULONG)VirtualAddress + ImpageImportDescriptor->FirstThunk);
		while (OriginalFirstThunk->u1.Ordinal)
		{
			PIMAGE_IMPORT_BY_NAME ImageImportByName = (PIMAGE_IMPORT_BY_NAME)((PUCHAR)VirtualAddress + OriginalFirstThunk->u1.AddressOfData);
			//��ŵ���
			if (IMAGE_SNAP_BY_ORDINAL32(OriginalFirstThunk->u1.Ordinal))
			{
				//�ں���ò��û����ŵ�����
				KdPrint(("�������:%d", ImageImportByName->Hint));
			}
			else
			{
				//Ntos.exe  �����  FirstThunk       Hal.dll  ModuleBase  �������л�ȡ������ַ
				ANSI_STRING NameStr;
				RtlInitAnsiString(&NameStr, ImageImportByName->Name);
				FirstThunk->u1.Function = (ULONG)FindExportedRoutineByName(ModuleBase, &NameStr);       //GetProcAddress [][][]
			}
			OriginalFirstThunk++;
			FirstThunk++;
		}
		ImpageImportDescriptor++;
	}
	KdPrint(("Fix Import Ok!!"));
}

PVOID FindExportedRoutineByName(IN PVOID ModuleBase, IN PANSI_STRING FunctionName)
{
	ULONG ExportLength;
	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(ModuleBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &ExportLength);
	if (ImageExportDirectory == NULL) {
		return NULL;
	}

	PULONG AddressOfNames = (PULONG)((PCHAR)ModuleBase + (ULONG)ImageExportDirectory->AddressOfNames);
	PULONG AddressOfNameOrdinals = (PULONG)((PCHAR)ModuleBase + (ULONG)ImageExportDirectory->AddressOfNameOrdinals);

	ULONG NamesSize = ImageExportDirectory->NumberOfNames - 1;
	ULONG Low = 0, Middle = 0, High = NamesSize;

	while (High >= Low) 
	{
		Middle = (Low + High) >> 1;
		int Result = strcmp(FunctionName->Buffer, (PCHAR)ModuleBase + AddressOfNames[Middle]);
		if (Result < 0) 
		{
			High = Middle - 1;
		}
		else if (Result > 0) 
		{
			Low = Middle + 1;
		}
		else 
		{
			break;
		}
	}
	if (High < Low) {
		return NULL;
	}
	ULONG Index = AddressOfNameOrdinals[Middle];

	if ((ULONG)Index >= ImageExportDirectory->NumberOfFunctions) {
		return NULL;
	}
	PULONG FunctionArray = (PULONG)((PCHAR)ModuleBase + (ULONG)ImageExportDirectory->AddressOfFunctions);

	return (PVOID)((PCHAR)ModuleBase + FunctionArray[Index]);
}

VOID FixBaseRelocTable(IN PVOID VirtualAddress, IN PVOID ModuleBase)
{
	ULONG ViewSize;
	PIMAGE_BASE_RELOCATION ImageBaseRelocation = RtlImageDirectoryEntryToData(VirtualAddress, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &ViewSize);
	if (NULL == ImageBaseRelocation)
	{
		KdPrint(("û�ҵ��ض����!"));
		return;
	}
	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)VirtualAddress;
	PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)(ImageDosHeader->e_lfanew + (UINT8*)VirtualAddress);
	do
	{
		ULONG ItemCount = (ImageBaseRelocation->SizeOfBlock - 8) / 2; //-8 ����Ϊ ��ȥ4�ֽڵ�ҳ����ʼ��ַ 4�ֽڵı�ҳ���ض�λ���� һ����ַ���ֽڣ�16bit��
		for (ULONG i = 0; i < ItemCount; i++)
		{
			USHORT TypeOffset = ((PUSHORT)((ULONG)ImageBaseRelocation + 8))[i];
			if (TypeOffset >> 12 == IMAGE_REL_BASED_HIGHLOW) //����λ����
			{
				ULONG RelocationAddress = ImageBaseRelocation->VirtualAddress + (TypeOffset & 0x0FFF) + (ULONG)VirtualAddress;
				if (ModuleBase == NULL)
				{
					*(PULONG)RelocationAddress = *(PULONG)RelocationAddress + (ULONG)VirtualAddress - ImageNtHeaders->OptionalHeader.ImageBase;
				}
				else
				{
					*(PULONG)RelocationAddress = *(PULONG)RelocationAddress + (ULONG)ModuleBase - ImageNtHeaders->OptionalHeader.ImageBase;
				}
			}
		}
		ImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG)ImageBaseRelocation + ImageBaseRelocation->SizeOfBlock);

	} while (ImageBaseRelocation->VirtualAddress);  //��һ��VirtualAddress������0

	KdPrint(("�ض�����޸����!"));
}

NTSTATUS GetKernelModuleInfo(PCHAR ModuleName, PVOID ModuleBase, SIZE_T* ModuleSize)
{
	ULONG ReturnLength;
	NTSTATUS Status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &ReturnLength);  //SSDT
	if (Status != STATUS_INFO_LENGTH_MISMATCH)              //û���ڴ�
	{
		return Status;
	}

	PVOID Buffer = ExAllocatePool(PagedPool, ReturnLength);   //PagedPool(���ݶ� �û�������)  NonPagedPool(����� ���û�������)
	if (Buffer == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	Status = ZwQuerySystemInformation(SystemModuleInformation, Buffer, ReturnLength, &ReturnLength);
	if (!NT_SUCCESS(Status))
	{
		ExFreePool(Buffer);
		return Status;
	}

	for (SIZE_T i = 0; i < ((PSYSTEM_MODULE_INFORMATION)Buffer)->NumberOfModules; i++)
	{
		if (strstr(((PSYSTEM_MODULE_INFORMATION)Buffer)->Modules[i].ModuleName, ModuleName) != NULL)  //Ntoskernel.exe   
		{
			ModuleBase = ((PSYSTEM_MODULE_INFORMATION)Buffer)->Modules[i].ModuleBase;
			*ModuleSize = ((PSYSTEM_MODULE_INFORMATION)Buffer)->Modules[i].ModuleSize;
			if (Buffer != NULL)
			{
				ExFreePool(Buffer);
				Buffer = NULL;
			}
			return STATUS_SUCCESS;
		}
	}
	if (Buffer != NULL)
	{
		ExFreePool(Buffer);
		Buffer = NULL;
	}

	return Status;
}
