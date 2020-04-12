#include "MmUnloadedDriversh.h"
#pragma warning(disable:4700)

#define IMAGE_SCN_CNT_CODE 0x00000020
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000
#define IMAGE_NT_SIGNATURE 0x00004550
#define IMAGE_DOS_SIGNATURE 0x5A4D // MZ

#define STANDARD_RIGHTS_ALL 0x001F0000L


//Allocate buffer for name of shared memory

PACL Dacl = NULL;

SECURITY_DESCRIPTOR SecDescriptor;


HANDLE sectionHandle;
PVOID SharedSection = NULL;


DWORD WriteSignature[2] = { 0x2a92, 0x139a };
DWORD ReadSignature[2] = { 0x2a92, 0x139b };


DWORD localPlayer = 0x10F4F4;
DWORD healthOffset = 0xF8;
DWORD64 entAddress;
DWORD64 OFFSET_ENTITYLIST = 0x1898f38;
DWORD64 OFFSET_GLOW_ENABLE		=	0x390;
DWORD64 OFFSET_GLOW_CONTEXT		=	0x310;
DWORD64 OFFSET_GLOW_RANGE		=	0x2FC;
DWORD64 OFFSET_GLOW_FADE		=	0x2B8;
DWORD64 OFFSET_GLOW_COLORS		=	0x1D0;
DWORD64 OFFSET_GLOW_MAGIC		=	0x278;


struct RWProcessMemory
{
	DWORD Signature[2];
	DWORD processPID;
	DWORD64 Address;
	DWORD64 SourceAddress;
	float myFloat[10];
	DWORD64 extra[16];
};

VOID driverUnload(IN PDRIVER_OBJECT pDriverObject) {

	DbgPrint("Driver Unloading routine called! \n");

	if (SharedSection)
		ZwUnmapViewOfSection(NtCurrentProcess(), SharedSection);

	if (sectionHandle)
		ZwClose(sectionHandle);

}

ULONG KernelSize;

PVOID getKernelBase(OUT PULONG pSize)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG Bytes = 0;
	PRTL_PROCESS_MODULES arrayOfModules;
	PVOID routinePtr = NULL; /*RoutinePtr points to a

	routine and checks if it is in Ntoskrnl*/

	UNICODE_STRING routineName;

	if (KernelBase != NULL)
	{
		if (pSize)
			*pSize = KernelSize;
		return KernelBase;
	}

	RtlUnicodeStringInit(&routineName, L"NtOpenFile");
	routinePtr = MmGetSystemRoutineAddress(&routineName); //get address of NtOpenFile


	if (routinePtr == NULL)
	{
		return NULL;
	}
	else
	{

		DbgPrint("MmGetSystemRoutineAddress inside getkernelbase succeed\n");
	}


	//get size of system module information
	Status = ZwQuerySystemInformation(SystemModuleInformation, 0, Bytes, &Bytes);
	if (Bytes == 0)
	{
		DbgPrint("%s: Invalid SystemModuleInformation size\n");
		return NULL;
	}


	arrayOfModules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, Bytes, 0x454E4F45); //array of loaded kernel modules
	RtlZeroMemory(arrayOfModules, Bytes); //clean memory


	Status = ZwQuerySystemInformation(SystemModuleInformation, arrayOfModules, Bytes, &Bytes);
	if (NT_SUCCESS(Status))
	{
		DbgPrint("ZwQuerySystemInformation inside getkernelbase succeed\n");
		PRTL_PROCESS_MODULE_INFORMATION pMod = arrayOfModules->Modules;
		for (int i = 0; i < arrayOfModules->NumberOfModules; ++i)
		{

			if (routinePtr >= pMod[i].ImageBase && routinePtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
			{

				KernelBase = pMod[i].ImageBase;
				KernelSize = pMod[i].ImageSize;

				if (pSize)
					*pSize = KernelSize;
				break;
			}
		}
	}
	if (arrayOfModules)
		ExFreePoolWithTag(arrayOfModules, 0x454E4F45); // 'ENON'

	DbgPrint("KernelSize : %i\n", KernelSize);
	DbgPrint("g_KernelBase : %p\n", KernelBase);
	return (PVOID)KernelBase;
}


NTSTATUS BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;

	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}



NTSTATUS BBScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound, PVOID base)
{
	//ASSERT(ppFound != NULL);
	if (ppFound == NULL)
		return STATUS_ACCESS_DENIED; //STATUS_INVALID_PARAMETER

	if (nullptr == base)
		base = getKernelBase(NULL);
	if (base == nullptr)
		return STATUS_ACCESS_DENIED; //STATUS_NOT_FOUND;

	PIMAGE_NT_HEADERS64 pHdr = (PIMAGE_NT_HEADERS64)RtlImageNtHeader(base);
	if (!pHdr)
		return STATUS_ACCESS_DENIED; // STATUS_INVALID_IMAGE_FORMAT;

	//PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)((uintptr_t)&pHdr->FileHeader + pHdr->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
	{
		//DbgPrint("section: %s\r\n", pSection->Name);
		ANSI_STRING s1, s2;
		RtlInitAnsiString(&s1, section);
		RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
		if (RtlCompareString(&s1, &s2, TRUE) == 0)
		{
			PVOID ptr = NULL;
			NTSTATUS status = BBSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
			if (NT_SUCCESS(status)) {
				*(PULONG64)ppFound = (ULONG_PTR)(ptr); //- (PUCHAR)base
				//DbgPrint("found\r\n");
				return status;
			}
			//we continue scanning because there can be multiple sections with the same name.
		}
	}

	return STATUS_ACCESS_DENIED; //STATUS_NOT_FOUND;
}


const char* PiddbCacheTableSig = "";





NTSTATUS CreateSharedMemory()
{
	NTSTATUS Status = STATUS_SUCCESS;
	DbgPrint("reached point 1\n");


	Status = RtlCreateSecurityDescriptor(&SecDescriptor, SECURITY_DESCRIPTOR_REVISION);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("RtlCreateSecurityDescriptor  failed\n");
	}
	DbgPrint("RtlCreateSecurityDescriptor created  success!!: %i\n", Status);




	ULONG DaclLength = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) * 3 + RtlLengthSid(SeExports->SeLocalSystemSid) +
		RtlLengthSid(SeExports->SeAliasAdminsSid) + RtlLengthSid(SeExports->SeWorldSid);


	Dacl = reinterpret_cast<PACL>(ExAllocatePoolWithTag(PagedPool, DaclLength, 'lcaD')); // stem cell proliferation

	if (Dacl == NULL)
	{
		DbgPrint("ExAllocatePoolWithTag failed!!!! %i\n", Status);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	else
	DbgPrint("ExAllocatePoolWithTag  succeed  : %i\n", Status);



	Status = RtlCreateAcl(Dacl, DaclLength, ACL_REVISION);// stem cell differentiation

	if (!NT_SUCCESS(Status))
	{
		ExFreePool(Dacl);
		DbgPrint("RtlCreateAcl Failed: %i\n", Status);
		return Status;
	}
	else
	DbgPrint("RtlCreateAcl  succeed  : %i\n", Status);







	Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, FILE_ALL_ACCESS,
		SeExports->SeAliasAdminsSid);

	if (!NT_SUCCESS(Status)) {
		ExFreePool(Dacl);
		DbgPrint("RtlAddAccessAllowedAce SeAliasAdminsSid failed  !!!: %i\n", Status);
		return Status;
	}
	else
	DbgPrint("RtlAddAccessAllowedAce SeAliasAdminsSid succeed!!!! : %i\n", Status);



	Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, FILE_ALL_ACCESS, SeExports->SeWorldSid);

	if (!NT_SUCCESS(Status)) {
		ExFreePool(Dacl);
		DbgPrint("RtlAddAccessAllowedAce SeWorldSid fail!!!!  : %i\n", Status);
		return Status;
	}
	DbgPrint("RtlAddAccessAllowedAce SeWorldSid succeed!!!  : %i\n", Status);



	Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, FILE_ALL_ACCESS,
		SeExports->SeLocalSystemSid);

	if (!NT_SUCCESS(Status)) {
		ExFreePool(Dacl);
		DbgPrint("RtlAddAccessAllowedAce SeLocalSystemSid failed  : %i\n", Status);
		return Status;
	}

	Status = RtlSetDaclSecurityDescriptor(&SecDescriptor,
		TRUE,
		Dacl,
		FALSE);

	if (!NT_SUCCESS(Status)) {
		ExFreePool(Dacl);
		DbgPrint("RtlSetDaclSecurityDescriptor failed  : %i\n", Status);
		return Status;
	}



	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING sectionName;
	RtlInitUnicodeString(&sectionName, L"\\BaseNamedObjects\\SharedMemory");

	InitializeObjectAttributes(&objAttr, &sectionName,
		OBJ_CASE_INSENSITIVE, NULL, &SecDescriptor); //create attributes



	LARGE_INTEGER lMaxSize = { 0 };
	lMaxSize.HighPart = 0;
	lMaxSize.LowPart = 1024 * 10;

	//actually create the thing
	Status = ZwCreateSection(&sectionHandle,
		SECTION_ALL_ACCESS, &objAttr, &lMaxSize, PAGE_READWRITE, SEC_COMMIT, NULL);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("ZwCreateSection failed: %i\n", Status);
		return Status;
	}

	SIZE_T sectionViewSize = 1024 * 5;

	Status = ZwMapViewOfSection(sectionHandle, NtCurrentProcess(), &SharedSection,
		0, sectionViewSize, NULL, &sectionViewSize, ViewShare, 0, PAGE_READWRITE | PAGE_NOCACHE);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("ZwMapViewOfSection 1 failed!!!\n");
		return Status;
	}


	ExFreePool(Dacl);


	DbgPrint("finished creating shared memory!!!\n");
	return Status;

}






VOID ReadSharedMemory()
{
	if (sectionHandle)
	{
		return; // if there already is a view of section, don't need to map again
	}
	if (SharedSection)
	{
		ZwUnmapViewOfSection(NtCurrentProcess(), SharedSection);
	}
	SIZE_T ViewSize = 1024 * 10;

	NTSTATUS Status = ZwMapViewOfSection(sectionHandle, NtCurrentProcess(),
		&SharedSection, 0, ViewSize, NULL, &ViewSize, ViewShare, 0, PAGE_READWRITE | PAGE_NOCACHE);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("ZwMapViewOfSection 2 fail!!!:  %p\n", Status);
		ZwClose(sectionHandle);
		return;
	}

	return;

}



ULONG64 GetModuleBasex64(PEPROCESS proc, UNICODE_STRING module_name) {
	PPEB pPeb = (PPEB)PsGetProcessPeb(proc); // get Process PEB, function is unexported and undoc

	if (!pPeb) {
		return 0; // failed
	}

	KAPC_STATE state;

	KeStackAttachProcess(proc, &state);

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	if (!pLdr) {
		KeUnstackDetachProcess(&state);
		return 0; // failed
	}

	UNICODE_STRING name;

	// loop the linked list
	for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->ModuleListLoadOrder.Flink;
		list != &pLdr->ModuleListLoadOrder; list = (PLIST_ENTRY)list->Flink) {
		PLDR_DATA_TABLE_ENTRY pEntry =
			CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
		if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) ==
			0) {
			ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
			KeUnstackDetachProcess(&state);
			return baseAddr;
		}
	}

	KeUnstackDetachProcess(&state);

	return 0; // failed
}

DWORD64 BaseAddress;
DWORD ProcessID;
NTSTATUS DispatchHandle()
{

	NTSTATUS Status = STATUS_SUCCESS;
	DbgPrint("waiting for command...\n");
	while (1)
	{
		
		LARGE_INTEGER Timeout;
		Timeout.QuadPart = -20000000;
		KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
		ReadSharedMemory();

		if (strcmp((PCHAR)SharedSection, "Stop") == 0) //if string is equal
		{
			DbgPrint("stopping driver loop\n");
			return Status;
		}


		if ((reinterpret_cast<RWProcessMemory*>(SharedSection)->Signature[0] == 0x2a92) && reinterpret_cast<RWProcessMemory*>(SharedSection)->Signature[1] == 0x1393) // check signature, 13 93 means glow
		{
			DbgPrint("glow Request\n");
			RWProcessMemory* WriteRequest = (RWProcessMemory*)SharedSection;


			PEPROCESS process;
			Status = PsLookupProcessByProcessId((HANDLE)WriteRequest->processPID, &process);
			
			BaseAddress = (DWORD64)PsGetProcessSectionBaseAddress(process);
			UNICODE_STRING ProcessName;
			RtlInitUnicodeString(&ProcessName, L"r5apex.exe");
			BaseAddress = GetModuleBasex64(process, ProcessName);


			//pslookupprocessbyprocessid works

		
			WriteRequest->extra[5] = Status;
			WriteRequest->extra[6] = BaseAddress;					/*	debug messsages		*/
			WriteRequest->extra[7] = WriteRequest->processPID;
			
			if (NT_SUCCESS(Status))
			{
				DbgPrint("PsLookupProcessByProcessId succedd\n");

			}
			else
			{
				DbgPrint("PslookupProcessByProcessId Fail!!\n");
				ObDereferenceObject(process);
				return Status;
			}
			DWORD64 i;
			int type;
			if (WriteRequest->extra[0] == 3) // if type is item only
			{
				i = 60;
				type = 10000;
			}
			else if (WriteRequest->extra[0] == 60) //if the type is player only
			{
				i = 0;
				type = 60;

			}
			else if (WriteRequest->extra[0] == 10000) // if type is player and item
			{
				i = 0;
				type = 10000;
			}
			else
			{
				i = 0;
				type = 10000;
			}
			SIZE_T Bytes;

			

			NTSTATUS Status;



			bool	glowEnable = true;
			DWORD	glowContext = 1;
			DWORD64 Dest;		//destination of memcpy for debugging


			while (i < type)										//Loop through entity list ( I love this code section, it is so neat and easy to read)
			{
				Status = MmCopyVirtualMemory(process, reinterpret_cast<void*>(BaseAddress + OFFSET_ENTITYLIST + (i << 5)), IoGetCurrentProcess(), reinterpret_cast<void*>(&entAddress), sizeof(void*), UserMode, &Bytes);
				//set ntstatus and address, for debugging 0-3 is ntstatus, 4-7 means address
				// + OFFSET_ENTITYLIST + (i << 5);
				WriteRequest->extra[8] = entAddress;
				WriteRequest->extra[9] = Status;
				WriteRequest->extra[10] = BaseAddress + OFFSET_ENTITYLIST + (i << 5);
				Status = MmCopyVirtualMemory(PsGetCurrentProcess(), &glowEnable, process, (DWORD*)(entAddress + OFFSET_GLOW_ENABLE), sizeof(bool), KernelMode, &Bytes);
				Status = MmCopyVirtualMemory(PsGetCurrentProcess(), &glowContext, process, (DWORD*)(entAddress + OFFSET_GLOW_CONTEXT), sizeof(int), KernelMode, &Bytes);

				WriteRequest->extra[11] = entAddress + OFFSET_GLOW_CONTEXT;

				Status = MmCopyVirtualMemory(PsGetCurrentProcess(), &WriteRequest->myFloat[0], process, (DWORD*)(entAddress + OFFSET_GLOW_COLORS), sizeof(DWORD[3]), KernelMode, &Bytes);

				Status = MmCopyVirtualMemory(PsGetCurrentProcess(), &WriteRequest->myFloat[3], process, (DWORD*)(entAddress + OFFSET_GLOW_RANGE), sizeof(DWORD), KernelMode, &Bytes);
			}



				
		}
	}
	return Status;
}




/*VOID glowThread(IN PVOID StartContext)
{
	DbgPrint("2nd thread start!!\n");
	SIZE_T ViewSize = 1024 * 4;
	LARGE_INTEGER ViewOffset = { 0 };
	ViewOffset.HighPart = 0;
	ViewOffset.LowPart = 1024 * 4;


	ZwMapViewOfSection(sectionHandle, NtCurrentProcess(), &SharedSection, 0, ViewSize, &ViewOffset, &ViewSize, ViewUnmap, 0, PAGE_READWRITE | PAGE_NOCACHE);
	
	float r;
	float g;
	float b;

} */





NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS Status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(RegistryPath);

	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -20000000;

	DriverObject->DriverUnload = driverUnload;

	DbgPrint("driver load!!!!\n");

	CreateSharedMemory();

	BOOLEAN status1 = ClearPiddbCacheTable();

	
	KeDelayExecutionThread(KernelMode, FALSE, &Timeout);

	BOOLEAN status2 = cleanUnloadedDriverString();

	if (status1 = FALSE)
	{
		DbgPrint("piddbcachetable fail\n");
	}
	if (status2 == FALSE)
	{
		DbgPrint("mmunloadeddrivers fail\n");
	}
	if (status1 != FALSE && status2 != FALSE)
	{
		DbgPrint("success with piddbcachetable mmunloadeddrivers\n");
	}


/*
	PVOID Threadreference;
	HANDLE glo_thread = 0;
	OBJECT_ATTRIBUTES ThreadObject;
	ThreadObject.Length = 24;
	ThreadObject.RootDirectory = 0;
	ThreadObject.ObjectName = 0;
	ThreadObject.Attributes = 512;
	ThreadObject.SecurityDescriptor = 0;
	ThreadObject.SecurityQualityOfService = 0;


	InitializeObjectAttributes(&ThreadObject, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	Status = PsCreateSystemThread(&glo_thread, (ACCESS_MASK)STANDARD_RIGHTS_ALL, &ThreadObject, 0, 0, (PKSTART_ROUTINE)glowThread, 0);
	

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("pscreatesystemthread failed!!!\n");
	}
	else
	{
		DbgPrint("Pscreatesystemthread succeed!!!\n");
	}

	Status = ObReferenceObjectByHandle(glo_thread, THREAD_ALL_ACCESS, NULL,
		KernelMode, &Threadreference, NULL);*/

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("getting pointer for thread failed!!\n");
	}
	else
	{
		DbgPrint("getting pointer for thread succed!!!\n");
	}

	DispatchHandle();
	DbgPrint("driver load has success!!\n");
	return Status;

}

NTSTATUS Drivera(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	DbgPrint("hello world!!\n");
	return IoCreateDriver(NULL, &DriverEntry);
}