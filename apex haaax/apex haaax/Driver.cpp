#include "MmUnloadedDriversh.h"
#pragma warning(disable:4700)

#define IMAGE_SCN_CNT_CODE 0x00000020
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000

//Allocate buffer for name of shared memory

PACL Dacl = NULL;

SECURITY_DESCRIPTOR SecDescriptor;


HANDLE sectionHandle;
PVOID	pSharedSection = NULL;
PVOID	pSectionObj = NULL;
PVOID SharedSection = NULL;


DWORD WriteSignature[2] = { 0x2a92, 0x139a };
DWORD ReadSignature[2] = { 0x2a92, 0x139b };


DWORD localPlayer = 0x10F4F4;
DWORD healthOffset = 0xF8;




struct RWProcessMemory
{
	DWORD Signature[2];
	DWORD processPID;
	DWORD Address;
	DWORD SourceAddress;
	float aimbotAngle[3];
};



VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("Driver unload \n");
}





PVOID KernelBase;
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
		DbgPrint("KernelSize : %i\n", KernelSize);
		DbgPrintEx(0, 0, "g_KernelBase : %p\n", KernelBase);
	}
	if (arrayOfModules)
		ExFreePoolWithTag(arrayOfModules, 0x454E4F45); // 'ENON'

	return (PVOID)KernelSize;
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



NTSTATUS ScanSection(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound)
{
	ASSERT(ppFound != NULL);
	if (ppFound == NULL)
		return STATUS_INVALID_PARAMETER;

	PVOID base = getKernelBase(NULL);
	if (!base)
		return STATUS_NOT_FOUND;


	PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
	if (!pHdr)
		return STATUS_INVALID_IMAGE_FORMAT;

	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
	{

		if ((pSection->Characteristics & IMAGE_SCN_CNT_CODE) && (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) || !(pSection->Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
		{
			PVOID ptr = NULL;
			NTSTATUS status = BBSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
			if (NT_SUCCESS(status))
				*(PULONG)ppFound = (ULONG)((PUCHAR)ptr - (PUCHAR)base);

			return status;
		}
	}

	return STATUS_NOT_FOUND;
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

	SIZE_T sectionViewSize = 1024 * 10;

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
	SIZE_T ulViewSize = 1024 * 10;

	NTSTATUS Status = ZwMapViewOfSection(sectionHandle, NtCurrentProcess(),
		&SharedSection, 0, ulViewSize, NULL, &ulViewSize, ViewShare, 0, PAGE_READWRITE | PAGE_NOCACHE);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("ZwMapViewOfSection 2 fail!!!:  %p\n", Status);
		ZwClose(sectionHandle);
		return;
	}

	return;

}


DWORD BaseAddress;
DWORD ProcessID;
NTSTATUS DriverLoop()
{

	NTSTATUS Status = STATUS_SUCCESS;
	DbgPrint("waiting for command...\n");
	while (1)
	{
		
		LARGE_INTEGER Timeout;
		Timeout.QuadPart = -10000000;
		KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
		ReadSharedMemory();
		if (strcmp((PCHAR)SharedSection, "Stop") == 0) //if string is equal
		{
			DbgPrint("stopping health write loop\n");
		}

		if ((reinterpret_cast<RWProcessMemory*>(SharedSection)->Signature[0] == 0x2a92) && reinterpret_cast<RWProcessMemory*>(SharedSection)->Signature[1] == 0x139a) //check fake "IOCTL", 139a means health
		{
			DbgPrint("Write Request\n");
			RWProcessMemory* WriteRequest = (RWProcessMemory*)SharedSection;
			

			PEPROCESS process;
			WriteRequest->processPID = ProcessID;
			Status = PsLookupProcessByProcessId((HANDLE)WriteRequest->processPID, &process);


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

			SIZE_T Bytes;
			DWORD health = 10000;
			DWORD playerAddress = 0;

			MmCopyVirtualMemory(process, (DWORD*)(BaseAddress + localPlayer), PsGetCurrentProcess(), &playerAddress, sizeof(DWORD), KernelMode, &Bytes);
			Status = MmCopyVirtualMemory(PsGetCurrentProcess(), &health, process, (DWORD*)(playerAddress + healthOffset), sizeof(health), KernelMode, &Bytes);


		}
		if ((reinterpret_cast<RWProcessMemory*>(SharedSection)->Signature[0] == 0x2a92) && reinterpret_cast<RWProcessMemory*>(SharedSection)->Signature[1] == 0x1391) // check signature, 1391 means get process id
		{
			
			ProcessID = reinterpret_cast<RWProcessMemory*>(SharedSection)->Address;
			DbgPrint("received Process ID %i\n", ProcessID);
		}
		if ((reinterpret_cast<RWProcessMemory*>(SharedSection)->Signature[0] == 0x2a92) && reinterpret_cast<RWProcessMemory*>(SharedSection)->Signature[1] == 0x1393) // check signature, 1393 means get base address
		{
			
			BaseAddress = reinterpret_cast<RWProcessMemory*>(SharedSection)->Address;
			DbgPrint("received Base Address! %i\n", BaseAddress);
		}
	}
	return Status;
}




NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS Status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(RegistryPath);
	
	DriverObject->DriverUnload = Unload;

	DbgPrint("driver load!!!!\n");

	CreateSharedMemory();



	DriverLoop();



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