#include "MmUnloadedDriversh.h"
#include "ReadWrite.h"
#pragma warning(disable:4700)



#define FLT_MAX         3.402823466e+38F       /* max value */



//Allocate buffer for name of shared memory

PACL Dacl = NULL;

SECURITY_DESCRIPTOR SecDescriptor;


HANDLE sectionHandle;
PVOID SharedSection = NULL;


DWORD WriteSignature[2] = { 0x2a92, 0x139a };
DWORD ReadSignature[2] = { 0x2a92, 0x139b };




DWORD64		OFFSET_ENTITYLIST	 =	0x1897F38;
DWORD64		OFFSET_GLOW_ENABLE	 =	0x390;
DWORD64		OFFSET_GLOW_CONTEXT  =	0x310;
DWORD64 	OFFSET_GLOW_RANGE	 =	0x2FC;
DWORD64		OFFSET_GLOW_COLORS	 =	0x1D0;
DWORD64		OFFSET_GLOW_DURATION =  0x2D0;
DWORD64		OFFSET_GLOW_MAGIC	 =	0x278;
DWORD64		OFFSET_HEALTH 		 =	0x3E0;




struct RWProcessMemory
{
	DWORD Signature[2];
	DWORD processPID;
	DWORD64 Address;
	DWORD64 SourceAddress;
	float myFloat[10];
	DWORD64 extra[16];
	bool mybools[4];
	int extraInts[4];
	UCHAR MyChars[6];
};



VOID driverUnload(IN PDRIVER_OBJECT pDriverObject) {

	DbgPrint("Driver Unloading routine called! \n");

	if (SharedSection)
		ZwUnmapViewOfSection(NtCurrentProcess(), SharedSection);

	if (sectionHandle)
		ZwClose(sectionHandle);

}





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







PDRIVER_OBJECT driverObject;
DWORD64 BaseAddress;
DWORD ProcessID;
DWORD64 entAddress;
//the PEPROCESS used is outside

NTSTATUS DispatchHandle()
{

	NTSTATUS Status = STATUS_SUCCESS;
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -10000000;
	DbgPrint("waiting for command...\n");
	while (1)
	{


		KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
		ReadSharedMemory();



		if (strcmp((PCHAR)SharedSection, "Stop") == 0) //if string is equal
		{
			if (process)
			{
				ObDereferenceObject(process);
			}
			driverUnload(driverObject);


			DbgPrint("stopping driver loop\n");

			return Status;
		}



		if ((reinterpret_cast<RWProcessMemory*>(SharedSection)->Signature[0] == 0x2a92) && reinterpret_cast<RWProcessMemory*>(SharedSection)->Signature[1] == 0x1392) // check signature, 13 92 means ProcessID send
		{
			RWProcessMemory* WriteRequest = (RWProcessMemory*)SharedSection;
			ProcessID = WriteRequest->processPID;


			//Entitylist Sig		7F 24 B8 FE 3F 00 00 48 8D 15 ? ? ? ? 2B C1
			//Localplayer Sig		48 8D 0D ? ? ? ? 48 8B D7 FF 50 58

			UCHAR EntityList_Sig[] = "\x7F\x24\xB8\xFE\x3F\x00\x00\x48\x8D\x15\xCC\xCC\xCC\xCC\x2B\xC1";


			/*-------------------Get PEPROCESS--------------------------*/
			Status = PsLookupProcessByProcessId((HANDLE)ProcessID, &process);
			BOOLEAN isWow64 = (PsGetProcessWow64Process(process) != NULL) ? TRUE : FALSE;



			/*-------------------Get Base Address--------------------------*/
			UNICODE_STRING programImage;
			RtlInitUnicodeString(&programImage, L"r5apex.exe");


			/*--------------- IMPORTANT INFO: ppFound in Bbscansection is location of the beginning of the Sig !!! Add some bytes to get to pointer, add some bytes to get to offset*/
			KAPC_STATE apc;
			KeStackAttachProcess(process, &apc);
			BaseAddress = (ULONG64)GetUserModule(process, &programImage, isWow64);
			BBScanSection("safdah", EntityList_Sig, 0xCC, sizeof(EntityList_Sig) - 1, reinterpret_cast<PVOID*>(&OFFSET_ENTITYLIST), (PVOID64)BaseAddress);

			//OFFSET_ENTITYLIST =	*(DWORD*)ResolveRelativeAddress((PVOID)OFFSET_ENTITYLIST, 10, 14);
			OFFSET_ENTITYLIST = (DWORD64)(ResolveRelativeAddress((PVOID)OFFSET_ENTITYLIST, 10, 14));
			KeUnstackDetachProcess(&apc);
			WriteRequest->extra[8] = OFFSET_ENTITYLIST;
//			OFFSET_ENTITYLIST -= BaseAddress;
			ObDereferenceObject(process);

			WriteRequest->Signature[0] = 0x00;
		}



		if ((reinterpret_cast<RWProcessMemory*>(SharedSection)->Signature[0] == 0x2a92) && reinterpret_cast<RWProcessMemory*>(SharedSection)->Signature[1] == 0x1393) // check signature, 13 93 means glow
		{
			DbgPrint("glow Request\n");
			RWProcessMemory* WriteRequest = (RWProcessMemory*)SharedSection;


			/*-------------------Floating point thing--------------------------*/
			KFLOATING_SAVE     save;
			KeSaveFloatingPointState(&save);


			/*-------------------Get PEPROCESS--------------------------*/
			Status = PsLookupProcessByProcessId((HANDLE)ProcessID, &process);
			BOOLEAN isWow64 = (PsGetProcessWow64Process(process) != NULL) ? TRUE : FALSE;



			/*-------------------Get Base Address--------------------------*/
			UNICODE_STRING programImage;
			RtlInitUnicodeString(&programImage, L"r5apex.exe");

			KAPC_STATE apc;
			KeStackAttachProcess(process, &apc);
			BaseAddress = (ULONG64)GetUserModule(process, &programImage, isWow64);
			KeUnstackDetachProcess(&apc);


			//pslookupprocessbyprocessid works


			WriteRequest->extra[5] = Status;
			WriteRequest->extra[6] = BaseAddress;					/*	debug messsages		*/
			WriteRequest->extra[7] = ProcessID;
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


			int i;
			int upperBounds;
			if (WriteRequest->extra[0] == 3) // if type is item only
			{
				i = 60;
				upperBounds = 10000;
			}
			else if (WriteRequest->extra[0] == 60) //if the type is player only
			{
				i = 0;
				upperBounds = 60;

			}
			else if (WriteRequest->extra[0] == 10000) // if type is player and item
			{
				i = 0;
				upperBounds = 10000;
			}
			else
			{
				i = 0;
				upperBounds = 10000;
			}
			SIZE_T Bytes;




			KIRQL irql = KeGetCurrentIrql();
			WriteRequest->MyChars[0] = irql;

			if (BaseAddress)
			{
				while (i < upperBounds)										//Loop through entity list ( I love this code section, it is so neat and easy to read)
				{

					if (strcmp((PCHAR)SharedSection, "Stop") == 0) //if string is equal
					{
						if (process)
						{
							ObDereferenceObject(process);
						}
						driverUnload(driverObject);


						DbgPrint("stopping driver loop\n");

						return Status;
					}

					entAddress = READ<ULONG64>(BaseAddress + OFFSET_ENTITYLIST + (i << 5));


					//set Debug flags
					// OFFSET_ENTITYLIST + (i << 5);
\
					if (entAddress > 0)
					{

						Write<bool>(entAddress + OFFSET_GLOW_ENABLE, true);
						Write<int>(entAddress + OFFSET_GLOW_CONTEXT, 1);
						Write<float>(entAddress + OFFSET_GLOW_COLORS, 0.f);
						Write<float>(entAddress + OFFSET_GLOW_COLORS + 0x4, 0.f);
						Write<float>(entAddress + OFFSET_GLOW_COLORS + 0x8, 255.f);

						for (int offset = 0x2D0; offset <= 0x2E8; offset += 0x4) //beginning of glow is what i find in glow xref - 0x18, or -24 
						{
							Write<float>(entAddress + offset, FLT_MAX);
						}		
						Write<float>(entAddress + OFFSET_GLOW_RANGE, FLT_MAX);  //Write glow range

					}
					i += 1;

				}


			}
			KeRestoreFloatingPointState(&save);
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
	driverObject = DriverObject;

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