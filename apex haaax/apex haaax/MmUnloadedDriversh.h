#pragma once
#include "undocumented.h"

#define MM_UNLOADED_DRIVERS_SIZE 50

NTSTATUS ScanSection(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound);


PVOID ResolveRelativeAddress(
	_In_ PVOID Instruction,
	_In_ ULONG OffsetOffset,
	_In_ ULONG InstructionSize
)
{
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

	return ResolvedAddr;
}

extern NTKERNELAPI ERESOURCE PsLoadedModuleResource;
PMM_UNLOADED_DRIVER MmUnloadedDrivers;
PULONG				MmLastUnloadedDriver;
NTSTATUS findMMunloadedDrivers()
{	
	// IDA PATTERN   4C 8B 15 ? ? ? ? 4C 8B C9
	UCHAR MmUnloadedDriverSig[] = "\x48\x8B\x05\x00\x00\x00\x00\x48\x8D\x1C\xD0";
	PVOID MmUnloadedDriversPtr = NULL;

	NTSTATUS status = ScanSection(MmUnloadedDriverSig, 0x00, sizeof(MmUnloadedDriverSig) - 1, (PVOID*)(&MmUnloadedDriversPtr));
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "Unable to find MmUnloadedDriversPtr sig.\n");
		return FALSE;
	}
	DbgPrintEx(0, 0, "MmUnloadedDriversPtr func address : %p  \n", MmUnloadedDriversPtr);

	RtlZeroMemory(MmUnloadedDriverSig, sizeof(MmUnloadedDriverSig) - 1);



	//// APEX LEGENDS HACK SOURCE CODE 

	// i AM AFK
	UCHAR MmLastUnloadedDriversSig[] = "\x8B\x05\x00\x00\x00\x00\x83\xF8\x32";

	PVOID MmLastUnloadedDriversPtr = NULL;
	status = ScanSection(MmLastUnloadedDriversSig, 0x00, sizeof(MmLastUnloadedDriversSig) - 1, (PVOID*)(&MmLastUnloadedDriversPtr));

	if (!NT_SUCCESS(status)) {
		DbgPrint("%i\n", status);
		return FALSE;
	}

	
	DbgPrint("MMlastUnloadDriverptr: %p\n", MmLastUnloadedDriversPtr);
	RtlZeroMemory(MmLastUnloadedDriversSig, sizeof(MmLastUnloadedDriversSig) - 1);


	MmUnloadedDrivers = *(PMM_UNLOADED_DRIVER*)ResolveRelativeAddress(MmUnloadedDriverSig, 3, 7);
	MmLastUnloadedDriver = (PULONG)ResolveRelativeAddress(MmLastUnloadedDriversSig, 2, 6);



	return status;
}


NTSTATUS clearUnloadedDrivers(PUNICODE_STRING DriverName, BOOLEAN AcquireResource)
{
	if (AcquireResource)
	{
		ExAcquireResourceExclusiveLite(&PsLoadedModuleResource, TRUE);
	}

	BOOLEAN modified = FALSE;
	BOOLEAN Filled = isMmUnloadedDriversFilled();
	for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index)
	{
		PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
		if (modified)
		{
			PMM_UNLOADED_DRIVER PrevEntry 
		}
	}

}