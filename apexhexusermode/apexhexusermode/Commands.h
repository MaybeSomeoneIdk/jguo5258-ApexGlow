#pragma once

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <string>
#include <algorithm>

using namespace std;

void sendMessage(char* message);
bool OpenSharedMemory();
DWORD getProcId(const wchar_t* procName);
DWORD ProcessID;
HANDLE hMapFile;


struct RWProcessMemory
{
	DWORD Signature[2];
	DWORD processPID;
	DWORD64 Address;
	DWORD64 SourceAddress;
	float myFloat[10];
	DWORD64 extra[16];
};

void sendPID()
{
	RWProcessMemory* pointerToBuffer = (RWProcessMemory*)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 4096);
	RWProcessMemory proto;
	proto.processPID = ProcessID;
	proto.Signature[0] = 0x2a92;
	proto.Signature[1] = 0x1392;
	cout << "sent process id: " << proto.processPID << endl;

	RtlCopyMemory(pointerToBuffer, &proto, sizeof(proto));

	return;
}

void glowEnable(int type) //60 for player only, 10000 for player and item, 3 for item only
{
	RWProcessMemory* pointerToBuffer = (RWProcessMemory*)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 4096);

	RWProcessMemory proto;

	float	glowDistance = FLT_MAX;

	proto.extra[0] = type; //set it to type of esp
	proto.Signature[0] = 0x2a92;//set signature
	proto.Signature[1] = 0x1393;
	proto.myFloat[0] = 1.8;
	proto.myFloat[1] = 1;	 //set colors
	proto.myFloat[2] = 1.9;
	proto.myFloat[3] = glowDistance; //set distance
	proto.myFloat[4] = FLT_MAX; //set duration


	RtlCopyMemory(pointerToBuffer, &proto, sizeof(proto));

	Sleep(5000);

	cout << "status peprocess is: " << std::dec << pointerToBuffer->extra[5] << endl;
	cout << "base address is: " << std::hex << pointerToBuffer->extra[6] << endl;
	cout << "Process ID is: " << std::dec << pointerToBuffer->extra[7] << endl;
	cout << "entity pointer value is: " << std::hex << pointerToBuffer->extra[8] << endl;
	cout << "mmcopyvirtualmemory status is: " << std::dec << pointerToBuffer->extra[9] << endl;
	cout << "entity pointer location is: " << std::hex << pointerToBuffer->extra[10] << endl;
	cout << "glow context + entity pointer is: " << std::hex << pointerToBuffer->extra[11] << endl;
	cout << "random entity health is: " << std::dec << pointerToBuffer->extra[12] << endl;
	UnmapViewOfFile(pointerToBuffer);
	return;
}

void Stop()
{
	PCHAR CharArray = (PCHAR)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 4096);
	strcpy(CharArray, "Stop");
	UnmapViewOfFile(CharArray);
	return;
}