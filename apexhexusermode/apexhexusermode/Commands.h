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





void glowEnable(int type) //60 for player only, 10000 for player and item, 3 for item only
{
	RWProcessMemory* pointerToBuffer = (RWProcessMemory*)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 4096);

	RWProcessMemory proto;

	bool	glowEnable = 1;
	float   glowColors[3] = { 180.8, 60.5, 180.2 };
	float	glowDistance = 400.3;


	proto.extra[0] = type; //set it to type of esp
	proto.Signature[0] = 0x2a92;//set signature
	proto.Signature[1] = 0x1393;
	proto.processPID = ProcessID;

	cout << "sent process id: " << proto.processPID << endl;

	proto.myFloat[0] = glowColors[0];
	proto.myFloat[1] = glowColors[1];//set colors
	proto.myFloat[2] = glowColors[2];
	proto.myFloat[3] = glowDistance; //set distance


	RtlCopyMemory(pointerToBuffer, &proto, sizeof(proto));

	Sleep(5000);

	cout << "status peprocess is: " << pointerToBuffer->extra[5] << endl;
	cout << "base address is: " << pointerToBuffer->extra[6] << endl;
	cout << "Process ID is: " << pointerToBuffer->extra[7] << endl;
	cout << "entity pointer value is: " << pointerToBuffer->extra[8] << endl;
	cout << "mmcopyvirtualmemory status is: " << pointerToBuffer->extra[9] << endl;
	cout << "entity pointer location is: " << pointerToBuffer->extra[10] << endl;
	cout << "glow context + entity pointer is: " << pointerToBuffer->extra[11] << endl;
	UnmapViewOfFile(pointerToBuffer);
	return;
}

void Stop()
{
	PCHAR CharArray = (PCHAR)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 4096);
	strcpy(CharArray, "Stop");
	return;
}