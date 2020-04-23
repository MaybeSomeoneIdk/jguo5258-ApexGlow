#include "Commands.h"
using namespace std;


DWORD dwRes;
SECURITY_ATTRIBUTES sa;
PSECURITY_DESCRIPTOR pSD = NULL;
SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
PACL pAcl = NULL;
PSID pEveryoneSID = NULL;






DWORD getProcId(const wchar_t* procName)
{
	DWORD procID = 0;
	HANDLE hSnap = (CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(procEntry);
		if (Process32First(hSnap, &procEntry))
		{
			do
			{
				if (!_wcsicmp(procEntry.szExeFile, procName))
				{
					procID = procEntry.th32ProcessID;
					break;
				}

			} while (Process32Next(hSnap, &procEntry));
		}
	}
	CloseHandle(hSnap);
	return procID;
}






bool OpenSharedMemory() {
	hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, "Global\\SharedMemory");
	if (!hMapFile || hMapFile == INVALID_HANDLE_VALUE)
	{
		std::cout << "Open Shared memory Fail!!!       " << GetLastError() << "\n";
		return false;
	}

	std::cout << "shared memory open!!\n";
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0xA);
	return true;
}





int main()
{
	std::cout << "Hello World!\n";
	bool open;
	

	while (1)
	{
		ProcessID = getProcId(L"r5apex.exe");
		open = OpenSharedMemory();

		if ((ProcessID != 0) && (open != 0))
		{
			cout << "found process and shared memory!!1\n";
			cout << ProcessID << endl;
			break;
		}
		
		Sleep(2000);
		cout << "apex legends and/or shared memory not found!!@!!!!!\n";
	}
	ProcessID = getProcId(L"r5apex.exe");//set pid

	cout << "please wait for driver to scan for sigs...\n";
	sendPID();


	int input;
	while (1)
	{
		cin >> input;
		if (input == 2) //stop
		{
			Stop();
		}
		if (input == 3)
		{
			glowEnable(60); //player only
			
		}
		if (input == 4)
		{
			glowEnable(10000); // for player and item
		}
		if (input == 5)
		{
			glowEnable(3); // for item only
		}
	}
	return 0;
}
