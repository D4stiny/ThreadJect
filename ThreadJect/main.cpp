/*
MIT License

Copyright (c) 2017 Bill Demirkapi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, LPCSTR);

typedef BOOL(WINAPI *PDLL_MAIN)(HMODULE, DWORD, PVOID);

typedef struct _MANUAL_INJECT
{
	PVOID ImageBase;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;
}MANUAL_INJECT, *PMANUAL_INJECT;

DWORD WINAPI LoadDll(PVOID p)
{
	PMANUAL_INJECT ManualInject;

	HMODULE hModule;
	DWORD i, Function, count, delta;

	PDWORD ptr;
	PWORD list;

	PIMAGE_BASE_RELOCATION pIBR;
	PIMAGE_IMPORT_DESCRIPTOR pIID;
	PIMAGE_IMPORT_BY_NAME pIBN;
	PIMAGE_THUNK_DATA FirstThunk, OrigFirstThunk;

	PDLL_MAIN EntryPoint;

	ManualInject = (PMANUAL_INJECT)p;

	pIBR = ManualInject->BaseRelocation;
	delta = (DWORD)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

																										  // Relocate the image

	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			list = (PWORD)(pIBR + 1);

			for (i = 0; i<count; i++)
			{
				if (list[i])
				{
					ptr = (PDWORD)((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	pIID = ManualInject->ImportDirectory;

	// Resolve DLL imports

	while (pIID->Characteristics)
	{
		OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
		FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);

		hModule = ManualInject->fnLoadLibraryA((LPCSTR)ManualInject->ImageBase + pIID->Name);

		if (!hModule)
		{
			return FALSE;
		}

		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal

				Function = (DWORD)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function;
			}

			else
			{
				// Import by name

				pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + OrigFirstThunk->u1.AddressOfData);
				Function = (DWORD)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);

				if (!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function;
			}

			OrigFirstThunk++;
			FirstThunk++;
		}

		pIID++;
	}

	if (ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
		return EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
	}

	return TRUE;
}

DWORD WINAPI LoadDllEnd()
{
	return 0;
}


#pragma comment(lib,"ntdll.lib")

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege,BOOLEAN Enable,BOOLEAN CurrentThread,PBOOLEAN Enabled);

char code[]=
{
	0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x81, 0xEB, 0x06, 0x00, 0x00, 0x00, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xBA, 0xCC, 0xCC, 0xCC, 0xCC, 0x52, 0xFF, 0xD0, 0x61, 0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0xC3
}; // x86 ONLY shellcode - will need to change for x64

int main(int argc,char* argv[])
{
	
	LPBYTE ptr;
	HANDLE hProcess,hThread,hSnap,hFile;
	PVOID mem, mem1;
	DWORD ProcessId, FileSize, read, i;
	PVOID buffer, image;
	BOOLEAN bl;
	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_SECTION_HEADER pISH;

	THREADENTRY32 te32;
	CONTEXT ctx;

	MANUAL_INJECT ManualInject;

	printf("\n***********************************************************\n");
	printf("\nThreadJect by zwclose7 and github.com/D4stiny - Manual DLL injection via thread hijacking\n");
	printf("\n***********************************************************\n");
	te32.dwSize=sizeof(te32);
	ctx.ContextFlags=CONTEXT_FULL;

	if(argc!=3)
	{
		printf("\nUsage: ThreadJect [PID] [DLL name]\n");
		return -1;
	}

	printf("\nOpening the DLL.\n");
	hFile = CreateFile(argv[2], GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL); // Open the DLL

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("\nError: Unable to open the DLL (%d)\n", GetLastError());
		return -1;
	}

	FileSize = GetFileSize(hFile, NULL);
	buffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!buffer)
	{
		printf("\nError: Unable to allocate memory for DLL data (%d)\n", GetLastError());

		CloseHandle(hFile);
		return -1;
	}

	// Read the DLL

	if (!ReadFile(hFile, buffer, FileSize, &read, NULL))
	{
		printf("\nError: Unable to read the DLL (%d)\n", GetLastError());

		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(hFile);

		return -1;
	}
	
	CloseHandle(hFile);

	pIDH = (PIMAGE_DOS_HEADER)buffer;

	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("\nError: Invalid executable image.\n");

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	pINH = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + pIDH->e_lfanew);

	if (pINH->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("\nError: Invalid PE header.\n");

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	if (!(pINH->FileHeader.Characteristics & IMAGE_FILE_DLL))
	{
		printf("\nError: The image is not DLL.\n");

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	RtlAdjustPrivilege(20,TRUE,FALSE,&bl);

	printf("\nOpening target process handle.\n");

	ProcessId=atoi(argv[1]);
	hProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,ProcessId);

	if(!hProcess)
	{
		printf("\nError: Unable to open target process handle (%d)\n",GetLastError());
		return -1;
	}

	printf("\nAllocating memory for the DLL.\n");
	image = VirtualAllocEx(hProcess, NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate memory for the DLL

	if (!image)
	{
		printf("\nError: Unable to allocate memory for the DLL (%d)\n", GetLastError());

		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(hProcess);

		return -1;
	}

	// Copy the header to target process

	printf("\nCopying headers into target process.\n");

	if (!WriteProcessMemory(hProcess, image, buffer, pINH->OptionalHeader.SizeOfHeaders, NULL))
	{
		printf("\nError: Unable to copy headers to target process (%d)\n", GetLastError());

		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
		CloseHandle(hProcess);

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	pISH = (PIMAGE_SECTION_HEADER)(pINH + 1);

	// Copy the DLL to target process

	printf("\nCopying sections to target process.\n");

	for (i = 0; i<pINH->FileHeader.NumberOfSections; i++)
	{
		WriteProcessMemory(hProcess, (PVOID)((LPBYTE)image + pISH[i].VirtualAddress), (PVOID)((LPBYTE)buffer + pISH[i].PointerToRawData), pISH[i].SizeOfRawData, NULL);
	}

	printf("\nAllocating memory for the loader code.\n");
	mem1 = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate memory for the loader code

	if (!mem1)
	{
		printf("\nError: Unable to allocate memory for the loader code (%d)\n", GetLastError());

		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
		CloseHandle(hProcess);

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	printf("\nLoader code allocated at %#x\n", mem1);
	memset(&ManualInject, 0, sizeof(MANUAL_INJECT));

	ManualInject.ImageBase = image;
	ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)image + pIDH->e_lfanew);
	ManualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	ManualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	ManualInject.fnLoadLibraryA = LoadLibraryA;
	ManualInject.fnGetProcAddress = GetProcAddress;

	printf("\nWriting loader code to target process.\n");

	WriteProcessMemory(hProcess, mem1, &ManualInject, sizeof(MANUAL_INJECT), NULL); // Write the loader information to target process
	WriteProcessMemory(hProcess, (PVOID)((PMANUAL_INJECT)mem1 + 1), LoadDll, (DWORD)LoadDllEnd - (DWORD)LoadDll, NULL); // Write the loader code to target process

	hSnap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);

	Thread32First(hSnap,&te32);
	printf("\nFinding a thread to hijack.\n");

	while(Thread32Next(hSnap,&te32))
	{
		if(te32.th32OwnerProcessID==ProcessId)
		{
			printf("\nTarget thread found. Thread ID: %d\n",te32.th32ThreadID);
			break;
		}
	}

	CloseHandle(hSnap);

	printf("\nAllocating memory in target process.\n");

	mem=VirtualAllocEx(hProcess,NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);

	if(!mem)
	{
		printf("\nError: Unable to allocate memory in target process (%d)",GetLastError());
		
		CloseHandle(hProcess);
		return -1;
	}

	printf("\nMemory allocated at %#x\n",mem);
	printf("\nOpening target thread handle.\n");

	hThread=OpenThread(THREAD_ALL_ACCESS,FALSE,te32.th32ThreadID);

	if(!hThread)
	{
		printf("\nError: Unable to open target thread handle (%d)\n",GetLastError());
		
		VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
		CloseHandle(hProcess);
		return -1;
	}

	printf("\nSuspending target thread.\n");

	SuspendThread(hThread);
	GetThreadContext(hThread,&ctx);

	buffer=VirtualAlloc(NULL,65536,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
	ptr=(LPBYTE)buffer;

	memcpy(buffer,code,sizeof(code));

	while(1)
	{
		if(*ptr==0xb8 && *(PDWORD)(ptr+1)==0xCCCCCCCC)
		{
			*(PDWORD)(ptr+1)=(DWORD)((PMANUAL_INJECT)mem1 + 1);
		}

		if(*ptr==0x68 && *(PDWORD)(ptr+1)==0xCCCCCCCC)
		{
			*(PDWORD)(ptr+1)=ctx.Eip;
		}

		if (*ptr == 0xba && *(PDWORD)(ptr + 1) == 0xCCCCCCCC)
		{
			*(PDWORD)(ptr + 1) = (DWORD)(mem1);
		}

		if(*ptr==0xc3)
		{
			ptr++;
			break;
		}

		ptr++;
	}

	printf("\nWriting shellcode into target process.\n");

	if(!WriteProcessMemory(hProcess,mem,buffer,sizeof(code),NULL)) // + 0x4 because a DWORD is 0x4 big
	{
		printf("\nError: Unable to write shellcode into target process (%d)\n",GetLastError());

		VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
		ResumeThread(hThread);

		CloseHandle(hThread);
		CloseHandle(hProcess);

		VirtualFree(buffer,0,MEM_RELEASE);
		return -1;
	}

	ctx.Eip=(DWORD)mem;

	printf("\nHijacking target thread.\n");

	if(!SetThreadContext(hThread,&ctx))
	{
		printf("\nError: Unable to hijack target thread (%d)\n",GetLastError());

		VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
		ResumeThread(hThread);

		CloseHandle(hThread);
		CloseHandle(hProcess);

		VirtualFree(buffer,0,MEM_RELEASE);
		return -1;
	}

	printf("\nResuming target thread.\n");

	ResumeThread(hThread);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	VirtualFree(buffer,0,MEM_RELEASE);
	return 0;
}