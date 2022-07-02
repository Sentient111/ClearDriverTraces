#pragma once
#include <Ntifs.h>
#include <ntimage.h> 

#define Print(fmt, ...) DbgPrint("[s11]: " fmt, ##__VA_ARGS__)

PVOID GetKernelBase(ULONG* Size)
{
	typedef unsigned char uint8_t;
	auto Idt_base = reinterpret_cast<uintptr_t>(KeGetPcr()->IdtBase);
	auto align_page = *reinterpret_cast<uintptr_t*>(Idt_base + 4) >> 0xc << 0xc;

	for (; align_page; align_page -= PAGE_SIZE)
	{
		for (int index = 0; index < PAGE_SIZE - 0x7; index++)
		{
			auto current_address = static_cast<intptr_t>(align_page) + index;

			if (*reinterpret_cast<uint8_t*>(current_address) == 0x48
				&& *reinterpret_cast<uint8_t*>(current_address + 1) == 0x8D
				&& *reinterpret_cast<uint8_t*>(current_address + 2) == 0x1D
				&& *reinterpret_cast<uint8_t*>(current_address + 6) == 0xFF) //48 8d 1D ?? ?? ?? FF
			{
				auto nto_base_offset = *reinterpret_cast<int*>(current_address + 3);
				auto nto_base_ = (current_address + nto_base_offset + 7);
				if (!(nto_base_ & 0xfff))
				{
					if (Size)
						*Size = reinterpret_cast<IMAGE_NT_HEADERS64*>(nto_base_ + reinterpret_cast<IMAGE_DOS_HEADER*>(nto_base_)->e_lfanew)->OptionalHeader.SizeOfImage;

					return (PVOID)nto_base_;
				}
			}
		}
	}

	return NULL;
}


inline ULONG RandomNumber()
{
	ULONG64 tickCount;
	KeQueryTickCount(&tickCount);
	return RtlRandomEx((PULONG)&tickCount);
}

void WriteRandom(ULONG64 addr, ULONG size)
{
	for (size_t i = 0; i < size; i++)
	{
		*(char*)(addr + i) = RandomNumber() % 255;
	}
}

//zwquerysysteminformation
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;


extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

PVOID QuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInfoClass, ULONG* size)
{

	int currAttempt = 0;
	int maxAttempt = 20;


QueryTry:
	if (currAttempt >= maxAttempt)
		return 0;

	currAttempt++;
	ULONG neededSize = 0;
	ZwQuerySystemInformation(SystemInfoClass, NULL, neededSize, &neededSize);
	if (!neededSize)
		goto QueryTry;

	ULONG allocationSize = neededSize;
	PVOID informationBuffer = ExAllocatePool(NonPagedPool, allocationSize);
	if (!informationBuffer)
		goto QueryTry;

	NTSTATUS status = ZwQuerySystemInformation(SystemInfoClass, informationBuffer, neededSize, &neededSize);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(informationBuffer, 0);
		goto QueryTry;
	}

	*size = allocationSize;
	return informationBuffer;
}


typedef struct _SYSTEM_MODULE_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Count;
	SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

UINT64 GetKernelModuleBase(const char* name)
{

	ULONG size = 0;
	PSYSTEM_MODULE_INFORMATION moduleInformation = (PSYSTEM_MODULE_INFORMATION)QuerySystemInformation(SystemModuleInformation, &size);

	if (!moduleInformation || !size)
		return 0;

	for (size_t i = 0; i < moduleInformation->Count; i++)
	{
		char* fileName = (char*)moduleInformation->Module[i].FullPathName + moduleInformation->Module[i].OffsetToFileName;
		if (!strcmp(fileName, name))
		{
			UINT64 imageBase = (UINT64)moduleInformation->Module[i].ImageBase;
			ExFreePoolWithTag(moduleInformation, 0);
			return imageBase;
		}
	}

	ExFreePoolWithTag(moduleInformation, 0);
}