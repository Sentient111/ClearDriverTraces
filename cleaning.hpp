#include "misc.h"


//21h1, you can get these from ida
ULONG PiDDBCacheTableOffset = 0xD2F000; 
ULONG PiDDBLockOffset = 0xC44940;

ULONG g_KernelHashBucketListOffset = 0xBC080;
ULONG g_HashCacheLockOffset = 0x37F20;


typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	PVOID GpValue;
	PVOID NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused;
	PVOID SectionPointer;
	ULONG CheckSum;
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

void RemoveMmUnloadedDrivers(PDRIVER_OBJECT driverObject)
{
    reinterpret_cast<PKLDR_DATA_TABLE_ENTRY>(driverObject->DriverSection)->BaseDllName.Length = 0; // when unloading the driver no entry is added because a check fails
}

typedef struct PiDDBCacheEntry
{
	LIST_ENTRY		list;
	UNICODE_STRING	driverName;
	ULONG			driverStamp;
	NTSTATUS		loadStatus;
};

NTSTATUS RemovePiDDBCacheTableEntry(PDRIVER_OBJECT driverObject)
{
	//get table and lock addresses
	ULONG64 kernelBase = (ULONG64)GetKernelBase(NULL);
	PRTL_AVL_TABLE PiDDBCacheTable = PRTL_AVL_TABLE(kernelBase + PiDDBCacheTableOffset);
	PERESOURCE PiDDBLock = PERESOURCE(kernelBase + PiDDBLockOffset);

	//create lookup entry
	PiDDBCacheEntry lookupEntry;
	RtlInitUnicodeString(&lookupEntry.driverName, PKLDR_DATA_TABLE_ENTRY(driverObject->DriverSection)->BaseDllName.Buffer);

	//get spinlock
	if (!ExAcquireResourceExclusiveLite(PiDDBLock, true))
	{
		Print("could not aquire PiDDB spinlock\n");
		return STATUS_UNSUCCESSFUL;
	}

	//look for entry
	PiDDBCacheEntry* foundEntry = (PiDDBCacheEntry*)(RtlLookupElementGenericTableAvl(PiDDBCacheTable, &lookupEntry));


	if (!foundEntry)
	{
		Print("could not find PiDDB entry\n");
		ExReleaseResourceLite(PiDDBLock);
		return STATUS_UNSUCCESSFUL;
	}

	//get prev and next list entries to remove our entry from list
	PLIST_ENTRY nextEntry = foundEntry->list.Flink;
	PLIST_ENTRY prevEntry = foundEntry->list.Blink;

	if (!nextEntry || !prevEntry)
	{
		Print("could not find PiDDB list links\n");
		ExReleaseResourceLite(PiDDBLock);
		return STATUS_UNSUCCESSFUL;
	}

	//replace links
	prevEntry->Flink = foundEntry->list.Flink;
	nextEntry->Blink = foundEntry->list.Blink;

	foundEntry->list.Blink = prevEntry;
	foundEntry->list.Flink = nextEntry;


	//clean entry
	WriteRandom((ULONG64)foundEntry->driverName.Buffer, foundEntry->driverName.Length);
	foundEntry->driverStamp = RandomNumber() % sizeof(ULONG);
	WriteRandom((ULONG64)&foundEntry->list, sizeof(LIST_ENTRY));
	foundEntry->loadStatus = RandomNumber() % sizeof(NTSTATUS);
	RtlDeleteElementGenericTableAvl(PiDDBCacheTable, foundEntry);

	//check if entry can still be found
	foundEntry = (PiDDBCacheEntry*)(RtlLookupElementGenericTableAvl(PiDDBCacheTable, &lookupEntry));

	if (foundEntry)
	{
		Print("could not delete PiDDB entry\n");
		ExReleaseResourceLite(PiDDBLock);
		return STATUS_UNSUCCESSFUL;
	}

	Print("cleaned PiDDB entry\n");
	ExReleaseResourceLite(PiDDBLock);
	return STATUS_SUCCESS;
}

typedef struct _HashBucketEntry
{
	struct _HashBucketEntry* Next;
	UNICODE_STRING DriverName;
	ULONG CertHash[5];
} HashBucketEntry;

NTSTATUS RemoveKernelHashBucketListEntry(PDRIVER_OBJECT driverObject)
{
	UINT64 cidllBase = GetKernelModuleBase(skCrypt("CI.dll"));
	if (!cidllBase)
	{
		Print("failed to get ci base\n");
		return STATUS_UNSUCCESSFUL;
	}

	PSINGLE_LIST_ENTRY g_KernelHashBucketList = PSINGLE_LIST_ENTRY(cidllBase + g_KernelHashBucketListOffset);
	PERESOURCE g_HashCacheLock = PERESOURCE(cidllBase + g_HashCacheLockOffset);

	UNICODE_STRING driverName;
	RtlInitUnicodeString(&driverName, PKLDR_DATA_TABLE_ENTRY(driverObject->DriverSection)->FullDllName.Buffer + 6); //remove \??\C:

	if (!ExAcquireResourceExclusiveLite(g_HashCacheLock, true))
	{
		Print("could not get hash bucket list spinlock\n");
		return STATUS_UNSUCCESSFUL;
	}

	HashBucketEntry* currEntry = (HashBucketEntry*)g_KernelHashBucketList->Next;
	HashBucketEntry* prevEntry = (HashBucketEntry*)g_KernelHashBucketList;

	while (currEntry)
	{
		if (!RtlCompareUnicodeString(&driverName, &currEntry->DriverName, true))
		{
			//unlink
			prevEntry->Next = currEntry->Next;

			//overwrite
			currEntry->Next = (HashBucketEntry*)(RandomNumber() % sizeof(PVOID));
			WriteRandom((UINT64)&currEntry->CertHash, sizeof(currEntry->CertHash));
			WriteRandom((ULONG64)currEntry->DriverName.Buffer, currEntry->DriverName.Length);

			//free 
			ExFreePoolWithTag(currEntry, 0);
			break;
		}

		prevEntry = currEntry;
		currEntry = currEntry->Next;
	}

	currEntry = (HashBucketEntry*)g_KernelHashBucketList->Next;
	while (currEntry)
	{
		if (!RtlCompareUnicodeString(&driverName, &currEntry->DriverName, true))
		{
			Print("failed to clear hasbucketList\n");
			ExReleaseResourceLite(g_HashCacheLock);
			return STATUS_UNSUCCESSFUL;
		}
		currEntry = currEntry->Next;
	}

	Print("cleared hashbucketList\n");
	ExReleaseResourceLite(g_HashCacheLock);
	return STATUS_SUCCESS;
}


//mm unloaded drivers

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	PVOID GpValue;
	PVOID NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused;
	PVOID SectionPointer;
	ULONG CheckSum;
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;