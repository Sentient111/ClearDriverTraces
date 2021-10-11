//did not find these structs
typedef struct PiDDBCacheEntry
{
	LIST_ENTRY		list;
	UNICODE_STRING	driverName;
	ULONG			driverStamp;
	NTSTATUS		loadStatus;
};

typedef struct _HashBucketEntry
{
    struct _HashBucketEntry* Next;
    UNICODE_STRING DriverName;
    ULONG CertHash[5];
} HashBucketEntry, * PHashBucketEntry;


uintptr_t kiNmiInProgress = 0;
int numOfProcessors = 0;

void ClearMMunloadedDrivers(PDRIVER_OBJECT driverObject)
{
    reinterpret_cast<PKLDR_DATA_TABLE_ENTRY>(driverObject->DriverSection)->BaseDllName.Length = 0; 
}

bool BypassNmicallback()
{
    numOfProcessors = KeQueryActiveProcessorCount(NULL);
    if (numOfProcessors == 0)
    {
        DebugMessage("[s11] could not get num of processors");
        return false;
    }

    DebugMessage("[s11] num of processors ->%d", numOfProcessors);

    kiNmiInProgress = (uintptr_t)FindPatternInSectionInKernel(".text", 
        "\x48\x8B\x05\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x81\x25\x00\x00\x00\x00\x00\x00\x00\x00\xB9\x00\x00\x00\x00\xE8\x00\x00\x00\x00", 
        "xxx????x????xx????????x????x????");

    if (kiNmiInProgress == 0)
    {
        DebugMessage("[s11] could not find kinmiinprogress");
        return false;
    }

    kiNmiInProgress = (uintptr_t)ResolveRelativeAddress(kiNmiInProgress, 3, 7);
    DebugMessage("[s11] kinmiinprogress at ->%p", kiNmiInProgress);

    for (int i = 0; i < numOfProcessors; i++)
        InterlockedBitTestAndSet64((LONG64*)&kiNmiInProgress, i);

    return true;
} 

bool ClearHashBucketList(PDRIVER_OBJECT driverObject)
{

    UNICODE_STRING path;
    path.Length = reinterpret_cast<PKLDR_DATA_TABLE_ENTRY>(driverObject->DriverSection)->FullDllName.Length - 12;
    path.MaximumLength = path.Length;
    path.Buffer = reinterpret_cast<PWCH>(ExAllocatePool(NonPagedPool, path.Length));

    memcpy(path.Buffer, reinterpret_cast<PKLDR_DATA_TABLE_ENTRY>(driverObject->DriverSection)->FullDllName.Buffer + 6, path.Length);


    ULONG size;
    PVOID ciBase;
    ciBase = GetModuleInKernel(&size, "CI.dll");

    if (ciBase == 0x0)
    {
        DebugMessage("[s11] Could not get ci base");
        return false;
    }

    uintptr_t hashLock = (uintptr_t)FindPattern((uintptr_t)ciBase, size, "\xE8\x00\x00\x00\x00\xEB\x94", "x????xx");
    uintptr_t hashTable = (uintptr_t)FindPattern((uintptr_t)ciBase, size, "\x77\x14\x83\xFD\x34", "xxxxx");
    hashLock += 0xB2;
    hashTable += 0x16;
    hashLock = (uintptr_t)ResolveRelativeAddress(hashLock, 3, 7);
    hashTable = (uintptr_t)ResolveRelativeAddress(hashTable, 3, 7);

    DebugMessage("[s11] found lock at ->%p", hashLock);


    bool spinlock = ExAcquireResourceExclusiveLite(reinterpret_cast<PERESOURCE>(hashLock), true);
    if (!spinlock)
    {
        ExFreePool(path.Buffer);
        DebugMessage("[s11] failed to get hashbucket lock");
        return false;
    }


    //lookup entry
    HashBucketEntry* prevEntry = reinterpret_cast<PHashBucketEntry>(hashTable);
    HashBucketEntry* entry = reinterpret_cast<PHashBucketEntry>(hashTable);

    while (entry)
    {
        DebugMessage("[s11] found entry with name ->%wZ", entry->DriverName);
        if (RtlCompareUnicodeString(&entry->DriverName, &path, false) == 0)
        {
            DebugMessage("[s11] found entry");
            prevEntry->Next = entry->Next;


            entry = reinterpret_cast<PHashBucketEntry>(hashTable);
            while (entry)
            {
                if (RtlCompareUnicodeString(&entry->DriverName, &path, false) == 0)
                {
                    DebugMessage("[s11] failed to clear kernelhash");
                    ExFreePool(path.Buffer);
                    ExReleaseResourceLite(reinterpret_cast<PERESOURCE>(hashLock));
                    return false;
                }
                entry = entry->Next;
            }

            DebugMessage("[s11] clear hash");
            ExFreePool(path.Buffer);
            ExReleaseResourceLite(reinterpret_cast<PERESOURCE>(hashLock));
            return true;
        }
        prevEntry = entry;
        entry = entry->Next;
    }


    DebugMessage("[s11] did not find entry");
    ExFreePool(path.Buffer);
    ExReleaseResourceLite(reinterpret_cast<PERESOURCE>(hashLock));
    return true;
}

bool ClearPiDDBCash(PDRIVER_OBJECT driverObject)
{
    uintptr_t piddbLockPtr;
    uintptr_t piddbTablePtr;

    piddbLockPtr = (uintptr_t)FindPatternInSectionInKernel("PAGE", 
        "\xE8\x00\x00\x00\x00\x8B\xD8\x8D\x90\x00\x00\x00\x00", 
        "x????xxxx????");
    piddbLockPtr -= 0x247;
    piddbLockPtr = (uintptr_t)ResolveRelativeAddress(piddbLockPtr, 3, 7);
    DebugMessage("[s11] lock at addr ->%p", piddbLockPtr);

    piddbTablePtr = (uintptr_t)FindPatternInSectionInKernel("PAGE",
        "\x66\x03\xD2\x48\x8D\x0D\x00\x00\x00\x00",
        "xxxxxx????");
    piddbTablePtr += 0x3;
    piddbTablePtr = (uintptr_t)ResolveRelativeAddress(piddbTablePtr, 3, 7);
    DebugMessage("[s11] table at addr ->%p", piddbTablePtr);

    bool aquireSpinLock = ExAcquireResourceExclusiveLite(reinterpret_cast<PERESOURCE>(piddbLockPtr), true);
    if (!aquireSpinLock)
    {
        DebugMessage("[s11] could not aquire PiDDB lock");
        return false;
    }
    DebugMessage("[s11] got the spinlock");


    PiDDBCacheEntry lookForEntry;
    RtlInitUnicodeString(&lookForEntry.driverName, reinterpret_cast<PKLDR_DATA_TABLE_ENTRY>(driverObject->DriverSection)->BaseDllName.Buffer);

    PiDDBCacheEntry* foundEntry =
        reinterpret_cast<PiDDBCacheEntry*>(
            RtlLookupElementGenericTableAvl(reinterpret_cast<PRTL_AVL_TABLE>(piddbTablePtr),
            reinterpret_cast<void*>(&lookForEntry)
        ));

    if (!foundEntry)
    {
        DebugMessage("[s11] Could not find piddb entry");
        ExReleaseResourceLite(reinterpret_cast<PERESOURCE>(piddbLockPtr));
        return false;
    }

    PLIST_ENTRY NextEntry = foundEntry->list.Flink;
    PLIST_ENTRY PrevEntry = foundEntry->list.Blink;

    PrevEntry->Flink = foundEntry->list.Flink;
    NextEntry->Blink = foundEntry->list.Blink;

    foundEntry->list.Blink = PrevEntry;
    foundEntry->list.Flink = NextEntry;

    if (!RtlDeleteElementGenericTableAvl(reinterpret_cast<PRTL_AVL_TABLE>(piddbTablePtr), foundEntry))
    {
        DebugMessage("[s11] Could not delete table");
        ExReleaseResourceLite(reinterpret_cast<PERESOURCE>(piddbLockPtr));
        return false;
    }


    foundEntry =
        reinterpret_cast<PiDDBCacheEntry*>(
            RtlLookupElementGenericTableAvl(reinterpret_cast<PRTL_AVL_TABLE>(piddbTablePtr),
                reinterpret_cast<void*>(&lookForEntry)
            ));

    if (!foundEntry)
    {
        ExReleaseResourceLite(reinterpret_cast<PERESOURCE>(piddbLockPtr));
        DebugMessage("[s11] cleared piddbcashe");
        return true;
    }
    ExReleaseResourceLite(reinterpret_cast<PERESOURCE>(piddbLockPtr));
    DebugMessage("[s11] clearing piddbcashe failed");
    return false;

}

//credit to nbq 
bool null_pfn(ULONG64 pool_address, ULONG pool_size) //working but missing some shit header
{
    PMDL poolMdl = IoAllocateMdl((PVOID)pool_address, pool_size, 0, 0, 0);
    MmBuildMdlForNonPagedPool(poolMdl);
    PPFN_NUMBER mdl_pages = MmGetMdlPfnArray(poolMdl);
    if (!mdl_pages) { return false; }

    ULONG mdl_page_count = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(poolMdl), MmGetMdlByteCount(poolMdl));

    ULONG null_pfn = 0x0;
    MM_COPY_ADDRESS source_address = { 0 };
    source_address.VirtualAddress = &null_pfn;

    for (ULONG i = 0; i < mdl_page_count; i++)
    {
        size_t bytes = 0;
        MmCopyMemory(&mdl_pages[i], source_address, sizeof(ULONG), MM_COPY_MEMORY_VIRTUAL, &bytes);
    }
    return true;
}
