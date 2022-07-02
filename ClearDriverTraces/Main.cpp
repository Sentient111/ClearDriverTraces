#include "Cleaning.h"

void MyUnload(PDRIVER_OBJECT driverObject)
{
	Print("[s11] unloading mapper\n");
}


NTSTATUS DriverEntry(PDRIVER_OBJECT  driverObject, PUNICODE_STRING  RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	driverObject->DriverUnload = MyUnload;

	NTSTATUS status = STATUS_SUCCESS;
	RemoveMmUnloadedDrivers(driverObject);

	status = RemovePiDDBCacheTableEntry(driverObject);
	if (!NT_SUCCESS(status))
	{
		Print("failed to clear piddb cache %x\n", status);
		return status;
	}

	status = RemoveKernelHashBucketListEntry(driverObject);
	if (!NT_SUCCESS(status))
	{
		Print("failed to clear hashbucket list cache %x\n", status);
		return status;
	}

	status = DeleteCiEaCacheLookasideList();
	if (!NT_SUCCESS(status))
	{
		Print("failed to delete lookaside list %x\n", status);
		return status;
	}

	return status;
}

