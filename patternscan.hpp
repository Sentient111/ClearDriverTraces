//PVOID FindPattern(uintptr_t start, ULONG size, char* pattern, char* mask) NOT MADE BY ME


PVOID GetModuleInKernel(ULONG* size, char* name)
{
	PVOID buffer = 0;
	ULONG buffer_size = 0;

	NTSTATUS status = ZwQuerySystemInformation(11, buffer, buffer_size, &buffer_size);

	PVOID allocated = ExAllocatePool(NonPagedPool, buffer_size);
	status = ZwQuerySystemInformation(11, allocated, buffer_size, &buffer_size);

	PRTL_PROCESS_MODULES modules = static_cast<PRTL_PROCESS_MODULES>(allocated);
	if (!modules)
	{
		DebugMessage("[s11] could not get module information");
		return 0x0;
	}

	for (int i = 0; i < modules->NumberOfModules; i++)
	{
		char* currentName = reinterpret_cast<char*>(modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName);
		if (!strcmp(currentName, name))
		{
			DebugMessage("[s11] found module");
			*size = modules->Modules[i].ImageSize;
			return modules->Modules[i].ImageBase;
		}
	}

	return 0x0;
}

PVOID GetKernelBase(ULONG* size)
{
	//find list header
	ULONG listHeaderSize = 0;
	NTSTATUS status = ZwQuerySystemInformation(0xB, nullptr, listHeaderSize, &listHeaderSize); //get sytem size

	//allocate stuff for it?
	PVOID listHeader = ExAllocatePool(NonPagedPool, listHeaderSize);
	if (listHeader == NULL)
		return 0x0;

	if (status = ZwQuerySystemInformation(0xB, listHeader, listHeaderSize, &listHeaderSize))
		DebugMessage("[s11] that didn work");

	auto currentModule = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Module;

	for (int i = 0; i < reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Count; ++i, ++currentModule)
	{
		auto currentModuleName = reinterpret_cast<const char*>(currentModule->FullPathName + currentModule->OffsetToFileName);
		if (!strcmp("ntoskrnl.exe", currentModuleName))
		{
			*size = currentModule->ImageSize;
			ExFreePool(listHeader);
			return currentModule->ImageBase;
		}
	}
	ExFreePool(listHeader);
	return 0x0;
}


PVOID FindSectionInModule(uintptr_t moduleBase, char* sectionName, ULONG* size)
{
	PIMAGE_DOS_HEADER dosHeaders = reinterpret_cast<PIMAGE_DOS_HEADER>(moduleBase);
	PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(moduleBase + dosHeaders->e_lfanew);

	PIMAGE_SECTION_HEADER currentImageSection = IMAGE_FIRST_SECTION(ntHeaders);

	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
	{
		//DebugMessage("[s11] found section with name ->%s", reinterpret_cast<char*>(currentImageSection[i].Name));
		if (!strcmp(reinterpret_cast<char*>(currentImageSection[i].Name), sectionName))
		{
			PVOID sectionAddress = reinterpret_cast<PVOID>(moduleBase + currentImageSection[i].VirtualAddress);
			*size = currentImageSection[i].Misc.VirtualSize;
			DebugMessage("[s11] Found Section at ->%p", sectionAddress);
			return sectionAddress;
		}
	}
	DebugMessage("[s11] didn find");
	return 0x0;
}

PVOID FindPatternInSectionInKernel(char* sectionName, char* pattern, char* mask)
{
	ULONG size = 0;
	PVOID address = GetKernelBase(&size);
	return FindPatternInSection(address, sectionName, pattern, mask);
}


PVOID FindPatternInSection(PVOID base, char* sectionName, char* pattern, char* mask)
{
	uintptr_t sectionAddr = 0;
	ULONG sectionSize = 0;
	sectionAddr = reinterpret_cast<uintptr_t>(FindSectionInModule(reinterpret_cast<uintptr_t>(base), sectionName, &sectionSize));
	return FindPattern(sectionAddr, sectionSize, pattern, mask);
}

PVOID FindPattern(uintptr_t start, ULONG size, char* pattern, char* mask)
{
	int maskLength = strlen(mask);
	for (int i = 0; i < size - maskLength; i++)
	{
		for (int j = 0; j < maskLength; j++)
		{
			if (mask[j] != '?' && *reinterpret_cast<uint8_t*>(start + i + j) != static_cast<uint8_t>(pattern[j]))
				break;

			if (j == maskLength - 1)
				return reinterpret_cast<PVOID>(start + i);
		}
	}
}

PVOID FindPatternInKernel(char* pattern, char* mask)
{
	PVOID kernelBase;
	ULONG kernelSize;

	kernelBase = GetKernelBase(&kernelSize);
	return FindPattern((uintptr_t)kernelBase, kernelSize, pattern, mask);
}

PVOID ResolveRelativeAddress(uintptr_t instruction, ULONG offsetOffset, ULONG instructionSize)
{
	LONG ripOffset = 0;
	memcpy(&ripOffset, reinterpret_cast<PVOID>(instruction + offsetOffset), sizeof(LONG));
	if (ripOffset == 0)
		return 0x0;

	return reinterpret_cast<PVOID>(instruction + instructionSize + ripOffset);
}
