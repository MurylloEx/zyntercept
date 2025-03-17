#include <Zyntercept/Core/Syscall/Windows/Windows.h>

#include <map>
#include <mutex>
#include <vector>
#include <string>
#include <algorithm>
#include <Windows.h>
#include <winternl.h>

#define CURRENT_PROCESS_IDENTIFIER (ZyanVoidPointer)-1
#define ZYNTERCEPT_CAST_INTEGER(Type, ProcessIdentifier, Integer) \
	ZynterceptIs32BitProcessWindows(ProcessIdentifier) \
		? (Type)((ZyanU64)Integer & 0xFFFFFFFFUL) \
		: (Type)Integer

typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation,          // MEMORY_BASIC_INFORMATION
	MemoryWorkingSetInformation,     // MEMORY_WORKING_SET_INFORMATION
	MemoryMappedFilenameInformation, // UNICODE_STRING
	MemoryRegionInformation,         // MEMORY_REGION_INFORMATION
	MemoryWorkingSetExInformation,   // MEMORY_WORKING_SET_EX_INFORMATION
	MemorySharedCommitInformation    // MEMORY_SHARED_COMMIT_INFORMATION
} MEMORY_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_)(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG_PTR ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);

typedef NTSTATUS(NTAPI* NtFreeVirtualMemory_)(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG FreeType);

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_)(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

typedef NTSTATUS(NTAPI* NtQueryVirtualMemory_)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	IN OUT PVOID MemoryInformation,
	IN SIZE_T MemoryInformationLength,
	OUT PSIZE_T ReturnLength OPTIONAL);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten);

typedef NTSTATUS(NTAPI* NtReadVirtualMemory_)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN OUT PVOID Buffer,
	IN SIZE_T NumberOfBytesToRead,
	OUT PSIZE_T NumberOfBytesRead);

typedef NTSTATUS(NTAPI* NtFlushInstructionCache_)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN SIZE_T Length);

static std::mutex SyscallMutex;

static void* Syscall(std::string Procedure)
{
	std::lock_guard<std::mutex> Guard(SyscallMutex);

	size_t Separator = Procedure.find('!');

	if (Separator == std::string::npos) {
		return nullptr;
	}

	std::string ModuleName = Procedure.substr(0, Separator);
	std::string SyscallName = Procedure.substr(Separator + 1);
	std::transform(ModuleName.begin(), ModuleName.end(), ModuleName.begin(), std::tolower);

	void* ModuleBase = (void*)GetModuleHandleA(ModuleName.c_str());

	if (!ModuleBase) {
		ModuleBase = (void*)LoadLibraryA(ModuleName.c_str());
	}

	if (!ModuleBase) {
		return nullptr;
	}

	void* SyscallPointer = (void*)GetProcAddress((HMODULE)ModuleBase, SyscallName.c_str());

	return SyscallPointer;
}

NTSTATUS NtAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG_PTR ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect)
{
	void* Pointer = Syscall("ntdll.dll!NtAllocateVirtualMemory");
	NtAllocateVirtualMemory_ Invoke = (NtAllocateVirtualMemory_)Pointer;

	return Invoke(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS NtFreeVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG FreeType)
{
	void* Pointer = Syscall("ntdll.dll!NtFreeVirtualMemory");
	NtFreeVirtualMemory_ Invoke = (NtFreeVirtualMemory_)Pointer;

	return Invoke(ProcessHandle, BaseAddress, RegionSize, FreeType);
}

NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect)
{
	void* Pointer = Syscall("ntdll.dll!NtProtectVirtualMemory");
	NtProtectVirtualMemory_ Invoke = (NtProtectVirtualMemory_)Pointer;

	return Invoke(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

NTSTATUS NtQueryVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	IN OUT PVOID MemoryInformation,
	IN SIZE_T MemoryInformationLength,
	OUT PSIZE_T ReturnLength OPTIONAL)
{
	void* Pointer = Syscall("ntdll.dll!NtQueryVirtualMemory");
	NtQueryVirtualMemory_ Invoke = (NtQueryVirtualMemory_)Pointer;

	return Invoke(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
}

NTSTATUS NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten)
{
	void* Pointer = Syscall("ntdll.dll!NtWriteVirtualMemory");
	NtWriteVirtualMemory_ Invoke = (NtWriteVirtualMemory_)Pointer;

	return Invoke(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS NtReadVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN OUT PVOID Buffer,
	IN SIZE_T NumberOfBytesToRead,
	OUT PSIZE_T NumberOfBytesRead)
{
	void* Pointer = Syscall("ntdll.dll!NtReadVirtualMemory");
	NtReadVirtualMemory_ Invoke = (NtReadVirtualMemory_)Pointer;

	return Invoke(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
}

NTSTATUS NtFlushInstructionCache(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN SIZE_T Length)
{
	void* Pointer = Syscall("ntdll.dll!NtFlushInstructionCache");
	NtFlushInstructionCache_ Invoke = (NtFlushInstructionCache_)Pointer;

	return Invoke(ProcessHandle, BaseAddress, Length);
}

ZyanBool __zyntercept_cdecl ZynterceptMapPageProtectionFromWindows(
	__zyntercept_in DWORD WindowsPageProtection, 
	__zyntercept_out ZyanU32* ZynterceptPageProtection)
{
	static std::map<DWORD, ZyanU32> ProtectionMap = {
		{ NULL, ZYNTERCEPT_PAGE_PROTECTION_NONE },
		{ PAGE_NOACCESS, ZYNTERCEPT_PAGE_PROTECTION_NONE },
		{ PAGE_READONLY, ZYNTERCEPT_PAGE_PROTECTION_READ },
		{ PAGE_READWRITE, ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_WRITE },
		{ PAGE_WRITECOPY, ZYNTERCEPT_PAGE_PROTECTION_WRITE | ZYNTERCEPT_PAGE_PROTECTION_READ },
		{ PAGE_EXECUTE, ZYNTERCEPT_PAGE_PROTECTION_EXECUTE },
		{ PAGE_EXECUTE_READ, ZYNTERCEPT_PAGE_PROTECTION_EXECUTE | ZYNTERCEPT_PAGE_PROTECTION_READ },
		{ PAGE_EXECUTE_READWRITE, ZYNTERCEPT_PAGE_PROTECTION_EXECUTE | ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_WRITE },
		{ PAGE_EXECUTE_WRITECOPY, ZYNTERCEPT_PAGE_PROTECTION_EXECUTE | ZYNTERCEPT_PAGE_PROTECTION_WRITE | ZYNTERCEPT_PAGE_PROTECTION_READ }
	};

	if (ProtectionMap.count(WindowsPageProtection) == 0) {
		return ZYAN_FALSE;
	}

	*ZynterceptPageProtection = ProtectionMap[WindowsPageProtection];

	return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptMapPageProtectionToWindows(
	__zyntercept_in ZyanU32 ZynterceptPageProtection,
	__zyntercept_out DWORD* WindowsPageProtection)
{
	static std::map<ZyanU32, ULONG> ProtectionMap = {
		{ ZYNTERCEPT_PAGE_PROTECTION_NONE, PAGE_NOACCESS },
		{ ZYNTERCEPT_PAGE_PROTECTION_READ, PAGE_READONLY },
		{ ZYNTERCEPT_PAGE_PROTECTION_EXECUTE, PAGE_EXECUTE },
		{ ZYNTERCEPT_PAGE_PROTECTION_WRITE | ZYNTERCEPT_PAGE_PROTECTION_EXECUTE, PAGE_EXECUTE_READWRITE },
		{ ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_WRITE, PAGE_READWRITE },
		{ ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_EXECUTE, PAGE_EXECUTE_READ },
		{ ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_WRITE | ZYNTERCEPT_PAGE_PROTECTION_EXECUTE, PAGE_EXECUTE_READWRITE }
	};

	if (ProtectionMap.count(ZynterceptPageProtection) == 0) {
		return ZYAN_FALSE;
	}

	*WindowsPageProtection = ProtectionMap[ZynterceptPageProtection];

	return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptMapPageStateFromWindows(
	__zyntercept_in DWORD WindowsPageState,
	__zyntercept_out ZyanU32* ZynterceptPageState)
{
	static std::map<DWORD, ZyanU32> StateMap = {
		{ MEM_FREE, ZYNTERCEPT_PAGE_STATE_FREE },
		{ MEM_COMMIT, ZYNTERCEPT_PAGE_STATE_COMMITTED },
		{ MEM_RESERVE, ZYNTERCEPT_PAGE_STATE_RESERVED }
	};

	if (StateMap.count(WindowsPageState) == 0) {
		return ZYAN_FALSE;
	}

	*ZynterceptPageState = StateMap[WindowsPageState];

	return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptMapPageStateToWindows(
	__zyntercept_in ZyanU32 ZynterceptPageState,
	__zyntercept_out DWORD* WindowsPageState)
{
	static std::map<DWORD, ZyanU32> StateMap = {
		{ ZYNTERCEPT_PAGE_STATE_FREE, MEM_FREE },
		{ ZYNTERCEPT_PAGE_STATE_COMMITTED, MEM_COMMIT },
		{ ZYNTERCEPT_PAGE_STATE_RESERVED, MEM_RESERVE },
		{ ZYNTERCEPT_PAGE_STATE_RESERVED | ZYNTERCEPT_PAGE_STATE_COMMITTED, MEM_RESERVE | MEM_COMMIT }
	};

	if (StateMap.count(ZynterceptPageState) == 0) {
		return ZYAN_FALSE;
	}

	*WindowsPageState = StateMap[ZynterceptPageState];

	return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptIs64BitSystemWindows()
{
	static bool IsCached = false;
	static ZyanBool Status = ZYAN_FALSE;

	if (IsCached) {
		return Status;
	}

	DWORD LastError = GetLastError();
	UNREFERENCED_PARAMETER(GetSystemWow64DirectoryW(NULL, 0));
	Status = (GetLastError() == ERROR_CALL_NOT_IMPLEMENTED) ? ZYAN_FALSE : ZYAN_TRUE;
	IsCached = true;
	SetLastError(LastError);

	return Status;
}

ZyanBool __zyntercept_cdecl ZynterceptIs32BitSystemWindows()
{
	return ZynterceptIs64BitSystemWindows() ? ZYAN_FALSE : ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptIs32BitProcessWindows(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier)
{
	DWORD LastError = GetLastError();
	BOOL Is32BitProcess = FALSE;

	if (ProcessIdentifier == CURRENT_PROCESS_IDENTIFIER) {
		return sizeof(void*) == 4 ? ZYAN_TRUE : ZYAN_FALSE;
	}

	if (ZynterceptIs32BitSystemWindows()) {
		return ZYAN_TRUE;
	}

	UNREFERENCED_PARAMETER(IsWow64Process((HANDLE)ProcessIdentifier, &Is32BitProcess));
	SetLastError(LastError);

	return Is32BitProcess ? ZYAN_TRUE : ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptIs64BitProcessWindows(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier)
{
	return ZynterceptIs32BitProcessWindows(ProcessIdentifier) ? ZYAN_FALSE : ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptIsUnsupportedProcessArchitectureWindows(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier)
{
	if (ZynterceptIs32BitSystemWindows())
	{
		return ZYAN_FALSE;
	}

	if (ZynterceptIs32BitProcessWindows(CURRENT_PROCESS_IDENTIFIER) &&
		ZynterceptIs64BitProcessWindows(ProcessIdentifier))
	{
		return ZYAN_TRUE;
	}

	return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptIsCurrentProcessWindows(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier)
{
	if (ProcessIdentifier == CURRENT_PROCESS_IDENTIFIER)
	{
		return ZYAN_TRUE;
	}

	return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptVirtualMemoryInformationWindows(
	__zyntercept_out ZynterceptPagedMemoryInformation* Information)
{
	static bool IsCached = false;
	static SYSTEM_INFO SystemInfo = { 0 };

	if (!IsCached) {
		GetSystemInfo(&SystemInfo);
		IsCached = true;
	}

	Information->Ring3LowestAddress = (ZyanU64)SystemInfo.lpMinimumApplicationAddress;
	Information->Ring3HighestAddress = (ZyanU64)SystemInfo.lpMaximumApplicationAddress;
	Information->AllocationGranularity = (ZyanU32)SystemInfo.dwAllocationGranularity;
	Information->AllocationPageSize = (ZyanU32)SystemInfo.dwPageSize;

	return ZYAN_TRUE;
}

ZyanU64 __zyntercept_cdecl ZynterceptAllocateMemoryWindows(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier,
	__zyntercept_in ZynterceptPagedMemory* Page)
{
	DWORD PageState = 0;
	DWORD PageProtection = 0;

	if (ZynterceptIsUnsupportedProcessArchitectureWindows(ProcessIdentifier))
	{
		return 0;
	}

	if (!ZynterceptMapPageStateToWindows(Page->State, &PageState) ||
		!ZynterceptMapPageProtectionToWindows(Page->Protection, &PageProtection))
	{
		return 0;
	}

	HANDLE ProcessHandle = (HANDLE)ProcessIdentifier;
	PVOID BaseAddress = ZYNTERCEPT_CAST_INTEGER(PVOID, ProcessIdentifier, Page->Address);
	SIZE_T RegionSize = ZYNTERCEPT_CAST_INTEGER(SIZE_T, ProcessIdentifier, Page->Size);
	ULONG AllocationType = PageState;
	ULONG Protect = PageProtection;

	NTSTATUS Status = NtAllocateVirtualMemory(
		ProcessHandle, &BaseAddress, NULL, &RegionSize, AllocationType, Protect);

	if (!NT_SUCCESS(Status))
	{
		return 0;
	}

	return (ZyanU64)BaseAddress;
}

ZyanBool __zyntercept_cdecl ZynterceptReleaseMemoryWindows(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier,
	__zyntercept_in ZynterceptPagedMemory* Page)
{
	if (ZynterceptIsUnsupportedProcessArchitectureWindows(ProcessIdentifier))
	{
		return ZYAN_FALSE;
	}

	HANDLE ProcessHandle = (HANDLE)ProcessIdentifier;
	PVOID BaseAddress = ZYNTERCEPT_CAST_INTEGER(PVOID, ProcessIdentifier, Page->Address);
	SIZE_T RegionSize = NULL;
	ULONG FreeType = MEM_RELEASE;

	NTSTATUS Status = NtFreeVirtualMemory(ProcessHandle, &BaseAddress, &RegionSize, FreeType);

	if (!NT_SUCCESS(Status)) {
		return ZYAN_FALSE;
	}

	Page->Address = 0;
	Page->Size = 0;

	return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptProtectMemoryWindows(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier,
	__zyntercept_in ZynterceptPagedMemory* Page)
{
	DWORD NewPageProtection = 0;

	if (ZynterceptIsUnsupportedProcessArchitectureWindows(ProcessIdentifier))
	{
		return ZYAN_FALSE;
	}

	if (!ZynterceptMapPageProtectionToWindows(Page->Protection, &NewPageProtection))
	{
		return ZYAN_FALSE;
	}

	HANDLE ProcessHandle = (HANDLE)ProcessIdentifier;
	PVOID BaseAddress = ZYNTERCEPT_CAST_INTEGER(PVOID, ProcessIdentifier, Page->Address);
	SIZE_T RegionSize = ZYNTERCEPT_CAST_INTEGER(SIZE_T, ProcessIdentifier, Page->Size);
	ULONG NewProtect = NewPageProtection;
	ULONG OldProtect = NULL;

	NTSTATUS Status = NtProtectVirtualMemory(
		ProcessHandle, &BaseAddress, &RegionSize, NewProtect, &OldProtect);

	if (!NT_SUCCESS(Status))
	{
		return ZYAN_FALSE;
	}

	if (!ZynterceptMapPageProtectionFromWindows(OldProtect, &Page->Protection))
	{
		return ZYAN_FALSE;
	}

	if (Page->Protection & ZYNTERCEPT_PAGE_PROTECTION_EXECUTE)
	{
		ZYNTERCEPT_UNREFERENCED(ZynterceptFlushMicroprocessorCacheWindows(ProcessIdentifier, Page));
	}

	return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptQueryMemoryWindows(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier,
	__zyntercept_in ZynterceptPagedMemory* Page)
{
	if (ZynterceptIsUnsupportedProcessArchitectureWindows(ProcessIdentifier))
	{
		return ZYAN_FALSE;
	}

	HANDLE ProcessHandle = (HANDLE)ProcessIdentifier;
	PVOID BaseAddress = ZYNTERCEPT_CAST_INTEGER(PVOID, ProcessIdentifier, Page->Address);
	SIZE_T ReturnLength = 0;

	MEMORY_BASIC_INFORMATION MemoryInfo = { 0 };

	NTSTATUS Status = NtQueryVirtualMemory(
		ProcessHandle,
		BaseAddress,
		MemoryBasicInformation,
		&MemoryInfo,
		sizeof(MEMORY_BASIC_INFORMATION),
		&ReturnLength);

	if (!NT_SUCCESS(Status))
	{
		return ZYAN_FALSE;
	}

	Page->State = 0;
	Page->Protection = 0;
	Page->Size = (ZyanU64)MemoryInfo.RegionSize;
	Page->Address = (ZyanU64)MemoryInfo.BaseAddress;
	
	if (!Page->Address) {
		Page->Address = (ZyanU64)MemoryInfo.AllocationBase;
	}

	MemoryInfo.Protect = MemoryInfo.Protect & ~PAGE_GUARD;
	MemoryInfo.Protect = MemoryInfo.Protect & ~PAGE_NOCACHE;
	MemoryInfo.Protect = MemoryInfo.Protect & ~PAGE_WRITECOMBINE;
	MemoryInfo.Protect = MemoryInfo.Protect & ~PAGE_TARGETS_INVALID;
	MemoryInfo.Protect = MemoryInfo.Protect & ~PAGE_TARGETS_NO_UPDATE;

	if (!ZynterceptMapPageStateFromWindows(MemoryInfo.State, &Page->State) || 
		!ZynterceptMapPageProtectionFromWindows(MemoryInfo.Protect, &Page->Protection))
	{
		return ZYAN_FALSE;
	}

	/* It's useless for our purpose */
	UNREFERENCED_PARAMETER(ReturnLength);

	return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptWriteMemoryWindows(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier,
	__zyntercept_in ZynterceptPagedMemoryOperation* Operation)
{
	if (ZynterceptIsUnsupportedProcessArchitectureWindows(ProcessIdentifier))
	{
		return ZYAN_FALSE;
	}

	HANDLE ProcessHandle = (HANDLE)ProcessIdentifier;
	PVOID BaseAddress = ZYNTERCEPT_CAST_INTEGER(PVOID, ProcessIdentifier, Operation->Address);
	PVOID Buffer = ZYNTERCEPT_CAST_INTEGER(PVOID, ProcessIdentifier, Operation->Buffer);
	SIZE_T NumberOfBytesToWrite = ZYNTERCEPT_CAST_INTEGER(SIZE_T, ProcessIdentifier, Operation->Size);
	SIZE_T NumberOfBytesWritten = 0;

	if (ZynterceptIsCurrentProcessWindows(ProcessIdentifier))
	{
		std::memcpy(BaseAddress, Buffer, NumberOfBytesToWrite);
		return ZYAN_TRUE;
	}

	NTSTATUS Status = NtWriteVirtualMemory(
		ProcessHandle,
		BaseAddress,
		Buffer,
		NumberOfBytesToWrite,
		&NumberOfBytesWritten);

	/* It's useless for our purpose */
	UNREFERENCED_PARAMETER(NumberOfBytesWritten);

	return NT_SUCCESS(Status) ? ZYAN_TRUE : ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptReadMemoryWindows(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier,
	__zyntercept_in ZynterceptPagedMemoryOperation* Operation)
{
	if (ZynterceptIsUnsupportedProcessArchitectureWindows(ProcessIdentifier))
	{
		return ZYAN_FALSE;
	}

	HANDLE ProcessHandle = (HANDLE)ProcessIdentifier;
	PVOID BaseAddress = ZYNTERCEPT_CAST_INTEGER(PVOID, ProcessIdentifier, Operation->Address);
	PVOID Buffer = ZYNTERCEPT_CAST_INTEGER(PVOID, ProcessIdentifier, Operation->Buffer);
	SIZE_T NumberOfBytesToRead = ZYNTERCEPT_CAST_INTEGER(SIZE_T, ProcessIdentifier, Operation->Size);
	SIZE_T NumberOfBytesRead = 0;

	if (ZynterceptIsCurrentProcessWindows(ProcessIdentifier))
	{
		std::memcpy(Buffer, BaseAddress, NumberOfBytesToRead);
		return ZYAN_TRUE;
	}

	NTSTATUS Status = NtReadVirtualMemory(
		ProcessHandle,
		BaseAddress,
		Buffer,
		NumberOfBytesToRead,
		&NumberOfBytesRead);

	/* It's useless for our purpose */
	UNREFERENCED_PARAMETER(NumberOfBytesRead);

	return NT_SUCCESS(Status) ? ZYAN_TRUE : ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptFlushMicroprocessorCacheWindows(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier,
	__zyntercept_in ZynterceptPagedMemory* Page)
{
	if (ZynterceptIsUnsupportedProcessArchitectureWindows(ProcessIdentifier))
	{
		return ZYAN_FALSE;
	}

	HANDLE ProcessHandle = (HANDLE)ProcessIdentifier;
	PVOID BaseAddress = ZYNTERCEPT_CAST_INTEGER(PVOID, ProcessIdentifier, Page->Address);
	SIZE_T Length = ZYNTERCEPT_CAST_INTEGER(SIZE_T, ProcessIdentifier, Page->Size);

	NTSTATUS Status = NtFlushInstructionCache(
		ProcessHandle,
		BaseAddress,
		Length);

	return NT_SUCCESS(Status) ? ZYAN_TRUE : ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptAtomicWriteMemoryWindows(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier,
	__zyntercept_in ZynterceptPagedMemoryOperation* Operations,
	__zyntercept_in ZyanU32 NumberOfOperations)
{
	std::vector<ZynterceptPagedMemory> Pages = {};
	std::vector<ZynterceptPagedMemoryOperation> ReadOperations = {};
	std::vector<ZynterceptPagedMemoryOperation> WriteOperations = {};

	for (ZyanU32 Offset = 0; Offset < NumberOfOperations; Offset++) {
		ZynterceptPagedMemory Page = { 0 };

		Page.Address = Operations[Offset].Address;
		Page.Size = Operations[Offset].Size;
		Page.Protection = ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_EXECUTE | ZYNTERCEPT_PAGE_PROTECTION_WRITE;

		if (!ZynterceptProtectMemoryWindows(ProcessIdentifier, &Page)) {
			goto REVERT_PARTIAL_CHANGES;
		}

		Pages.push_back(Page);
	}

	for (ZyanU32 Offset = 0; Offset < NumberOfOperations; Offset++) {
		ZynterceptPagedMemoryOperation Operation = { 0 };

		Operation.Address = Operations[Offset].Address;
		Operation.Size = Operations[Offset].Size;
		Operation.Buffer = (ZyanU8*)std::malloc(Operations[Offset].Size & 0xFFFFFFFFUL);

		if (!Operation.Buffer) {
			goto REVERT_PARTIAL_CHANGES;
		}

		ZyanBool Status = ZynterceptReadMemoryWindows(ProcessIdentifier, &Operation);

		if (!Status) {
			std::free(Operation.Buffer);

			goto REVERT_PARTIAL_CHANGES;
		}

		ReadOperations.push_back(Operation);
	}

	for (ZyanU32 Offset = 0; Offset < NumberOfOperations; Offset++) {
		ZyanBool Status = ZynterceptWriteMemoryWindows(ProcessIdentifier, &Operations[Offset]);

		WriteOperations.push_back(Operations[Offset]);

		if (!Status) {
			goto REVERT_PARTIAL_CHANGES;
		}
	}

	// Revert all changes in page protections
	for (auto& Page : Pages) {
		ZYNTERCEPT_UNREFERENCED(ZynterceptProtectMemoryWindows(ProcessIdentifier, &Page));
	}

	// Free all read buffers
	for (const auto& ReadOperation : ReadOperations) {
		std::free(ReadOperation.Buffer);
	}

	Pages.clear();
	ReadOperations.clear();
	WriteOperations.clear();

	return ZYAN_TRUE;

REVERT_PARTIAL_CHANGES:
	// Revert all write operations
	for (ZyanU64 Offset = 0; Offset < WriteOperations.size(); Offset++) {
		ZynterceptPagedMemoryOperation* ReadOperation = &ReadOperations[Offset];
		ZYNTERCEPT_UNREFERENCED(ZynterceptWriteMemoryWindows(ProcessIdentifier, ReadOperation));
	}

	// Revert all changes in page protections
	for (auto& Page : Pages) {
		ZYNTERCEPT_UNREFERENCED(ZynterceptProtectMemoryWindows(ProcessIdentifier, &Page));
	}

	// Free all read buffers
	for (const auto& ReadOperation : ReadOperations) {
		std::free(ReadOperation.Buffer);
	}

	Pages.clear();
	ReadOperations.clear();
	WriteOperations.clear();

	return ZYAN_FALSE;
}
