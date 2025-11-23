#include <Zyntercept/Core/Syscall/Unix/Unix.h>

#include <fstream>
#include <sstream>
#include <map>
#include <string>
#include <vector>
#include <limits>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <elf.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/utsname.h>

static ZyanBool ZynterceptReadProcessElfClassUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_out ZyanU8* ElfClass)
{
    std::ifstream ExeFile("/proc/" + std::to_string((uint64_t)ProcessIdentifier) + "/exe", std::ios::binary);
    if (!ExeFile.is_open()) {
        return ZYAN_FALSE;
    }

    uint8_t Ident[EI_NIDENT] = { 0 };
    ExeFile.read(reinterpret_cast<char*>(Ident), sizeof(Ident));

    std::streamsize BytesRead = ExeFile.gcount();
    ExeFile.close();

    if (BytesRead < (std::streamsize)(EI_CLASS + 1)) {
        return ZYAN_FALSE;
    }

    if (Ident[0] != 0x7F || 
        Ident[1] != 'E' || 
        Ident[2] != 'L' || 
        Ident[3] != 'F') 
    {
        return ZYAN_FALSE;
    }

    *ElfClass = Ident[EI_CLASS];
    return ZYAN_TRUE;
}

static ZyanBool ZynterceptMapPageProtectionFromUnix(
    __zyntercept_in const char* UnixProtection,
    __zyntercept_out ZyanU32* ZynterceptPageProtection)
{
    ZyanU32 Protection = 0;

    if (std::strlen(UnixProtection) < 3) {
        return ZYAN_FALSE;
    }

    if (UnixProtection[0] == 'r') {
        Protection |= ZYNTERCEPT_PAGE_PROTECTION_READ;
    }
    if (UnixProtection[1] == 'w') {
        Protection |= ZYNTERCEPT_PAGE_PROTECTION_WRITE;
    }
    if (UnixProtection[2] == 'x') {
        Protection |= ZYNTERCEPT_PAGE_PROTECTION_EXECUTE;
    }

    if (Protection == 0) {
        Protection = ZYNTERCEPT_PAGE_PROTECTION_NONE;
    }

    *ZynterceptPageProtection = Protection;
    return ZYAN_TRUE;
}

static ZyanBool ZynterceptMapPageProtectionToUnix(
    __zyntercept_in ZyanU32 ZynterceptPageProtection,
    __zyntercept_out int* UnixProtection)
{
    int Protection = PROT_NONE;

    ZyanU32 PageProtectionsMask = 
        ZYNTERCEPT_PAGE_PROTECTION_NONE |
        ZYNTERCEPT_PAGE_PROTECTION_READ |
        ZYNTERCEPT_PAGE_PROTECTION_WRITE |
        ZYNTERCEPT_PAGE_PROTECTION_EXECUTE;

    if ((ZynterceptPageProtection & ~PageProtectionsMask) != 0)
    {
        return ZYAN_FALSE;
    }

    if (ZynterceptPageProtection == ZYNTERCEPT_PAGE_PROTECTION_NONE) {
        Protection = PROT_NONE;
    } else {
        if (ZynterceptPageProtection & ZYNTERCEPT_PAGE_PROTECTION_READ) {
            Protection |= PROT_READ;
        }
        
        if (ZynterceptPageProtection & ZYNTERCEPT_PAGE_PROTECTION_WRITE) {
            Protection |= PROT_WRITE;
        }
    
        if (ZynterceptPageProtection & ZYNTERCEPT_PAGE_PROTECTION_EXECUTE) {
            Protection |= PROT_EXEC;
        }
    }

    *UnixProtection = Protection;
    return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptIs64BitSystemUnix()
{
    static bool IsCached = false;
    static ZyanBool Status = ZYAN_FALSE;

    if (IsCached) {
        return Status;
    }

    #if defined(__x86_64__) || defined(__aarch64__) || defined(__LP64__)
        Status = ZYAN_TRUE;
    #else
        if (sizeof(void*) == 8) {
            Status = ZYAN_TRUE;
        } else {
            struct utsname UtsName;
            if (uname(&UtsName) == 0) {
                if (std::strstr(UtsName.machine, "64") != nullptr || 
                    std::strcmp(UtsName.machine, "x86_64") == 0 ||
                    std::strcmp(UtsName.machine, "aarch64") == 0 ||
                    std::strcmp(UtsName.machine, "amd64") == 0) {
                    Status = ZYAN_TRUE;
                } else {
                    Status = ZYAN_FALSE;
                }
            }
        }
    #endif

    IsCached = true;
    return Status;
}

ZyanBool __zyntercept_cdecl ZynterceptIs32BitSystemUnix()
{
    return ZynterceptIs64BitSystemUnix() ? ZYAN_FALSE : ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptIs32BitProcessUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier)
{
    if (ZynterceptIsCurrentProcessUnix(ProcessIdentifier)) {
        return (sizeof(void*) == 4) ? ZYAN_TRUE : ZYAN_FALSE;
    }

    ZyanU8 ElfClass = ELFCLASSNONE;

    if (!ZynterceptReadProcessElfClassUnix(ProcessIdentifier, &ElfClass)) {
        return ZYAN_FALSE;
    }

    return (ElfClass == ELFCLASS32) ? ZYAN_TRUE : ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptIs64BitProcessUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier)
{
    if (ZynterceptIsCurrentProcessUnix(ProcessIdentifier)) {
        return (sizeof(void*) == 8) ? ZYAN_TRUE : ZYAN_FALSE;
    }

    ZyanU8 ElfClass = ELFCLASSNONE;

    if (!ZynterceptReadProcessElfClassUnix(ProcessIdentifier, &ElfClass)) {
        return ZYAN_FALSE;
    }

    return (ElfClass == ELFCLASS64) ? ZYAN_TRUE : ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptIsUnsupportedProcessArchitectureUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier)
{
    if (!ZynterceptIs64BitSystemUnix()) {
        return ZYAN_FALSE;
    }

    if (ZynterceptIs32BitProcessUnix((ZyanVoidPointer)(ZyanU64)getpid()) &&
        ZynterceptIs64BitProcessUnix(ProcessIdentifier))
    {
        return ZYAN_TRUE;
    }

    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptIsCurrentProcessUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier)
{
    if (ProcessIdentifier == (ZyanVoidPointer)(ZyanU64)getpid()) {
        return ZYAN_TRUE;
    }

    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptVirtualMemoryInformationUnix(
    __zyntercept_out ZynterceptPagedMemoryInformation* Information)
{
    static bool IsCached = false;
    static ZynterceptPagedMemoryInformation CachedInfo = { 0 };

    if (IsCached) {
        *Information = CachedInfo;
        return ZYAN_TRUE;
    }

    long PageSize = sysconf(_SC_PAGESIZE);
    if (PageSize == -1) {
        PageSize = getpagesize();
    }

    if (PageSize <= 0) {
        return ZYAN_FALSE;
    }

    CachedInfo.AllocationPageSize = (ZyanU32)PageSize;
    CachedInfo.AllocationGranularity = (ZyanU32)PageSize;

    if (ZynterceptIs64BitSystemUnix()) {
        CachedInfo.Ring3LowestAddress = 0x0000000000000000ULL;
        CachedInfo.Ring3HighestAddress = 0x00007FFFFFFFFFFFULL;
    } else {
        CachedInfo.Ring3LowestAddress = 0x00000000ULL;
        CachedInfo.Ring3HighestAddress = 0x7FFFFFFFULL;
    }

    IsCached = true;
    *Information = CachedInfo;

    return ZYAN_TRUE;
}

ZyanU64 __zyntercept_cdecl ZynterceptAllocateMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page)
{
    if (ZynterceptIsUnsupportedProcessArchitectureUnix(ProcessIdentifier)) {
        return 0;
    }

    if (!ZynterceptIsCurrentProcessUnix(ProcessIdentifier)) {
        return 0;
    }

    if (!Page || Page->Size == 0) {
        return 0;
    }

    int UnixProtection = PROT_NONE;
    if (!ZynterceptMapPageProtectionToUnix(Page->Protection, &UnixProtection)) {
        return 0;
    }

    int Flags = MAP_PRIVATE | MAP_ANONYMOUS;

    if (ZynterceptIs32BitProcessUnix(ProcessIdentifier)) {
        Flags |= MAP_32BIT;
    }

    void* Allocation = mmap(
        (void*)Page->Address,
        Page->Size,
        UnixProtection,
        Flags,
        -1, 0);

    if (Allocation == MAP_FAILED) {
        return 0;
    }

    return (ZyanU64)(ZyanUPointer)Allocation;
}

ZyanBool __zyntercept_cdecl ZynterceptReleaseMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page)
{
    if (ZynterceptIsUnsupportedProcessArchitectureUnix(ProcessIdentifier)) {
        return ZYAN_FALSE;
    }

    if (!ZynterceptIsCurrentProcessUnix(ProcessIdentifier)) {
        return ZYAN_FALSE;
    }

    if (munmap((void*)Page->Address, Page->Size) != 0) {
        return ZYAN_FALSE;
    }

    Page->Address = 0;
    Page->Size = 0;

    return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptProtectMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page)
{
    if (!ZynterceptIsCurrentProcessUnix(ProcessIdentifier)) {
        return ZYAN_FALSE;
    }

    if (!Page || !Page->Address || !Page->Size) {
        return ZYAN_FALSE;
    }

    ZynterceptPagedMemory PreviousInformation = {0};

    PreviousInformation.Address = Page->Address;
    PreviousInformation.Size = Page->Size;

    if (!ZynterceptQueryMemoryUnix(ProcessIdentifier, &PreviousInformation)) {
        return ZYAN_FALSE;
    }

    int UnixProtection = PROT_NONE;

    if (!ZynterceptMapPageProtectionToUnix(Page->Protection, &UnixProtection)) {
        return ZYAN_FALSE;
    }

    ZynterceptPagedMemoryInformation Information = { 0 };

    if (!ZynterceptVirtualMemoryInformationUnix(&Information)) {
        return ZYAN_FALSE;
    }

    ZyanUPointer PageSize = Information.AllocationPageSize;
    ZyanUPointer AlignedAddress = Page->Address & ~(PageSize - 1);
    ZyanUSize Offset = Page->Address - AlignedAddress;
    ZyanUSize AlignedSize = ((Page->Size + Offset + PageSize - 1) / PageSize) * PageSize;

    if (mprotect((void*)AlignedAddress, AlignedSize, UnixProtection) != 0) {
        return ZYAN_FALSE;
    }

    Page->Protection = PreviousInformation.Protection;

    if (Page->Protection & ZYNTERCEPT_PAGE_PROTECTION_EXECUTE) {
        ZYNTERCEPT_UNREFERENCED(ZynterceptFlushMicroprocessorCacheUnix(ProcessIdentifier, Page));
    }

    return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptQueryMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page)
{
    if (ZynterceptIsUnsupportedProcessArchitectureUnix(ProcessIdentifier)) {
        return ZYAN_FALSE;
    }

    if (!Page || !Page->Address) {
        return ZYAN_FALSE;
    }

    pid_t TargetPid = (pid_t)(ZyanU64)ProcessIdentifier;

    std::ifstream AllocationTable("/proc/" + std::to_string(TargetPid) + "/maps");

    if (!AllocationTable.is_open()) {
        return ZYAN_FALSE;
    }

    std::string Line;
    bool HasFoundAllocation = false;

    while (std::getline(AllocationTable, Line)) {
        unsigned long long BeginAddress = 0;
        unsigned long long EndAddress = 0;
        char Permissions[5] = {0};
        unsigned long long Offset = 0;
        unsigned int Major = 0;
        unsigned int Minor = 0;
        unsigned long long Inode = 0;
        char Pathname[256] = {0};

        int Parsed = std::sscanf(
            Line.c_str(), 
            "%llx-%llx %4s %llx %x:%x %llu %255[^\n]",
            &BeginAddress, 
            &EndAddress, 
            Permissions, 
            &Offset, 
            &Major, 
            &Minor, 
            &Inode, 
            Pathname);

        if (Parsed < 3) continue;

        if (Page->Address >= (ZyanU64)BeginAddress && Page->Address < (ZyanU64)EndAddress)
        {
            if (!ZynterceptMapPageProtectionFromUnix(Permissions, &Page->Protection)) {
                goto UNSUCCESSFUL_STATUS;
            }

            Page->Address = (ZyanU64)BeginAddress;
            Page->Size = (ZyanU64)EndAddress - (ZyanU64)BeginAddress;
            Page->State = ZYNTERCEPT_PAGE_STATE_COMMITTED;

            HasFoundAllocation = true;
            break;
        }
    }

    if (!HasFoundAllocation) {
        ZynterceptPagedMemoryInformation Information = { 0 };

        if (!ZynterceptVirtualMemoryInformationUnix(&Information)) {
            goto UNSUCCESSFUL_STATUS;
        }

        ZyanU64 PageMask = Information.AllocationPageSize - 1;
        ZyanU64 AlignedAddress = Page->Address & ~PageMask;

        Page->Address = AlignedAddress;
        Page->Size = Information.AllocationPageSize;
        Page->Protection = ZYNTERCEPT_PAGE_PROTECTION_NONE;
        Page->State = ZYNTERCEPT_PAGE_STATE_FREE;
    }

    AllocationTable.close();
    return ZYAN_TRUE;

UNSUCCESSFUL_STATUS:
    AllocationTable.close();
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptWriteMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemoryOperation* Operation)
{
    if (ZynterceptIsUnsupportedProcessArchitectureUnix(ProcessIdentifier)) {
        return ZYAN_FALSE;
    }

    if (!ZynterceptIsCurrentProcessUnix(ProcessIdentifier)) {
        return ZYAN_FALSE;
    }

    memcpy((void*)Operation->Address, Operation->Buffer, Operation->Size);

    return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptReadMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemoryOperation* Operation)
{
    if (ZynterceptIsUnsupportedProcessArchitectureUnix(ProcessIdentifier)) {
        return ZYAN_FALSE;
    }

    if (!ZynterceptIsCurrentProcessUnix(ProcessIdentifier)) {
        return ZYAN_FALSE;
    }

    memcpy(Operation->Buffer, (void*)Operation->Address, Operation->Size);

    return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptFlushMicroprocessorCacheUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page)
{
    if (ZynterceptIsUnsupportedProcessArchitectureUnix(ProcessIdentifier)) {
        return ZYAN_FALSE;
    }

    if (!ZynterceptIsCurrentProcessUnix(ProcessIdentifier)) {
        return ZYAN_FALSE;
    }

    void* BeginAddress = (void*)Page->Address;
    void* EndAddress = (void*)((char*)BeginAddress + Page->Size);
    
    __builtin___clear_cache(BeginAddress, EndAddress);
    
    return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptAtomicWriteMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemoryOperation* Operations,
    __zyntercept_in ZyanU32 NumberOfOperations)
{
    if (!Operations || NumberOfOperations == 0) {
        return ZYAN_FALSE;
    }

    std::vector<ZynterceptPagedMemory> Pages;
    std::vector<ZynterceptPagedMemoryOperation> ReadOperations;
    std::vector<ZynterceptPagedMemoryOperation> WriteOperations;

    Pages.reserve(NumberOfOperations);
    ReadOperations.reserve(NumberOfOperations);
    WriteOperations.reserve(NumberOfOperations);

    for (ZyanU32 Offset = 0; Offset < NumberOfOperations; ++Offset) {
        ZynterceptPagedMemory Page = { 0 };
        Page.Address = Operations[Offset].Address;
        Page.Size = Operations[Offset].Size;
        Page.Protection = ZYNTERCEPT_PAGE_PROTECTION_READ |
            ZYNTERCEPT_PAGE_PROTECTION_WRITE |
            ZYNTERCEPT_PAGE_PROTECTION_EXECUTE;

        if (!ZynterceptProtectMemoryUnix(ProcessIdentifier, &Page)) {
            goto REVERT_PARTIAL_CHANGES;
        }

        Pages.push_back(Page);
    }

    for (ZyanU32 Offset = 0; Offset < NumberOfOperations; ++Offset) {
        ZynterceptPagedMemoryOperation Operation = { 0 };
        Operation.Address = Operations[Offset].Address;
        Operation.Size = Operations[Offset].Size;
        Operation.Buffer = (ZyanU8*)std::malloc((size_t)Operations[Offset].Size);

        if (!Operation.Buffer) {
            goto REVERT_PARTIAL_CHANGES;
        }

        if (!ZynterceptReadMemoryUnix(ProcessIdentifier, &Operation)) {
            std::free(Operation.Buffer);
            goto REVERT_PARTIAL_CHANGES;
        }

        ReadOperations.push_back(Operation);
    }

    for (ZyanU32 Offset = 0; Offset < NumberOfOperations; ++Offset) {
        if (!ZynterceptWriteMemoryUnix(ProcessIdentifier, &Operations[Offset])) {
            goto REVERT_PARTIAL_CHANGES;
        }

        WriteOperations.push_back(Operations[Offset]);
    }

    for (auto& Page : Pages) {
        ZYNTERCEPT_UNREFERENCED(ZynterceptProtectMemoryUnix(ProcessIdentifier, &Page));
    }

    for (const auto& ReadOperation : ReadOperations) {
        std::free(ReadOperation.Buffer);
    }

    Pages.clear();
    ReadOperations.clear();
    WriteOperations.clear();

    return ZYAN_TRUE;

REVERT_PARTIAL_CHANGES:
    for (ZyanU64 Offset = 0; Offset < WriteOperations.size(); ++Offset) {
        ZynterceptPagedMemoryOperation* ReadOperation = &ReadOperations[Offset];
        ZYNTERCEPT_UNREFERENCED(ZynterceptWriteMemoryUnix(ProcessIdentifier, ReadOperation));
    }

    for (auto& Page : Pages) {
        ZYNTERCEPT_UNREFERENCED(ZynterceptProtectMemoryUnix(ProcessIdentifier, &Page));
    }

    for (const auto& ReadOperation : ReadOperations) {
        std::free(ReadOperation.Buffer);
    }

    Pages.clear();
    ReadOperations.clear();
    WriteOperations.clear();

    return ZYAN_FALSE;
}
