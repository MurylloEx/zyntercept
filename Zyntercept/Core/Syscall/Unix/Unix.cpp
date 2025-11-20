#include <Zyntercept/Core/Syscall/Unix/Unix.h>

#include <unistd.h>
#include <sys/utsname.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <vector>
#include <cstdio>
#include <elf.h>
#include <limits>
#include <cstdint>
#include <cstdlib>

#define CURRENT_PROCESS_IDENTIFIER_UNIX (ZyanVoidPointer)-1

static ZyanBool ZynterceptReadProcessElfClassUnix(
    __zyntercept_in pid_t ProcessId,
    __zyntercept_out ZyanU8* ElfClass)
{
    char ExePath[64] = { 0 };
    std::snprintf(ExePath, sizeof(ExePath), "/proc/%d/exe", ProcessId);

    std::ifstream ExeFile(ExePath, std::ios::binary);
    if (!ExeFile.is_open()) {
        return ZYAN_FALSE;
    }

    unsigned char Ident[EI_NIDENT] = { 0 };
    ExeFile.read(reinterpret_cast<char*>(Ident), sizeof(Ident));

    std::streamsize BytesRead = ExeFile.gcount();
    ExeFile.close();

    if (BytesRead < (std::streamsize)(EI_CLASS + 1)) {
        return ZYAN_FALSE;
    }

    if (Ident[0] != 0x7F || Ident[1] != 'E' || Ident[2] != 'L' || Ident[3] != 'F') {
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
    int Protection = 0;

    if ((ZynterceptPageProtection & ~(
            ZYNTERCEPT_PAGE_PROTECTION_NONE |
            ZYNTERCEPT_PAGE_PROTECTION_READ |
            ZYNTERCEPT_PAGE_PROTECTION_WRITE |
            ZYNTERCEPT_PAGE_PROTECTION_EXECUTE)) != 0) {
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

        if (Protection == 0) {
            Protection = PROT_NONE;
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

    pid_t TargetPid = (pid_t)(ZyanU64)ProcessIdentifier;
    ZyanU8 ElfClass = ELFCLASSNONE;

    if (!ZynterceptReadProcessElfClassUnix(TargetPid, &ElfClass)) {
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

    pid_t TargetPid = (pid_t)(ZyanU64)ProcessIdentifier;
    ZyanU8 ElfClass = ELFCLASSNONE;

    if (!ZynterceptReadProcessElfClassUnix(TargetPid, &ElfClass)) {
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

    if (ZynterceptIs32BitProcessUnix(CURRENT_PROCESS_IDENTIFIER_UNIX) &&
        ZynterceptIs64BitProcessUnix(ProcessIdentifier))
    {
        return ZYAN_TRUE;
    }

    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptIsCurrentProcessUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier)
{
    if (ProcessIdentifier == CURRENT_PROCESS_IDENTIFIER_UNIX) {
        return ZYAN_TRUE;
    }

    pid_t CurrentPid = getpid();
    if ((pid_t)(ZyanU64)ProcessIdentifier == CurrentPid) {
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
    __zyntercept_in ZynterceptPagedMemory* MemoryBlock)
{
    if (!ZynterceptIsCurrentProcessUnix(ProcessIdentifier)) {
        return 0;
    }

    if (!MemoryBlock || MemoryBlock->Size == 0) {
        return 0;
    }

    ZynterceptPagedMemoryInformation VmInfo = { 0 };
    if (!ZynterceptVirtualMemoryInformationUnix(&VmInfo)) {
        return 0;
    }

    int UnixProtection = PROT_NONE;
    if (!ZynterceptMapPageProtectionToUnix(MemoryBlock->Protection, &UnixProtection)) {
        return 0;
    }

    ZyanU64 AllocationGranularity = (ZyanU64)VmInfo.AllocationGranularity;
    ZyanU64 GranularityMask = AllocationGranularity - 1;
    ZyanU64 AdjustedSize = (MemoryBlock->Size + GranularityMask) & ~GranularityMask;

    if (AdjustedSize == 0 ||
        AdjustedSize > (ZyanU64)std::numeric_limits<size_t>::max()) {
        return 0;
    }

    void* RequestedAddress = nullptr;
    if (MemoryBlock->Address != 0) {
        RequestedAddress = reinterpret_cast<void*>(
            (uintptr_t)(MemoryBlock->Address & ~GranularityMask));
    }

    void* Allocation = mmap(
        RequestedAddress,
        (size_t)AdjustedSize,
        UnixProtection,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0);

    if (Allocation == MAP_FAILED) {
        return 0;
    }

    ZynterceptPagedMemory QueriedBlock = { 0 };
    QueriedBlock.Address = (ZyanU64)(uintptr_t)Allocation;

    if (ZynterceptQueryMemoryUnix(CURRENT_PROCESS_IDENTIFIER_UNIX, &QueriedBlock)) {
        *MemoryBlock = QueriedBlock;
    } else {
        MemoryBlock->Address = (ZyanU64)(uintptr_t)Allocation;
        MemoryBlock->Size = AdjustedSize;
        MemoryBlock->State = ZYNTERCEPT_PAGE_STATE_COMMITED;
        MemoryBlock->Protection = ZYNTERCEPT_PAGE_PROTECTION_NONE;
    }

    return (ZyanU64)(uintptr_t)Allocation;
}

ZyanBool __zyntercept_cdecl ZynterceptReleaseMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page)
{
    if (!ZynterceptIsCurrentProcessUnix(ProcessIdentifier)) {
        return ZYAN_FALSE;
    }

    if (!Page || Page->Address == 0 || Page->Size == 0) {
        return ZYAN_FALSE;
    }

    void* UnmapAddress = reinterpret_cast<void*>((uintptr_t)Page->Address);
    size_t UnmapSize = (size_t)Page->Size;

    if (munmap(UnmapAddress, UnmapSize) != 0) {
        return ZYAN_FALSE;
    }

    Page->Address = 0;
    Page->Size = 0;
    Page->State = ZYNTERCEPT_PAGE_STATE_FREE;
    Page->Protection = ZYNTERCEPT_PAGE_PROTECTION_NONE;

    return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptProtectMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* MemoryBlock)
{
    if (!ZynterceptIsCurrentProcessUnix(ProcessIdentifier)) {
        return ZYAN_FALSE;
    }

    if (!MemoryBlock || MemoryBlock->Address == 0) {
        return ZYAN_FALSE;
    }

    ZynterceptPagedMemory CurrentInfo = { 0 };
    CurrentInfo.Address = MemoryBlock->Address;

    if (!ZynterceptQueryMemoryUnix(ProcessIdentifier, &CurrentInfo)) {
        return ZYAN_FALSE;
    }

    ZyanU64 RequestedProtection = MemoryBlock->Protection;
    int UnixProtection = PROT_NONE;

    if (!ZynterceptMapPageProtectionToUnix(RequestedProtection, &UnixProtection)) {
        return ZYAN_FALSE;
    }

    long PageSize = sysconf(_SC_PAGESIZE);
    if (PageSize <= 0) {
        PageSize = getpagesize();
    }

    if (PageSize <= 0) {
        return ZYAN_FALSE;
    }

    ZyanU64 RegionSize = MemoryBlock->Size ? MemoryBlock->Size : CurrentInfo.Size;
    if (RegionSize == 0) {
        return ZYAN_FALSE;
    }

    ZyanU64 PageSizeU = (ZyanU64)PageSize;
    ZyanU64 PageMask = PageSizeU - 1;
    ZyanU64 AlignedAddress = MemoryBlock->Address & ~PageMask;
    ZyanU64 Offset = MemoryBlock->Address - AlignedAddress;
    ZyanU64 AdjustedSize = RegionSize + Offset;
    AdjustedSize = (AdjustedSize + PageMask) & ~PageMask;

    if (AlignedAddress > (ZyanU64)std::numeric_limits<uintptr_t>::max() ||
        AdjustedSize > (ZyanU64)std::numeric_limits<size_t>::max()) {
        return ZYAN_FALSE;
    }

    void* ProtectAddress = reinterpret_cast<void*>((uintptr_t)AlignedAddress);
    size_t ProtectSize = (size_t)AdjustedSize;

    if (mprotect(ProtectAddress, ProtectSize, UnixProtection) != 0) {
        return ZYAN_FALSE;
    }

    MemoryBlock->Protection = CurrentInfo.Protection;

    if (MemoryBlock->Protection & ZYNTERCEPT_PAGE_PROTECTION_EXECUTE) {
        ZYNTERCEPT_UNREFERENCED(ZynterceptFlushMicroprocessorCacheUnix(ProcessIdentifier, MemoryBlock));
    }

    return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptQueryMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* MemoryBlock)
{
    pid_t TargetPid;
    
    if (ZynterceptIsCurrentProcessUnix(ProcessIdentifier)) {
        TargetPid = getpid();
    } else {
        TargetPid = (pid_t)(ZyanU64)ProcessIdentifier;
    }

    char MapsPath[256];
    std::snprintf(MapsPath, sizeof(MapsPath), "/proc/%d/maps", TargetPid);

    std::ifstream MapsFile(MapsPath);
    if (!MapsFile.is_open()) {
        return ZYAN_FALSE;
    }

    ZyanU64 TargetAddress = MemoryBlock->Address;
    std::string Line;

    while (std::getline(MapsFile, Line)) {
        unsigned long long StartAddr, EndAddr;
        char Permissions[5] = {0};
        unsigned long long Offset;
        unsigned int Major, Minor;
        unsigned long long Inode;
        char Pathname[256] = {0};

        int Parsed = std::sscanf(Line.c_str(), "%llx-%llx %4s %llx %x:%x %llu %255[^\n]",
            &StartAddr, &EndAddr, Permissions, &Offset, &Major, &Minor, &Inode, Pathname);

        if (Parsed < 3) {
            continue;
        }

        if (TargetAddress >= (ZyanU64)StartAddr && TargetAddress < (ZyanU64)EndAddr) {
            MemoryBlock->Address = (ZyanU64)StartAddr;
            MemoryBlock->Size = (ZyanU64)EndAddr - (ZyanU64)StartAddr;

            if (!ZynterceptMapPageProtectionFromUnix(Permissions, &MemoryBlock->Protection)) {
                MapsFile.close();
                return ZYAN_FALSE;
            }

            MemoryBlock->State = ZYNTERCEPT_PAGE_STATE_COMMITED;

            MapsFile.close();
            return ZYAN_TRUE;
        }
    }

    MapsFile.close();
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptWriteMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemoryOperation* Request)
{
    if (ZynterceptIsCurrentProcessUnix(ProcessIdentifier)) {
        std::memcpy((void*)Request->Address, Request->Buffer, Request->Size);
        return ZYAN_TRUE;
    }

    pid_t TargetPid = (pid_t)(ZyanU64)ProcessIdentifier;
    
    struct iovec LocalIov;
    LocalIov.iov_base = Request->Buffer;
    LocalIov.iov_len = Request->Size;

    struct iovec RemoteIov;
    RemoteIov.iov_base = (void*)Request->Address;
    RemoteIov.iov_len = Request->Size;

    ssize_t BytesWritten = process_vm_writev(TargetPid, &LocalIov, 1, &RemoteIov, 1, 0);
    
    if (BytesWritten == -1) {
        return ZYAN_FALSE;
    }

    if ((ZyanU64)BytesWritten != Request->Size) {
        return ZYAN_FALSE;
    }

    return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptReadMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemoryOperation* Request)
{
    if (ZynterceptIsCurrentProcessUnix(ProcessIdentifier)) {
        std::memcpy(Request->Buffer, (void*)Request->Address, Request->Size);
        return ZYAN_TRUE;
    }

    pid_t TargetPid = (pid_t)(ZyanU64)ProcessIdentifier;
    
    struct iovec LocalIov;
    LocalIov.iov_base = Request->Buffer;
    LocalIov.iov_len = Request->Size;

    struct iovec RemoteIov;
    RemoteIov.iov_base = (void*)Request->Address;
    RemoteIov.iov_len = Request->Size;

    ssize_t BytesRead = process_vm_readv(TargetPid, &LocalIov, 1, &RemoteIov, 1, 0);
    
    if (BytesRead == -1) {
        return ZYAN_FALSE;
    }

    if ((ZyanU64)BytesRead != Request->Size) {
        return ZYAN_FALSE;
    }

    return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptFlushMicroprocessorCacheUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* MemoryBlock)
{
    if (!ZynterceptIsCurrentProcessUnix(ProcessIdentifier)) {
        return ZYAN_FALSE;
    }

    void* Begin = (void*)MemoryBlock->Address;
    void* End = (void*)((char*)Begin + MemoryBlock->Size);
    
    __builtin___clear_cache(Begin, End);
    
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
