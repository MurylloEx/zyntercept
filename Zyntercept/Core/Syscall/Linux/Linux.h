#ifndef ZYNTERCEPT_LINUX_H
#define ZYNTERCEPT_LINUX_H

#include <Zyntercept/Core/Common/Common.h>

#define ZYNTERCEPT_PAGE_PROTECTION_NONE     (1UL << 0)
#define ZYNTERCEPT_PAGE_PROTECTION_READ     (1UL << 1)
#define ZYNTERCEPT_PAGE_PROTECTION_WRITE    (1UL << 2)
#define ZYNTERCEPT_PAGE_PROTECTION_EXECUTE  (1UL << 3)

#define ZYNTERCEPT_PAGE_STATE_FREE      (1UL << 0)
#define ZYNTERCEPT_PAGE_STATE_COMMITED  (1UL << 1)
#define ZYNTERCEPT_PAGE_STATE_RESERVED  (1UL << 2)

typedef struct ZYNTERCEPT_PAGED_MEMORY_ {
    ZyanU64 Address;
    ZyanU64 Size;
    ZyanU32 State;
    ZyanU32 Protection;
} ZYNTERCEPT_PAGED_MEMORY;

typedef struct ZYNTERCEPT_PAGED_MEMORY_OPERATION_ {
    ZyanU64 Address;
    ZyanU64 Size;
    ZyanU8* Buffer;
} ZYNTERCEPT_PAGED_MEMORY_OPERATION;

typedef struct ZYNTERCEPT_PAGED_MEMORY_INFORMATION_ {
    ZyanU64 Ring3LowestAddress;
    ZyanU64 Ring3HighestAddress;
    ZyanU32 AllocationGranularity;
    ZyanU32 AllocationPageSize;
} ZYNTERCEPT_PAGED_MEMORY_INFORMATION;

typedef ZYNTERCEPT_PAGED_MEMORY ZynterceptPagedMemory;
typedef ZYNTERCEPT_PAGED_MEMORY_OPERATION ZynterceptPagedMemoryOperation;
typedef ZYNTERCEPT_PAGED_MEMORY_INFORMATION ZynterceptPagedMemoryInformation;

ZyanBool __zyntercept_cdecl ZynterceptIs64BitSystemLinux();
ZyanBool __zyntercept_cdecl ZynterceptIs32BitSystemLinux();

ZyanBool __zyntercept_cdecl ZynterceptIs32BitProcessLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier);

ZyanBool __zyntercept_cdecl ZynterceptIs64BitProcessLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier);

ZyanBool __zyntercept_cdecl ZynterceptIsUnsupportedProcessArchitectureLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier);

ZyanBool __zyntercept_cdecl ZynterceptIsCurrentProcessLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier);

ZyanBool __zyntercept_cdecl ZynterceptVirtualMemoryInformationLinux(
    __zyntercept_out ZynterceptPagedMemoryInformation* Information);

ZyanU64 __zyntercept_cdecl ZynterceptAllocateMemoryLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page);

ZyanBool __zyntercept_cdecl ZynterceptReleaseMemoryLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page);

ZyanBool __zyntercept_cdecl ZynterceptProtectMemoryLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page);

ZyanBool __zyntercept_cdecl ZynterceptQueryMemoryLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page);

ZyanBool __zyntercept_cdecl ZynterceptWriteMemoryLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemoryOperation* Operation);

ZyanBool __zyntercept_cdecl ZynterceptReadMemoryLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemoryOperation* Operation);

ZyanBool __zyntercept_cdecl ZynterceptFlushMicroprocessorCacheLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page);

ZyanBool __zyntercept_cdecl ZynterceptAtomicWriteMemoryLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemoryOperation* Operations,
    __zyntercept_in ZyanU32 NumberOfOperations);

#endif // ZYNTERCEPT_LINUX_H
