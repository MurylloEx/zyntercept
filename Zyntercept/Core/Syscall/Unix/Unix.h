#ifndef ZYNTERCEPT_UNIX_H
#define ZYNTERCEPT_UNIX_H

#include <Zyntercept/Core/Common/Common.h>

#define ZYNTERCEPT_PAGE_PROTECTION_NONE     (1UL << 0)
#define ZYNTERCEPT_PAGE_PROTECTION_READ     (1UL << 1)
#define ZYNTERCEPT_PAGE_PROTECTION_WRITE    (1UL << 2)
#define ZYNTERCEPT_PAGE_PROTECTION_EXECUTE  (1UL << 3)

#define ZYNTERCEPT_PAGE_STATE_FREE          (1UL << 0)
#define ZYNTERCEPT_PAGE_STATE_COMMITTED     (1UL << 1)
#define ZYNTERCEPT_PAGE_STATE_RESERVED      (1UL << 2)

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

ZyanBool __zyntercept_cdecl ZynterceptIs64BitSystemUnix();
ZyanBool __zyntercept_cdecl ZynterceptIs32BitSystemUnix();

ZyanBool __zyntercept_cdecl ZynterceptIs32BitProcessUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier);

ZyanBool __zyntercept_cdecl ZynterceptIs64BitProcessUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier);

ZyanBool __zyntercept_cdecl ZynterceptIsUnsupportedProcessArchitectureUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier);

ZyanBool __zyntercept_cdecl ZynterceptIsCurrentProcessUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier);

ZyanBool __zyntercept_cdecl ZynterceptVirtualMemoryInformationUnix(
    __zyntercept_out ZynterceptPagedMemoryInformation* Information);

ZyanU64 __zyntercept_cdecl ZynterceptAllocateMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page);

ZyanBool __zyntercept_cdecl ZynterceptReleaseMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page);

ZyanBool __zyntercept_cdecl ZynterceptProtectMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page);

ZyanBool __zyntercept_cdecl ZynterceptQueryMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page);

ZyanBool __zyntercept_cdecl ZynterceptWriteMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemoryOperation* Operation);

ZyanBool __zyntercept_cdecl ZynterceptReadMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemoryOperation* Operation);

ZyanBool __zyntercept_cdecl ZynterceptFlushMicroprocessorCacheUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page);

ZyanBool __zyntercept_cdecl ZynterceptAtomicWriteMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemoryOperation* Operations,
    __zyntercept_in ZyanU32 NumberOfOperations);

#endif // ZYNTERCEPT_UNIX_H
