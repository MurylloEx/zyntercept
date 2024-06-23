#ifndef ZYNTERCEPT_WINDOWS_H
#define ZYNTERCEPT_WINDOWS_H

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

ZyanBool __zyntercept_cdecl ZynterceptIs64BitSystemWindows();
ZyanBool __zyntercept_cdecl ZynterceptIs32BitSystemWindows();

ZyanBool __zyntercept_cdecl ZynterceptIs32BitProcessWindows(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier);

ZyanBool __zyntercept_cdecl ZynterceptIs64BitProcessWindows(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier);

ZyanBool __zyntercept_cdecl ZynterceptIsUnsupportedProcessArchitectureWindows(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier);

ZyanBool __zyntercept_cdecl ZynterceptIsCurrentProcessWindows(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier);

ZyanBool __zyntercept_cdecl ZynterceptVirtualMemoryInformationWindows(
    __zyntercept_out ZynterceptPagedMemoryInformation* Information);

ZyanU64 __zyntercept_cdecl ZynterceptAllocateMemoryWindows(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page);

ZyanBool __zyntercept_cdecl ZynterceptReleaseMemoryWindows(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page);

ZyanBool __zyntercept_cdecl ZynterceptProtectMemoryWindows(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page);

ZyanBool __zyntercept_cdecl ZynterceptQueryMemoryWindows(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page);

ZyanBool __zyntercept_cdecl ZynterceptWriteMemoryWindows(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemoryOperation* Operation);

ZyanBool __zyntercept_cdecl ZynterceptReadMemoryWindows(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemoryOperation* Operation);

ZyanBool __zyntercept_cdecl ZynterceptFlushMicroprocessorCacheWindows(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* Page);

ZyanBool __zyntercept_cdecl ZynterceptAtomicWriteMemoryWindows(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemoryOperation* Operations,
    __zyntercept_in ZyanU32 NumberOfOperations);

#endif // ZYNTERCEPT_WINDOWS_H
