#ifndef ZYNTERCEPT_ALLOCATOR_H
#define ZYNTERCEPT_ALLOCATOR_H

#include <Zyntercept/Core/Common/Common.h>

ZyanU64 __zyntercept_cdecl ZynterceptAllocateNearLowerPage(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZyanU64 Address,
    __zyntercept_in ZyanU64 MinAddress,
    __zyntercept_in ZyanU64 MaxAddress,
    __zyntercept_in ZyanU64 AllocationSize,
    __zyntercept_in ZyanU64 AllocationType,
    __zyntercept_in ZyanU32 AllocationProtection,
    __zyntercept_in ZyanU32 AllocationGranularity);

ZyanU64 __zyntercept_cdecl ZynterceptAllocateNearUpperPage(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZyanU64 Address,
    __zyntercept_in ZyanU64 MinAddress,
    __zyntercept_in ZyanU64 MaxAddress,
    __zyntercept_in ZyanU64 AllocationSize,
    __zyntercept_in ZyanU64 AllocationType,
    __zyntercept_in ZyanU32 AllocationProtection,
    __zyntercept_in ZyanU32 AllocationGranularity);

ZyanU64 __zyntercept_cdecl ZynterceptAllocateNearPage(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZyanU64 Address,
    __zyntercept_in ZyanU64 MinAddress,
    __zyntercept_in ZyanU64 MaxAddress,
    __zyntercept_in ZyanU64 AllocationSize,
    __zyntercept_in ZyanU64 AllocationType,
    __zyntercept_in ZyanU32 AllocationProtection,
    __zyntercept_in ZyanU32 AllocationGranularity);

ZyanU64 __zyntercept_cdecl ZynterceptAllocateNearestAddress(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZyanU64 Address,
    __zyntercept_in ZyanU64 AllocationSize,
    __zyntercept_in ZyanU64 AllocationType,
    __zyntercept_in ZyanU32 AllocationProtection);

#endif // ZYNTERCEPT_ALLOCATOR_H
