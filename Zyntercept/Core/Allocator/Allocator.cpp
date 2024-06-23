#include <Zyntercept/Core/Allocator/Allocator.h>

#define ZYNTERCEPT_MAXIMUM_MEMORY_RANGE 0x40000000
#define ZYNTERCEPT_IS_POINTER_BETWEEN(P, MAX, MIN) ((P < MAX) && (P > MIN))

ZyanU64 __zyntercept_cdecl ZynterceptAllocateNearLowerPage(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZyanU64 Address,
    __zyntercept_in ZyanU64 MinAddress,
    __zyntercept_in ZyanU64 MaxAddress,
    __zyntercept_in ZyanU64 AllocationSize,
    __zyntercept_in ZyanU64 AllocationType,
    __zyntercept_in ZyanU32 AllocationProtection,
    __zyntercept_in ZyanU32 AllocationGranularity)
{
    ZynterceptPagedMemory Page = { 0 };
    ZyanU64 CurrentAddress = Address;

    CurrentAddress -= CurrentAddress % AllocationGranularity;
    CurrentAddress -= AllocationGranularity;

    Page.Address = CurrentAddress;

    while (ZynterceptQueryMemory(ProcessIdentifier, &Page))
    {
        if (!ZYNTERCEPT_IS_POINTER_BETWEEN(CurrentAddress, MaxAddress, MinAddress)) {
            break;
        }

        if (!ZYNTERCEPT_IS_POINTER_BETWEEN(CurrentAddress, MaxAddress, AllocationGranularity)) {
            break;
        }

        if (Page.State == ZYNTERCEPT_PAGE_STATE_FREE) {
            Page.Address = CurrentAddress;
            Page.Size = AllocationSize;
            Page.Protection = AllocationProtection;
            Page.State = ZYNTERCEPT_PAGE_STATE_RESERVED | ZYNTERCEPT_PAGE_STATE_COMMITTED;

            return ZynterceptAllocateMemory(ProcessIdentifier, &Page);
        }

        CurrentAddress -= AllocationGranularity;
        Page.Address = CurrentAddress;
    }

    return 0;
}

ZyanU64 __zyntercept_cdecl ZynterceptAllocateNearUpperPage(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZyanU64 Address,
    __zyntercept_in ZyanU64 MinAddress,
    __zyntercept_in ZyanU64 MaxAddress,
    __zyntercept_in ZyanU64 AllocationSize,
    __zyntercept_in ZyanU64 AllocationType,
    __zyntercept_in ZyanU32 AllocationProtection,
    __zyntercept_in ZyanU32 AllocationGranularity)
{
    ZynterceptPagedMemory Page = { 0 };
    ZyanU64 CurrentAddress = Address;

    CurrentAddress -= CurrentAddress % AllocationGranularity;
    CurrentAddress += AllocationGranularity;

    Page.Address = CurrentAddress;

    while (ZynterceptQueryMemory(ProcessIdentifier, &Page))
    {
        if (!ZYNTERCEPT_IS_POINTER_BETWEEN(Page.Address, MaxAddress, MinAddress)) {
            break;
        }

        if (Page.State == ZYNTERCEPT_PAGE_STATE_FREE) {
            Page.Address = CurrentAddress;
            Page.Size = AllocationSize;
            Page.Protection = AllocationProtection;
            Page.State = ZYNTERCEPT_PAGE_STATE_RESERVED | ZYNTERCEPT_PAGE_STATE_COMMITTED;

            return ZynterceptAllocateMemory(ProcessIdentifier, &Page);
        }

        CurrentAddress = Page.Address + Page.Size;
        CurrentAddress += static_cast<ZyanU64>(AllocationGranularity) - 1;
        CurrentAddress -= CurrentAddress % AllocationGranularity;

        Page.Address = CurrentAddress;
    }

    return 0;
}

ZyanU64 __zyntercept_cdecl ZynterceptAllocateNearPage(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZyanU64 Address,
    __zyntercept_in ZyanU64 MinAddress,
    __zyntercept_in ZyanU64 MaxAddress,
    __zyntercept_in ZyanU64 AllocationSize,
    __zyntercept_in ZyanU64 AllocationType,
    __zyntercept_in ZyanU32 AllocationProtection,
    __zyntercept_in ZyanU32 AllocationGranularity)
{
    ZyanU64 NearLowerPageAddress = ZynterceptAllocateNearLowerPage(
        ProcessIdentifier,
        Address,
        MinAddress,
        MaxAddress,
        AllocationSize,
        AllocationType,
        AllocationProtection,
        AllocationGranularity);

    if (NearLowerPageAddress) {
        return NearLowerPageAddress;
    }

    ZyanU64 NearUpperPageAddress = ZynterceptAllocateNearUpperPage(
        ProcessIdentifier,
        Address,
        MinAddress,
        MaxAddress,
        AllocationSize,
        AllocationType,
        AllocationProtection,
        AllocationGranularity);

    return NearUpperPageAddress;
}

ZyanU64 __zyntercept_cdecl ZynterceptAllocateNearestAddress(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZyanU64 Address,
    __zyntercept_in ZyanU64 AllocationSize,
    __zyntercept_in ZyanU64 AllocationType,
    __zyntercept_in ZyanU32 AllocationProtection)
{
    ZynterceptPagedMemoryInformation Information = { 0 };
    ZynterceptVirtualMemoryInformation(&Information);

    ZyanU64 HighestAddress = Information.Ring3HighestAddress;
    ZyanU64 LowestAddress = Information.Ring3LowestAddress;

    /* Look only for the +/- 1GB virtual memory around */
    if (Information.Ring3LowestAddress < Address - ZYNTERCEPT_MAXIMUM_MEMORY_RANGE && Address > ZYNTERCEPT_MAXIMUM_MEMORY_RANGE)
        LowestAddress = Address - ZYNTERCEPT_MAXIMUM_MEMORY_RANGE;

    /* Look only for the +/- 1GB virtual memory around */
    if (Information.Ring3HighestAddress > Address + ZYNTERCEPT_MAXIMUM_MEMORY_RANGE)
        HighestAddress = Address + ZYNTERCEPT_MAXIMUM_MEMORY_RANGE;

    /* Subtract 1 allocation granularity size from maximum address */
    HighestAddress -= static_cast<ZyanU64>(Information.AllocationGranularity) - 1;

    return ZynterceptAllocateNearPage(
        ProcessIdentifier,
        Address,
        LowestAddress,
        HighestAddress,
        AllocationSize,
        AllocationType,
        AllocationProtection,
        Information.AllocationGranularity);
}
