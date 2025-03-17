#include <Zyntercept/Core/Allocator/Allocator.h>
#include <Zyntercept/Core/Syscall/Syscall.h>

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

    Page.Address = Address;
    Page.Address -= Page.Address % AllocationGranularity;
    Page.Address -= AllocationGranularity;

    while (true)
    {
        if (!ZYNTERCEPT_IS_POINTER_BETWEEN(Page.Address, MaxAddress, MinAddress)) {
            break;
        }

        if (!ZYNTERCEPT_IS_POINTER_BETWEEN(Page.Address, MaxAddress, AllocationGranularity)) {
            break;
        }

        if (!ZynterceptQueryMemory(ProcessIdentifier, &Page)) {
            break;
        }

        if (Page.State == ZYNTERCEPT_PAGE_STATE_FREE) {
            Page.Size = AllocationSize;
            Page.Protection = AllocationProtection;
            Page.State = ZYNTERCEPT_PAGE_STATE_RESERVED | ZYNTERCEPT_PAGE_STATE_COMMITTED;

            ZyanU64 AllocationAddress = ZynterceptAllocateMemory(ProcessIdentifier, &Page);

            if (AllocationAddress) {
                return AllocationAddress;
            }
        }

        Page.Address -= AllocationGranularity;
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

    Page.Address = Address;
    Page.Address -= Page.Address % static_cast<ZyanU64>(AllocationGranularity);
    Page.Address += static_cast<ZyanU64>(AllocationGranularity);

    while (true)
    {
        if (!ZYNTERCEPT_IS_POINTER_BETWEEN(Page.Address, MaxAddress, MinAddress)) {
            break;
        }

        if (!ZYNTERCEPT_IS_POINTER_BETWEEN(Page.Address, MaxAddress, AllocationGranularity)) {
            break;
        }

        if (!ZynterceptQueryMemory(ProcessIdentifier, &Page)) {
            break;
        }

        if (Page.State == ZYNTERCEPT_PAGE_STATE_FREE) {
            Page.Size = AllocationSize;
            Page.Protection = AllocationProtection;
            Page.State = ZYNTERCEPT_PAGE_STATE_RESERVED | ZYNTERCEPT_PAGE_STATE_COMMITTED;

            ZyanU64 AllocationAddress = ZynterceptAllocateMemory(ProcessIdentifier, &Page);

            if (AllocationAddress) {
                return AllocationAddress;
            }
        }

        Page.Address = Page.Address + Page.Size;
        Page.Address += static_cast<ZyanU64>(AllocationGranularity) - 1;
        Page.Address -= Page.Address % static_cast<ZyanU64>(AllocationGranularity);
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
