#include <catch2/catch_test_macros.hpp>
#include <Zyntercept/Core/Allocator/Allocator.h>
#include <Zyntercept/Core/Syscall/Syscall.h>

#if defined(ZYNTERCEPT_WINDOWS)
#include <Windows.h>
static ZyanVoidPointer ProcessIdentifier = GetCurrentProcess();
#endif

#if defined(ZYNTERCEPT_UNIX)
#include <unistd.h>
static ZyanVoidPointer ProcessIdentifier = (ZyanVoidPointer)getpid();
#endif

SCENARIO("Zyntercept memory allocation near a target address", "[allocator]")
{
    GIVEN("A minimum and maximum range of valid addresses and a specific allocation size, type, and protection")
    {
        ZyanU64 TargetAddress = 0x70000000ULL;
        ZyanU64 MinAddress = 0x10000000ULL;
        ZyanU64 MaxAddress = 0x7fffffffULL;
        ZyanU64 AllocationSize = 0x1000ULL;
        ZyanU32 AllocationType = ZYNTERCEPT_PAGE_STATE_RESERVED | ZYNTERCEPT_PAGE_STATE_COMMITTED;
        ZyanU32 AllocationProtection = ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_WRITE;
        ZyanU64 AllocationGranularity = 0x10000ULL;
        ZynterceptPagedMemory Page = { 0 };

        AND_GIVEN("I want to allocate memory near a target address")
        {
            Page.Address = ZynterceptAllocateNearPage(
                ProcessIdentifier,
                TargetAddress,
                MinAddress,
                MaxAddress,
                AllocationSize,
                AllocationType,
                AllocationProtection,
                AllocationGranularity);

            REQUIRE(ZynterceptQueryMemory(ProcessIdentifier, &Page) == ZYAN_TRUE);

            WHEN("I allocate the memory using ZynterceptAllocateNearPage")
            {
                THEN("The allocation should succeed")
                {
                    REQUIRE(Page.Address != 0);
                }

                AND_THEN("The allocated address should be within the maximum allowed range of the target address")
                {
                    if (TargetAddress > Page.Address) {
                        REQUIRE(TargetAddress - Page.Address <= ZYNTERCEPT_MAXIMUM_MEMORY_RANGE);
                    }
                    else {
                        REQUIRE(Page.Address - TargetAddress <= ZYNTERCEPT_MAXIMUM_MEMORY_RANGE);
                    }
                }

                AND_THEN("The allocated address should be between the minimum and maximum range")
                {
                    REQUIRE(Page.Address >= MinAddress);
                    REQUIRE(Page.Address <= MaxAddress);
                }

                AND_THEN("The allocation size should be as specified")
                {
                    REQUIRE(Page.Size == AllocationSize);
                }

                AND_THEN("The allocation state should match the specified allocation type")
                {
                    REQUIRE(Page.State == (AllocationType & ZYNTERCEPT_PAGE_STATE_COMMITTED));
                }

                AND_THEN("The allocation protection should match the specified protection")
                {
                    REQUIRE(Page.Protection == AllocationProtection);
                }
            }
        }

        REQUIRE(ZynterceptReleaseMemory(ProcessIdentifier, &Page) == ZYAN_TRUE);
    }
}

SCENARIO("Zyntercept memory allocation near a higher target address", "[allocator]")
{
    GIVEN("A minimum and maximum range of valid addresses and a specific allocation size, type, and protection")
    {
        ZyanU64 TargetAddress = 0x70000000ULL;
        ZyanU64 MinAddress = 0x00010000ULL;
        ZyanU64 MaxAddress = 0x7fffffffULL;
        ZyanU64 AllocationSize = 0x1000ULL;
        ZyanU32 AllocationType = ZYNTERCEPT_PAGE_STATE_RESERVED | ZYNTERCEPT_PAGE_STATE_COMMITTED;
        ZyanU32 AllocationProtection = ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_WRITE;
        ZyanU64 AllocationGranularity = 0x10000ULL;
        ZynterceptPagedMemory Page = { 0 };
        
        AND_GIVEN("I want to allocate memory near a target address, but higher than it")
        {
            Page.Address = ZynterceptAllocateNearUpperPage(
                ProcessIdentifier,
                TargetAddress,
                MinAddress,
                MaxAddress,
                AllocationSize,
                AllocationType,
                AllocationProtection,
                AllocationGranularity);

            REQUIRE(ZynterceptQueryMemory(ProcessIdentifier, &Page) == ZYAN_TRUE);

            WHEN("I allocate the memory using ZynterceptAllocateNearUpperPage")
            {
                THEN("The allocation should succeed")
                {
                    REQUIRE(Page.Address != 0);
                }

                AND_THEN("The allocated address should be within the maximum allowed range of the target address")
                {
                    REQUIRE(Page.Address - TargetAddress <= ZYNTERCEPT_MAXIMUM_MEMORY_RANGE);
                }

                AND_THEN("The allocated address should be greater than the target address")
                {
                    REQUIRE(Page.Address > TargetAddress);
                }

                AND_THEN("The allocated address should be between the minimum and maximum range")
                {
                    REQUIRE(Page.Address >= MinAddress);
                    REQUIRE(Page.Address <= MaxAddress);
                }

                AND_THEN("The allocation size should be as specified")
                {
                    REQUIRE(Page.Size == AllocationSize);
                }

                AND_THEN("The allocation state should match the specified allocation type")
                {
                    REQUIRE(Page.State == (AllocationType & ZYNTERCEPT_PAGE_STATE_COMMITTED));
                }

                AND_THEN("The allocation protection should match the specified protection")
                {
                    REQUIRE(Page.Protection == AllocationProtection);
                }
            }
        }

        REQUIRE(ZynterceptReleaseMemory(ProcessIdentifier, &Page) == ZYAN_TRUE);
    }
}

SCENARIO("Zyntercept memory allocation near a lower target address", "[allocator]")
{
    GIVEN("A minimum and maximum range of valid addresses and a specific allocation size, type, and protection")
    {
        ZyanU64 TargetAddress = 0x70000000ULL;
        ZyanU64 MinAddress = 0x10000000ULL;
        ZyanU64 MaxAddress = 0x7fffffffULL;
        ZyanU64 AllocationSize = 0x1000ULL;
        ZyanU32 AllocationType = ZYNTERCEPT_PAGE_STATE_RESERVED | ZYNTERCEPT_PAGE_STATE_COMMITTED;
        ZyanU32 AllocationProtection = ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_WRITE;
        ZyanU64 AllocationGranularity = 0x10000ULL;
        ZYNTERCEPT_PAGED_MEMORY Page = { 0 };

        AND_GIVEN("I want to allocate memory near a target address, but lower than it")
        {
            Page.Address = ZynterceptAllocateNearLowerPage(
                ProcessIdentifier,
                TargetAddress,
                MinAddress,
                MaxAddress,
                AllocationSize,
                AllocationType,
                AllocationProtection,
                AllocationGranularity);

            REQUIRE(ZynterceptQueryMemory(ProcessIdentifier, &Page) == ZYAN_TRUE);

            WHEN("I allocate the memory using ZynterceptAllocateNearLowerPage")
            {
                THEN("The allocation should succeed")
                {
                    REQUIRE(Page.Address != 0);
                }

                AND_THEN("The allocated address should be within the maximum allowed range of the target address")
                {
                    if (TargetAddress > Page.Address) {
                        REQUIRE(TargetAddress - Page.Address <= ZYNTERCEPT_MAXIMUM_MEMORY_RANGE);
                    }
                    else {
                        REQUIRE(Page.Address - TargetAddress <= ZYNTERCEPT_MAXIMUM_MEMORY_RANGE);
                    }
                }

                AND_THEN("The allocated address should be between the minimum and maximum range")
                {
                    REQUIRE(Page.Address >= MinAddress);
                    REQUIRE(Page.Address <= MaxAddress);
                }

                AND_THEN("The allocation size should be as specified")
                {
                    REQUIRE(Page.Size == AllocationSize);
                }

                AND_THEN("The allocation state should match the specified allocation type")
                {
                    REQUIRE(Page.State == (AllocationType & ZYNTERCEPT_PAGE_STATE_COMMITTED));
                }

                AND_THEN("The allocation protection should match the specified protection")
                {
                    REQUIRE(Page.Protection == AllocationProtection);
                }
            }
        }

        REQUIRE(ZynterceptReleaseMemory(ProcessIdentifier, &Page) == ZYAN_TRUE);
    }
}

SCENARIO("Zyntercept memory allocation at the nearest address to the target address", "[allocator]")
{
    GIVEN("A specific allocation size, type, and protection")
    {
        ZyanU64 TargetAddress = 0x70000000ULL;
        ZyanU64 AllocationSize = 0x1000ULL;
        ZyanU32 AllocationType = ZYNTERCEPT_PAGE_STATE_RESERVED | ZYNTERCEPT_PAGE_STATE_COMMITTED;
        ZyanU32 AllocationProtection = ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_WRITE;
        ZYNTERCEPT_PAGED_MEMORY Page = { 0 };

        AND_GIVEN("I want to allocate memory at the nearest address to the target address")
        {
            Page.Address = ZynterceptAllocateNearestAddress(
                ProcessIdentifier,
                TargetAddress,
                AllocationSize,
                AllocationType,
                AllocationProtection);

            REQUIRE(ZynterceptQueryMemory(ProcessIdentifier, &Page) == ZYAN_TRUE);

            WHEN("I allocate the memory using ZynterceptAllocateNearestAddress")
            {
                THEN("The allocation should succeed")
                {
                    REQUIRE(Page.Address != 0);
                }

                AND_THEN("The allocated address should be within the maximum allowed range of the target address")
                {
                    if (TargetAddress > Page.Address) {
                        REQUIRE(TargetAddress - Page.Address <= ZYNTERCEPT_MAXIMUM_MEMORY_RANGE);
                    }
                    else {
                        REQUIRE(Page.Address - TargetAddress <= ZYNTERCEPT_MAXIMUM_MEMORY_RANGE);
                    }
                }

                AND_THEN("The allocation size should be as specified")
                {
                    REQUIRE(Page.Size == AllocationSize);
                }

                AND_THEN("The allocation state should match the specified allocation type")
                {
                    REQUIRE(Page.State == (AllocationType & ZYNTERCEPT_PAGE_STATE_COMMITTED));
                }

                AND_THEN("The allocation protection should match the specified protection")
                {
                    REQUIRE(Page.Protection == AllocationProtection);
                }
            }
        }

        REQUIRE(ZynterceptReleaseMemory(ProcessIdentifier, &Page) == ZYAN_TRUE);
    }
}
