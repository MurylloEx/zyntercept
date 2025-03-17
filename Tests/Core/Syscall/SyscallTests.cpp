#include <catch2/catch_test_macros.hpp>
#include <Zyntercept/Core/Syscall/Syscall.h>

#if defined(ZYNTERCEPT_WINDOWS)
#include <Windows.h>
static ZyanVoidPointer ProcessIdentifier = GetCurrentProcess();
#endif

#if defined(ZYNTERCEPT_UNIX)
#include <unistd.h>
static ZyanVoidPointer ProcessIdentifier = (ZyanVoidPointer)getpid();
#endif

SCENARIO("Zyntercept system architecture detection", "[syscall]")
{
    GIVEN("I want to verify the system's architecture")
    {
        WHEN("I check if the system is 64-bit if it really is a 64-bit system")
        {
            THEN("It should confirm whether the system is 64-bit if it really is a 64-bit system")
            {
                if (ZynterceptIs32BitSystem() == ZYAN_TRUE) {
                    REQUIRE(ZynterceptIs64BitSystem() == ZYAN_FALSE);
                }
                else {
                    REQUIRE(ZynterceptIs64BitSystem() == ZYAN_TRUE);
                }
            }
        }

        WHEN("I check if the system is 32-bit if it really is a 32-bit system")
        {
            THEN("It should confirm whether the system is 32-bit if it really is a 32-bit system")
            {
                if (ZynterceptIs64BitSystem() == ZYAN_TRUE) {
                    REQUIRE(ZynterceptIs32BitSystem() == ZYAN_FALSE);
                }
                else {
                    REQUIRE(ZynterceptIs32BitSystem() == ZYAN_TRUE);
                }
            }
        }
    }
}

SCENARIO("Zyntercept process architecture detection", "[syscall]")
{
    GIVEN("A specific process identifier")
    {
        WHEN("I check if the process architecture is unsupported")
        {
            THEN("It should confirm whether the process architecture is unsupported")
            {
                REQUIRE(ZynterceptIsUnsupportedProcessArchitecture(ProcessIdentifier) == ZYAN_FALSE);
            }
        }

        AND_WHEN("I check if the process is the current process")
        {
            THEN("It should confirm whether the process is the current process")
            {
                REQUIRE(ZynterceptIsCurrentProcess(ProcessIdentifier) == ZYAN_TRUE);
            }
        }
    }
}

SCENARIO("Zyntercept virtual memory information query", "[syscall]")
{
    GIVEN("I want to query virtual memory information")
    {
        ZynterceptPagedMemoryInformation Info = { 0 };

        WHEN("I retrieve the information")
        {
            REQUIRE(ZynterceptVirtualMemoryInformation(&Info) == ZYAN_TRUE);

            THEN("The information should include valid data")
            {
                REQUIRE(Info.AllocationGranularity > 0);
                REQUIRE(Info.Ring3LowestAddress < Info.Ring3HighestAddress);
            }
        }
    }
}

SCENARIO("Zyntercept memory allocation and management", "[syscall]")
{
    GIVEN("I want to allocate memory")
    {
        ZynterceptPagedMemory Page = { 0 };

        Page.Size = 0x1000;
        Page.State = ZYNTERCEPT_PAGE_STATE_COMMITTED;
        Page.Protection = ZYNTERCEPT_PAGE_PROTECTION_READ;

        WHEN("I allocate a page of memory")
        {
            Page.Address = ZynterceptAllocateMemory(ProcessIdentifier, &Page);

            THEN("The allocation should succeed")
            {
                REQUIRE(Page.Address != 0);
            }

            REQUIRE(ZynterceptReleaseMemory(ProcessIdentifier, &Page) == ZYAN_TRUE);
        }
    }

    GIVEN("I have allocated memory")
    {
        ZynterceptPagedMemory Page = { 0 };

        Page.Size = 0x1000;
        Page.State = ZYNTERCEPT_PAGE_STATE_COMMITTED;
        Page.Protection = ZYNTERCEPT_PAGE_PROTECTION_READ;
        Page.Address = ZynterceptAllocateMemory(ProcessIdentifier, &Page);

        WHEN("I release the allocated memory")
        {
            REQUIRE(ZynterceptReleaseMemory(ProcessIdentifier, &Page) == ZYAN_TRUE);

            THEN("The memory should be released successfully")
            {
                REQUIRE(Page.Address == 0);
            }
        }
    }

    GIVEN("I have a memory page with specific protection settings")
    {
        ZynterceptPagedMemory Page = { 0 };

        Page.Size = 0x1000;
        Page.State = ZYNTERCEPT_PAGE_STATE_COMMITTED;
        Page.Protection = ZYNTERCEPT_PAGE_PROTECTION_READ;
        Page.Address = ZynterceptAllocateMemory(ProcessIdentifier, &Page);

        WHEN("I change the protection of the page")
        {
            Page.Protection = ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_WRITE;

            REQUIRE(ZynterceptProtectMemory(ProcessIdentifier, &Page) == ZYAN_TRUE);

            THEN("The protection should be updated")
            {
                REQUIRE(Page.Protection == ZYNTERCEPT_PAGE_PROTECTION_READ);
            }
        }

        REQUIRE(ZynterceptReleaseMemory(ProcessIdentifier, &Page) == ZYAN_TRUE);
    }

    GIVEN("I want to query a memory page's properties")
    {
        ZynterceptPagedMemory Page = { 0 };

        Page.Size = 0x1000;
        Page.State = ZYNTERCEPT_PAGE_STATE_COMMITTED;
        Page.Protection = ZYNTERCEPT_PAGE_PROTECTION_READ;
        Page.Address = ZynterceptAllocateMemory(ProcessIdentifier, &Page);

        WHEN("I query the memory page")
        {
            REQUIRE(ZynterceptQueryMemory(ProcessIdentifier, &Page) == ZYAN_TRUE);

            THEN("The state and protection should match the expected values")
            {
                REQUIRE(Page.State == ZYNTERCEPT_PAGE_STATE_COMMITTED);
                REQUIRE(Page.Protection == ZYNTERCEPT_PAGE_PROTECTION_READ);
            }
        }

        REQUIRE(ZynterceptReleaseMemory(ProcessIdentifier, &Page) == ZYAN_TRUE);
    }
}

SCENARIO("Zyntercept memory read and write operations", "[syscall]")
{
    ZynterceptPagedMemory Page = { 0 };

    Page.Size = 0x1000;
    Page.State = ZYNTERCEPT_PAGE_STATE_COMMITTED;
    Page.Protection = ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_WRITE;
    Page.Address = ZynterceptAllocateMemory(ProcessIdentifier, &Page);

    GIVEN("I want to write to a memory page")
    {
        ZyanU8 Buffer[128] = { 0 };

        memset(Buffer, 1, sizeof(Buffer));

        ZynterceptPagedMemoryOperation Operation = { 0 };

        Operation.Address = Page.Address;
        Operation.Buffer = Buffer;
        Operation.Size = sizeof(Buffer);

        WHEN("I write to the memory")
        {
            REQUIRE(ZynterceptWriteMemory(ProcessIdentifier, &Operation) == ZYAN_TRUE);

            THEN("The write operation should succeed")
            {
                ZyanU8* TargetRegion = (ZyanU8*)Operation.Address;

                REQUIRE(TargetRegion[0] == 1u);
                REQUIRE(TargetRegion[1] == 1u);
                REQUIRE(TargetRegion[2] == 1u);
            }

            REQUIRE(ZynterceptReadMemory(ProcessIdentifier, &Operation) == ZYAN_TRUE);

            THEN("The read operation should succeed")
            {
                REQUIRE(Operation.Buffer[0] == 1u);
                REQUIRE(Operation.Buffer[1] == 1u);
                REQUIRE(Operation.Buffer[2] == 1u);
            }
        }
    }

    REQUIRE(ZynterceptReleaseMemory(ProcessIdentifier, &Page) == ZYAN_TRUE);
}

SCENARIO("Zyntercept flush microprocessor cache", "[syscall]")
{
    GIVEN("I want to flush the microprocessor cache for a memory page")
    {
        ZynterceptPagedMemory Page = { 0 };

        Page.Size = 0x1000;
        Page.State = ZYNTERCEPT_PAGE_STATE_COMMITTED;
        Page.Protection = ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_EXECUTE;
        Page.Address = ZynterceptAllocateMemory(ProcessIdentifier, &Page);

        WHEN("I flush the cache")
        {
            ZyanBool FlushStatus = ZynterceptFlushMicroprocessorCache(ProcessIdentifier, &Page);

            THEN("The cache flush should succeed")
            {
                REQUIRE(FlushStatus == ZYAN_TRUE);
            }
        }

        REQUIRE(ZynterceptReleaseMemory(ProcessIdentifier, &Page) == ZYAN_TRUE);
    }
}

SCENARIO("Zyntercept atomic memory write operations", "[syscall]")
{
    GIVEN("I want to perform atomic memory writes")
    {
        ZynterceptPagedMemoryOperation Operations[2] = { 0 };

        ZyanU8 FirstTargetBuffer[128] = { 0 };
        ZyanU8 SecondTargetBuffer[64] = { 0 };

        ZyanU8 FirstSourceBuffer[128] = { 0 };
        ZyanU8 SecondSourceBuffer[64] = { 0 };

        memset(FirstSourceBuffer, 1, sizeof(FirstSourceBuffer));
        memset(SecondSourceBuffer, 2, sizeof(SecondSourceBuffer));

        Operations[0].Address = reinterpret_cast<ZyanU64>(FirstTargetBuffer);
        Operations[0].Size = sizeof(FirstTargetBuffer);
        Operations[0].Buffer = FirstSourceBuffer;

        Operations[1].Address = reinterpret_cast<ZyanU64>(SecondTargetBuffer);
        Operations[1].Size = sizeof(SecondTargetBuffer);
        Operations[1].Buffer = SecondSourceBuffer;

        WHEN("I write multiple operations atomically")
        {
            REQUIRE(ZynterceptAtomicWriteMemory(ProcessIdentifier, Operations, 2) == ZYAN_TRUE);

            THEN("The atomic write should succeed")
            {
                REQUIRE(FirstTargetBuffer[0] == 1);
                REQUIRE(FirstTargetBuffer[1] == 1);
                REQUIRE(SecondTargetBuffer[0] == 2);
                REQUIRE(SecondTargetBuffer[1] == 2);
            }
        }
    }
}
