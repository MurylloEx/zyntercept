#include <catch2/catch_test_macros.hpp>
#include <Zyntercept/Core/Detour/Detour.h>
#include <Zyntercept/Core/Syscall/Syscall.h>

#include <cmath>

#if defined(ZYNTERCEPT_WINDOWS)
#include <Windows.h>
static ZyanVoidPointer ProcessIdentifier = GetCurrentProcess();
#endif

#if defined(ZYNTERCEPT_UNIX)
#include <unistd.h>
static ZyanVoidPointer ProcessIdentifier = (ZyanVoidPointer)(uint64_t)getpid();
#endif

static void NoopFunction() {
    static uint64_t NoopCounter = 0;
    NoopCounter++;
}

// Source: https://www.geeksforgeeks.org/check-for-prime-number/

// [Expected Approach - 2] Optimized Trial Division Method - O(sqrt(n)) Time and O(1) Space

// We know that any integer number can be written in the form of 6k+i, where k is a non-negative integer (like 0, 1, 2, 3,...) 
// and i is a number between 0 and 5 (so i can be 0, 1, 2, 3, 4, or 5).

// If we look closely, we�ll notice that when i is 0, 2, 3, or 4, the numbers 6k, 6k + 2, 6k + 3, and 6k + 4 are all divisible by
// either 2 or 3. But prime numbers greater than 3 can't be divisible by 2 or 3. Therefore, the only forms left that a prime 
// number can have are 6k + 1 or 6k + 5 (since these forms are not divisible by 2 or 3).

// Instead of checking every number up to the sqrt(n) to see if it divides n, we only check numbers of the form 6k + 1 and 6k + 5.
// This reduces the number of checks needed.

static bool IsPrime(int n) {
    NoopFunction();

    if (n <= 1) {
        return false;
    }

    if (n == 2 || n == 3) {
        return true;
    }

    if (n % 2 == 0 || n % 3 == 0) {
        return false;
    }

    for (int i = 5; i <= sqrt(n); i = i + 6) {
        if (n % i == 0 || n % (i + 2) == 0) {
            return false;
        }
    }

    return true;
}

static bool IsPrimeHooked(int n) {
    return false;
}

SCENARIO("Zyntercept detour in 64-bit functions", "[detour]")
{
    if (!ZynterceptIs64BitProcess(ProcessIdentifier))
    {
        SKIP();
    }

    static ZyanU64 TargetFunction = reinterpret_cast<ZyanU64>(IsPrime);
    static ZyanU64 HookedFunction = reinterpret_cast<ZyanU64>(IsPrimeHooked);
    static ZyanU64 TrampolineFunction = 0;
    static ZyanU8* OriginalPrologue = nullptr;
    static ZyanU64 OriginalPrologueSize = 0;
    static ZyanBool Status = ZYAN_FALSE;

    GIVEN("A target 64-bit function to be detoured")
    {
        WHEN("I apply a detour using ZynterceptDetourFunction64")
        {
            REQUIRE(IsPrime(3) == true);
            REQUIRE(IsPrime(5) == true);
            REQUIRE(IsPrime(7) == true);
            REQUIRE(IsPrime(11) == true);
            REQUIRE(IsPrime(13) == true);
            REQUIRE(IsPrime(17) == true);
            REQUIRE(IsPrime(19) == true);

            Status = ZynterceptDetourFunction64(
                ProcessIdentifier,
                TargetFunction,
                HookedFunction,
                &TrampolineFunction,
                &OriginalPrologue,
                &OriginalPrologueSize);

            THEN("The detour should be successfully applied")
            {
                REQUIRE(Status == ZYAN_TRUE);
                REQUIRE(TrampolineFunction != 0);
                REQUIRE(OriginalPrologue != nullptr);
                REQUIRE(OriginalPrologueSize != 0);

                AND_THEN("The detoured function should execute the hook instead of the original function")
                {
                    REQUIRE(IsPrime(3) == false);
                    REQUIRE(IsPrime(5) == false);
                    REQUIRE(IsPrime(7) == false);
                    REQUIRE(IsPrime(11) == false);
                    REQUIRE(IsPrime(13) == false);
                    REQUIRE(IsPrime(17) == false);
                    REQUIRE(IsPrime(19) == false);
                }
            }
        }
    }

    GIVEN("A previously detoured 64-bit function")
    {
        WHEN("I revert the detour using ZynterceptRevertDetourFunction64")
        {
            THEN("The original function should be restored successfully")
            {
                Status = ZynterceptRevertDetourFunction64(
                    ProcessIdentifier,
                    TargetFunction,
                    TrampolineFunction,
                    OriginalPrologue,
                    OriginalPrologueSize);

                AND_THEN("The function should execute normally without the hook")
                {
                    REQUIRE(IsPrime(3) == true);
                    REQUIRE(IsPrime(5) == true);
                    REQUIRE(IsPrime(7) == true);
                    REQUIRE(IsPrime(11) == true);
                    REQUIRE(IsPrime(13) == true);
                    REQUIRE(IsPrime(17) == true);
                    REQUIRE(IsPrime(19) == true);
                }
            }
        }
    }
}

SCENARIO("Zyntercept detour in 32-bit functions", "[detour]")
{
    if (!ZynterceptIs32BitProcess(ProcessIdentifier))
    {
        SKIP();
    }

    static ZyanU64 TargetFunction = reinterpret_cast<ZyanU64>(IsPrime);
    static ZyanU64 HookedFunction = reinterpret_cast<ZyanU64>(IsPrimeHooked);
    static ZyanU64 TrampolineFunction = 0;
    static ZyanU8* OriginalPrologue = nullptr;
    static ZyanU64 OriginalPrologueSize = 0;
    static ZyanBool Status = ZYAN_FALSE;

    GIVEN("A target function to be detoured")
    {
        WHEN("I apply a detour using ZynterceptDetourFunction32")
        {
            REQUIRE(IsPrime(3) == true);
            REQUIRE(IsPrime(5) == true);
            REQUIRE(IsPrime(7) == true);
            REQUIRE(IsPrime(11) == true);
            REQUIRE(IsPrime(13) == true);
            REQUIRE(IsPrime(17) == true);
            REQUIRE(IsPrime(19) == true);

            Status = ZynterceptDetourFunction32(
                ProcessIdentifier,
                TargetFunction,
                HookedFunction,
                &TrampolineFunction,
                &OriginalPrologue,
                &OriginalPrologueSize);

            THEN("The detour should be successfully applied")
            {
                REQUIRE(Status == ZYAN_TRUE);
                REQUIRE(TrampolineFunction != 0);
                REQUIRE(OriginalPrologue != nullptr);
                REQUIRE(OriginalPrologueSize != 0);            
                
                AND_THEN("The detoured function should execute the hook instead of the original function")
                {
                    REQUIRE(IsPrime(3) == false);
                    REQUIRE(IsPrime(5) == false);
                    REQUIRE(IsPrime(7) == false);
                    REQUIRE(IsPrime(11) == false);
                    REQUIRE(IsPrime(13) == false);
                    REQUIRE(IsPrime(17) == false);
                    REQUIRE(IsPrime(19) == false);
                }
            }
        }
    }

    GIVEN("A previously detoured function")
    {
        WHEN("I revert the detour using ZynterceptRevertDetourFunction32")
        {
            Status = ZynterceptRevertDetourFunction32(
                ProcessIdentifier,
                TargetFunction,
                TrampolineFunction,
                OriginalPrologue,
                OriginalPrologueSize);

            THEN("The original function should be restored successfully")
            {
                REQUIRE(Status == ZYAN_TRUE);

                AND_THEN("The function should execute normally without the hook")
                {
                    REQUIRE(IsPrime(3) == true);
                    REQUIRE(IsPrime(5) == true);
                    REQUIRE(IsPrime(7) == true);
                    REQUIRE(IsPrime(11) == true);
                    REQUIRE(IsPrime(13) == true);
                    REQUIRE(IsPrime(17) == true);
                    REQUIRE(IsPrime(19) == true);
                }
            }
        }
    }
}
