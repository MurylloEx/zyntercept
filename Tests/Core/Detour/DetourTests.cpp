#include <catch2/catch_test_macros.hpp>
#include <Zyntercept/Core/Detour/Detour.h>
#include <Zyntercept/Core/Syscall/Syscall.h>

#if defined(ZYNTERCEPT_WINDOWS)
#include <Windows.h>
static ZyanVoidPointer ProcessIdentifier = GetCurrentProcess();
#endif

#if defined(ZYNTERCEPT_UNIX)
#include <unistd.h>
static ZyanVoidPointer ProcessIdentifier = (ZyanVoidPointer)getpid();
#endif

SCENARIO("Detouring a 64-bit function with Zyntercept", "[detour]")
{
    GIVEN("A target 64-bit function to be detoured")
    {
        WHEN("I apply a detour using ZynterceptDetourFunction64")
        {
            THEN("The detour should be successfully applied")
            {
                // Implementa��o do teste
            }

            AND_THEN("The detoured function should execute the hook instead of the original function")
            {
                // Implementa��o do test
            }
        }
    }
}

SCENARIO("Detouring a 32-bit function with Zyntercept", "[detour]")
{
    GIVEN("A target 32-bit function to be detoured")
    {
        WHEN("I apply a detour using ZynterceptDetourFunction32")
        {
            THEN("The detour should be successfully applied")
            {
                // Implementa��o do teste
            }

            AND_THEN("The detoured function should execute the hook instead of the original function")
            {
                // Implementa��o do teste
            }
        }
    }
}

SCENARIO("Reverting a 64-bit function detour with Zyntercept", "[detour]")
{
    GIVEN("A previously detoured 64-bit function")
    {
        WHEN("I revert the detour using ZynterceptRevertDetourFunction64")
        {
            THEN("The original function should be restored successfully")
            {
                // Implementa��o do teste
            }

            AND_THEN("The function should execute normally without the hook")
            {
                // Implementa��o do teste
            }
        }
    }
}

SCENARIO("Reverting a 32-bit function detour with Zyntercept", "[detour]")
{
    GIVEN("A previously detoured 32-bit function")
    {
        WHEN("I revert the detour using ZynterceptRevertDetourFunction32")
        {
            THEN("The original function should be restored successfully")
            {
                // Implementa��o do teste
            }

            AND_THEN("The function should execute normally without the hook")
            {
                // Implementa��o do teste
            }
        }
    }
}
