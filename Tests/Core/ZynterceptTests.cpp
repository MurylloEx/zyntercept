#include <Zyntercept/Zyntercept.h>
#include <Zyntercept/Core/Syscall/Syscall.h>
#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>

#if defined(ZYNTERCEPT_WINDOWS)
#include <Windows.h>
static ZyanVoidPointer ProcessIdentifier = GetCurrentProcess();
#endif

#if defined(ZYNTERCEPT_UNIX)
#include <unistd.h>
static ZyanVoidPointer ProcessIdentifier = (ZyanVoidPointer)(ZyanUPointer)getpid();
#endif

static void NoopFunction() {
    static uint64_t NoopCounter = 0;
    NoopCounter++;
}

static float Sum(float a, float b) {
    NoopFunction();
    return a + b;
}

static float Subtract(float a, float b) {
    NoopFunction();
    return a - b;
}

static float Pow(float a, unsigned short b) {
    NoopFunction();
    float accumulator = 1;

    while (b) {
        accumulator *= a;
        --b;
    }

    return accumulator;
}

static int Fibonacci(int n) {
    NoopFunction();

    if (n == 0 || n > 46) {
        return 0;
    }

    if (n < 2) {
        return 1;
    }

    return Fibonacci(n - 1) + Fibonacci(n - 2);
}

TRAMPOLINE(Sum);
TRAMPOLINE(Subtract);
TRAMPOLINE(Pow);
TRAMPOLINE(Fibonacci);

static float InterceptSum(float a, float b) {
    return OriginalSum(a, b) * 2;
}

static float InterceptSubtract(float a, float b) {
    return OriginalSubtract(a, b) * 2;
}

static float InterceptPow(float a, unsigned short b) {
    return OriginalPow(a, b) * OriginalPow(a, b);
}

static int InterceptFibonacci(int n) {
    if (n > 46) {
        // We can't return the Fibonacci value when n > 46 because
        // it's too long for the signed int to hold in memory.
        // It will need more bits to hold in memory.
        // I'm not going to waste your computer's time and energy calculating this.
        // So, this function will return -1 for every call that meets that criteria.
        return -1;
    }

    return OriginalFibonacci(n);
}

SCENARIO("Zyntercept transactions", "[zyntercept]")
{
    ZynterceptProcess Process = { 0 };

    Process.Identifier = ProcessIdentifier;
    Process.Architecture = ZynterceptIs64BitProcess(ProcessIdentifier)
        ? ZYNTERCEPT_ARCHITECTURE_64BIT
        : ZYNTERCEPT_ARCHITECTURE_32BIT;

    GIVEN("A single hook in a transaction with full rollback")
    {
        REQUIRE(ZynterceptTransactionBegin() == true);
        REQUIRE(ZynterceptAttachProcess(&Process) == true);
        REQUIRE(ZynterceptAttach(ROUTINE(Sum), INTERCEPTION(Sum)) == true);
        REQUIRE(ZynterceptTransactionCommit() == true);

        REQUIRE(Sum(5.f, 5.f) == 20.f);
        REQUIRE(Sum(10.f, 20.f) == 60.f);
        REQUIRE(Sum(-10.f, 10.f) == 0.f);

        REQUIRE(ZynterceptTransactionBegin() == true);
        REQUIRE(ZynterceptAttachProcess(&Process) == true);
        REQUIRE(ZynterceptDetach(ROUTINE(Sum)) == true);
        REQUIRE(ZynterceptTransactionCommit() == true);

        WHEN("I attach a hook and rollback the transaction")
        {
            THEN("The hook should be removed and original function behavior restored")
            {
                REQUIRE(Sum(5.f, 5.f) == 10.f);
                REQUIRE(Sum(10.f, 20.f) == 30.f);
                REQUIRE(Sum(-10.f, 10.f) == 0.f);
            }
        }
    }

    GIVEN("A double hook in a transaction with full rollback")
    {
        WHEN("I attach two hooks and rollback the transaction")
        {
            REQUIRE(ZynterceptTransactionBegin() == true);
            REQUIRE(ZynterceptAttachProcess(&Process) == true);
            REQUIRE(ZynterceptAttach(ROUTINE(Sum), INTERCEPTION(Sum)) == true);
            REQUIRE(ZynterceptAttach(ROUTINE(Subtract), INTERCEPTION(Subtract)) == true);
            REQUIRE(ZynterceptTransactionCommit() == true);

            REQUIRE(Sum(10.f, 20.f) == 60.f);
            REQUIRE(Sum(20.f, 40.f) == 120.f);
            REQUIRE(Sum(40.f, 80.f) == 240.f);

            REQUIRE(Subtract(10.f, 20.f) == -20.f);
            REQUIRE(Subtract(20.f, 40.f) == -40.f);
            REQUIRE(Subtract(40.f, 40.f) == 0.f);

            REQUIRE(ZynterceptTransactionBegin() == true);
            REQUIRE(ZynterceptAttachProcess(&Process) == true);
            REQUIRE(ZynterceptDetach(ROUTINE(Sum)) == true);
            REQUIRE(ZynterceptDetach(ROUTINE(Subtract)) == true);
            REQUIRE(ZynterceptTransactionCommit() == true);

            THEN("Both hooks should be removed and original function behavior restored")
            {
                REQUIRE(Sum(10.f, 20.f) == 30.f);
                REQUIRE(Sum(20.f, 40.f) == 60.f);
                REQUIRE(Sum(40.f, 80.f) == 120.f);

                REQUIRE(Subtract(10.f, 20.f) == -10.f);
                REQUIRE(Subtract(20.f, 40.f) == -20.f);
                REQUIRE(Subtract(40.f, 40.f) == -0.f);
            }
        }
    }

    GIVEN("A double hook in a transaction with partial rollback")
    {
        WHEN("I attach two hooks and rollback only one")
        {
            REQUIRE(ZynterceptTransactionBegin() == true);
            REQUIRE(ZynterceptAttachProcess(&Process) == true);
            REQUIRE(ZynterceptAttach(ROUTINE(Sum), INTERCEPTION(Sum)) == true);
            REQUIRE(ZynterceptAttach(ROUTINE(Subtract), INTERCEPTION(Subtract)) == true);
            REQUIRE(ZynterceptTransactionCommit() == true);

            REQUIRE(Sum(2.f, 1.f) == 6.f);
            REQUIRE(Sum(4.f, 5.f) == 18.f);
            REQUIRE(Sum(-12.f, 17.f) == 10.f);

            REQUIRE(Subtract(2.f, 1.f) == 2.f);
            REQUIRE(Subtract(4.f, 5.f) == -2.f);
            REQUIRE(Subtract(-12.f, 17.f) == -58.f);

            REQUIRE(ZynterceptTransactionBegin() == true);
            REQUIRE(ZynterceptAttachProcess(&Process) == true);
            REQUIRE(ZynterceptDetach(ROUTINE(Sum)) == true);
            REQUIRE(ZynterceptTransactionCommit() == true);

            THEN("One hook should be removed while the other remains active")
            {
                REQUIRE(Sum(2.f, 1.f) == 3.f);
                REQUIRE(Sum(4.f, 5.f) == 9.f);
                REQUIRE(Sum(-12.f, 17.f) == 5.f);

                REQUIRE(Subtract(2.f, 1.f) == 2.f);
                REQUIRE(Subtract(4.f, 5.f) == -2.f);
                REQUIRE(Subtract(-12.f, 17.f) == -58.f);
            }

            REQUIRE(ZynterceptTransactionBegin() == true);
            REQUIRE(ZynterceptAttachProcess(&Process) == true);
            REQUIRE(ZynterceptDetach(ROUTINE(Subtract)) == true);
            REQUIRE(ZynterceptTransactionCommit() == true);
        }
    }

    GIVEN("A function with a loop in his prologue")
    {
        WHEN("I attach a hook and rollback the transaction")
        {
            REQUIRE(ZynterceptTransactionBegin() == true);
            REQUIRE(ZynterceptAttachProcess(&Process) == true);
            REQUIRE(ZynterceptAttach(ROUTINE(Pow), INTERCEPTION(Pow)) == true);
            REQUIRE(ZynterceptTransactionCommit() == true);

            REQUIRE(Pow(10.f, 0) == 1.f);
            REQUIRE(Pow(10.f, 1) == 100.f);
            REQUIRE(Pow(20.f, 3) == 64000000.f);

            REQUIRE(ZynterceptTransactionBegin() == true);
            REQUIRE(ZynterceptAttachProcess(&Process) == true);
            REQUIRE(ZynterceptDetach(ROUTINE(Pow)) == true);
            REQUIRE(ZynterceptTransactionCommit() == true);

            THEN("The function should execute normally without the hook interference")
            {
                REQUIRE(Pow(10.f, 0) == 1.f);
                REQUIRE(Pow(10.f, 1) == 10.f);
                REQUIRE(Pow(20.f, 3) == 8000.f);
            }
        }
    }

    GIVEN("A recursive and reentrant function with a hook")
    {
        WHEN("I attach a hook in the transaction")
        {
            REQUIRE(ZynterceptTransactionBegin() == true);
            REQUIRE(ZynterceptAttachProcess(&Process) == true);
            REQUIRE(ZynterceptAttach(ROUTINE(Fibonacci), INTERCEPTION(Fibonacci)) == true);
            REQUIRE(ZynterceptTransactionCommit() == true);

            THEN("The function should execute as expected with interference of the hook")
            {
                REQUIRE(Fibonacci(4) == 3);
                REQUIRE(Fibonacci(47) == -1);
                REQUIRE(Fibonacci(100) == -1);
                REQUIRE(Fibonacci(2000) == -1);
                REQUIRE(Fibonacci(3000) == -1);

                REQUIRE(ZynterceptTransactionBegin() == true);
                REQUIRE(ZynterceptAttachProcess(&Process) == true);
                REQUIRE(ZynterceptDetach(ROUTINE(Fibonacci)) == true);
                REQUIRE(ZynterceptTransactionCommit() == true);
            }
        }
    }

    GIVEN("A recursive and reentrant function with a hook")
    {
        WHEN("I attach and rollback the transaction")
        {
            REQUIRE(ZynterceptTransactionBegin() == true);
            REQUIRE(ZynterceptAttachProcess(&Process) == true);
            REQUIRE(ZynterceptAttach(ROUTINE(Fibonacci), INTERCEPTION(Fibonacci)) == true);
            REQUIRE(ZynterceptTransactionCommit() == true);

            REQUIRE(Fibonacci(4) == 3);
            REQUIRE(Fibonacci(47) == -1);
            REQUIRE(Fibonacci(100) == -1);
            REQUIRE(Fibonacci(2000) == -1);
            REQUIRE(Fibonacci(3000) == -1);

            REQUIRE(ZynterceptTransactionBegin() == true);
            REQUIRE(ZynterceptAttachProcess(&Process) == true);
            REQUIRE(ZynterceptDetach(ROUTINE(Fibonacci)) == true);
            REQUIRE(ZynterceptTransactionCommit() == true);

            THEN("The function should execute as expected without any hook effects")
            {
                REQUIRE(Fibonacci(4) == 3);
                REQUIRE(Fibonacci(47) == 0);
                REQUIRE(Fibonacci(100) == 0);
                REQUIRE(Fibonacci(2000) == 0);
                REQUIRE(Fibonacci(3000) == 0);
            }
        }
    }
}

SCENARIO("Zyntercept transactions error handling", "[zyntercept]")
{
    ZynterceptProcess Process = { 0 };

    Process.Identifier = ProcessIdentifier;
    Process.Architecture = ZynterceptIs64BitProcess(ProcessIdentifier)
        ? ZYNTERCEPT_ARCHITECTURE_64BIT
        : ZYNTERCEPT_ARCHITECTURE_32BIT;

    GIVEN("A nonexistent hook")
    {
        WHEN("I attempt to remove the nonexistent hook")
        {
            REQUIRE(ZynterceptTransactionBegin() == true);
            REQUIRE(ZynterceptAttachProcess(&Process) == true);
            
            THEN("It should fail gracefully without affecting the system")
            {
                REQUIRE(ZynterceptDetach(ROUTINE(Sum)) == false);
                REQUIRE(ZynterceptTransactionAbandon() == true);
            }
        }
    }

    GIVEN("A duplicated transaction")
    {
        WHEN("I attempt to open a transaction that already exists")
        {
            REQUIRE(ZynterceptTransactionBegin() == true);

            THEN("It should return an error")
            {
                REQUIRE(ZynterceptTransactionBegin() == false);
                REQUIRE(ZynterceptTransactionAbandon() == true);
            }
        }
    }

    GIVEN("A closed transaction")
    {
        WHEN("I attempt to attach a hook")
        {
            THEN("It should return an error")
            {
                REQUIRE(ZynterceptAttach(ROUTINE(Sum), INTERCEPTION(Sum)) == false);
            }
        }
    }

    GIVEN("A closed transaction")
    {
        WHEN("I attempt to remove a hook")
        {
            THEN("It should return an error")
            {
                REQUIRE(ZynterceptDetach(ROUTINE(Sum)) == false);
            }
        }
    }
}

SCENARIO("Zyntercept individual measurements with transactions", "[zyntercept]")
{
    ZynterceptProcess Process = { 0 };

    Process.Identifier = ProcessIdentifier;
    Process.Architecture = ZynterceptIs64BitProcess(ProcessIdentifier)
        ? ZYNTERCEPT_ARCHITECTURE_64BIT
        : ZYNTERCEPT_ARCHITECTURE_32BIT;

    GIVEN("A performance measurement for ZynterceptTransactionBegin")
    {
        WHEN("I call the function")
        {
            THEN("It should execute within acceptable time limits")
            {
                BENCHMARK("ZynterceptTransactionBegin")
                {
                    return ZynterceptTransactionBegin();
                };

                REQUIRE(ZynterceptTransactionAbandon() == true);
            }
        }
    }

    GIVEN("A performance measurement for ZynterceptAttachProcess")
    {
        REQUIRE(ZynterceptTransactionBegin() == true);

        WHEN("I call the function")
        {
            THEN("It should execute within acceptable time limits")
            {
                BENCHMARK("ZynterceptAttachProcess")
                {
                    REQUIRE(ZynterceptAttachProcess(&Process) == true);

                    return;
                };
            }
        }

        REQUIRE(ZynterceptTransactionAbandon() == true);
    }

    GIVEN("A performance measurement for ZynterceptAttach")
    {
        REQUIRE(ZynterceptTransactionBegin() == true);

        WHEN("I call the function")
        {
            THEN("It should execute within acceptable time limits")
            {
                BENCHMARK("ZynterceptAttach")
                {
                    return ZynterceptAttach(ROUTINE(Subtract), INTERCEPTION(Subtract));
                };
            }
        }

        REQUIRE(ZynterceptTransactionAbandon() == true);
    }

    GIVEN("A performance measurement for ZynterceptDetach")
    {
        REQUIRE(ZynterceptTransactionBegin() == true);

        WHEN("I call the function")
        {
            THEN("It should execute within acceptable time limits")
            {
                BENCHMARK("ZynterceptDetach")
                {
                    return ZynterceptDetach(ROUTINE(Subtract));
                };
            }
        }

        REQUIRE(ZynterceptTransactionAbandon() == true);
    }

    GIVEN("A performance measurement for ZynterceptTransactionBegin + ZynterceptTransactionCommit")
    {
        WHEN("I call the function")
        {
            THEN("It should execute within acceptable time limits")
            {
                BENCHMARK("ZynterceptTransactionBegin + ZynterceptTransactionCommit")
                {
                    REQUIRE(ZynterceptTransactionBegin() == true);
                    REQUIRE(ZynterceptTransactionCommit() == true);

                    return;
                };
            }
        }
    }

    GIVEN("A performance measurement for ZynterceptTransactionBegin + ZynterceptTransactionAbandon")
    {
        WHEN("I call the function")
        {
            THEN("It should execute within acceptable time limits")
            {
                BENCHMARK("ZynterceptTransactionBegin + ZynterceptTransactionAbandon")
                {
                    REQUIRE(ZynterceptTransactionBegin() == true);
                    REQUIRE(ZynterceptTransactionAbandon() == true);

                    return;
                };
            }
        }
    }

    GIVEN("A performance measurement for hooking a single function")
    {
        WHEN("I call the functions")
        {
            THEN("It should execute within acceptable time limits")
            {
                BENCHMARK("Single function hooking")
                {
                    // Perform the hooking Fibonacci -> InterceptFibonacci
                    REQUIRE(ZynterceptTransactionBegin() == true);
                    REQUIRE(ZynterceptAttachProcess(&Process) == true);
                    REQUIRE(ZynterceptAttach(ROUTINE(Fibonacci), INTERCEPTION(Fibonacci)) == true);
                    REQUIRE(ZynterceptTransactionCommit() == true);

                    // Revert the hooking Fibonacci -> InterceptFibonacci
                    REQUIRE(ZynterceptTransactionBegin() == true);
                    REQUIRE(ZynterceptAttachProcess(&Process) == true);
                    REQUIRE(ZynterceptDetach(ROUTINE(Fibonacci)) == true);
                    REQUIRE(ZynterceptTransactionCommit() == true);

                    return;
                };
            }
        }
    }

    GIVEN("A performance measurement for hooking two functions at once")
    {
        WHEN("I call the functions")
        {
            THEN("It should execute within acceptable time limits")
            {
                BENCHMARK("Two functions hooking")
                {
                    // Perform the hooking Sum -> InterceptSum
                    // Perform the hooking Subtract -> InterceptSubtract
                    REQUIRE(ZynterceptTransactionBegin() == true);
                    REQUIRE(ZynterceptAttachProcess(&Process) == true);
                    REQUIRE(ZynterceptAttach(ROUTINE(Sum), INTERCEPTION(Sum)) == true);
                    REQUIRE(ZynterceptAttach(ROUTINE(Subtract), INTERCEPTION(Subtract)) == true);
                    REQUIRE(ZynterceptTransactionCommit() == true);

                    // Revert the hooking Sum -> InterceptSum
                    // Revert the hooking Subtract -> InterceptSubtract
                    REQUIRE(ZynterceptTransactionBegin() == true);
                    REQUIRE(ZynterceptAttachProcess(&Process) == true);
                    REQUIRE(ZynterceptDetach(ROUTINE(Sum)) == true);
                    REQUIRE(ZynterceptDetach(ROUTINE(Subtract)) == true);
                    REQUIRE(ZynterceptTransactionCommit() == true);

                    return;
                };
            }
        }
    }
}
