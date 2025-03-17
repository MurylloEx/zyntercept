#include <catch2/catch_test_macros.hpp>
#include <Zyntercept/Core/Common/Common.h>

SCENARIO("Zyntercept difference calculus between pointers", "[common]") 
{
    GIVEN("Two unsigned numbers where the first is greater than the second") 
    {
        ZyanU64 a = 0x84732400ULL;
        ZyanU64 b = 0x43244431ULL;

        WHEN("I call the Difference function")
        {
            THEN("It should return a positive result")
            {
                REQUIRE(Difference(a, b) == 0x414EDFCFLL);
            }
        }
    }

    GIVEN("Two unsigned numbers where the first is less than the second") 
    {
        ZyanU64 a = 0x7fffffffULL;
        ZyanU64 b = 0x84732400ULL;

        WHEN("I call the Difference function") 
        {
            THEN("It should return a negative result") 
            {
                REQUIRE(Difference(a, b) == -0x4732401LL);
            }
        }
    }

    GIVEN("Two unsigned numbers where both numbers are equal") 
    {
        ZyanU64 a = 0x7fffffffULL;
        ZyanU64 b = 0x7fffffffULL;

        WHEN("I call the Difference function") 
        {
            THEN("It should return zero") {
                REQUIRE(Difference(a, b) == 0x00000000ULL);
            }
        }
    }

    GIVEN("Two zero values") 
    {
        ZyanU64 a = 0x00000000ULL;
        ZyanU64 b = 0x00000000ULL;

        WHEN("I call the Difference function") 
        {
            THEN("It should return zero") 
            {
                REQUIRE(Difference(a, b) == 0x00000000ULL);
            }
        }
    }

    GIVEN("Two negative numbers represented as unsigned") 
    {
        ZyanU64 a = static_cast<ZyanU64>(-0x00001000LL);
        ZyanU64 b = static_cast<ZyanU64>(-0x00000800LL);

        WHEN("I call the Difference function") 
        {
            THEN("It should return a positive result") 
            {
                REQUIRE(Difference(a, b) == -0x00000800LL);
            }
        }
    }

    GIVEN("Two unsigned numbers causing positive overflow") 
    {
        constexpr ZyanU64 a = std::numeric_limits<ZyanU64>::max();
        constexpr ZyanU64 b = 0x00000000ULL;

        WHEN("I call the Difference function") 
        {
            THEN("It should handle the maximum value without overflow") 
            {
                REQUIRE(Difference(a, b) == static_cast<ZyanI64>(std::numeric_limits<ZyanU64>::max()));
            }
        }
    }

    GIVEN("Two unsigned numbers causing negative overflow") 
    {
        constexpr ZyanU64 a = 0x00000000ULL;
        constexpr ZyanU64 b = std::numeric_limits<ZyanU64>::max();

        WHEN("I call the Difference function") 
        {
            THEN("It should handle the minimum value without underflow") 
            {
                REQUIRE(Difference(a, b) == static_cast<ZyanI64>(0x00000000ULL) - static_cast<ZyanI64>(std::numeric_limits<ZyanU64>::max()));
            }
        }
    }
}
