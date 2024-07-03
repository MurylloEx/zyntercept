#include <gtest/gtest.h>
#include <Zyntercept/Core/Common/Common.h>

TEST(CommonTestSuite, CheckIfDifferenceMethodReturnCorrectValues) {
	bool DifferenceResult1 = Difference(0x7fffff, 0x847324);
	ASSERT_EQ(DifferenceResult1, -0x47325);

	bool DifferenceResult2 = Difference(0x847324, 0x432444);
	ASSERT_EQ(DifferenceResult2, 0x414EE0);

	bool DifferenceResult3 = Difference(0xffffffff, 0x84732400);
	ASSERT_EQ(DifferenceResult3, 0x7B8CDBFF);

	bool DifferenceResult4 = Difference(0xffffffffffffffff, 0xffffffffffffffff);
	ASSERT_EQ(DifferenceResult4, 0);

	bool DifferenceResult5 = Difference(0x7fffffffffffffff, 0x7fffffffffffffff);
	ASSERT_EQ(DifferenceResult5, 0);

	bool DifferenceResult6 = Difference(0x8000000000000000, 0x7fffffffffffffff);
	ASSERT_EQ(DifferenceResult6, 1);

	bool DifferenceResult7 = Difference(0x7fffff, 0x7ffffe);
	ASSERT_EQ(DifferenceResult7, -1);
}
