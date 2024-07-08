#include <catch2/catch_test_macros.hpp>
#include <Zyntercept/Core/Disassembler/Disassembler.h>

//TEST(DisassemblerTestSuite, TestName) {
//	//IsRelative();
//	//IsRet();
//	//IsCall();
//	//IsJmp();
//	//IsJcc();
//	//SizeOfDecodedDesiredInstructions();
//	//FindReplaceableInstructions();
//	//FindNextFunctionBranch();
//	//FindFunctionBranchs();
//	//HasFunctionBranchDestinationsBetween();
//
//	ASSERT_EQ(0, 0);
//}


TEST_CASE("Check if IsRelative identify <jmp dword ptr 0xaabbccdd> as relative instruction", "[disassembler]") {
	uint8_t Buffer[] = { 0xe9, 0xd9, 0xcc, 0xbb, 0xaa };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));
	
	REQUIRE(IsRelative(&Decoded) == ZYAN_TRUE);
}

TEST_CASE("Check if IsRelative identify <call dword ptr 0xaabbccdd> as relative instruction", "[disassembler]") {
	uint8_t Buffer[] = { 0xe8, 0xd9, 0xcc, 0xbb, 0xaa };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	REQUIRE(IsRelative(&Decoded) == ZYAN_TRUE);
}

TEST_CASE("Check if IsRet identify <ret> as return instruction", "[disassembler]") {
	uint8_t Buffer[] = { 0xc3 };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	REQUIRE(IsRet(&Decoded) == ZYAN_TRUE);
}

TEST_CASE("Check if IsRet identify <ret> as near return instruction", "[disassembler]") {
	uint8_t Buffer[] = { 0xc3 };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	REQUIRE(IsRet(&Decoded) == ZYAN_TRUE);
}

TEST_CASE("Check if IsRet identify <ret> as far return instruction", "[disassembler]") {
	uint8_t Buffer[] = { 0xcb };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	REQUIRE(IsRet(&Decoded) == ZYAN_TRUE);
}

TEST_CASE("Check if IsCall identify <call dword ptr 0xaabbccdd> as call instruction", "[disassembler]") {
	SKIP();

	uint8_t Buffer[] = { 0xe8, 0xd9, 0xcc, 0xbb, 0xaa };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	ZydisDecodedOperand* Operand = nullptr;

	REQUIRE(IsCall(&Decoded, &Operand) == ZYAN_TRUE);

	REQUIRE(Operand != nullptr);
	REQUIRE(Operand->imm.value.u & 0xaabbccd9ULL == 0xaabbccd9ULL);
}
