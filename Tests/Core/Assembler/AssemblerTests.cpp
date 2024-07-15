#include <catch2/catch_test_macros.hpp>
#include <Zyntercept/Core/Assembler/Assembler.h>

//builder->Call32(); OK
//builder->Call64(); OK
//builder->Jmp32(); OK
//builder->Jmp64(); OK
//builder->Nop(); OK
//builder->Encode(); OK
//builder->Reencode(); OK
//builder->GetBaseAddress();  OK
//builder->LastInstructionLength(); OK
//builder->Offset(); OK
//builder->Size(); OK
//builder->Success(); OK
//builder->Failed(); OK
//builder->CopyTo();
//builder->Jcc(); OK
//builder->Jncc();

TEST_CASE("AssemblyBuilder should be instantiated without errors", "[assembler]") {
	REQUIRE_NOTHROW(std::make_unique<AssemblyBuilder>(0x7ffffd50ULL));
}

TEST_CASE("Should generate a valid <call dword ptr imm32> instruction when call Call32 method", "[assembler]") {
	std::unique_ptr<AssemblyBuilder> Builder = std::make_unique<AssemblyBuilder>(0x7ffffd50ULL);

	REQUIRE_NOTHROW(Builder->Call32(0xaabbccddULL));

	REQUIRE(Builder->Success() == ZYAN_TRUE);
	REQUIRE(Builder->Failed() == ZYAN_FALSE);
	REQUIRE(Builder->Size() == 5);
	REQUIRE(Builder->LastInstructionLength() == 5);

	ZyanU8 Buffer[32] = { 0 };

	REQUIRE(Builder->CopyTo(Buffer, sizeof(Buffer)) == ZYAN_TRUE);

	REQUIRE(Buffer[0] == 0xe8);
	REQUIRE(Buffer[1] == 0x88);
	REQUIRE(Buffer[2] == 0xcf);
	REQUIRE(Buffer[3] == 0xbb);
	REQUIRE(Buffer[4] == 0x2a);
}

TEST_CASE("Should generate a valid <call qword ptr [rip+0x02]> instruction when call Call64 method", "[assembler]") {
	std::unique_ptr<AssemblyBuilder> Builder = std::make_unique<AssemblyBuilder>(0x7ffffd50ULL);

	REQUIRE_NOTHROW(Builder->Call64(0x7ffee000ULL));

	REQUIRE(Builder->Success() == ZYAN_TRUE);
	REQUIRE(Builder->Failed() == ZYAN_FALSE);
	REQUIRE(Builder->Size() == 16);
	REQUIRE(Builder->LastInstructionLength() == 16);

	struct AssemblyInstruction {
		ZyanU8 Call64Opcode;
		ZyanU8 ModRM;
		ZyanU8 Call64Immediate[4];
		ZyanU8 Jmp8Opcode;
		ZyanI8 Jmp8RelativeAddress;
		ZyanU8 Call64AbsoluteAddress[8];
	};

	AssemblyInstruction Instruction = { 0 };

	REQUIRE(Builder->CopyTo(&Instruction, sizeof(Instruction)) == ZYAN_TRUE);

	REQUIRE(Instruction.Call64Opcode == 0xff);
	REQUIRE(Instruction.ModRM == 0x15);
	REQUIRE(Instruction.Jmp8Opcode == 0xeb);
	REQUIRE(Instruction.Jmp8RelativeAddress == 0x08);

	// TODO: Valid pointers and immediates
}

TEST_CASE("Should generate a valid <jmp dword ptr imm32> instruction when call Jmp32 method", "[assembler]") {
	std::unique_ptr<AssemblyBuilder> Builder = std::make_unique<AssemblyBuilder>(0x7ffffd50ULL);

	REQUIRE_NOTHROW(Builder->Jmp32(0x7ffee000ULL));

	REQUIRE(Builder->Success() == ZYAN_TRUE);
	REQUIRE(Builder->Failed() == ZYAN_FALSE);
	REQUIRE(Builder->Size() == 5);
	REQUIRE(Builder->LastInstructionLength() == 5);

	struct AssemblyInstruction {
		ZyanU8 Jmp32Opcode;
		ZyanU8 Jmp32Immediate[4];
	};

	AssemblyInstruction Instruction = { 0 };

	REQUIRE(Builder->CopyTo(&Instruction, sizeof(Instruction)) == ZYAN_TRUE);

	REQUIRE(Instruction.Jmp32Opcode == 0xe9);

	ZyanI32 Jmp32Immediate = 0;

	std::memcpy(&Jmp32Immediate, &Instruction.Jmp32Immediate, sizeof(Jmp32Immediate));

	// TODO: Valid immediate
}

TEST_CASE("Should generate a valid <jmp qword ptr [rip+0x02]> instruction when call Jmp64 method", "[assembler]") {
	std::unique_ptr<AssemblyBuilder> Builder = std::make_unique<AssemblyBuilder>(0x7ffffd50ULL);

	REQUIRE_NOTHROW(Builder->Jmp64(0x7ffee000ULL));

	REQUIRE(Builder->Success() == ZYAN_TRUE);
	REQUIRE(Builder->Failed() == ZYAN_FALSE);
	REQUIRE(Builder->Size() == 16);
	REQUIRE(Builder->LastInstructionLength() == 16);

	// jmp qword ptr [rip+0x02]
	// jmp 0x08
	// ptr data

	struct AssemblyInstruction {
		ZyanU8 Jmp64Opcode;
		ZyanU8 ModRM;
		ZyanU8 Jmp64Immediate[4];
		ZyanU8 Jmp8Opcode;
		ZyanI8 Jmp8RelativeAddress;
		ZyanU8 Jmp64AbsoluteAddress[8];
	};

	AssemblyInstruction Instruction = { 0 };

	REQUIRE(Builder->CopyTo(&Instruction, sizeof(Instruction)) == ZYAN_TRUE);

	REQUIRE(Instruction.Jmp64Opcode == 0xff);
	REQUIRE(Instruction.ModRM == 0x25);
	REQUIRE(Instruction.Jmp8Opcode == 0xeb);
	REQUIRE(Instruction.Jmp8RelativeAddress == 0x08);

	ZyanI32 Jmp64Immediate = 0;
	ZyanU64 Jmp64AbsoluteAddress = 0;

	std::memcpy(&Jmp64Immediate, &Instruction.Jmp64Immediate, sizeof(Jmp64Immediate));
	std::memcpy(&Jmp64AbsoluteAddress, &Instruction.Jmp64AbsoluteAddress, sizeof(Jmp64AbsoluteAddress));

	REQUIRE(Jmp64Immediate == 0x00000002UL);
	REQUIRE(Jmp64AbsoluteAddress == 0x7ffee000ULL);
}

TEST_CASE("Should generate valid <nop> instructions when call Nop method", "[assembler]") {
	std::unique_ptr<AssemblyBuilder> Builder = std::make_unique<AssemblyBuilder>(0x7ffffd50ULL);

	REQUIRE_NOTHROW(Builder->Nop(0x100));

	REQUIRE(Builder->Success() == ZYAN_TRUE);
	REQUIRE(Builder->Failed() == ZYAN_FALSE);
	REQUIRE(Builder->Size() == 0x100);
	REQUIRE(Builder->LastInstructionLength() == 0x100);
}

TEST_CASE("Offset method should return the valid instruction offset after each generated instruction", "[assembler]") {
	std::unique_ptr<AssemblyBuilder> Builder = std::make_unique<AssemblyBuilder>(0x7ffffd50ULL);

	REQUIRE_NOTHROW(Builder->Jmp32(0x7ffee000ULL));
	REQUIRE(Builder->GetBaseAddress() + Builder->Offset() == 0x7ffffd54ULL);

	REQUIRE_NOTHROW(Builder->Jmp64(0x7ffee000ULL));
	REQUIRE(Builder->GetBaseAddress() + Builder->Offset() == 0x7ffffd64ULL);

	REQUIRE_NOTHROW(Builder->Call32(0x7ffee000ULL));
	REQUIRE(Builder->GetBaseAddress() + Builder->Offset() == 0x7ffffd69ULL);

	REQUIRE_NOTHROW(Builder->Call64(0x7ffee000ULL));
	REQUIRE(Builder->GetBaseAddress() + Builder->Offset() == 0x7ffffd79ULL);

	REQUIRE_NOTHROW(Builder->Nop(0x100));
	REQUIRE(Builder->GetBaseAddress() + Builder->Offset() == 0x7ffffe79ULL);
}

TEST_CASE("LastInstructionLength method should return the valid instruction length after each generated instruction", "[assembler]") {
	std::unique_ptr<AssemblyBuilder> Builder = std::make_unique<AssemblyBuilder>(0x7ffffd50ULL);

	REQUIRE_NOTHROW(Builder->Jmp32(0x7ffee000ULL));
	REQUIRE(Builder->LastInstructionLength() == 5);

	REQUIRE_NOTHROW(Builder->Jmp64(0x7ffee000ULL));
	REQUIRE(Builder->LastInstructionLength() == 16);

	REQUIRE_NOTHROW(Builder->Call32(0x7ffee000ULL));
	REQUIRE(Builder->LastInstructionLength() == 5);

	REQUIRE_NOTHROW(Builder->Call64(0x7ffee000ULL));
	REQUIRE(Builder->LastInstructionLength() == 16);

	REQUIRE_NOTHROW(Builder->Nop(0x100));
	REQUIRE(Builder->LastInstructionLength() == 256);
}

TEST_CASE("GetBaseAddress method should return the base address provided in class constructor", "[assembler]") {
	std::unique_ptr<AssemblyBuilder> Builder = std::make_unique<AssemblyBuilder>(0x7ffffd50ULL);

	REQUIRE(Builder->GetBaseAddress() == 0x7ffffd50ULL);
}

TEST_CASE("Size method should return the total size of instructions", "[assembler]") {
	std::unique_ptr<AssemblyBuilder> Builder = std::make_unique<AssemblyBuilder>(0x7ffffd50ULL);

	REQUIRE_NOTHROW(Builder->Jmp32(0x7ffee000ULL));   // 5 bytes
	REQUIRE_NOTHROW(Builder->Jmp64(0x7ffee000ULL));   // 16 bytes
	REQUIRE_NOTHROW(Builder->Call32(0x7ffee000ULL));  // 5 bytes
	REQUIRE_NOTHROW(Builder->Call64(0x7ffee000ULL));  // 16 bytes
	REQUIRE_NOTHROW(Builder->Nop(0x100));             // 256 bytes

	REQUIRE(Builder->Success() == ZYAN_TRUE);
	REQUIRE(Builder->Failed() == ZYAN_FALSE);
	REQUIRE(Builder->Size() == 298);
}

TEST_CASE("Success method should return ZYAN_TRUE after each generated instruction", "[assembler]") {
	std::unique_ptr<AssemblyBuilder> Builder = std::make_unique<AssemblyBuilder>(0x7ffffd50ULL);

	REQUIRE_NOTHROW(Builder->Jmp32(0x7ffee000ULL));
	REQUIRE(Builder->Success() == ZYAN_TRUE);

	REQUIRE_NOTHROW(Builder->Jmp64(0x7ffee000ULL));
	REQUIRE(Builder->Success() == ZYAN_TRUE);

	REQUIRE_NOTHROW(Builder->Call32(0x7ffee000ULL));
	REQUIRE(Builder->Success() == ZYAN_TRUE);

	REQUIRE_NOTHROW(Builder->Call64(0x7ffee000ULL));
	REQUIRE(Builder->Success() == ZYAN_TRUE);

	REQUIRE_NOTHROW(Builder->Nop(0x100));
	REQUIRE(Builder->Success() == ZYAN_TRUE);
}

TEST_CASE("Failed method should return ZYAN_FALSE after each generated instruction", "[assembler]") {
	std::unique_ptr<AssemblyBuilder> Builder = std::make_unique<AssemblyBuilder>(0x7ffffd50ULL);

	REQUIRE_NOTHROW(Builder->Jmp32(0x7ffee000ULL));
	REQUIRE(Builder->Failed() == ZYAN_FALSE);

	REQUIRE_NOTHROW(Builder->Jmp64(0x7ffee000ULL));
	REQUIRE(Builder->Failed() == ZYAN_FALSE);

	REQUIRE_NOTHROW(Builder->Call32(0x7ffee000ULL));
	REQUIRE(Builder->Failed() == ZYAN_FALSE);

	REQUIRE_NOTHROW(Builder->Call64(0x7ffee000ULL));
	REQUIRE(Builder->Failed() == ZYAN_FALSE);

	REQUIRE_NOTHROW(Builder->Nop(0x100));
	REQUIRE(Builder->Failed() == ZYAN_FALSE);
}

TEST_CASE("Encode method should generate the proper provided instruction", "[assembler]") {
	std::unique_ptr<AssemblyBuilder> Builder = std::make_unique<AssemblyBuilder>(0x7ffffd50ULL);

	ZydisEncoderRequest EncoderRequest = {};

	EncoderRequest.mnemonic = ZYDIS_MNEMONIC_PUSH;
	EncoderRequest.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
	EncoderRequest.operand_count = 1;

	EncoderRequest.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
	EncoderRequest.operands[0].reg.value = ZYDIS_REGISTER_RAX;

	REQUIRE_NOTHROW(Builder->Encode(&EncoderRequest));

	REQUIRE(Builder->Size() == 1);

	ZyanU8 Buffer[1] = { 0 };

	REQUIRE(Builder->CopyTo(Buffer, sizeof(Buffer)) == ZYAN_TRUE);

	REQUIRE(Buffer[0] == 0x50);
}

TEST_CASE("Reencode method should encode the decoded instruction", "[assembler]") {
	std::unique_ptr<AssemblyBuilder> Builder = std::make_unique<AssemblyBuilder>(0x7ffffd50ULL);

	ZyanU8 Buffer[] = { 
		0xe9, 0xaa, 0xbb, 0xcc, 0xdd // jmp dword ptr 0xddccbbaa
	};

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};
	ZyanStatus Status = 0;

	Status = ZydisDecoderInit(
		&Decoder, 
		ZYDIS_MACHINE_MODE_LONG_64, 
		ZYDIS_STACK_WIDTH_64);

	REQUIRE(ZYAN_SUCCESS(Status));

	Status = ZydisDecoderDecodeFull(
		&Decoder,
		Buffer,
		sizeof(Buffer),
		&Decoded.Instruction,
		Decoded.Operands);

	REQUIRE(ZYAN_SUCCESS(Status));

	REQUIRE_NOTHROW(Builder->Reencode(&Decoded));
	REQUIRE(Builder->Success() == ZYAN_TRUE);
	REQUIRE(Builder->Failed() == ZYAN_FALSE);
	REQUIRE(Builder->LastInstructionLength() == 5);
	REQUIRE(Builder->Size() == 5);
}

TEST_CASE("Jcc method should encode a decoded je instruction", "[assembler]") {
	std::unique_ptr<AssemblyBuilder> Builder = std::make_unique<AssemblyBuilder>(0x7ffffd50ULL);

	ZyanU8 Buffer[] = {
		0x74, 0x06 // je 0x06
	};

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};
	ZyanStatus Status = 0;

	Status = ZydisDecoderInit(
		&Decoder,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64);

	REQUIRE(ZYAN_SUCCESS(Status));

	Status = ZydisDecoderDecodeFull(
		&Decoder,
		Buffer,
		sizeof(Buffer),
		&Decoded.Instruction,
		Decoded.Operands);

	REQUIRE(ZYAN_SUCCESS(Status));

	REQUIRE_NOTHROW(Builder->Jcc(&Decoded, 0x7ffee000ULL));
	REQUIRE(Builder->Success() == ZYAN_TRUE);
	REQUIRE(Builder->Failed() == ZYAN_FALSE);
	REQUIRE(Builder->LastInstructionLength() == 6);
	REQUIRE(Builder->Size() == 6);
}

