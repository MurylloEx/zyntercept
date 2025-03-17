#include <catch2/catch_test_macros.hpp>
#include <Zyntercept/Core/Assembler/Assembler.h>
#include <Zyntercept/Core/Disassembler/Disassembler.h>

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

	struct AssemblyInstruction {
		ZyanU8 Call32Opcode;
		ZyanU8 Call32Immediate[4];
	};

	AssemblyInstruction Instruction = { 0 };

	REQUIRE(Builder->CopyTo(&Instruction, sizeof(Instruction)) == ZYAN_TRUE);

	REQUIRE(Instruction.Call32Opcode == 0xe8);

	REQUIRE(Instruction.Call32Immediate[0] == 0x88);
	REQUIRE(Instruction.Call32Immediate[1] == 0xcf);
	REQUIRE(Instruction.Call32Immediate[2] == 0xbb);
	REQUIRE(Instruction.Call32Immediate[3] == 0x2a);
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

	REQUIRE(Instruction.Call64Immediate[0] == 0x02);
	REQUIRE(Instruction.Call64Immediate[1] == 0x00);
	REQUIRE(Instruction.Call64Immediate[2] == 0x00);
	REQUIRE(Instruction.Call64Immediate[3] == 0x00);

	REQUIRE(Instruction.Call64AbsoluteAddress[0] == 0x00);
	REQUIRE(Instruction.Call64AbsoluteAddress[1] == 0xe0);
	REQUIRE(Instruction.Call64AbsoluteAddress[2] == 0xfe);
	REQUIRE(Instruction.Call64AbsoluteAddress[3] == 0x7f);
	REQUIRE(Instruction.Call64AbsoluteAddress[4] == 0x00);
	REQUIRE(Instruction.Call64AbsoluteAddress[5] == 0x00);
	REQUIRE(Instruction.Call64AbsoluteAddress[6] == 0x00);
	REQUIRE(Instruction.Call64AbsoluteAddress[7] == 0x00);
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

	REQUIRE(Instruction.Jmp32Immediate[0] == 0xab);
	REQUIRE(Instruction.Jmp32Immediate[1] == 0xe2);
	REQUIRE(Instruction.Jmp32Immediate[2] == 0xfe);
	REQUIRE(Instruction.Jmp32Immediate[3] == 0xff);
}

TEST_CASE("Should generate a valid <jmp qword ptr [rip+0x02]> instruction when call Jmp64 method", "[assembler]") {
	std::unique_ptr<AssemblyBuilder> Builder = std::make_unique<AssemblyBuilder>(0x7ffffd50ULL);

	REQUIRE_NOTHROW(Builder->Jmp64(0x7ffee000ULL));

	REQUIRE(Builder->Success() == ZYAN_TRUE);
	REQUIRE(Builder->Failed() == ZYAN_FALSE);
	REQUIRE(Builder->Size() == 14);
	REQUIRE(Builder->LastInstructionLength() == 14);

	// jmp qword ptr [rip+0x00]
	// ptr data

	struct AssemblyInstruction {
		ZyanU8 Jmp64Opcode;
		ZyanU8 ModRM;
		ZyanU8 Jmp64Immediate[4];
		ZyanU8 Jmp64AbsoluteAddress[8];
	};

	AssemblyInstruction Instruction = { 0 };

	REQUIRE(Builder->CopyTo(&Instruction, sizeof(Instruction)) == ZYAN_TRUE);

	REQUIRE(Instruction.Jmp64Opcode == 0xff);
	REQUIRE(Instruction.ModRM == 0x25);

	REQUIRE(Instruction.Jmp64Immediate[0] == 0x00);
	REQUIRE(Instruction.Jmp64Immediate[1] == 0x00);
	REQUIRE(Instruction.Jmp64Immediate[2] == 0x00);
	REQUIRE(Instruction.Jmp64Immediate[3] == 0x00);

	REQUIRE(Instruction.Jmp64AbsoluteAddress[0] == 0x00);
	REQUIRE(Instruction.Jmp64AbsoluteAddress[1] == 0xe0);
	REQUIRE(Instruction.Jmp64AbsoluteAddress[2] == 0xfe);
	REQUIRE(Instruction.Jmp64AbsoluteAddress[3] == 0x7f);
	REQUIRE(Instruction.Jmp64AbsoluteAddress[4] == 0x00);
	REQUIRE(Instruction.Jmp64AbsoluteAddress[5] == 0x00);
	REQUIRE(Instruction.Jmp64AbsoluteAddress[6] == 0x00);
	REQUIRE(Instruction.Jmp64AbsoluteAddress[7] == 0x00);
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

	// 0x7ffffd50 | jmp 0x7ffee000   ; jmp dword ptr imm32
	// 0x7ffffd54 | jmp 0x7ffee100   ; jmp qword ptr [rip+0x00]
	// 0x7ffffd62 | call 0x7ffee200  ; call dword ptr imm32
	// 0x7ffffd67 | call 0x7ffee300  ; call qword ptr [rip+0x02]
	// 0x7ffffd6d | jmp 0x02         ; jmp byte ptr imm8
	// 0x7ffffd77 | nop
	// 0x7ffff??? | nop (...)

	REQUIRE_NOTHROW(Builder->Jmp32(0x7ffee000ULL));
	REQUIRE(Builder->Offset() == 0x04);

	REQUIRE_NOTHROW(Builder->Jmp64(0x7ffee100ULL));
	REQUIRE(Builder->Offset() == 0x12);

	REQUIRE_NOTHROW(Builder->Call32(0x7ffee200ULL));
	REQUIRE(Builder->Offset() == 0x17);

	REQUIRE_NOTHROW(Builder->Call64(0x7ffee300ULL));
	REQUIRE(Builder->Offset() == 0x27);

	REQUIRE_NOTHROW(Builder->Nop(0x100));
	REQUIRE(Builder->Offset() == 0x127);
}

TEST_CASE("LastInstructionLength method should return the valid instruction length after each generated instruction", "[assembler]") {
	std::unique_ptr<AssemblyBuilder> Builder = std::make_unique<AssemblyBuilder>(0x7ffffd50ULL);

	REQUIRE_NOTHROW(Builder->Jmp32(0x7ffee000ULL));
	REQUIRE(Builder->LastInstructionLength() == 5);

	REQUIRE_NOTHROW(Builder->Jmp64(0x7ffee000ULL));
	REQUIRE(Builder->LastInstructionLength() == 14);

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
	REQUIRE_NOTHROW(Builder->Jmp64(0x7ffee000ULL));   // 14 bytes
	REQUIRE_NOTHROW(Builder->Call32(0x7ffee000ULL));  // 5 bytes
	REQUIRE_NOTHROW(Builder->Call64(0x7ffee000ULL));  // 16 bytes
	REQUIRE_NOTHROW(Builder->Nop(0x100));             // 256 bytes

	REQUIRE(Builder->Success() == ZYAN_TRUE);
	REQUIRE(Builder->Failed() == ZYAN_FALSE);
	REQUIRE(Builder->Size() == 296);
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

TEST_CASE("Encode method should generate the proper provided <push rax> instruction", "[assembler]") {
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

	struct AssemblyInstruction {
		ZyanU8 Jmp32Opcode;
		ZyanU8 Jmp32Immediate[4];
	};

	AssemblyInstruction Instruction = { 0 };

	REQUIRE(Builder->CopyTo(&Instruction, sizeof(Instruction)) == ZYAN_TRUE);

	REQUIRE(Instruction.Jmp32Opcode == 0xe9);

	REQUIRE(Instruction.Jmp32Immediate[0] == 0xaa);
	REQUIRE(Instruction.Jmp32Immediate[1] == 0xbb);
	REQUIRE(Instruction.Jmp32Immediate[2] == 0xcc);
	REQUIRE(Instruction.Jmp32Immediate[3] == 0xdd);
}

TEST_CASE("Jcc method should encode a decoded <je rel imm8> instruction", "[assembler]") {
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

	struct AssemblyInstruction {
		ZyanU8 ExtensionFlag32;
		ZyanU8 Jcc32Opcode;
		ZyanU8 Jcc32Immediate[4];
	};

	AssemblyInstruction Instruction = { 0 };

	REQUIRE(Builder->CopyTo(&Instruction, sizeof(Instruction)) == ZYAN_TRUE);

	REQUIRE(Instruction.ExtensionFlag32 == 0x0f);
	REQUIRE(Instruction.Jcc32Opcode == 0x84);

	REQUIRE(Instruction.Jcc32Immediate[0] == 0xaa);
	REQUIRE(Instruction.Jcc32Immediate[1] == 0xe2);
	REQUIRE(Instruction.Jcc32Immediate[2] == 0xfe);
	REQUIRE(Instruction.Jcc32Immediate[3] == 0xff);
}

TEST_CASE("Jncc method should encode a decoded <je rel imm8> instruction into <jne rel imm32> instruction", "[assembler]") {
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

	REQUIRE_NOTHROW(Builder->Jncc(ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64, &Decoded, 0x7ffee000ULL));

	REQUIRE(Builder->Success() == ZYAN_TRUE);
	REQUIRE(Builder->Failed() == ZYAN_FALSE);
	REQUIRE(Builder->LastInstructionLength() == 6);
	REQUIRE(Builder->Size() == 6);

	struct AssemblyInstruction {
		ZyanU8 ExtensionFlag32;
		ZyanU8 Jcc32Opcode;
		ZyanU8 Jcc32Immediate[4];
	};

	AssemblyInstruction Instruction = { 0 };

	REQUIRE(Builder->CopyTo(&Instruction, sizeof(Instruction)) == ZYAN_TRUE);

	REQUIRE(Instruction.ExtensionFlag32 == 0x0f);
	REQUIRE(Instruction.Jcc32Opcode == 0x85);
}

TEST_CASE("Should copy bytes of encoded instructions to a new buffer", "[assembler]") {
	std::unique_ptr<AssemblyBuilder> Builder = std::make_unique<AssemblyBuilder>(0x7ffffd50ULL);

	REQUIRE_NOTHROW(Builder->Call32(0x7ffee000ULL));
	REQUIRE(Builder->Success() == ZYAN_TRUE);
	REQUIRE(Builder->Failed() == ZYAN_FALSE);

	REQUIRE_NOTHROW(Builder->Jmp32(0x7ffee000ULL));
	REQUIRE(Builder->Success() == ZYAN_TRUE);
	REQUIRE(Builder->Failed() == ZYAN_FALSE);

	REQUIRE_NOTHROW(Builder->Nop(0x100));
	REQUIRE(Builder->Success() == ZYAN_TRUE);
	REQUIRE(Builder->Failed() == ZYAN_FALSE);

	REQUIRE_NOTHROW(Builder->Call64(0x7ffee000ULL));
	REQUIRE(Builder->Success() == ZYAN_TRUE);
	REQUIRE(Builder->Failed() == ZYAN_FALSE);

	REQUIRE_NOTHROW(Builder->Jmp64(0x7ffee000ULL));
	REQUIRE(Builder->Success() == ZYAN_TRUE);
	REQUIRE(Builder->Failed() == ZYAN_FALSE);

	ZyanU8* Buffer = new ZyanU8[Builder->Size()];

	std::memset(Buffer, 0, Builder->Size());

	REQUIRE(Builder->CopyTo(Buffer, Builder->Size()) == ZYAN_TRUE);

	delete[] Buffer;
}
