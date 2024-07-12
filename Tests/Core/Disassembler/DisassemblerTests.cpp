#include <catch2/catch_test_macros.hpp>
#include <Zyntercept/Core/Disassembler/Disassembler.h>

//IsRelative();
//IsRet();
//IsCall();
//IsJmp();
//IsJcc();
//SizeOfDecodedDesiredInstructions();
//FindReplaceableInstructions();
//FindNextFunctionBranch();
//FindFunctionBranchs();
//HasFunctionBranchDestinationsBetween();

static int __cdecl Fibonacci(int n)
{
	if (n <= 1) {
		return n;
	}

	return Fibonacci(n - 1) + Fibonacci(n - 2);
}


TEST_CASE("Check if IsRelative recognize <jmp dword ptr 0xaabbccd9> as relative instruction", "[disassembler]") {
	uint8_t Buffer[] = { 0xe9, 0xd9, 0xcc, 0xbb, 0xaa };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));
	
	REQUIRE(IsRelative(&Decoded) == ZYAN_TRUE);
}

TEST_CASE("Check if IsRelative recognize <call dword ptr 0xaabbccd9> as relative instruction", "[disassembler]") {
	uint8_t Buffer[] = { 0xe8, 0xd9, 0xcc, 0xbb, 0xaa };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	REQUIRE(IsRelative(&Decoded) == ZYAN_TRUE);
}

TEST_CASE("Check if IsRet recognize <ret> as near return instruction", "[disassembler]") {
	uint8_t Buffer[] = { 0xc3 };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	REQUIRE(IsRet(&Decoded) == ZYAN_TRUE);
}

TEST_CASE("Check if IsRet recognize <ret> as far return instruction", "[disassembler]") {
	uint8_t Buffer[] = { 0xcb };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	REQUIRE(IsRet(&Decoded) == ZYAN_TRUE);
}

TEST_CASE("Check if IsCall recognize <call dword ptr 0xaabbccd9> as call instruction", "[disassembler]") {
	uint8_t Buffer[] = { 0xe8, 0xd9, 0xcc, 0xbb, 0xaa };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	ZydisDecodedOperand* Operand = nullptr;

	REQUIRE(IsCall(&Decoded, &Operand) == ZYAN_TRUE);

	REQUIRE(Operand != nullptr);
	REQUIRE((Operand->imm.value.u & 0xffffffffUL) == 0xaabbccd9UL);
}

TEST_CASE("Check if IsJmp recognize <jmp dword ptr 0xaabbccd9> as jmp instruction", "[disassembler]") {
	uint8_t Buffer[] = { 0xe9, 0xd9, 0xcc, 0xbb, 0xaa };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	ZydisDecodedOperand* Operand = nullptr;

	REQUIRE(IsJmp(&Decoded, &Operand) == ZYAN_TRUE);

	REQUIRE(Operand != nullptr);
	REQUIRE((Operand->imm.value.u & 0xffffffffUL) == 0xaabbccd9UL);
}

TEST_CASE("Check if IsJmp dont recognize <jne dword ptr 0xaabbccd9> as jmp instruction", "[disassembler]") {
	uint8_t Buffer[] = { 0x0f, 0x85, 0xd9, 0xcc, 0xbb, 0xaa };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	ZydisDecodedOperand* Operand = nullptr;

	REQUIRE(IsJmp(&Decoded, &Operand) == ZYAN_FALSE);

	REQUIRE(Operand == nullptr);
}

TEST_CASE("Check if IsJcc recognize <jne dword ptr 0xaabbccd9> as jcc instruction", "[disassembler]") {
	uint8_t Buffer[] = { 0x0f, 0x85, 0xd9, 0xcc, 0xbb, 0xaa };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	ZydisDecodedOperand* Operand = nullptr;

	REQUIRE(IsJcc(&Decoded, &Operand) == ZYAN_TRUE);

	REQUIRE(Operand != nullptr);
	REQUIRE((Operand->imm.value.u & 0xffffffffUL) == 0xaabbccd9UL);
}

TEST_CASE("Check if IsJcc dont recognize <jmp dword ptr 0xaabbccd9> as jcc instruction", "[disassembler]") {
	uint8_t Buffer[] = { 0xe9, 0xd9, 0xcc, 0xbb, 0xaa };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	ZydisDecodedOperand* Operand = nullptr;

	REQUIRE(IsJcc(&Decoded, &Operand) == ZYAN_FALSE);

	REQUIRE(Operand == nullptr);
}

TEST_CASE("Check if SizeOfDecodedDesiredInstructions return the correct length in x86 real function", "[disassembler]") {
	uint8_t Buffer[] = {
		0x8B, 0xFF,                      // 0x10000 | mov edi, edi
		0x55,                            // 0x10002 | push ebp
		0x8B, 0xEC,                      // 0x10003 | mov ebp, esp
		0x8B, 0x45, 0x08,                // 0x10005 | mov eax, dword ptr ss:[ebp + 8]
		0x83, 0xF8, 0x0B,                // 0x10008 | cmp eax, 0B
		0x73, 0x11,                      // 0x1000B | jae 0x1001E
		0x6B, 0xC8, 0x28,                // 0x1000D | imul ecx, eax, 0x28
		0xA1, 0x50, 0x6C, 0x75, 0x77,    // 0x10010 | mov eax, dword ptr ds:[0x776C50]
		0x05, 0xA4, 0x03, 0x00, 0x00,    // 0x10015 | add eax, 0x3A4
		0x03, 0xC1,                      // 0x1001A | add eax, ecx
		0xEB, 0x02,                      // 0x1001C | jmp 0x10020
		0x33, 0xC0,                      // 0x1001E | xor eax, eax
		0x5D,                            // 0x10020 | pop ebp
		0xC2, 0x04, 0x00                 // 0x10021 | ret 0x4
	};

	ZyanU32 DesiredSize = 5; // 5 bytes

	ZyanU64 SizeOfDecodedInstructions = SizeOfDecodedDesiredInstructions(
		ZYDIS_MACHINE_MODE_LEGACY_32, 
		ZYDIS_STACK_WIDTH_32, 
		Buffer, 
		sizeof(Buffer), 
		DesiredSize);

	REQUIRE(SizeOfDecodedInstructions != 0);
}

TEST_CASE("Check if SizeOfDecodedDesiredInstructions return the correct length in x64 real function", "[disassembler]") {
	uint8_t Buffer[] = {
		0x83, 0xF9, 0x0B,                          // 0x10000 | cmp ecx,B
		0x73, 0x19,                                // 0x10003 | jae 0x1001E
		0x8B, 0xC1,                                // 0x10005 | mov eax,ecx
		0x48, 0x8D, 0x0C, 0x80,                    // 0x10007 | lea rcx,qword ptr ds:[rax+rax*4]
		0x48, 0x8B, 0x05, 0xA6, 0x8B, 0x03, 0x00,  // 0x1000B | mov rax,qword ptr ds:[0x1030B]
		0x48, 0x8D, 0x04, 0xC8,                    // 0x10012 | lea rax,qword ptr ds:[rax+rcx*8]
		0x48, 0x05,	0xA4, 0x03, 0x00, 0x00,        // 0x10016 | add rax,3A4
		0xC3,                                      // 0x1001C | ret 
		0xCC,                                      // 0x1001D | int3 
		0x33, 0xC0,                                // 0x1001E | xor eax,eax
		0xC3                                       // 0x10020 | ret
	};

	ZyanU32 DesiredSize = 5; // 5 bytes

	ZyanU64 SizeOfDecodedInstructions = SizeOfDecodedDesiredInstructions(
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64,
		Buffer,
		sizeof(Buffer),
		DesiredSize);

	REQUIRE(SizeOfDecodedInstructions != 0);
}

TEST_CASE("Check if SizeOfDecodedDesiredInstructions return zero when x86 real function is too short", "[disassembler]") {
	uint8_t Buffer[] = { 
		0x8B, 0xFF, 0x55 // 0x10000 | mov edi, edi
	};

	ZyanU32 DesiredSize = 5; // 5 bytes

	ZyanU64 SizeOfDecodedInstructions = SizeOfDecodedDesiredInstructions(
		ZYDIS_MACHINE_MODE_LEGACY_32,
		ZYDIS_STACK_WIDTH_32,
		Buffer,
		sizeof(Buffer),
		DesiredSize);

	REQUIRE(SizeOfDecodedInstructions == 0);
}

TEST_CASE("Check if SizeOfDecodedDesiredInstructions return zero when x64 real function is too short", "[disassembler]") {
	uint8_t Buffer[] = { 
		0x83, 0xF9, 0x0B // 0x10000 | cmp ecx,B
	};

	ZyanU32 DesiredSize = 5; // 5 bytes

	ZyanU64 SizeOfDecodedInstructions = SizeOfDecodedDesiredInstructions(
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64,
		Buffer,
		sizeof(Buffer),
		DesiredSize);

	REQUIRE(SizeOfDecodedInstructions == 0);
}

TEST_CASE("Check if SizeOfDecodedDesiredInstructions return zero when x86 prologue has invalid instructions, paddings or returns", "[disassembler]") {
	uint8_t Buffer[] = { 
		0x8B, 0xFF, 0x55,              // 0x10000 | mov edi, edi
		0xc3,                          // 0x10003 | ret
		0xe9, 0xd9, 0xcc, 0xbb, 0xaa   // 0x10004 | jmp 0xaabbccd9
	};

	ZyanU32 DesiredSize = 5; // 5 bytes

	ZyanU64 SizeOfDecodedInstructions = SizeOfDecodedDesiredInstructions(
		ZYDIS_MACHINE_MODE_LEGACY_32,
		ZYDIS_STACK_WIDTH_32,
		Buffer,
		sizeof(Buffer),
		DesiredSize);

	REQUIRE(SizeOfDecodedInstructions == 0);
}

TEST_CASE("Check if SizeOfDecodedDesiredInstructions return zero when x64 prologue has invalid instructions, paddings or returns", "[disassembler]") {
	uint8_t Buffer[] = { 
		0x83, 0xF9, 0x0B,             // 0x10000 | cmp ecx,B
		0xc3,                         // 0x10003 | ret
		0xe9, 0xd9, 0xcc, 0xbb, 0xaa  // 0x10004 | jmp 0xaabbccd9
	};

	ZyanU32 DesiredSize = 5; // 5 bytes

	ZyanU64 SizeOfDecodedInstructions = SizeOfDecodedDesiredInstructions(
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64,
		Buffer,
		sizeof(Buffer),
		DesiredSize);

	REQUIRE(SizeOfDecodedInstructions == 0);
}

TEST_CASE("Check if FindReplaceableInstructions can find the instructions to replace in a x86 real function", "[disassembler]") {
	uint8_t Buffer[] = {
		0x8B, 0xFF,                      // 0x10000 | mov edi, edi
		0x55,                            // 0x10002 | push ebp
		0x8B, 0xEC,                      // 0x10003 | mov ebp, esp
		0x8B, 0x45, 0x08,                // 0x10005 | mov eax, dword ptr ss:[ebp + 8]
		0x83, 0xF8, 0x0B,                // 0x10008 | cmp eax, 0B
		0x73, 0x11,                      // 0x1000B | jae 0x1001E
		0x6B, 0xC8, 0x28,                // 0x1000D | imul ecx, eax, 0x28
		0xA1, 0x50, 0x6C, 0x75, 0x77,    // 0x10010 | mov eax, dword ptr ds:[0x776C50]
		0x05, 0xA4, 0x03, 0x00, 0x00,    // 0x10015 | add eax, 0x3A4
		0x03, 0xC1,                      // 0x1001A | add eax, ecx
		0xEB, 0x02,                      // 0x1001C | jmp 0x10020
		0x33, 0xC0,                      // 0x1001E | xor eax, eax
		0x5D,                            // 0x10020 | pop ebp
		0xC2, 0x04, 0x00                 // 0x10021 | ret 0x4
	};

	ZyanU32 DesiredSize = 5; // 5 bytes

	ZyanU64 SizeOfDecodedInstructions = SizeOfDecodedDesiredInstructions(
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64,
		Buffer,
		sizeof(Buffer),
		DesiredSize);

	ZydisDecoded* DecodedBuffer = (ZydisDecoded*)malloc(SizeOfDecodedInstructions);
	ZyanU64 NumberOfFoundInstructions = 0;
	ZyanUSize SizeOfFoundInstructions = 0;

	REQUIRE(DecodedBuffer != nullptr);

	ZyanBool Status = FindReplaceableInstructions(
		ZYDIS_MACHINE_MODE_LEGACY_32,
		ZYDIS_STACK_WIDTH_32,
		Buffer,
		sizeof(Buffer),
		DesiredSize,
		SizeOfDecodedInstructions,
		DecodedBuffer,
		&NumberOfFoundInstructions,
		&SizeOfFoundInstructions);

	free(DecodedBuffer);

	REQUIRE(Status == ZYAN_TRUE);
	REQUIRE(NumberOfFoundInstructions == 3);
	REQUIRE(SizeOfFoundInstructions == 5);
	REQUIRE(SizeOfDecodedInstructions == NumberOfFoundInstructions * sizeof(ZydisDecoded));
}

TEST_CASE("Check if FindReplaceableInstructions can find the instructions to replace in a x64 real function", "[disassembler]") {
	uint8_t Buffer[] = {
		0x83, 0xF9, 0x0B,                         // 0x10000 | cmp ecx,B
		0x73, 0x19,                               // 0x10003 | jae 0x1001E
		0x8B, 0xC1,                               // 0x10005 | mov eax,ecx
		0x48, 0x8D, 0x0C, 0x80,                   // 0x10007 | lea rcx,qword ptr ds:[rax+rax*4]
		0x48, 0x8B, 0x05, 0xA6, 0x8B, 0x03, 0x00, // 0x1000B | mov rax,qword ptr ds:[0x1030B]
		0x48, 0x8D, 0x04, 0xC8,                   // 0x10012 | lea rax,qword ptr ds:[rax+rcx*8]
		0x48, 0x05,	0xA4, 0x03, 0x00, 0x00,       // 0x10016 | add rax,3A4
		0xC3,                                     // 0x1001C | ret 
		0xCC,                                     // 0x1001D | int3 
		0x33, 0xC0,                               // 0x1001E | xor eax,eax
		0xC3                                      // 0x10020 | ret
	};

	ZyanU32 DesiredSize = 5; // 5 bytes

	ZyanU64 SizeOfDecodedInstructions = SizeOfDecodedDesiredInstructions(
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64,
		Buffer,
		sizeof(Buffer),
		DesiredSize);

	ZydisDecoded* DecodedBuffer = (ZydisDecoded*)malloc(SizeOfDecodedInstructions);
	ZyanU64 NumberOfFoundInstructions = 0;
	ZyanUSize SizeOfFoundInstructions = 0;

	REQUIRE(DecodedBuffer != nullptr);

	ZyanBool Status = FindReplaceableInstructions(
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64,
		Buffer,
		sizeof(Buffer),
		DesiredSize,
		SizeOfDecodedInstructions,
		DecodedBuffer,
		&NumberOfFoundInstructions,
		&SizeOfFoundInstructions);

	free(DecodedBuffer);

	REQUIRE(Status == ZYAN_TRUE);
	REQUIRE(NumberOfFoundInstructions == 2);
	REQUIRE(SizeOfFoundInstructions == 5);
	REQUIRE(SizeOfDecodedInstructions == NumberOfFoundInstructions * sizeof(ZydisDecoded));
}

TEST_CASE("Check if FindNextFunctionBranch find the next branch correctly in a x86 real function", "[disassembler]") {
	uint8_t Buffer[] = {
		0x8B, 0xFF,                   // 0x10000 | mov edi, edi
		0x55,                         // 0x10002 | push ebp
		0x8B, 0xEC,                   // 0x10003 | mov ebp, esp
		0x8B, 0x45, 0x08,             // 0x10005 | mov eax, dword ptr ss:[ebp + 8]
		0x83, 0xF8, 0x0B,             // 0x10008 | cmp eax, 0B
		0x73, 0x11,                   // 0x1000B | jae 0x1001E
		0x6B, 0xC8, 0x28,             // 0x1000D | imul ecx, eax, 0x28
		0xA1, 0x50, 0x6C, 0x75, 0x77, // 0x10010 | mov eax, dword ptr ds:[0x776C50]
		0x05, 0xA4, 0x03, 0x00, 0x00, // 0x10015 | add eax, 0x3A4
		0x03, 0xC1,                   // 0x1001A | add eax, ecx
		0xEB, 0x02,                   // 0x1001C | jmp 0x10020
		0x33, 0xC0,                   // 0x1001E | xor eax, eax
		0x5D,                         // 0x10020 | pop ebp
		0xC2, 0x04, 0x00              // 0x10021 | ret 0x4
	};

	ZydisDecoded Decoded = {};
	ZyanU64 BaseAddress = 0x10000ULL;

	ZyanU64 InstructionAddress = 0;
	ZyanU64 GreenBranchAddress = 0;
	ZyanU64 RedBranchAddress = 0;

	ZyanBool Status = FindNextFunctionBranch(
		ZYDIS_MACHINE_MODE_LEGACY_32,
		ZYDIS_STACK_WIDTH_32,
		Buffer,
		sizeof(Buffer),
		BaseAddress,
		&Decoded,
		&InstructionAddress,
		&GreenBranchAddress,
		&RedBranchAddress);

	REQUIRE(Status == ZYAN_TRUE);
	REQUIRE(InstructionAddress == BaseAddress + 0x0b);
	REQUIRE(GreenBranchAddress == BaseAddress + 0x1e);
	REQUIRE(RedBranchAddress == BaseAddress + 0x0d);
}

TEST_CASE("Check if FindNextFunctionBranch find the next branch correctly in a x64 real function", "[disassembler]") {
	uint8_t Buffer[] = {
		0x83, 0xF9, 0x0B,                           // 0x10000 | cmp ecx,B
		0x73, 0x19,                                 // 0x10003 | jae 0x1001E
		0x8B, 0xC1,                                 // 0x10005 | mov eax,ecx
		0x48, 0x8D, 0x0C, 0x80,                     // 0x10007 | lea rcx,qword ptr ds:[rax+rax*4]
		0x48, 0x8B, 0x05, 0xA6, 0x8B, 0x03, 0x00,   // 0x1000B | mov rax,qword ptr ds:[0x1030B]
		0x48, 0x8D, 0x04, 0xC8,                     // 0x10012 | lea rax,qword ptr ds:[rax+rcx*8]
		0x48, 0x05, 0xA4, 0x03, 0x00, 0x00,         // 0x10016 | add rax,3A4
		0xC3,                                       // 0x1001C | ret
		0xCC,                                       // 0x1001D | int3
		0x33, 0xC0,                                 // 0x1001E | xor eax,eax
		0xC3                                        // 0x10020 | ret
	};

	ZydisDecoded Decoded = {};
	ZyanU64 BaseAddress = 0x10000ULL;

	ZyanU64 InstructionAddress = 0;
	ZyanU64 GreenBranchAddress = 0;
	ZyanU64 RedBranchAddress = 0;

	ZyanBool Status = FindNextFunctionBranch(
		ZYDIS_MACHINE_MODE_LEGACY_32,
		ZYDIS_STACK_WIDTH_32,
		Buffer,
		sizeof(Buffer),
		BaseAddress,
		&Decoded,
		&InstructionAddress,
		&GreenBranchAddress,
		&RedBranchAddress);

	REQUIRE(Status == ZYAN_TRUE);
	REQUIRE(InstructionAddress == BaseAddress + 0x03);
	REQUIRE(GreenBranchAddress == BaseAddress + 0x1e);
	REQUIRE(RedBranchAddress == BaseAddress + 0x05);
}

TEST_CASE("Check if FindFunctionBranchs find the all branchs correctly in a x86 real function", "[disassembler]") {
	SKIP();
}

TEST_CASE("Check if FindFunctionBranchs find the all branchs correctly in a x64 real function", "[disassembler]") {
	SKIP();
}

TEST_CASE("Check if FindFunctionBranchs not find the all branchs correctly in an invalid function", "[disassembler]") {
	SKIP();
}

TEST_CASE("Check if HasFunctionBranchDestinationsBetween detect recursivity in a x86 real function", "[disassembler]") {
	SKIP();
}

TEST_CASE("Check if HasFunctionBranchDestinationsBetween detect recursivity in a x64 real function", "[disassembler]") {
	SKIP();
}