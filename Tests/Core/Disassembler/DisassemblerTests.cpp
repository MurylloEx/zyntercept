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
	//mov edi, edi
	//push ebp
	//mov ebp, esp
	//mov eax, dword ptr ss : [ebp + 8]
	//cmp eax, B
	//jae user32.777315EE
	//imul ecx, eax, 28
	//mov eax, dword ptr ds : [77756C50]
	//add eax, 3A4
	//add eax, ecx
	//jmp user32.777315F0
	//xor eax, eax
	//pop ebp
	//ret 4

	uint8_t Buffer[] = { 
		0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 
		0x83, 0xF8, 0x0B, 0x73, 0x11, 0x6B, 0xC8, 0x28, 
		0xA1, 0x50, 0x6C, 0x75, 0x77, 0x05, 0xA4, 0x03, 
		0x00, 0x00, 0x03, 0xC1, 0xEB, 0x02, 0x33, 0xC0, 
		0x5D, 0xC2, 0x04, 0x00
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
	//cmp ecx,B
	//jae user32.7FFA7296A6FE
	//mov eax,ecx
	//lea rcx,qword ptr ds:[rax+rax*4]
	//mov rax,qword ptr ds:[7FFA729A3298]
	//lea rax,qword ptr ds:[rax+rcx*8]
	//add rax,3A4
	//ret 
	//int3 
	//xor eax,eax
	//ret

	uint8_t Buffer[] = {
		0x83, 0xF9, 0x0B, 0x73, 0x19, 0x8B, 0xC1, 0x48,
		0x8D, 0x0C, 0x80, 0x48, 0x8B, 0x05, 0xA6, 0x8B,
		0x03, 0x00, 0x48, 0x8D, 0x04, 0xC8, 0x48, 0x05,
		0xA4, 0x03, 0x00, 0x00, 0xC3, 0xCC, 0x33, 0xC0,
		0xC3
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
	//mov edi, edi

	uint8_t Buffer[] = { 0x8B, 0xFF, 0x55 };

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
	//cmp ecx,B

	uint8_t Buffer[] = { 0x83, 0xF9, 0x0B };

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
	//mov edi, edi
	//ret
	//jmp 0xaabbccd9

	uint8_t Buffer[] = { 0x8B, 0xFF, 0x55, 0xc3, 0xe9, 0xd9, 0xcc, 0xbb, 0xaa };

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
	//cmp ecx,B
	//ret
	//jmp 0xaabbccd9

	uint8_t Buffer[] = { 0x83, 0xF9, 0x0B, 0xc3, 0xe9, 0xd9, 0xcc, 0xbb, 0xaa };

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
	//mov edi, edi
	//push ebp
	//mov ebp, esp
	//mov eax, dword ptr ss : [ebp + 8]
	//cmp eax, B
	//jae user32.777315EE
	//imul ecx, eax, 28
	//mov eax, dword ptr ds : [77756C50]
	//add eax, 3A4
	//add eax, ecx
	//jmp user32.777315F0
	//xor eax, eax
	//pop ebp
	//ret 4

	uint8_t Buffer[] = {
		0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08,
		0x83, 0xF8, 0x0B, 0x73, 0x11, 0x6B, 0xC8, 0x28,
		0xA1, 0x50, 0x6C, 0x75, 0x77, 0x05, 0xA4, 0x03,
		0x00, 0x00, 0x03, 0xC1, 0xEB, 0x02, 0x33, 0xC0,
		0x5D, 0xC2, 0x04, 0x00
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

	REQUIRE(Status == ZYAN_TRUE);
	REQUIRE(NumberOfFoundInstructions == 3);
	REQUIRE(SizeOfFoundInstructions == 5);
	REQUIRE(SizeOfDecodedInstructions == NumberOfFoundInstructions * sizeof(ZydisDecoded));
}

TEST_CASE("Check if FindReplaceableInstructions can find the instructions to replace in a x64 real function", "[disassembler]") {
	//cmp ecx,B
	//jae user32.7FFA7296A6FE
	//mov eax,ecx
	//lea rcx,qword ptr ds:[rax+rax*4]
	//mov rax,qword ptr ds:[7FFA729A3298]
	//lea rax,qword ptr ds:[rax+rcx*8]
	//add rax,3A4
	//ret 
	//int3 
	//xor eax,eax
	//ret

	uint8_t Buffer[] = {
		0x83, 0xF9, 0x0B, 0x73, 0x19, 0x8B, 0xC1, 0x48,
		0x8D, 0x0C, 0x80, 0x48, 0x8B, 0x05, 0xA6, 0x8B,
		0x03, 0x00, 0x48, 0x8D, 0x04, 0xC8, 0x48, 0x05,
		0xA4, 0x03, 0x00, 0x00, 0xC3, 0xCC, 0x33, 0xC0,
		0xC3
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

	REQUIRE(Status == ZYAN_TRUE);
	REQUIRE(NumberOfFoundInstructions == 2);
	REQUIRE(SizeOfFoundInstructions == 5);
	REQUIRE(SizeOfDecodedInstructions == NumberOfFoundInstructions * sizeof(ZydisDecoded));
}
