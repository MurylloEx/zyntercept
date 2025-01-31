#include <catch2/catch_test_macros.hpp>
#include <Zyntercept/Core/Syscall/Syscall.h>
#include <Zyntercept/Core/Disassembler/Disassembler.h>

#if defined(ZYNTERCEPT_WINDOWS)
#include <Windows.h>
static ZyanVoidPointer ProcessIdentifier = GetCurrentProcess();
#endif

#if defined(ZYNTERCEPT_UNIX)
#include <unistd.h>
static ZyanVoidPointer ProcessIdentifier = (ZyanVoidPointer)getpid();
#endif

TEST_CASE("Check if IsRelative recognize <jmp dword ptr 0xaabbccd9> as relative instruction", "[disassembler]") {
	ZyanU8 Buffer[] = { 0xe9, 0xd9, 0xcc, 0xbb, 0xaa };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));
	
	REQUIRE(ZynterceptIsRelative(&Decoded) == ZYAN_TRUE);
}

TEST_CASE("Check if IsRelative recognize <call dword ptr 0xaabbccd9> as relative instruction", "[disassembler]") {
	ZyanU8 Buffer[] = { 0xe8, 0xd9, 0xcc, 0xbb, 0xaa };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	REQUIRE(ZynterceptIsRelative(&Decoded) == ZYAN_TRUE);
}

TEST_CASE("Check if IsRet recognize <ret> as near return instruction", "[disassembler]") {
	ZyanU8 Buffer[] = { 0xc3 };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	REQUIRE(ZynterceptIsRet(&Decoded) == ZYAN_TRUE);
}

TEST_CASE("Check if IsRet recognize <ret> as far return instruction", "[disassembler]") {
	ZyanU8 Buffer[] = { 0xcb };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	REQUIRE(ZynterceptIsRet(&Decoded) == ZYAN_TRUE);
}

TEST_CASE("Check if IsCall recognize <call dword ptr 0xaabbccd9> as call instruction", "[disassembler]") {
	ZyanU8 Buffer[] = { 0xe8, 0xd9, 0xcc, 0xbb, 0xaa };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	ZydisDecodedOperand* Operand = nullptr;

	REQUIRE(ZynterceptIsCall(&Decoded, &Operand) == ZYAN_TRUE);

	REQUIRE(Operand != nullptr);
	REQUIRE((Operand->imm.value.u & 0xffffffffUL) == 0xaabbccd9UL);
}

TEST_CASE("Check if IsJmp recognize <jmp dword ptr 0xaabbccd9> as jmp instruction", "[disassembler]") {
	ZyanU8 Buffer[] = { 0xe9, 0xd9, 0xcc, 0xbb, 0xaa };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	ZydisDecodedOperand* Operand = nullptr;

	REQUIRE(ZynterceptIsJmp(&Decoded, &Operand) == ZYAN_TRUE);

	REQUIRE(Operand != nullptr);
	REQUIRE((Operand->imm.value.u & 0xffffffffUL) == 0xaabbccd9UL);
}

TEST_CASE("Check if IsJmp dont recognize <jne dword ptr 0xaabbccd9> as jmp instruction", "[disassembler]") {
	ZyanU8 Buffer[] = { 0x0f, 0x85, 0xd9, 0xcc, 0xbb, 0xaa };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	ZydisDecodedOperand* Operand = nullptr;

	REQUIRE(ZynterceptIsJmp(&Decoded, &Operand) == ZYAN_FALSE);

	REQUIRE(Operand == nullptr);
}

TEST_CASE("Check if IsJcc recognize <jne dword ptr 0xaabbccd9> as jcc instruction", "[disassembler]") {
	ZyanU8 Buffer[] = { 0x0f, 0x85, 0xd9, 0xcc, 0xbb, 0xaa };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	ZydisDecodedOperand* Operand = nullptr;

	REQUIRE(ZynterceptIsJcc(&Decoded, &Operand) == ZYAN_TRUE);

	REQUIRE(Operand != nullptr);
	REQUIRE((Operand->imm.value.u & 0xffffffffUL) == 0xaabbccd9UL);
}

TEST_CASE("Check if IsJcc dont recognize <jmp dword ptr 0xaabbccd9> as jcc instruction", "[disassembler]") {
	ZyanU8 Buffer[] = { 0xe9, 0xd9, 0xcc, 0xbb, 0xaa };

	ZydisDecoded Decoded = {};
	ZydisDecoder Decoder = {};

	REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
	REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

	ZydisDecodedOperand* Operand = nullptr;

	REQUIRE(ZynterceptIsJcc(&Decoded, &Operand) == ZYAN_FALSE);

	REQUIRE(Operand == nullptr);
}

TEST_CASE("Check if SizeOfDecodedDesiredInstructions return the correct length in x86 real function", "[disassembler]") {
	ZyanU8 Buffer[] = {
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

	ZyanU64 SizeOfDecodedInstructions = ZynterceptSizeOfDecodedDesiredInstructions(
		ZYDIS_MACHINE_MODE_LEGACY_32, 
		ZYDIS_STACK_WIDTH_32, 
		Buffer, 
		sizeof(Buffer), 
		DesiredSize);

	REQUIRE(SizeOfDecodedInstructions != 0);
}

TEST_CASE("Check if SizeOfDecodedDesiredInstructions return the correct length in x64 real function", "[disassembler]") {
	ZyanU8 Buffer[] = {
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

	ZyanU64 SizeOfDecodedInstructions = ZynterceptSizeOfDecodedDesiredInstructions(
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64,
		Buffer,
		sizeof(Buffer),
		DesiredSize);

	REQUIRE(SizeOfDecodedInstructions != 0);
}

TEST_CASE("Check if SizeOfDecodedDesiredInstructions return zero when x86 real function is too short", "[disassembler]") {
	ZyanU8 Buffer[] = {
		0x8B, 0xFF, 0x55 // 0x10000 | mov edi, edi
	};

	ZyanU32 DesiredSize = 5; // 5 bytes

	ZyanU64 SizeOfDecodedInstructions = ZynterceptSizeOfDecodedDesiredInstructions(
		ZYDIS_MACHINE_MODE_LEGACY_32,
		ZYDIS_STACK_WIDTH_32,
		Buffer,
		sizeof(Buffer),
		DesiredSize);

	REQUIRE(SizeOfDecodedInstructions == 0);
}

TEST_CASE("Check if SizeOfDecodedDesiredInstructions return zero when x64 real function is too short", "[disassembler]") {
	ZyanU8 Buffer[] = {
		0x83, 0xF9, 0x0B // 0x10000 | cmp ecx,B
	};

	ZyanU32 DesiredSize = 5; // 5 bytes

	ZyanU64 SizeOfDecodedInstructions = ZynterceptSizeOfDecodedDesiredInstructions(
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64,
		Buffer,
		sizeof(Buffer),
		DesiredSize);

	REQUIRE(SizeOfDecodedInstructions == 0);
}

TEST_CASE("Check if SizeOfDecodedDesiredInstructions return zero when x86 prologue has invalid instructions, paddings or returns", "[disassembler]") {
	ZyanU8 Buffer[] = {
		0x8B, 0xFF, 0x55,              // 0x10000 | mov edi, edi
		0xc3,                          // 0x10003 | ret
		0xe9, 0xd9, 0xcc, 0xbb, 0xaa   // 0x10004 | jmp 0xaabbccd9
	};

	ZyanU32 DesiredSize = 5; // 5 bytes

	ZyanU64 SizeOfDecodedInstructions = ZynterceptSizeOfDecodedDesiredInstructions(
		ZYDIS_MACHINE_MODE_LEGACY_32,
		ZYDIS_STACK_WIDTH_32,
		Buffer,
		sizeof(Buffer),
		DesiredSize);

	REQUIRE(SizeOfDecodedInstructions == 0);
}

TEST_CASE("Check if SizeOfDecodedDesiredInstructions return zero when x64 prologue has invalid instructions, paddings or returns", "[disassembler]") {
	ZyanU8 Buffer[] = {
		0x83, 0xF9, 0x0B,             // 0x10000 | cmp ecx,B
		0xc3,                         // 0x10003 | ret
		0xe9, 0xd9, 0xcc, 0xbb, 0xaa  // 0x10004 | jmp 0xaabbccd9
	};

	ZyanU32 DesiredSize = 5; // 5 bytes

	ZyanU64 SizeOfDecodedInstructions = ZynterceptSizeOfDecodedDesiredInstructions(
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64,
		Buffer,
		sizeof(Buffer),
		DesiredSize);

	REQUIRE(SizeOfDecodedInstructions == 0);
}

TEST_CASE("Check if FindReplaceableInstructions can find the instructions to replace in a x86 real function", "[disassembler]") {
	ZyanU8 Buffer[] = {
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

	ZyanU64 SizeOfDecodedInstructions = ZynterceptSizeOfDecodedDesiredInstructions(
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64,
		Buffer,
		sizeof(Buffer),
		DesiredSize);

	ZydisDecoded* DecodedBuffer = (ZydisDecoded*)malloc(SizeOfDecodedInstructions);
	ZyanU64 NumberOfFoundInstructions = 0;
	ZyanUSize SizeOfFoundInstructions = 0;

	REQUIRE(DecodedBuffer != nullptr);

	ZyanBool Status = ZynterceptFindReplaceableInstructions(
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
	ZyanU8 Buffer[] = {
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

	ZyanU64 SizeOfDecodedInstructions = ZynterceptSizeOfDecodedDesiredInstructions(
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64,
		Buffer,
		sizeof(Buffer),
		DesiredSize);

	ZydisDecoded* DecodedBuffer = (ZydisDecoded*)malloc(SizeOfDecodedInstructions);
	ZyanU64 NumberOfFoundInstructions = 0;
	ZyanUSize SizeOfFoundInstructions = 0;

	REQUIRE(DecodedBuffer != nullptr);

	ZyanBool Status = ZynterceptFindReplaceableInstructions(
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
	ZyanU8 Buffer[] = {
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

	ZyanBool Status = ZynterceptFindNextFunctionBranch(
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
	ZyanU8 Buffer[] = {
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

	ZyanBool Status = ZynterceptFindNextFunctionBranch(
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64,
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
	ZyanU8 Buffer[] = {
		0x83, 0xF8, 0x01,              // 0x10000 | cmp eax, 1          ; Compare n with 1
		0x76, 0x14,                    // 0x10003 | jbe 0x10019         ; If n <= 1, jump to base_case (0x10019)
		0x53,                          // 0x10005 | push ebx            ; Save ebx on the stack
		0x89, 0xC3,                    // 0x10006 | mov ebx, eax        ; Copy n to ebx
		0x48,                          // 0x10008 | dec eax             ; Decrement n (n-1)
		0xE8, 0xF1, 0xFF, 0xFF, 0xFF,  // 0x10009 | call 0x10000        ; Call fibonacci (address 0x10000)
		0x50,                          // 0x1000E | push eax            ; Save the result on the stack
		0x89, 0xD8,                    // 0x1000F | mov eax, ebx        ; Restore n to eax
		0x83, 0xE8, 0x02,              // 0x10011 | sub eax, 2          ; Decrement n by 2 (n-2)
		0xE8, 0xE7, 0xFF, 0xFF, 0xFF,  // 0x10014 | call 0x10000        ; Call fibonacci (address 0x10000)
		0x5B,                          // 0x10019 | pop ebx             ; Retrieve fibonacci(n-1) from ebx
		0x01, 0xD8,                    // 0x1001A | add eax, ebx        ; Add fibonacci(n-1) + fibonacci(n-2)
		0x5B,                          // 0x1001C | pop ebx             ; Restore ebx from the stack
		0xC3,                          // 0x1001D | ret                 ; Return
		0xB8, 0x01, 0x00, 0x00, 0x00,  // 0x1001E | mov eax, 1          ; Set Fibonacci(1) or Fibonacci(0) to 1
		0xC3                           // 0x10023 | ret                 ; Return
	};

	ZyanU64 BaseAddress = (ZyanU64)Buffer;
	ZydisBranch* FoundBranchs = nullptr;
	ZyanU64 NumberOfFoundBranchs = 0;

	ZyanBool Status = ZynterceptFindFunctionBranchs(
		ProcessIdentifier,
		ZYDIS_MACHINE_MODE_LEGACY_32,
		ZYDIS_STACK_WIDTH_32,
		BaseAddress,
		&FoundBranchs,
		&NumberOfFoundBranchs);

	REQUIRE(Status == ZYAN_TRUE);
	REQUIRE(NumberOfFoundBranchs == 2);
	REQUIRE(FoundBranchs != nullptr);

	for (ZyanU64 Offset = 0; Offset < NumberOfFoundBranchs; Offset++) {
		ZydisBranch* Branch = &FoundBranchs[Offset];

		if (Branch->Flow == ZYDIS_BRANCH_FLOW_GREEN) {
			REQUIRE(Branch->Mnemonic == ZYDIS_MNEMONIC_JBE);
			REQUIRE(Branch->Address == BaseAddress + 0x03);
			REQUIRE(Branch->Destination == BaseAddress + 0x19);
		}

		if (Branch->Flow == ZYDIS_BRANCH_FLOW_RED) {
			REQUIRE(Branch->Mnemonic == ZYDIS_MNEMONIC_JBE);
			REQUIRE(Branch->Address == BaseAddress + 0x03);
			REQUIRE(Branch->Destination == BaseAddress + 0x05);
		}
	}

	free(FoundBranchs);
}

TEST_CASE("Check if FindFunctionBranchs find the all branchs correctly in a x64 real function", "[disassembler]") {
	ZyanU8 Buffer[] = {
		0x53,                                      // 0x10000 | push rbx            ; Save rbx on the stack
		0x48, 0x83, 0xFF, 0x01,                    // 0x10001 | cmp rdi, 1          ; Compare n with 1
		0x76, 0x21,                                // 0x10005 | jbe 0x10028         ; If n <= 1, jump to base_case (offset 0x10028)
		0x48, 0x89, 0xDF,                          // 0x10007 | mov rbx, rdi        ; Copy n to rbx
		0x48, 0xFF, 0xCF,                          // 0x1000A | dec rdi             ; Decrement n (n-1)
		0xE8, 0xF1, 0xFF, 0xFF, 0xFF,              // 0x1000D | call 0x10003        ; Call fibonacci (address 0x10003)
		0x50,                                      // 0x10012 | push rax            ; Save the result on the stack
		0x48, 0x89, 0xDF,                          // 0x10013 | mov rdi, rbx        ; Restore n to rdi
		0x48, 0x83, 0xEF, 0x02,                    // 0x10016 | sub rdi, 2          ; Decrement n by 2 (n-2)
		0xE8, 0xE7, 0xFF, 0xFF, 0xFF,              // 0x1001A | call 0x10003        ; Call fibonacci (address 0x10003)
		0x5B,                                      // 0x1001F | pop rbx             ; Retrieve fibonacci(n-1) from rbx
		0x48, 0x01, 0xD8,                          // 0x10020 | add rax, rbx        ; Add fibonacci(n-1) + fibonacci(n-2)
		0x5B,                                      // 0x10023 | pop rbx             ; Restore rbx from the stack
		0xC3,                                      // 0x10024 | ret                 ; Return
		0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,  // 0x10025 | mov rax, 1          ; Set Fibonacci(1) or Fibonacci(0) to 1
		0xC3                                       // 0x1002C | ret                 ; Return
	};

	ZyanU64 BaseAddress = (ZyanU64)Buffer;
	ZydisBranch* FoundBranchs = nullptr;
	ZyanU64 NumberOfFoundBranchs = 0;

	ZyanBool Status = ZynterceptFindFunctionBranchs(
		ProcessIdentifier,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64,
		BaseAddress,
		&FoundBranchs,
		&NumberOfFoundBranchs);

	REQUIRE(Status == ZYAN_TRUE);
	REQUIRE(NumberOfFoundBranchs == 2);
	REQUIRE(FoundBranchs != nullptr);

	for (ZyanU64 Offset = 0; Offset < NumberOfFoundBranchs; Offset++) {
		ZydisBranch* Branch = &FoundBranchs[Offset];

		if (Branch->Flow == ZYDIS_BRANCH_FLOW_GREEN) {
			REQUIRE(Branch->Mnemonic == ZYDIS_MNEMONIC_JBE);
			REQUIRE(Branch->Address == BaseAddress + 0x05);
			REQUIRE(Branch->Destination == BaseAddress + 0x28);
		}

		if (Branch->Flow == ZYDIS_BRANCH_FLOW_RED) {
			REQUIRE(Branch->Mnemonic == ZYDIS_MNEMONIC_JBE);
			REQUIRE(Branch->Address == BaseAddress + 0x05);
			REQUIRE(Branch->Destination == BaseAddress + 0x07);
		}
	}

	free(FoundBranchs);
}

TEST_CASE("Check if FindFunctionBranchs not find the all branchs correctly in a function without jumps", "[disassembler]") {
	ZyanU8 Buffer[] = {
		0x55,                                // 0x10000 | push rbp              ; Save base pointer
		0x48, 0x89, 0xE5,                    // 0x10001 | mov rbp, rsp          ; Set base pointer to stack pointer
		0x48, 0x89, 0x7D, 0xF8,              // 0x10004 | mov [rbp-8], rdi      ; Store a in [rbp-8]
		0x48, 0x89, 0x75, 0xF0,              // 0x10008 | mov [rbp-16], rsi     ; Store x in [rbp-16]
		0x48, 0x89, 0x55, 0xE8,              // 0x1000C | mov [rbp-24], rdx     ; Store b in [rbp-24]
		0x48, 0x8B, 0x45, 0xF8,              // 0x10010 | mov rax, [rbp-8]      ; Move a to rax
		0x48, 0x0F, 0xAF, 0x45, 0xF0,        // 0x10014 | imul rax, [rbp-16]    ; Multiply rax (a) by x
		0x48, 0x03, 0x45, 0xE8,              // 0x10019 | add rax, [rbp-24]     ; Add b to rax
		0x48, 0x89, 0xEC,                    // 0x1001D | mov rsp, rbp          ; Restore stack pointer
		0x5D,                                // 0x10020 | pop rbp               ; Restore base pointer
		0xC3                                 // 0x10021 | ret                   ; Return
	};

	ZyanU64 BaseAddress = (ZyanU64)Buffer;
	ZydisBranch* FoundBranchs = nullptr;
	ZyanU64 NumberOfFoundBranchs = 0;

	ZyanBool Status = ZynterceptFindFunctionBranchs(
		ProcessIdentifier,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64,
		BaseAddress,
		&FoundBranchs,
		&NumberOfFoundBranchs);

	REQUIRE(Status == ZYAN_FALSE);
	REQUIRE(NumberOfFoundBranchs == 0);
	REQUIRE(FoundBranchs == nullptr);
}

TEST_CASE("Check if HasFunctionBranchDestinationsBetween detect recursivity in a x86 real function", "[disassembler]") {
	// TODO: Review all memory addresses in comments of right side
	ZyanU8 Buffer[] = {
		0x83, 0xF8, 0x01,              // 0x10000 | cmp eax, 1          ; Compare n with 1
		0x76, 0x14,                    // 0x10003 | jbe 0x10019         ; If n <= 1, jump to base_case (0x10019)
		0x53,                          // 0x10005 | push ebx            ; Save ebx on the stack
		0x89, 0xC3,                    // 0x10006 | mov ebx, eax        ; Copy n to ebx
		0x48,                          // 0x10008 | dec eax             ; Decrement n (n-1)
		0xE8, 0xF1, 0xFF, 0xFF, 0xFF,  // 0x10009 | call 0x10000        ; Call fibonacci (address 0x10000)
		0x50,                          // 0x1000E | push eax            ; Save the result on the stack
		0x89, 0xD8,                    // 0x1000F | mov eax, ebx        ; Restore n to eax
		0x83, 0xE8, 0x02,              // 0x10011 | sub eax, 2          ; Decrement n by 2 (n-2)
		0xE8, 0xE7, 0xFF, 0xFF, 0xFF,  // 0x10014 | call 0x10000        ; Call fibonacci (address 0x10000)
		0x5B,                          // 0x10019 | pop ebx             ; Retrieve fibonacci(n-1) from ebx
		0x01, 0xD8,                    // 0x1001A | add eax, ebx        ; Add fibonacci(n-1) + fibonacci(n-2)
		0x5B,                          // 0x1001C | pop ebx             ; Restore ebx from the stack
		0xC3,                          // 0x1001D | ret                 ; Return
		0xB8, 0x01, 0x00, 0x00, 0x00,  // 0x1001E | mov eax, 1          ; Set Fibonacci(1) or Fibonacci(0) to 1
		0xC3                           // 0x10023 | ret                 ; Return
	};

	ZyanU64 BaseAddress = (ZyanU64)Buffer;
	ZyanU64 BeginAddress = BaseAddress + 0x19;
	ZyanU64 EndAddress = BaseAddress + 0x19;

	ZyanBool Status = ZynterceptHasFunctionBranchDestinationsBetween(
		ProcessIdentifier,
		ZYDIS_MACHINE_MODE_LEGACY_32,
		ZYDIS_STACK_WIDTH_32,
		BaseAddress,
		BeginAddress,
		EndAddress);

	REQUIRE(Status == ZYAN_TRUE);
}

TEST_CASE("Check if HasFunctionBranchDestinationsBetween detect recursivity in a x64 real function", "[disassembler]") {
	// TODO: Review all memory addresses in comments of right side
	ZyanU8 Buffer[] = {
		0x53,                                      // 0x10000 | push rbx            ; Save rbx on the stack
		0x48, 0x83, 0xFF, 0x01,                    // 0x10001 | cmp rdi, 1          ; Compare n with 1
		0x76, 0x21,                                // 0x10005 | jbe 0x10028         ; If n <= 1, jump to base_case (offset 0x10028)
		0x48, 0x89, 0xDF,                          // 0x10007 | mov rbx, rdi        ; Copy n to rbx
		0x48, 0xFF, 0xCF,                          // 0x1000A | dec rdi             ; Decrement n (n-1)
		0xE8, 0xF1, 0xFF, 0xFF, 0xFF,              // 0x1000D | call 0x10003        ; Call fibonacci (address 0x10003)
		0x50,                                      // 0x10012 | push rax            ; Save the result on the stack
		0x48, 0x89, 0xDF,                          // 0x10013 | mov rdi, rbx        ; Restore n to rdi
		0x48, 0x83, 0xEF, 0x02,                    // 0x10016 | sub rdi, 2          ; Decrement n by 2 (n-2)
		0xE8, 0xE7, 0xFF, 0xFF, 0xFF,              // 0x1001A | call 0x10003        ; Call fibonacci (address 0x10003)
		0x5B,                                      // 0x1001F | pop rbx             ; Retrieve fibonacci(n-1) from rbx
		0x48, 0x01, 0xD8,                          // 0x10020 | add rax, rbx        ; Add fibonacci(n-1) + fibonacci(n-2)
		0x5B,                                      // 0x10023 | pop rbx             ; Restore rbx from the stack
		0xC3,                                      // 0x10024 | ret                 ; Return
		0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,  // 0x10025 | mov rax, 1          ; Set Fibonacci(1) or Fibonacci(0) to 1
		0xC3                                       // 0x1002C | ret                 ; Return
	};

	ZyanU64 BaseAddress = (ZyanU64)Buffer;
	ZyanU64 BeginAddress = BaseAddress + 0x28;
	ZyanU64 EndAddress = BaseAddress + 0x28;

	ZyanBool Status = ZynterceptHasFunctionBranchDestinationsBetween(
		ProcessIdentifier, 
		ZYDIS_MACHINE_MODE_LONG_64, 
		ZYDIS_STACK_WIDTH_64, 
		BaseAddress, 
		BeginAddress,
		EndAddress);

	REQUIRE(Status == ZYAN_TRUE);
}