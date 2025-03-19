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

TEST_CASE("Check if ZynterceptIsRelative recognize <jmp dword ptr 0x1004C> as relative instruction", "[disassembler]") {
    ZyanU8 Buffer[] = {
        0xe9, 0x47, 0x00, 0x00, 0x00 // 0x10000 | jmp 0x1004C
    };

    ZydisDecoded Decoded = {};
    ZydisDecoder Decoder = {};

    REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
    REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));
    
    REQUIRE(ZynterceptIsRelative(&Decoded) == ZYAN_TRUE);
}

TEST_CASE("Check if ZynterceptIsRelative recognize <call dword ptr 0x1004C> as relative instruction", "[disassembler]") {
    ZyanU8 Buffer[] = {
        0xe9, 0x47, 0x00, 0x00, 0x00 // 0x10000 | jmp 0x1004C
    };

    ZydisDecoded Decoded = {};
    ZydisDecoder Decoder = {};

    REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
    REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

    REQUIRE(ZynterceptIsRelative(&Decoded) == ZYAN_TRUE);
}

TEST_CASE("Check if ZynterceptIsRet recognize <ret> as near return instruction", "[disassembler]") {
    ZyanU8 Buffer[] = {
        0xc3 // 0x10000 | ret
    };

    ZydisDecoded Decoded = {};
    ZydisDecoder Decoder = {};

    REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
    REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

    REQUIRE(ZynterceptIsRet(&Decoded) == ZYAN_TRUE);
}

TEST_CASE("Check if ZynterceptIsRet recognize <ret> as far return instruction", "[disassembler]") {
    ZyanU8 Buffer[] = {
        0xcb // 0x10000 | retf
    };

    ZydisDecoded Decoded = {};
    ZydisDecoder Decoder = {};

    REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
    REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

    REQUIRE(ZynterceptIsRet(&Decoded) == ZYAN_TRUE);
}

TEST_CASE("Check if ZynterceptIsCall recognize <call dword ptr 0x1004C> as call instruction", "[disassembler]") {
    ZyanU8 Buffer[] = {
        0xe8, 0x47, 0x00, 0x00, 0x00 // 0x10000 | call 0x1004C
    };

    ZydisDecoded Decoded = {};
    ZydisDecoder Decoder = {};

    REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
    REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

    ZydisDecodedOperand* Operand = nullptr;

    REQUIRE(ZynterceptIsCall(&Decoded, &Operand) == ZYAN_TRUE);

    REQUIRE(Operand != nullptr);
    REQUIRE((Operand->imm.value.u & 0xffffffffUL) == 0x47UL);
}

TEST_CASE("Check if ZynterceptIsJmp recognize <jmp dword ptr 0x1004C> as jmp instruction", "[disassembler]") {
    ZyanU8 Buffer[] = {
        0xe9, 0x47, 0x00, 0x00, 0x00 // 0x10000 | jmp 0x1004C
    };

    ZydisDecoded Decoded = {};
    ZydisDecoder Decoder = {};

    REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
    REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

    ZydisDecodedOperand* Operand = nullptr;

    REQUIRE(ZynterceptIsJmp(&Decoded, &Operand) == ZYAN_TRUE);

    REQUIRE(Operand != nullptr);
    REQUIRE((Operand->imm.value.u & 0xffffffffUL) == 0x47UL);
}

TEST_CASE("Check if ZynterceptIsJmp dont recognize <jne dword ptr 0x1004C> as jmp instruction", "[disassembler]") {
    ZyanU8 Buffer[] = {
        0x0f, 0x85, 0x47, 0x00, 0x00, 0x00 // 0x10000 | jne 0x1004C
    };

    ZydisDecoded Decoded = {};
    ZydisDecoder Decoder = {};

    REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
    REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

    ZydisDecodedOperand* Operand = nullptr;

    REQUIRE(ZynterceptIsJmp(&Decoded, &Operand) == ZYAN_FALSE);

    REQUIRE(Operand == nullptr);
}

TEST_CASE("Check if ZynterceptIsJcc recognize <jne dword ptr 0x1004C> as jcc instruction", "[disassembler]") {
    ZyanU8 Buffer[] = {
        0x0f, 0x85, 0x47, 0x00, 0x00, 0x00 // 0x10000 | jne 0x1004C
    };

    ZydisDecoded Decoded = {};
    ZydisDecoder Decoder = {};

    REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
    REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

    ZydisDecodedOperand* Operand = nullptr;

    REQUIRE(ZynterceptIsJcc(&Decoded, &Operand) == ZYAN_TRUE);

    REQUIRE(Operand != nullptr);
    REQUIRE((Operand->imm.value.u & 0xffffffffUL) == 0x47UL);
}

TEST_CASE("Check if ZynterceptIsJcc dont recognize <jmp dword ptr 0x1004C> as jcc instruction", "[disassembler]") {
    ZyanU8 Buffer[] = {
        0xe9, 0x47, 0x00, 0x00, 0x00 // 0x10000 | jmp 0x1004C
    };

    ZydisDecoded Decoded = {};
    ZydisDecoder Decoder = {};

    REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)));
    REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Buffer, sizeof(Buffer), &Decoded.Instruction, Decoded.Operands)));

    ZydisDecodedOperand* Operand = nullptr;

    REQUIRE(ZynterceptIsJcc(&Decoded, &Operand) == ZYAN_FALSE);

    REQUIRE(Operand == nullptr);
}

TEST_CASE("Check if ZynterceptSizeOfDecodedDesiredInstructions return the correct length in x86 real function", "[disassembler]") {
    ZyanU8 Buffer[] = {
        0x8B, 0xFF,                      // 0x10000 | mov edi, edi
        0x55,                            // 0x10002 | push ebp
        0x8B, 0xEC,                      // 0x10003 | mov ebp, esp
        0x8B, 0x45, 0x08,                // 0x10005 | mov eax, dword ptr ss:[ebp + 8]
        0x83, 0xF8, 0x0B,                // 0x10008 | cmp eax, B
        0x73, 0x11,                      // 0x1000B | jae 0x1001E ---------------------+
        0x6B, 0xC8, 0x28,                // 0x1000D | imul ecx, eax, 0x28              |
        0xA1, 0x50, 0x6C, 0x75, 0x77,    // 0x10010 | mov eax, dword ptr ds:[0x776C50] |
        0x05, 0xA4, 0x03, 0x00, 0x00,    // 0x10015 | add eax, 0x3A4                   |
        0x03, 0xC1,                      // 0x1001A | add eax, ecx                     |
        0xEB, 0x02,                      // 0x1001C | jmp 0x10020 -----+               |
        0x33, 0xC0,                      // 0x1001E | xor eax, eax  <--|---------------+
        0x5D,                            // 0x10020 | pop ebp  <-------+
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

TEST_CASE("Check if ZynterceptSizeOfDecodedDesiredInstructions return the correct length in x64 real function", "[disassembler]") {
    ZyanU8 Buffer[] = {
        0x83, 0xF9, 0x0B,                          // 0x10000 | cmp ecx,B
        0x73, 0x19,                                // 0x10003 | jae 0x1001E -----------------------+
        0x8B, 0xC1,                                // 0x10005 | mov eax,ecx                        |
        0x48, 0x8D, 0x0C, 0x80,                    // 0x10007 | lea rcx,qword ptr ds:[rax+rax*4]   |
        0x48, 0x8B, 0x05, 0xA6, 0x8B, 0x03, 0x00,  // 0x1000B | mov rax,qword ptr ds:[0x1030B]     |
        0x48, 0x8D, 0x04, 0xC8,                    // 0x10012 | lea rax,qword ptr ds:[rax+rcx*8]   |
        0x48, 0x05, 0xA4, 0x03, 0x00, 0x00,        // 0x10016 | add rax,3A4                        |
        0xC3,                                      // 0x1001C | ret                                |
        0xCC,                                      // 0x1001D | int3                               |
        0x33, 0xC0,                                // 0x1001E | xor eax,eax  <---------------------+
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

TEST_CASE("Check if ZynterceptSizeOfDecodedDesiredInstructions return zero when x86 real function is too short", "[disassembler]") {
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

TEST_CASE("Check if ZynterceptSizeOfDecodedDesiredInstructions return zero when x64 real function is too short", "[disassembler]") {
    ZyanU8 Buffer[] = {
        0x83, 0xF9, 0x0B // 0x10000 | cmp ecx, 0x0B
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

TEST_CASE("Check if ZynterceptSizeOfDecodedDesiredInstructions return zero when x86 prologue has invalid instructions, paddings or returns", "[disassembler]") {
    ZyanU8 Buffer[] = {
        0x8B, 0xFF, 0x55,              // 0x10000 | mov edi, edi    ; Not enough space for unconditional jump
        0xc3,                          // 0x10003 | ret             ; Not enough space for unconditional jump
        0xe9, 0x47, 0x00, 0x00, 0x00   // 0x10004 | jmp 0x10050     ; Jump to outside of current function
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

TEST_CASE("Check if ZynterceptSizeOfDecodedDesiredInstructions return zero when x64 prologue has invalid instructions, paddings or returns", "[disassembler]") {
    ZyanU8 Buffer[] = {
        0x83, 0xF9, 0x0B,             // 0x10000 | cmp ecx,B       ; Not enough space for unconditional jump
        0xc3,                         // 0x10003 | ret             ; Not enough space for unconditional jump
        0xe9, 0x47, 0x00, 0x00, 0x00  // 0x10004 | jmp 0x10050     ; Jump to outside of current function
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

TEST_CASE("Check if ZynterceptFindReplaceableInstructions can find the instructions to replace in a x86 real function", "[disassembler]") {
    ZyanU8 Buffer[] = {
        0x8B, 0xFF,                      // 0x10000 | mov edi, edi
        0x55,                            // 0x10002 | push ebp
        0x8B, 0xEC,                      // 0x10003 | mov ebp, esp
        0x8B, 0x45, 0x08,                // 0x10005 | mov eax, dword ptr ss:[ebp + 8]
        0x83, 0xF8, 0x0B,                // 0x10008 | cmp eax,B
        0x73, 0x11,                      // 0x1000B | jae 0x1001E -----------------------+
        0x6B, 0xC8, 0x28,                // 0x1000D | imul ecx, eax, 0x28                |
        0xA1, 0x50, 0x6C, 0x75, 0x77,    // 0x10010 | mov eax, dword ptr ds:[0x776C50]   |
        0x05, 0xA4, 0x03, 0x00, 0x00,    // 0x10015 | add eax, 0x3A4                     |
        0x03, 0xC1,                      // 0x1001A | add eax, ecx                       |
        0xEB, 0x02,                      // 0x1001C | jmp 0x10020 --------+              |
        0x33, 0xC0,                      // 0x1001E | xor eax, eax  <-----|--------------+
        0x5D,                            // 0x10020 | pop ebp  <----------+
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

TEST_CASE("Check if ZynterceptFindReplaceableInstructions can find the instructions to replace in a x64 real function", "[disassembler]") {
    ZyanU8 Buffer[] = {
        0x83, 0xF9, 0x0B,                         // 0x10000 | cmp ecx,B
        0x73, 0x19,                               // 0x10003 | jae 0x1001E ----------------------+
        0x8B, 0xC1,                               // 0x10005 | mov eax,ecx                       |
        0x48, 0x8D, 0x0C, 0x80,                   // 0x10007 | lea rcx,qword ptr ds:[rax+rax*4]  |
        0x48, 0x8B, 0x05, 0xA6, 0x8B, 0x03, 0x00, // 0x1000B | mov rax,qword ptr ds:[0x1030B]    |
        0x48, 0x8D, 0x04, 0xC8,                   // 0x10012 | lea rax,qword ptr ds:[rax+rcx*8]  |
        0x48, 0x05, 0xA4, 0x03, 0x00, 0x00,       // 0x10016 | add rax,3A4                       |
        0xC3,                                     // 0x1001C | ret                               |
        0xCC,                                     // 0x1001D | int3                              |
        0x33, 0xC0,                               // 0x1001E | xor eax,eax  <--------------------+
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

TEST_CASE("Check if ZynterceptFindNextFunctionBranch find the next branch correctly in a x86 real function", "[disassembler]") {
    ZyanU8 Buffer[] = {
        0x8B, 0xFF,                      // 0x10000 | mov edi, edi
        0x55,                            // 0x10002 | push ebp
        0x8B, 0xEC,                      // 0x10003 | mov ebp, esp
        0x8B, 0x45, 0x08,                // 0x10005 | mov eax, dword ptr ss:[ebp + 8]
        0x83, 0xF8, 0x0B,                // 0x10008 | cmp eax,B
        0x73, 0x11,                      // 0x1000B | jae 0x1001E -----------------------+
        0x6B, 0xC8, 0x28,                // 0x1000D | imul ecx, eax, 0x28                |
        0xA1, 0x50, 0x6C, 0x75, 0x77,    // 0x10010 | mov eax, dword ptr ds:[0x776C50]   |
        0x05, 0xA4, 0x03, 0x00, 0x00,    // 0x10015 | add eax, 0x3A4                     |
        0x03, 0xC1,                      // 0x1001A | add eax, ecx                       |
        0xEB, 0x02,                      // 0x1001C | jmp 0x10020 --------+              |
        0x33, 0xC0,                      // 0x1001E | xor eax, eax  <-----|--------------+
        0x5D,                            // 0x10020 | pop ebp  <----------+
        0xC2, 0x04, 0x00                 // 0x10021 | ret 0x4
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

TEST_CASE("Check if ZynterceptFindNextFunctionBranch find the next branch correctly in a x64 real function", "[disassembler]") {
    ZyanU8 Buffer[] = {
        0x83, 0xF9, 0x0B,                         // 0x10000 | cmp ecx,B
        0x73, 0x19,                               // 0x10003 | jae 0x1001E ----------------------+
        0x8B, 0xC1,                               // 0x10005 | mov eax,ecx                       |
        0x48, 0x8D, 0x0C, 0x80,                   // 0x10007 | lea rcx,qword ptr ds:[rax+rax*4]  |
        0x48, 0x8B, 0x05, 0xA6, 0x8B, 0x03, 0x00, // 0x1000B | mov rax,qword ptr ds:[0x1030B]    |
        0x48, 0x8D, 0x04, 0xC8,                   // 0x10012 | lea rax,qword ptr ds:[rax+rcx*8]  |
        0x48, 0x05, 0xA4, 0x03, 0x00, 0x00,       // 0x10016 | add rax,3A4                       |
        0xC3,                                     // 0x1001C | ret                               |
        0xCC,                                     // 0x1001D | int3                              |
        0x33, 0xC0,                               // 0x1001E | xor eax,eax  <--------------------+
        0xC3                                      // 0x10020 | ret
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

TEST_CASE("Check if ZynterceptFindFunctionBranchs find the all branchs correctly in a x86 real function", "[disassembler]") {
    ZyanU8 Buffer[] = {
        0x83, 0xF8, 0x01,              // 0x10000 | cmp eax, 1          ; Compare n with 1
        0x76, 0x14,                    // 0x10003 | jbe 0x10019 ----+   ; If n <= 1, jump to base_case (0x10019)
        0x53,                          // 0x10005 | push ebx        |   ; Save ebx on the stack
        0x89, 0xC3,                    // 0x10006 | mov ebx, eax    |   ; Copy n to ebx
        0x48,                          // 0x10008 | dec eax         |   ; Decrement n (n-1)
        0xE8, 0xF1, 0xFF, 0xFF, 0xFF,  // 0x10009 | call 0x10000    |   ; Call fibonacci (address 0x10000)
        0x50,                          // 0x1000E | push eax        |   ; Save the result on the stack
        0x89, 0xD8,                    // 0x1000F | mov eax, ebx    |   ; Restore n to eax
        0x83, 0xE8, 0x02,              // 0x10011 | sub eax, 2      |   ; Decrement n by 2 (n-2)
        0xE8, 0xE7, 0xFF, 0xFF, 0xFF,  // 0x10014 | call 0x10000    |   ; Call fibonacci (address 0x10000)
        0x5B,                          // 0x10019 | pop ebx  <------+   ; Retrieve fibonacci(n-1) from ebx
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

TEST_CASE("Check if ZynterceptFindFunctionBranchs find the all branchs correctly in a x64 real function", "[disassembler]") {
    // int fibonacci(int b);
    ZyanU8 Buffer[] = {
        0x40,                                      // 0x10000 | rex                      ; Extended instruction prefix
        0x57,                                      // 0x10001 | push rdi                 ; Save rdi on the stack
        0x48, 0x83, 0xEC, 0x20,                    // 0x10002 | sub rsp, 0x20            ; Allocate 32 bytes on the stack
        0x8B, 0xF9,                                // 0x10006 | mov edi, ecx             ; Move argument (n) from ecx to edi
        0x83, 0xF9, 0x02,                          // 0x10008 | cmp ecx, 0x2             ; Compare n with 2
        0x7D, 0x08,                                // 0x1000B | jge 0x10015 -----------+ ; If n >= 2, jump to recursive case
        0x8B, 0xC1,                                // 0x1000D | mov eax, ecx           | ; Return n directly for n <= 1
        0x48, 0x83, 0xC4, 0x20,                    // 0x1000F | add rsp, 0x20          | ; Restore the stack
        0x5F,                                      // 0x10013 | pop rdi                | ; Restore rdi from the stack
        0xC3,                                      // 0x10014 | ret                    | ; Return result
        0x83, 0xC1, 0xFE,                          // 0x10015 | add ecx, -2  <---------+ ; Decrement n by 2 (n - 2)
        0x48, 0x89, 0x5C, 0x24, 0x30,              // 0x10018 | mov [rsp + 0x30], rbx    ; Save rbx on the stack
        0xE8, 0xDE, 0xFF, 0xFF, 0xFF,              // 0x1001D | call 0x10000             ; Call fibonacci(n - 1)
        0x8D, 0x4F, 0xFF,                          // 0x10022 | lea ecx, [rdi - 1]       ; Load n - 1 into ecx
        0x8B, 0xD8,                                // 0x10025 | mov ebx, eax             ; Store fibonacci(n - 1) in ebx
        0xE8, 0xD4, 0xFF, 0xFF, 0xFF,              // 0x10027 | call 0x10000             ; Call fibonacci(n - 2)
        0x03, 0xC3,                                // 0x1002C | add eax, ebx             ; Add fibonacci(n - 1) + fibonacci(n - 2)
        0x48, 0x8B, 0x5C, 0x24, 0x30,              // 0x1002E | mov rbx, [rsp + 0x30]    ; Restore rbx from the stack
        0x48, 0x83, 0xC4, 0x20,                    // 0x10033 | add rsp, 0x20            ; Restore the stack
        0x5F,                                      // 0x10037 | pop rdi                  ; Restore rdi from the stack
        0xC3,                                      // 0x10038 | ret                      ; Return result
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,  // 0x10039 | int3 (padding)           ; Breakpoints for debugging
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
            REQUIRE(Branch->Mnemonic == ZYDIS_MNEMONIC_JNL);
            REQUIRE(Branch->Address == BaseAddress + 0x0B);
            REQUIRE(Branch->Destination == BaseAddress + 0x15);
        }

        if (Branch->Flow == ZYDIS_BRANCH_FLOW_RED) {
            REQUIRE(Branch->Mnemonic == ZYDIS_MNEMONIC_JNL);
            REQUIRE(Branch->Address == BaseAddress + 0x0B);
            REQUIRE(Branch->Destination == BaseAddress + 0x0D);
        }
    }

    free(FoundBranchs);
}

TEST_CASE("Check if ZynterceptFindFunctionBranchs find no branchs correctly in a function without jumps", "[disassembler]") {
    // int computeAffineFunction(int a, int x, int b);
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

TEST_CASE("Check if ZynterceptHasFunctionBranchDestinationsBetween detect jumps in specific areas in a x86 real function", "[disassembler]") {
    // int fibonacci(int n);
    ZyanU8 Buffer[] = {
        0x55,                                      // 0x10000 | push ebp                 ; Save ebp on the stack
        0x8B, 0xEC,                                // 0x10001 | mov ebp, esp             ; Create new stack frame
        0x57,                                      // 0x10003 | push edi                 ; Save edi on the stack
        0x8B, 0x7D, 0x08,                          // 0x10004 | mov edi, [ebp+0x8]       ; Load argument (n) into edi
        0x83, 0xFF, 0x02,                          // 0x10007 | cmp edi, 2               ; Compare n with 2
        0x7D, 0x05,                                // 0x1000A | jge 0x10011  --------+   ; If n >= 2, jump to recursive case
        0x8B, 0xC7,                                // 0x1000C | mov eax, edi         |   ; Return n directly for n <= 1
        0x5F,                                      // 0x1000E | pop edi              |   ; Restore edi from the stack
        0x5D,                                      // 0x1000F | pop ebp              |   ; Restore ebp from the stack
        0xC3,                                      // 0x10010 | ret                  |   ; Return result
        0x8D, 0x47, 0xFE,                          // 0x10011 | lea eax, [edi - 2] <-+   ; Load n - 2 into eax
        0x56,                                      // 0x10014 | push esi                 ; Save esi on the stack
        0x50,                                      // 0x10015 | push eax                 ; Push n - 2 as argument
        0xE8, 0xE5, 0xFF, 0xFF, 0xFF,              // 0x10016 | call 0x10000             ; Call fibonacci(n - 2)
        0x8D, 0x4F, 0xFF,                          // 0x1001B | lea ecx, [edi - 1]       ; Load n - 1 into ecx
        0x8B, 0xF0,                                // 0x1001E | mov esi, eax             ; Store fibonacci(n - 2) in esi
        0x51,                                      // 0x10020 | push ecx                 ; Push n - 1 as argument
        0xE8, 0xDA, 0xFF, 0xFF, 0xFF,              // 0x10021 | call 0x10000             ; Call fibonacci(n - 1)
        0x83, 0xC4, 0x08,                          // 0x10026 | add esp, 8               ; Restore stack (pop arguments)
        0x03, 0xC6,                                // 0x10029 | add eax, esi             ; Add fibonacci(n - 1) + fibonacci(n - 2)
        0x5E,                                      // 0x1002B | pop esi                  ; Restore esi from the stack
        0x5F,                                      // 0x1002C | pop edi                  ; Restore edi from the stack
        0x5D,                                      // 0x1002D | pop ebp                  ; Restore ebp from the stack
        0xC3,                                      // 0x1002E | ret                      ; Return result
        0xCC,                                      // 0x1002F | int3 (padding)           ; Breakpoints for debugging
    };

    ZyanU64 BaseAddress = (ZyanU64)Buffer;
    ZyanU64 BeginAddress = BaseAddress + 0x11;
    ZyanU64 EndAddress = BaseAddress + sizeof(Buffer);

    ZyanBool Status = ZynterceptHasFunctionBranchDestinationsBetween(
        ProcessIdentifier,
        ZYDIS_MACHINE_MODE_LEGACY_32,
        ZYDIS_STACK_WIDTH_32,
        BaseAddress,
        BeginAddress,
        EndAddress);

    REQUIRE(Status == ZYAN_TRUE);
}

TEST_CASE("Check if ZynterceptHasFunctionBranchDestinationsBetween detect jumps in specific areas in a x64 real function", "[disassembler]") {
    // int fibonacci(int n);
    ZyanU8 Buffer[] = {
        0x40,                                      // 0x10000 | rex                      ; Extended instruction prefix
        0x57,                                      // 0x10001 | push rdi                 ; Save rdi on the stack
        0x48, 0x83, 0xEC, 0x20,                    // 0x10002 | sub rsp, 0x20            ; Allocate 32 bytes on the stack
        0x8B, 0xF9,                                // 0x10006 | mov edi, ecx             ; Move argument (n) from ecx to edi
        0x83, 0xF9, 0x02,                          // 0x10008 | cmp ecx, 0x2             ; Compare n with 2
        0x7D, 0x08,                                // 0x1000B | jge 0x10015 -----------+ ; If n >= 2, jump to recursive case
        0x8B, 0xC1,                                // 0x1000D | mov eax, ecx           | ; Return n directly for n <= 1
        0x48, 0x83, 0xC4, 0x20,                    // 0x1000F | add rsp, 0x20          | ; Restore the stack
        0x5F,                                      // 0x10013 | pop rdi                | ; Restore rdi from the stack
        0xC3,                                      // 0x10014 | ret                    | ; Return result
        0x83, 0xC1, 0xFE,                          // 0x10015 | add ecx, -2  <---------+ ; Decrement n by 2 (n - 2)
        0x48, 0x89, 0x5C, 0x24, 0x30,              // 0x10018 | mov [rsp + 0x30], rbx    ; Save rbx on the stack
        0xE8, 0xDE, 0xFF, 0xFF, 0xFF,              // 0x1001D | call 0x10000             ; Call fibonacci(n - 1)
        0x8D, 0x4F, 0xFF,                          // 0x10022 | lea ecx, [rdi - 1]       ; Load n - 1 into ecx
        0x8B, 0xD8,                                // 0x10025 | mov ebx, eax             ; Store fibonacci(n - 1) in ebx
        0xE8, 0xD4, 0xFF, 0xFF, 0xFF,              // 0x10027 | call 0x10000             ; Call fibonacci(n - 2)
        0x03, 0xC3,                                // 0x1002C | add eax, ebx             ; Add fibonacci(n - 1) + fibonacci(n - 2)
        0x48, 0x8B, 0x5C, 0x24, 0x30,              // 0x1002E | mov rbx, [rsp + 0x30]    ; Restore rbx from the stack
        0x48, 0x83, 0xC4, 0x20,                    // 0x10033 | add rsp, 0x20            ; Restore the stack
        0x5F,                                      // 0x10037 | pop rdi                  ; Restore rdi from the stack
        0xC3,                                      // 0x10038 | ret                      ; Return result
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,  // 0x10039 | int3 (padding)           ; Breakpoints for debugging
    };

    ZyanU64 BaseAddress = (ZyanU64)Buffer;
    ZyanU64 BeginAddress = BaseAddress + 0x15;
    ZyanU64 EndAddress = BaseAddress + sizeof(Buffer);

    ZyanBool Status = ZynterceptHasFunctionBranchDestinationsBetween(
        ProcessIdentifier, 
        ZYDIS_MACHINE_MODE_LONG_64, 
        ZYDIS_STACK_WIDTH_64, 
        BaseAddress, 
        BeginAddress,
        EndAddress);

    REQUIRE(Status == ZYAN_TRUE);
}
