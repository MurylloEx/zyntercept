#include <catch2/catch_test_macros.hpp>
#include <Zyntercept/Core/Allocator/Allocator.h>
#include <Zyntercept/Core/Trampoline/Trampoline.h>

#if defined(ZYNTERCEPT_WINDOWS)
#include <Windows.h>
static ZyanVoidPointer ProcessIdentifier = GetCurrentProcess();
#endif

#if defined(ZYNTERCEPT_UNIX)
#include <unistd.h>
static ZyanVoidPointer ProcessIdentifier = (ZyanVoidPointer)getpid();
#endif

#define ZYNTERCEPT_SIZE_OF_DETOUR_JUMP 5

SCENARIO("Zyntercept trampoline compiler for x86 CISC CPU architecture", "[trampoline]")
{
    GIVEN("A function with a prologue containing a MOV absolute instruction")
    {
        // NtClose x86 | Windows 10 x86
        ZyanU8 Buffer[] = {
            0xB8, 0x0F, 0x00, 0x03, 0x00,         // 0x20000 | mov eax,0x3000F
            0xBA, 0x40, 0x8F, 0x65, 0x77,         // 0x20005 | mov edx,0x77658F40
            0xFF, 0xD2,                           // 0x2000A | call edx
            0xC2, 0x04, 0x00,                     // 0x2000C | ret 0x4
            0x90                                  // 0x2000F | nop
        };

        ZyanU64 TargetFunction = (ZyanU64)Buffer;
        ZyanU64 TrampolineFunction = TargetFunction - 0x10000;
        ZyanU8 TrampolineBuffer[96] = { 0 };
        ZyanUSize SizeOfFoundInstructions = 0;
        ZyanU64 NumberOfFoundInstructions = 0;

        WHEN("I call the ZynterceptCompileTrampoline32 function")
        {
            ZyanU64 SizeOfDecodedInstructions = ZynterceptSizeOfDecodedDesiredInstructions(
                ZYDIS_MACHINE_MODE_LEGACY_32,
                ZYDIS_STACK_WIDTH_32,
                Buffer,
                sizeof(Buffer),
                ZYNTERCEPT_SIZE_OF_DETOUR_JUMP);

            REQUIRE(SizeOfDecodedInstructions != 0);

            ZydisDecoded* ReplaceableInstructions = (ZydisDecoded*)std::malloc(SizeOfDecodedInstructions);

            REQUIRE(ReplaceableInstructions != nullptr);
            
            REQUIRE(ZynterceptFindReplaceableInstructions(
                ZYDIS_MACHINE_MODE_LEGACY_32,
                ZYDIS_STACK_WIDTH_32,
                Buffer,
                sizeof(Buffer),
                ZYNTERCEPT_SIZE_OF_DETOUR_JUMP,
                SizeOfDecodedInstructions,
                ReplaceableInstructions,
                &NumberOfFoundInstructions,
                &SizeOfFoundInstructions) == ZYAN_TRUE);

            REQUIRE(ZynterceptCompileTrampoline32(
                TargetFunction,
                TrampolineFunction,
                TrampolineBuffer,
                sizeof(TrampolineBuffer),
                ReplaceableInstructions,
                NumberOfFoundInstructions) == ZYAN_TRUE);

            THEN("It should generate a valid trampoline with relocated MOV absolute instruction")
            {
                // Expected trampoline:
                // 
                // 0x10000 | mov eax, 0x3000f   ; Very first instruction relocated
                // 0x10005 | jmp 0x10005        ; Jump to instruction immediatly after replaced prologue

                // mov eax, 0x3000f
                REQUIRE(TrampolineBuffer[0] == 0xB8); 
                REQUIRE(TrampolineBuffer[1] == 0x0F);
                REQUIRE(TrampolineBuffer[2] == 0x00);
                REQUIRE(TrampolineBuffer[3] == 0x03);
                REQUIRE(TrampolineBuffer[4] == 0x00);

                // jmp 0x20005
                REQUIRE(TrampolineBuffer[5] == 0xE9);
                REQUIRE(TrampolineBuffer[6] == 0xFB);
                REQUIRE(TrampolineBuffer[7] == 0xFF);
                REQUIRE(TrampolineBuffer[8] == 0x00);
                REQUIRE(TrampolineBuffer[9] == 0x00);
            }

            std::free(ReplaceableInstructions);
        }
    }

    GIVEN("A function with a prologue containing a CALL relative instruction")
    {
        ZyanU8 Buffer[] = {
            0x55,                                  // 0x20000 | push ebp
            0x89, 0xE5,                            // 0x20001 | mov ebp, esp
            0xE8, 0x07, 0x00, 0x00, 0x00,          // 0x20003 | call FunctionCall
            0xB8, 0x01, 0x00, 0x00, 0x00,          // 0x20008 | mov eax, 0x1
            0x5D,                                  // 0x2000D | pop ebp
            0xC3,                                  // 0x2000E | ret
            0xB8, 0x02, 0x00, 0x00, 0x00,          // 0x2000F | mov eax, 0x2 <FunctionCall>
            0xC3                                   // 0x20014 | ret
        };

        ZyanU64 TargetFunction = (ZyanU64)Buffer;
        ZyanU64 TrampolineFunction = TargetFunction - 0x10000;
        ZyanU8 TrampolineBuffer[96] = { 0 };
        ZyanUSize SizeOfFoundInstructions = 0;
        ZyanU64 NumberOfFoundInstructions = 0;

        WHEN("I call the ZynterceptCompileTrampoline32 function")
        {
            ZyanU64 SizeOfDecodedInstructions = ZynterceptSizeOfDecodedDesiredInstructions(
                ZYDIS_MACHINE_MODE_LEGACY_32,
                ZYDIS_STACK_WIDTH_32,
                Buffer,
                sizeof(Buffer),
                ZYNTERCEPT_SIZE_OF_DETOUR_JUMP);

            REQUIRE(SizeOfDecodedInstructions != 0);

            ZydisDecoded* ReplaceableInstructions = (ZydisDecoded*)std::malloc(SizeOfDecodedInstructions);

            REQUIRE(ReplaceableInstructions != nullptr);

            REQUIRE(ZynterceptFindReplaceableInstructions(
                ZYDIS_MACHINE_MODE_LEGACY_32,
                ZYDIS_STACK_WIDTH_32,
                Buffer,
                sizeof(Buffer),
                ZYNTERCEPT_SIZE_OF_DETOUR_JUMP,
                SizeOfDecodedInstructions,
                ReplaceableInstructions,
                &NumberOfFoundInstructions,
                &SizeOfFoundInstructions) == ZYAN_TRUE);

            REQUIRE(ZynterceptCompileTrampoline32(
                TargetFunction,
                TrampolineFunction,
                TrampolineBuffer,
                sizeof(TrampolineBuffer),
                ReplaceableInstructions,
                NumberOfFoundInstructions) == ZYAN_TRUE);

            THEN("It should generate a valid trampoline with relocated CALL relative instruction")
            {
                // Expected trampoline:
                // 
                // 0x20000 | push ebp       ; Save the old stack frame pointer
                // 0x20001 | mov ebp, esp   ; Move the current stack pointer to stack frame pointer
                // 0x20003 | call 0x1000f   ; Call <FunctionCall> at 0x2000F
                // 0x20008 | jmp 0x10008    ; Jump to instruction immediatly after replaced prologue

                // push ebp
                REQUIRE(TrampolineBuffer[0] == 0x55);

                // mov ebp, esp
                REQUIRE(TrampolineBuffer[1] == 0x89);
                REQUIRE(TrampolineBuffer[2] == 0xE5);

                // call 0x2000f
                REQUIRE(TrampolineBuffer[3] == 0xE8);
                REQUIRE(TrampolineBuffer[4] == 0x07);
                REQUIRE(TrampolineBuffer[5] == 0x00);
                REQUIRE(TrampolineBuffer[6] == 0x01);
                REQUIRE(TrampolineBuffer[7] == 0x00);

                // jmp 0x20008
                REQUIRE(TrampolineBuffer[8] == 0xE9);
                REQUIRE(TrampolineBuffer[9] == 0xFB);
                REQUIRE(TrampolineBuffer[10] == 0xFF);
                REQUIRE(TrampolineBuffer[11] == 0x00);
                REQUIRE(TrampolineBuffer[12] == 0x00);
            }

            std::free(ReplaceableInstructions);
        }
    }

    GIVEN("A function with a prologue containing a JMP relative instruction")
    {
        ZyanU8 Buffer[] = {
            0xE9, 0x05, 0x00, 0x00, 0x00,   // 0x10000 | jmp 0x1000A
            0xB8, 0x01, 0x00, 0x00, 0x00,   // 0x10005 | mov eax, 0x1 (not executed)
            0xB8, 0x02, 0x00, 0x00, 0x00,   // 0x1000A | mov eax, 0x2
            0xC3                            // 0x1000F | ret
        };

        ZyanU64 TargetFunction = (ZyanU64)Buffer;
        ZyanU64 TrampolineFunction = TargetFunction - 0x10000;
        ZyanU8 TrampolineBuffer[96] = { 0 };
        ZyanUSize SizeOfFoundInstructions = 0;
        ZyanU64 NumberOfFoundInstructions = 0;

        WHEN("I call the ZynterceptCompileTrampoline32 function")
        {
            ZyanU64 SizeOfDecodedInstructions = ZynterceptSizeOfDecodedDesiredInstructions(
                ZYDIS_MACHINE_MODE_LEGACY_32,
                ZYDIS_STACK_WIDTH_32,
                Buffer,
                sizeof(Buffer),
                ZYNTERCEPT_SIZE_OF_DETOUR_JUMP);

            REQUIRE(SizeOfDecodedInstructions != 0);

            ZydisDecoded* ReplaceableInstructions = (ZydisDecoded*)std::malloc(SizeOfDecodedInstructions);

            REQUIRE(ReplaceableInstructions != nullptr);

            REQUIRE(ZynterceptFindReplaceableInstructions(
                ZYDIS_MACHINE_MODE_LEGACY_32,
                ZYDIS_STACK_WIDTH_32,
                Buffer,
                sizeof(Buffer),
                ZYNTERCEPT_SIZE_OF_DETOUR_JUMP,
                SizeOfDecodedInstructions,
                ReplaceableInstructions,
                &NumberOfFoundInstructions,
                &SizeOfFoundInstructions) == ZYAN_TRUE);

            REQUIRE(ZynterceptCompileTrampoline32(
                TargetFunction,
                TrampolineFunction,
                TrampolineBuffer,
                sizeof(TrampolineBuffer),
                ReplaceableInstructions,
                NumberOfFoundInstructions) == ZYAN_TRUE);

            THEN("It should generate a valid trampoline with relocated JMP relative instruction")
            {
                // Expected trampoline:
                // 
                // 0x20000 | jmp 0x1000a    ; Jump to instruction at 0x1000a
                // 0x20005 | jmp 0x10005    ; Jump to instruction immediatly after replaced prologue (ignored due to previous jump)

                // jmp 0x1000a
                REQUIRE(TrampolineBuffer[0] == 0xE9);
                REQUIRE(TrampolineBuffer[1] == 0x05);
                REQUIRE(TrampolineBuffer[2] == 0x00);
                REQUIRE(TrampolineBuffer[3] == 0x01);
                REQUIRE(TrampolineBuffer[4] == 0x00);

                // jmp 0x10005
                REQUIRE(TrampolineBuffer[5] == 0xE9);
                REQUIRE(TrampolineBuffer[6] == 0xFB);
                REQUIRE(TrampolineBuffer[7] == 0xFF);
                REQUIRE(TrampolineBuffer[8] == 0x00);
                REQUIRE(TrampolineBuffer[9] == 0x00);
            }

            std::free(ReplaceableInstructions);
        }
    }

    GIVEN("A function with a prologue containing a JCC relative instruction")
    {
        ZyanU8 Buffer[] = {
            0x83, 0xF8, 0x00,               // 0x10000 | cmp eax, 0x0
            0x74, 0x05,                     // 0x10003 | je 0x1000A
            0xB8, 0x01, 0x00, 0x00, 0x00,   // 0x10005 | mov eax, 0x1
            0xC3                            // 0x1000A | ret
        };

        ZyanU64 TargetFunction = (ZyanU64)Buffer;
        ZyanU64 TrampolineFunction = TargetFunction - 0x10000;
        ZyanU8 TrampolineBuffer[96] = { 0 };
        ZyanUSize SizeOfFoundInstructions = 0;
        ZyanU64 NumberOfFoundInstructions = 0;

        WHEN("I call the ZynterceptCompileTrampoline32 function")
        {
            ZyanU64 SizeOfDecodedInstructions = ZynterceptSizeOfDecodedDesiredInstructions(
                ZYDIS_MACHINE_MODE_LEGACY_32,
                ZYDIS_STACK_WIDTH_32,
                Buffer,
                sizeof(Buffer),
                ZYNTERCEPT_SIZE_OF_DETOUR_JUMP);

            REQUIRE(SizeOfDecodedInstructions != 0);

            ZydisDecoded* ReplaceableInstructions = (ZydisDecoded*)std::malloc(SizeOfDecodedInstructions);

            REQUIRE(ReplaceableInstructions != nullptr);

            REQUIRE(ZynterceptFindReplaceableInstructions(
                ZYDIS_MACHINE_MODE_LEGACY_32,
                ZYDIS_STACK_WIDTH_32,
                Buffer,
                sizeof(Buffer),
                ZYNTERCEPT_SIZE_OF_DETOUR_JUMP,
                SizeOfDecodedInstructions,
                ReplaceableInstructions,
                &NumberOfFoundInstructions,
                &SizeOfFoundInstructions) == ZYAN_TRUE);

            REQUIRE(ZynterceptCompileTrampoline32(
                TargetFunction,
                TrampolineFunction,
                TrampolineBuffer,
                sizeof(TrampolineBuffer),
                ReplaceableInstructions,
                NumberOfFoundInstructions) == ZYAN_TRUE);

            THEN("It should generate a valid trampoline with relocated JCC relative instruction")
            {
                // Expected trampoline:
                // 
                // 0x20000 | cmp eax, 0x0   ; Very first instruction relocated
                // 0x20003 | jne 0x20021    ; Rewrote conditional JCC to JNCC keeping the semantic
                // 0x20009 | jmp 0x1000a    ; Jump to previous JCC target instruction
                // 0x2000e | nop            ; Skipped
                // 0x20017 | nop            ; Skipped
                // 0x20020 | nop            ; Skipped
                // 0x20021 | jmp 0x10005    ; Jump to instruction immediatly after replaced prologue

                // cmp eax, 0x0
                REQUIRE(TrampolineBuffer[0] == 0x83);
                REQUIRE(TrampolineBuffer[1] == 0xF8);
                REQUIRE(TrampolineBuffer[2] == 0x00);

                // jne 0x20021
                REQUIRE(TrampolineBuffer[3] == 0x0F);
                REQUIRE(TrampolineBuffer[4] == 0x85);
                REQUIRE(TrampolineBuffer[5] == 0x18);
                REQUIRE(TrampolineBuffer[6] == 0x00);
                REQUIRE(TrampolineBuffer[7] == 0x00);
                REQUIRE(TrampolineBuffer[8] == 0x00);

                // jmp 0x1000a
                REQUIRE(TrampolineBuffer[9] == 0xE9);
                REQUIRE(TrampolineBuffer[10] == 0xFC);
                REQUIRE(TrampolineBuffer[11] == 0xFF);
                REQUIRE(TrampolineBuffer[12] == 0x00);
                REQUIRE(TrampolineBuffer[13] == 0x00);

                // nop (omitted)
                // nop (omitted)
                // nop (omitted)

                // jmp 0x10005
                REQUIRE(TrampolineBuffer[33] == 0xE9);
                REQUIRE(TrampolineBuffer[34] == 0xDF);
                REQUIRE(TrampolineBuffer[35] == 0xFF);
                REQUIRE(TrampolineBuffer[36] == 0x00);
                REQUIRE(TrampolineBuffer[37] == 0x00);
            }

            std::free(ReplaceableInstructions);
        }
    }

    GIVEN("A function with a prologue too short to hook")
    {
        ZyanU8 Buffer[] = {
            0x90,   // 0x10000 | nop
            0xC3    // 0x10001 | ret
        };

        WHEN("I call the ZynterceptSizeOfDecodedDesiredInstructions function")
        {
            ZyanU64 SizeOfDecodedInstructions = ZynterceptSizeOfDecodedDesiredInstructions(
                ZYDIS_MACHINE_MODE_LEGACY_32,
                ZYDIS_STACK_WIDTH_32,
                Buffer,
                sizeof(Buffer),
                ZYNTERCEPT_SIZE_OF_DETOUR_JUMP);

            THEN("It should fail and return an invalid size of decoded instructions")
            {
                REQUIRE(SizeOfDecodedInstructions == 0);
            }
        }
    }
}

SCENARIO("Zyntercept trampoline compiler for x64 CISC CPU architecture", "[trampoline]")
{
    GIVEN("A function with a prologue containing a MOV absolute instruction")
    {
        // NtClose x64 | Windows 10
        ZyanU8 Buffer[] = {
            0x4C, 0x8B, 0xD1,                                             // 0x20000 | mov r10,rcx
            0xB8, 0x0F, 0x00, 0x00, 0x00,                                 // 0x20003 | mov eax,0xF
            0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01,               // 0x20008 | test byte ptr [0x7FFE0308],0x1
            0x75, 0x03,                                                   // 0x20010 | jne 0x10015
            0x0F, 0x05,                                                   // 0x20012 | syscall
            0xC3,                                                         // 0x20014 | ret
            0xCD, 0x2E,                                                   // 0x20015 | int 0x2E
            0xC3                                                          // 0x20017 | ret
        };

        ZyanU64 TargetFunction = (ZyanU64)Buffer;
        ZyanU64 TrampolineFunction = TargetFunction - 0x10000;
        ZyanU8 TrampolineBuffer[192] = { 0 };
        ZyanUSize SizeOfFoundInstructions = 0;
        ZyanU64 NumberOfFoundInstructions = 0;

        WHEN("I call the ZynterceptCompileTrampoline64 function")
        {
            ZyanU64 SizeOfDecodedInstructions = ZynterceptSizeOfDecodedDesiredInstructions(
                ZYDIS_MACHINE_MODE_LONG_64,
                ZYDIS_STACK_WIDTH_64,
                Buffer,
                sizeof(Buffer),
                ZYNTERCEPT_SIZE_OF_DETOUR_JUMP);

            REQUIRE(SizeOfDecodedInstructions != 0);

            ZydisDecoded* ReplaceableInstructions = (ZydisDecoded*)std::malloc(SizeOfDecodedInstructions);

            REQUIRE(ReplaceableInstructions != nullptr);

            REQUIRE(ZynterceptFindReplaceableInstructions(
                ZYDIS_MACHINE_MODE_LONG_64,
                ZYDIS_STACK_WIDTH_64,
                Buffer,
                sizeof(Buffer),
                ZYNTERCEPT_SIZE_OF_DETOUR_JUMP,
                SizeOfDecodedInstructions,
                ReplaceableInstructions,
                &NumberOfFoundInstructions,
                &SizeOfFoundInstructions) == ZYAN_TRUE);

            REQUIRE(ZynterceptCompileTrampoline64(
                TargetFunction,
                TrampolineFunction,
                TrampolineBuffer,
                sizeof(TrampolineBuffer),
                ReplaceableInstructions,
                NumberOfFoundInstructions) == ZYAN_TRUE);

            THEN("It should generate a valid trampoline with relocated MOV absolute instruction")
            {
                // Expected trampoline:
                // 
                // 0x10000 | mov r10, rcx   ; Very first instruction relocated
                // 0x10003 | mov eax, 0xf   ; Move syscall index to eax register
                // 0x10008 | jmp 0x20008    ; Jump to instruction immediatly after replaced prologue

                // mov r10, rcx
                REQUIRE(TrampolineBuffer[0] == 0x49);
                REQUIRE(TrampolineBuffer[1] == 0x89);
                REQUIRE(TrampolineBuffer[2] == 0xCA);

                // mov eax, 0xf
                REQUIRE(TrampolineBuffer[3] == 0xB8);
                REQUIRE(TrampolineBuffer[4] == 0x0F);
                REQUIRE(TrampolineBuffer[5] == 0x00);
                REQUIRE(TrampolineBuffer[6] == 0x00);
                REQUIRE(TrampolineBuffer[7] == 0x00);

                // jmp 0x20008
                REQUIRE(TrampolineBuffer[8] == 0xFF);
                REQUIRE(TrampolineBuffer[9] == 0x25);
                REQUIRE(TrampolineBuffer[10] == 0x00);
                REQUIRE(TrampolineBuffer[11] == 0x00);
                REQUIRE(TrampolineBuffer[12] == 0x00);
                REQUIRE(TrampolineBuffer[13] == 0x00);
            }

            std::free(ReplaceableInstructions);
        }
    }

    GIVEN("A function with a prologue containing a CALL relative instruction")
    {
        ZyanU8 Buffer[] = {
            0x55,                                                         // 0x20000 | push rbp
            0x48, 0x89, 0xE5,                                             // 0x20001 | mov rbp, rsp
            0xE8, 0x07, 0x00, 0x00, 0x00,                                 // 0x20004 | call FunctionCall
            0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0x20009 | mov rax, 0x1
            0x5D,                                                         // 0x20013 | pop rbp
            0xC3,                                                         // 0x20014 | ret
            0x48, 0xB8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0x20015 | mov rax, 0x2
            0xC3                                                          // 0x2001F | ret
        };

        ZyanU64 TargetFunction = (ZyanU64)Buffer;
        ZyanU64 TrampolineFunction = TargetFunction - 0x10000;
        ZyanU8 TrampolineBuffer[192] = { 0 };
        ZyanUSize SizeOfFoundInstructions = 0;
        ZyanU64 NumberOfFoundInstructions = 0;

        WHEN("I call the ZynterceptCompileTrampoline64 function")
        {
            ZyanU64 SizeOfDecodedInstructions = ZynterceptSizeOfDecodedDesiredInstructions(
                ZYDIS_MACHINE_MODE_LONG_64,
                ZYDIS_STACK_WIDTH_64,
                Buffer,
                sizeof(Buffer),
                ZYNTERCEPT_SIZE_OF_DETOUR_JUMP);

            REQUIRE(SizeOfDecodedInstructions != 0);

            ZydisDecoded* ReplaceableInstructions = (ZydisDecoded*)std::malloc(SizeOfDecodedInstructions);

            REQUIRE(ReplaceableInstructions != nullptr);

            REQUIRE(ZynterceptFindReplaceableInstructions(
                ZYDIS_MACHINE_MODE_LONG_64,
                ZYDIS_STACK_WIDTH_64,
                Buffer,
                sizeof(Buffer),
                ZYNTERCEPT_SIZE_OF_DETOUR_JUMP,
                SizeOfDecodedInstructions,
                ReplaceableInstructions,
                &NumberOfFoundInstructions,
                &SizeOfFoundInstructions) == ZYAN_TRUE);

            REQUIRE(ZynterceptCompileTrampoline64(
                TargetFunction,
                TrampolineFunction,
                TrampolineBuffer,
                sizeof(TrampolineBuffer),
                ReplaceableInstructions,
                NumberOfFoundInstructions) == ZYAN_TRUE);

            THEN("It should generate a valid trampoline with prefixed ModR/M CALL absolute instruction")
            {
                // Expected trampoline:
                // 
                // 0x10000 | push rbp                   ; Save the old stack frame pointer
                // 0x10001 | mov rbp, rsp               ; Move the current stack pointer to stack frame pointer
                // 0x10004 | call 0x20010               ; Call a function at 0x20010
                // 0x1000a | jmp 0x10014                ; Jump the next 8 bytes (x64 absolute pointer)
                // 0x1000c | 00 00 00 00 00 00 00 00    ; x64 absolute pointer
                // 0x10014 | jmp 0x20009                ; Jump to instruction immediatly after replaced prologue
                // 0x1001a | 00 00 00 00 00 00 00 00    ; x64 absolute pointer

                // push rbp
                REQUIRE(TrampolineBuffer[0] == 0x55);

                // mov rbp, rsp
                REQUIRE(TrampolineBuffer[1] == 0x48);
                REQUIRE(TrampolineBuffer[2] == 0x89);
                REQUIRE(TrampolineBuffer[3] == 0xE5);

                // call qword ptr [rip+0x2] 0x20010
                REQUIRE(TrampolineBuffer[4] == 0xFF);
                REQUIRE(TrampolineBuffer[5] == 0x15);
                REQUIRE(TrampolineBuffer[6] == 0x02);
                REQUIRE(TrampolineBuffer[7] == 0x00);
                REQUIRE(TrampolineBuffer[8] == 0x00);
                REQUIRE(TrampolineBuffer[9] == 0x00);

                // jmp 0x10014
                REQUIRE(TrampolineBuffer[10] == 0xEB);
                REQUIRE(TrampolineBuffer[11] == 0x08);

                // jmp qword ptr [rip+0x0] 0x20009
                REQUIRE(TrampolineBuffer[20] == 0xFF);
                REQUIRE(TrampolineBuffer[21] == 0x25);
                REQUIRE(TrampolineBuffer[22] == 0x00);
                REQUIRE(TrampolineBuffer[23] == 0x00);
                REQUIRE(TrampolineBuffer[24] == 0x00);
                REQUIRE(TrampolineBuffer[25] == 0x00);
            }

            std::free(ReplaceableInstructions);
        }
    }

    GIVEN("A function with a prologue containing a JMP relative instruction")
    {
        ZyanU8 Buffer[] = {
            0xE9, 0x07, 0x00, 0x00, 0x00,                                 // 0x20000 | jmp 0x1000A
            0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0x20005 | mov rax, 0x1 ; (not executed due to previous jump)
            0x48, 0xB8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0x2000F | mov rax, 0x2
            0xC3                                                          // 0x20019 | ret
        };

        ZyanU64 TargetFunction = (ZyanU64)Buffer;
        ZyanU64 TrampolineFunction = TargetFunction - 0x10000;
        ZyanU8 TrampolineBuffer[192] = { 0 };
        ZyanUSize SizeOfFoundInstructions = 0;
        ZyanU64 NumberOfFoundInstructions = 0;

        WHEN("I call the ZynterceptCompileTrampoline64 function")
        {
            ZyanU64 SizeOfDecodedInstructions = ZynterceptSizeOfDecodedDesiredInstructions(
                ZYDIS_MACHINE_MODE_LONG_64,
                ZYDIS_STACK_WIDTH_64,
                Buffer,
                sizeof(Buffer),
                ZYNTERCEPT_SIZE_OF_DETOUR_JUMP);

            REQUIRE(SizeOfDecodedInstructions != 0);

            ZydisDecoded* ReplaceableInstructions = (ZydisDecoded*)std::malloc(SizeOfDecodedInstructions);

            REQUIRE(ReplaceableInstructions != nullptr);

            REQUIRE(ZynterceptFindReplaceableInstructions(
                ZYDIS_MACHINE_MODE_LONG_64,
                ZYDIS_STACK_WIDTH_64,
                Buffer,
                sizeof(Buffer),
                ZYNTERCEPT_SIZE_OF_DETOUR_JUMP,
                SizeOfDecodedInstructions,
                ReplaceableInstructions,
                &NumberOfFoundInstructions,
                &SizeOfFoundInstructions) == ZYAN_TRUE);

            REQUIRE(ZynterceptCompileTrampoline64(
                TargetFunction,
                TrampolineFunction,
                TrampolineBuffer,
                sizeof(TrampolineBuffer),
                ReplaceableInstructions,
                NumberOfFoundInstructions) == ZYAN_TRUE);

            THEN("It should generate a valid trampoline with prefixed ModR/M JMP absolute instruction")
            {
                // Expected trampoline:
                // 
                // 0x10000 | jmp 0x2000c    ; Relocated jump from the very first instruction of prologue
                // 0x10005 | jmp 0x20005    ; Jump to instruction immediatly after replaced prologue

                // jmp qword ptr [rip+0x0] 0x2000c
                REQUIRE(TrampolineBuffer[0] == 0xFF);
                REQUIRE(TrampolineBuffer[1] == 0x25);
                REQUIRE(TrampolineBuffer[2] == 0x00);
                REQUIRE(TrampolineBuffer[3] == 0x00);
                REQUIRE(TrampolineBuffer[4] == 0x00);
                REQUIRE(TrampolineBuffer[5] == 0x00);

                // jmp qword ptr [rip+0x0] 0x20005
                REQUIRE(TrampolineBuffer[14] == 0xFF);
                REQUIRE(TrampolineBuffer[15] == 0x25);
                REQUIRE(TrampolineBuffer[16] == 0x00);
                REQUIRE(TrampolineBuffer[17] == 0x00);
                REQUIRE(TrampolineBuffer[18] == 0x00);
                REQUIRE(TrampolineBuffer[19] == 0x00);
            }

            std::free(ReplaceableInstructions);
        }
    }

    GIVEN("A function with a prologue containing a JCC relative instruction")
    {
        ZyanU8 Buffer[] = {
            0x48, 0x83, 0xF8, 0x00,                                         // 0x10000 | cmp rax, 0x0
            0x74, 0x05,                                                     // 0x10004 | je 0x1000B
            0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // 0x10006 | mov rax, 0x1
            0xC3                                                            // 0x10010 | ret
        };

        ZyanU64 TargetFunction = (ZyanU64)Buffer;
        ZyanU64 TrampolineFunction = TargetFunction - 0x10000;
        ZyanU8 TrampolineBuffer[192] = { 0 };
        ZyanUSize SizeOfFoundInstructions = 0;
        ZyanU64 NumberOfFoundInstructions = 0;

        WHEN("I call the ZynterceptCompileTrampoline64 function")
        {
            ZyanU64 SizeOfDecodedInstructions = ZynterceptSizeOfDecodedDesiredInstructions(
                ZYDIS_MACHINE_MODE_LONG_64,
                ZYDIS_STACK_WIDTH_64,
                Buffer,
                sizeof(Buffer),
                ZYNTERCEPT_SIZE_OF_DETOUR_JUMP);

            REQUIRE(SizeOfDecodedInstructions != 0);

            ZydisDecoded* ReplaceableInstructions = (ZydisDecoded*)std::malloc(SizeOfDecodedInstructions);

            REQUIRE(ReplaceableInstructions != nullptr);

            REQUIRE(ZynterceptFindReplaceableInstructions(
                ZYDIS_MACHINE_MODE_LONG_64,
                ZYDIS_STACK_WIDTH_64,
                Buffer,
                sizeof(Buffer),
                ZYNTERCEPT_SIZE_OF_DETOUR_JUMP,
                SizeOfDecodedInstructions,
                ReplaceableInstructions,
                &NumberOfFoundInstructions,
                &SizeOfFoundInstructions) == ZYAN_TRUE);

            REQUIRE(ZynterceptCompileTrampoline32(
                TargetFunction,
                TrampolineFunction,
                TrampolineBuffer,
                sizeof(TrampolineBuffer),
                ReplaceableInstructions,
                NumberOfFoundInstructions) == ZYAN_TRUE);

            THEN("It should generate a valid trampoline with prefixed ModR/M JMP absolute and JCC relative instructions")
            {
                // Expected trampoline:
                // 
                // 0x10000 | cmp rax, 0x0   ; Relocated jump from the very first instruction of prologue
                // 0x10004 | jne 0x10022    ; Rewrote conditional JCC to JNCC keeping the semantic
                // 0x1000a | jmp 0x2000b    ; Jump to previous JCC target instruction
                // 0x1000f | nop            ; Skipped
                // 0x10018 | nop            ; Skipped
                // 0x10021 | nop            ; Skipped
                // 0x10022 | jmp 0x20006    ; Jump to instruction immediatly after replaced prologue

                // cmp rax, 0x0
                REQUIRE(TrampolineBuffer[0] == 0x48);
                REQUIRE(TrampolineBuffer[1] == 0x83);
                REQUIRE(TrampolineBuffer[2] == 0xF8);
                REQUIRE(TrampolineBuffer[3] == 0x00);

                // jne 0x10022
                REQUIRE(TrampolineBuffer[4] == 0x0F);
                REQUIRE(TrampolineBuffer[5] == 0x85);
                REQUIRE(TrampolineBuffer[6] == 0x18);
                REQUIRE(TrampolineBuffer[7] == 0x00);
                REQUIRE(TrampolineBuffer[8] == 0x00);
                REQUIRE(TrampolineBuffer[9] == 0x00);

                // jmp 0x2000b
                REQUIRE(TrampolineBuffer[10] == 0xE9);
                REQUIRE(TrampolineBuffer[11] == 0xFC);
                REQUIRE(TrampolineBuffer[12] == 0xFF);
                REQUIRE(TrampolineBuffer[13] == 0x00);
                REQUIRE(TrampolineBuffer[14] == 0x00);

                // Nop (omitted)
                // Nop (omitted)
                // Nop (omitted)

                // jmp 0x20006
                REQUIRE(TrampolineBuffer[34] == 0xE9);
                REQUIRE(TrampolineBuffer[35] == 0xDF);
                REQUIRE(TrampolineBuffer[36] == 0xFF);
                REQUIRE(TrampolineBuffer[37] == 0x00);
                REQUIRE(TrampolineBuffer[38] == 0x00);
            }

            std::free(ReplaceableInstructions);
        }
    }

    GIVEN("A function with a prologue too short to hook")
    {
        ZyanU8 Buffer[] = {
            0x90,   // 0x10000 | nop
            0xC3    // 0x10001 | ret
        };

        WHEN("I call the ZynterceptSizeOfDecodedDesiredInstructions function")
        {
            ZyanU64 SizeOfDecodedInstructions = ZynterceptSizeOfDecodedDesiredInstructions(
                ZYDIS_MACHINE_MODE_LONG_64,
                ZYDIS_STACK_WIDTH_64,
                Buffer,
                sizeof(Buffer),
                ZYNTERCEPT_SIZE_OF_DETOUR_JUMP);

            THEN("It should fail and return an invalid size of decoded instructions")
            {
                REQUIRE(SizeOfDecodedInstructions == 0);
            }
        }
    }
}
