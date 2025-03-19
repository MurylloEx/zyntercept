#include <Zyntercept/Core/Trampoline/Trampoline.h>
#include <Zyntercept/Core/Assembler/Assembler.h>
#include <Zyntercept/Core/Disassembler/Disassembler.h>

ZyanBool __zyntercept_cdecl Relocate(
    __zyntercept_in std::shared_ptr<AssemblyBuilder> Builder,
    __zyntercept_in ZydisDecoded* Decoded)
{
    /* There's no logic to perform here, just perform the reencoding */
    Builder->Reencode(Decoded);

    return Builder->Success();
}

ZyanBool __zyntercept_cdecl RelocateRelative(
    __zyntercept_in std::shared_ptr<AssemblyBuilder> Builder,
    __zyntercept_in ZydisDecoded* Decoded,
    __zyntercept_in ZyanU64 OldAddress)
{
    ZydisDecodedOperand* ImmediateOperand = nullptr;

    /* Iterate over all operands in this decoded instruction */
    for (ZyanU8 Offset = 0; Offset < Decoded->Instruction.operand_count; Offset++) 
    {
        /* Find the immediate operand of this instruction */
        if (Decoded->Operands[Offset].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            ImmediateOperand = &Decoded->Operands[Offset];
            break;
        }
    }

    /* If immediate operand was not found, exit from the function */
    if (!ImmediateOperand) {
        return ZYAN_FALSE;
    }

    /* The destination address of this instruction */
    ZyanU64 DestinationAddress = 0;

    /* Calculate the address that this immediate operand is pointing to */
    if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(
        &Decoded->Instruction,
        ImmediateOperand,
        OldAddress,
        &DestinationAddress)))
    {
        return ZYAN_FALSE;
    }

    ZydisEncoderRequest Encoder = {};

    /* Translate the decoded instruction to an encoder request with his operands */
    if (ZYAN_FAILED(ZydisEncoderDecodedInstructionToEncoderRequest(
        &Decoded->Instruction,
        Decoded->Operands,
        Decoded->Instruction.operand_count_visible,
        &Encoder)))
    {
        return ZYAN_FALSE;
    }

    /* Iterate over all operands in instruction and search for immediate operand */
    for (ZyanU8 Offset = 0; Offset < Encoder.operand_count; Offset++) {
        ZydisEncoderOperand* Operand = &Encoder.operands[Offset];

        /* Ignore all operands that aren't immediate operands */
        if (Operand->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            /* Calculate the displacement between the new address of instruction and the destination of this instruction */
            ZyanI64 Displacement = Difference(DestinationAddress, Builder->GetBaseAddress() + Builder->Size() + Decoded->Instruction.length);

            /* Set the new displacement value based in the new position of instruction */
            Operand->imm.s = Displacement;

            /* For simplification purposes, set the unsigned value of immediate as 0 and use only the signed value */
            Operand->imm.u = 0;
        }
    }

    Builder->Encode(&Encoder);

    return Builder->Success();
}

ZyanBool __zyntercept_cdecl RelocateJmp(
    __zyntercept_in std::shared_ptr<AssemblyBuilder> Builder,
    __zyntercept_in ZyanBool IsX64Process,
    __zyntercept_in ZydisDecoded* Decoded,
    __zyntercept_in ZyanU64 OldAddress)
{
    /* Pointer to decoded immediate operand */
    ZydisDecodedOperand* ImmediateOperand = nullptr;

    /* If it's not a jmp instruction, ignore it and return FALSE */
    if (!ZynterceptIsJmp(Decoded, &ImmediateOperand)) {
        return ZYAN_FALSE;
    }

    /* The destination address of this instruction */
    ZyanU64 DestinationAddress = 0;

    /* Calculate the address that this immediate operand is pointing to */
    if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(
        &Decoded->Instruction,
        ImmediateOperand,
        OldAddress,
        &DestinationAddress)))
    {
        return ZYAN_FALSE;
    }

    IsX64Process
        ? Builder->Jmp64(DestinationAddress)
        : Builder->Jmp32(DestinationAddress);

    return Builder->Success();
}

ZyanBool __zyntercept_cdecl RelocateJcc(
    __zyntercept_in std::shared_ptr<AssemblyBuilder> Builder,
    __zyntercept_in ZyanBool IsX64Process,
    __zyntercept_in ZydisDecoded* Decoded,
    __zyntercept_in ZyanU64 OldAddress)
{
    /* The destination address of this instruction */
    ZyanU64 DestinationAddress = 0;
    /* Pointer to decoded immediate operand */
    ZydisDecodedOperand* ImmediateOperand = nullptr;

    /* If it's not a jmp instruction, ignore it and return FALSE */
    if (!ZynterceptIsJcc(Decoded, &ImmediateOperand)) {
        return ZYAN_FALSE;
    }

    /* Calculate the address that this immediate operand is pointing to */
    if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(
        &Decoded->Instruction,
        ImmediateOperand,
        OldAddress,
        &DestinationAddress)))
    {
        return ZYAN_FALSE;
    }

    if (IsX64Process) {
        /* Negate the JCC to skip the absolute jump when the condition is met */
        /* Jump to the last NOP instruction of the memory block */
        Builder->Jncc(ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64, Decoded, Builder->GetBaseAddress() + Builder->Size() + 30);

        /* Write the unconditional jump to where the jcc should point to */
        /* The trick is use an unconditional jump, negate the jcc and skip it */
        /* to get the same execution flow as before of rewrite the jcc */
        Builder->Jmp64(DestinationAddress);

        /* Pad with NOPs until get 24 bytes written since last instruction */
        Builder->Nop(24 - Builder->LastInstructionLength());
    }
    else {
        /* Negate the JCC to skip the absolute jump when the condition is met */
        /* Jump to the last NOP instruction of the memory block */
        Builder->Jncc(ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32, Decoded, Builder->GetBaseAddress() + Builder->Size() + 30);

        /* Write the unconditional jump to where the jcc should point to */
        /* The trick is use an unconditional jump, negate the jcc and skip it */
        /* to get the same execution flow as before of rewrite the jcc */
        Builder->Jmp32(DestinationAddress);

        /* Pad with NOPs until get 24 bytes written since last instruction */
        Builder->Nop(24 - Builder->LastInstructionLength());
    }

    return Builder->Success();
}

ZyanBool __zyntercept_cdecl RelocateCall(
    __zyntercept_in std::shared_ptr<AssemblyBuilder> Builder,
    __zyntercept_in ZyanBool IsX64Process,
    __zyntercept_in ZydisDecoded* Decoded,
    __zyntercept_in ZyanU64 OldAddress)
{
    /* Pointer to decoded immediate operand */
    ZydisDecodedOperand* ImmediateOperand = nullptr;

    /* If it's not a call instruction, ignore it and return FALSE */
    if (!ZynterceptIsCall(Decoded, &ImmediateOperand)) {
        return ZYAN_FALSE;
    }

    /* The destination address of this instruction */
    ZyanU64 DestinationAddress = 0;

    /* Calculate the address that this immediate operand is pointing to */
    if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(
        &Decoded->Instruction,
        ImmediateOperand,
        OldAddress,
        &DestinationAddress)))
    {
        return ZYAN_FALSE;
    }

    /* Write the proper instruction */
    IsX64Process
        ? Builder->Call64(DestinationAddress)
        : Builder->Call32(DestinationAddress);

    return Builder->Success();
}

ZyanBool __zyntercept_cdecl ZynterceptCompileTrampoline(
    __zyntercept_in ZyanBool Is64BitProcess,
    __zyntercept_in ZyanU64 TargetFunction,
    __zyntercept_in ZyanU64 TrampolineAddress,
    __zyntercept_out ZyanU8* TrampolineBuffer,
    __zyntercept_in ZyanU64 TrampolineBufferSize,
    __zyntercept_in ZydisDecoded* PrologueInstructions,
    __zyntercept_in ZyanU64 NumberOfPrologueInstructions)
{
    std::shared_ptr<AssemblyBuilder> Builder = std::make_shared<AssemblyBuilder>(TrampolineAddress);
    ZyanU64 OldInstructionAddress = TargetFunction;

    for (ZyanU64 Offset = 0; Offset < NumberOfPrologueInstructions; Offset++) {
        ZydisDecoded* Decoded = &PrologueInstructions[Offset];

        if (ZynterceptIsRelative(Decoded)) {
            if (ZynterceptIsJmp(Decoded, nullptr)) {
                if (!RelocateJmp(Builder, Is64BitProcess, Decoded, OldInstructionAddress)) {
                    return ZYAN_FALSE;
                }
            }
            else if (ZynterceptIsJcc(Decoded, nullptr)) {
                if (!RelocateJcc(Builder, Is64BitProcess, Decoded, OldInstructionAddress)) {
                    return ZYAN_FALSE;
                }
            }
            else if (ZynterceptIsCall(Decoded, nullptr)) {
                if (!RelocateCall(Builder, Is64BitProcess, Decoded, OldInstructionAddress)) {
                    return ZYAN_FALSE;
                }
            }
            else {
                if (!RelocateRelative(Builder, Decoded, OldInstructionAddress)) {
                    return ZYAN_FALSE;
                }
            }
        }
        else {
            /* Easiest scenario: just copy the same instruction to trampoline */
            if (!Relocate(Builder, Decoded)) {
                return ZYAN_FALSE;
            }
        }

        OldInstructionAddress += Decoded->Instruction.length;
    }

    /* Jump to original function after the overwritten instructions */
    Is64BitProcess
        ? Builder->Jmp64(OldInstructionAddress)
        : Builder->Jmp32(OldInstructionAddress);

    /* If the prologue is corrupted, return FALSE */
    if (Builder->Failed()) {
        return ZYAN_FALSE;
    }

    return Builder->CopyTo(TrampolineBuffer, TrampolineBufferSize);
}

ZyanBool __zyntercept_cdecl ZynterceptCompileTrampoline64(
    __zyntercept_in ZyanU64 TargetFunction,
    __zyntercept_in ZyanU64 TrampolineAddress,
    __zyntercept_out ZyanU8* TrampolineBuffer,
    __zyntercept_in ZyanU64 TrampolineBufferSize,
    __zyntercept_in ZydisDecoded* PrologueInstructions,
    __zyntercept_in ZyanU64 NumberOfPrologueInstructions)
{
    return ZynterceptCompileTrampoline(
        ZYAN_TRUE, // Is 64 bit process?
        TargetFunction,
        TrampolineAddress,
        TrampolineBuffer,
        TrampolineBufferSize,
        PrologueInstructions,
        NumberOfPrologueInstructions);
}

ZyanBool __zyntercept_cdecl ZynterceptCompileTrampoline32(
    __zyntercept_in ZyanU64 TargetFunction,
    __zyntercept_in ZyanU64 TrampolineAddress,
    __zyntercept_out ZyanU8* TrampolineBuffer,
    __zyntercept_in ZyanU64 TrampolineBufferSize,
    __zyntercept_in ZydisDecoded* PrologueInstructions,
    __zyntercept_in ZyanU64 NumberOfPrologueInstructions)
{
    return ZynterceptCompileTrampoline(
        ZYAN_FALSE, // Is 64 bit process?
        TargetFunction,
        TrampolineAddress,
        TrampolineBuffer,
        TrampolineBufferSize,
        PrologueInstructions,
        NumberOfPrologueInstructions);
}
