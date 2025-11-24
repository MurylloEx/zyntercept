#include <Zyntercept/Core/Common/Common.h>
#include <Zyntercept/Core/Syscall/Syscall.h>
#include <Zyntercept/Core/Disassembler/Disassembler.h>

#include <map>
#include <stack>
#include <vector>
#include <string>

ZyanBool __zyntercept_cdecl ZynterceptIsRelative(
    __zyntercept_in ZydisDecoded* DecodedInstruction)
{
    ZydisDecodedInstruction* Instruction = &DecodedInstruction->Instruction;

    /* Fast way using Zydis to check if instruction is relative */
    if (Instruction->attributes & ZYDIS_ATTRIB_IS_RELATIVE)
    {
        return ZYAN_TRUE;
    }

    /* If by some reason the fast check don't work, check each operand if it's relative to RIP or EIP */
    for (ZyanU8 Offset = 0; Offset < Instruction->operand_count; Offset++)
    {
        ZydisDecodedOperand *Operand = &DecodedInstruction->Operands[Offset];

        /* This operand isn't of type memory, thus we don't need to check it */
        if (Operand->type != ZYDIS_OPERAND_TYPE_MEMORY)
        {
            continue;
        }

        /* If the instruction has as target a x64 CPU and this operand has the memory base as RIP, so it's relative */
        if (Instruction->machine_mode == ZYDIS_MACHINE_MODE_LONG_64 &&
            Operand->mem.base == ZYDIS_REGISTER_RIP)
        {
            return ZYAN_TRUE;
        }

        /* If the instruction has as target a x86 CPU and this operand has the memory base as EIP, so it's relative */
        if ((
            Instruction->machine_mode == ZYDIS_MACHINE_MODE_LONG_COMPAT_32 ||
            Instruction->machine_mode == ZYDIS_MACHINE_MODE_LEGACY_32) &&
            Operand->mem.base == ZYDIS_REGISTER_EIP)
        {
            return ZYAN_TRUE;
        }
    }

    /* The instruction is not dependent of his position */
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptIsRet(
    __zyntercept_in ZydisDecoded *DecodedInstruction)
{
    if (DecodedInstruction->Instruction.meta.category == ZYDIS_CATEGORY_RET)
    {
        return ZYAN_TRUE;
    }

    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptIsCall(
    __zyntercept_in ZydisDecoded* DecodedInstruction,
    __zyntercept_out ZydisDecodedOperand** ImmediateOperand)
{
    ZydisDecodedOperand *FoundImmediateOperand = nullptr;

    /* It's not a CALL because his category is not call */
    if (DecodedInstruction->Instruction.meta.category != ZYDIS_CATEGORY_CALL)
    {
        return ZYAN_FALSE;
    }

    for (ZyanU8 Offset = 0; Offset < DecodedInstruction->Instruction.operand_count; Offset++)
    {
        ZydisDecodedOperand *Operand = &DecodedInstruction->Operands[Offset];

        /* If the operand is an immediate, set the immediate operand */
        if (Operand->type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            FoundImmediateOperand = Operand;
            continue;
        }

        /* Look for hidden register jumps operands that change EIP/RIP */
        if (Operand->visibility != ZYDIS_OPERAND_VISIBILITY_HIDDEN ||
            Operand->type != ZYDIS_OPERAND_TYPE_REGISTER)
        {
            continue;
        }

        /* If the HIDDEN operand is RIP or EIP, so it's a CALL instruction */
        if (Operand->reg.value == ZYDIS_REGISTER_RIP || Operand->reg.value == ZYDIS_REGISTER_EIP)
        {
            if (ImmediateOperand)
            {
                *ImmediateOperand = FoundImmediateOperand;
            }

            return ZYAN_TRUE;
        }
    }

    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptIsJcc(
    __zyntercept_in ZydisDecoded* DecodedInstruction,
    __zyntercept_out ZydisDecodedOperand** ImmediateOperand)
{
    ZydisDecodedOperand *FoundImmediateOperand = nullptr;
    ZyanBool IsProgramCounterDependent = ZYAN_FALSE;
    ZyanBool IsCounterDependent = ZYAN_FALSE;
    ZyanBool IsAccessingCpuFlags = DecodedInstruction->Instruction.cpu_flags->tested != 0;

    /* It's not a JCC because his category is not conditional branch */
    if (DecodedInstruction->Instruction.meta.category != ZYDIS_CATEGORY_COND_BR)
    {
        return ZYAN_FALSE;
    }

    /* Should look only for instructions that have hidden operands like JS, JNZ, JQ, etc */
    /* Conditional jumps have HIDDEN register operands like RIP/EIP and RFLAGS/EFLAGS */
    if (DecodedInstruction->Instruction.operand_count == DecodedInstruction->Instruction.operand_count_visible)
    {
        return ZYAN_FALSE;
    }

    for (ZyanU8 Offset = 0; Offset < DecodedInstruction->Instruction.operand_count; Offset++)
    {
        ZydisDecodedOperand *Operand = &DecodedInstruction->Operands[Offset];

        /* If the operand is an immediate, set the immediate operand */
        if (Operand->type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            FoundImmediateOperand = Operand;
            continue;
        }

        /* Look for hidden register jumps operands that change EIP/RIP */
        if (Operand->visibility == ZYDIS_OPERAND_VISIBILITY_HIDDEN &&
            Operand->type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            /* If the HIDDEN operand is RIP or EIP, so it's a JCC instruction */
            if (Operand->reg.value == ZYDIS_REGISTER_RIP || Operand->reg.value == ZYDIS_REGISTER_EIP)
            {
                IsProgramCounterDependent = ZYAN_TRUE;
                continue;
            }

            /* If the HIDDEN operand is RCX or ECX, so it may be a JCC */
            if (Operand->reg.value == ZYDIS_REGISTER_RCX || Operand->reg.value == ZYDIS_REGISTER_ECX)
            {
                IsCounterDependent = ZYAN_TRUE;
                continue;
            }
        }
    }

    /* If it hasn't RIP or EIP operands, it's not a JCC instruction */
    if (!IsProgramCounterDependent)
    {
        return ZYAN_FALSE;
    }

    /* If this instruction doesn't check any CPU flags in EFLAGS or the ECX/RCX, it's not a JCC */
    if (!IsCounterDependent && !IsAccessingCpuFlags)
    {
        return ZYAN_FALSE;
    }

    /* If the immediate operand pointer is null, just ignore it */
    if (ImmediateOperand)
    {
        *ImmediateOperand = FoundImmediateOperand;
    }

    return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptIsJmp(
    __zyntercept_in ZydisDecoded* DecodedInstruction,
    __zyntercept_out ZydisDecodedOperand** ImmediateOperand)
{
    ZydisDecodedOperand *FoundImmediateOperand = NULL;

    /* It's not a JMP because his category is not unconditional branch */
    if (DecodedInstruction->Instruction.meta.category != ZYDIS_CATEGORY_UNCOND_BR)
    {
        return ZYAN_FALSE;
    }

    /* Should look only for instructions that have hidden operands like JS, JNZ, JQ, etc */
    /* Unconditional jumps have HIDDEN register operands like RIP and EIP */
    if (DecodedInstruction->Instruction.operand_count == DecodedInstruction->Instruction.operand_count_visible)
    {
        return ZYAN_FALSE;
    }

    for (ZyanU8 Offset = 0; Offset < DecodedInstruction->Instruction.operand_count; Offset++)
    {
        ZydisDecodedOperand *Operand = &DecodedInstruction->Operands[Offset];

        /* If the operand is an immediate, set the immediate operand */
        if (Operand->type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            FoundImmediateOperand = Operand;
            continue;
        }

        /* Look for hidden register jumps operands that change EIP/RIP */
        if (Operand->visibility != ZYDIS_OPERAND_VISIBILITY_HIDDEN ||
            Operand->type != ZYDIS_OPERAND_TYPE_REGISTER)
        {
            continue;
        }

        /* If the HIDDEN operand is RIP or EIP, so it's a JCC or a JMP instruction */
        if (Operand->reg.value == ZYDIS_REGISTER_RIP || Operand->reg.value == ZYDIS_REGISTER_EIP)
        {
            if (ImmediateOperand)
            {
                *ImmediateOperand = FoundImmediateOperand;
            }

            return ZYAN_TRUE;
        }
    }

    /* If there's no operand of type REGISTER and IMMEDIATE, it's not a JMP */
    return ZYAN_FALSE;
}

ZyanU64 __zyntercept_cdecl ZynterceptSizeOfDecodedDesiredInstructions(
    __zyntercept_in ZydisMachineMode MachineMode,
    __zyntercept_in ZydisStackWidth StackWidth,
    __zyntercept_in ZyanU8* Buffer,
    __zyntercept_in ZyanUSize BufferSize,
    __zyntercept_in ZyanU32 DesiredSize)
{
    ZydisDecoder Decoder = {};
    ZydisDecodedInstruction Instruction = {};
    ZyanUSize SizeOfDecodedInstructions = 0;
    ZyanU64 SizeOfDecodedPrologue = 0;

    /* Initialize decoder with specified machine mode and stack width */
    if (ZYAN_FAILED(ZydisDecoderInit(&Decoder, MachineMode, StackWidth)))
    {
        return 0;
    }

    /* Decode prologue instructions until reach the size of detour */
    while (ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(
        &Decoder,
        nullptr,
        Buffer + SizeOfDecodedInstructions,
        BufferSize - SizeOfDecodedInstructions,
        &Instruction)))
    {
        /* Check if instruction is a padding around of the original function */
        if (Instruction.mnemonic == ZYDIS_MNEMONIC_INVALID ||
            Instruction.mnemonic == ZYDIS_MNEMONIC_INT3)
        {
            return 0;
        }

        /* Check if instruction is a return */
        if (Instruction.mnemonic == ZYDIS_MNEMONIC_RET) 
        {
            return 0;
        }

        SizeOfDecodedPrologue += sizeof(ZydisDecoded);
        SizeOfDecodedInstructions += Instruction.length;

        /* If the prologue size is enought to our use case, get the size of decoded prologue */
        if (SizeOfDecodedInstructions >= DesiredSize)
        {
            return SizeOfDecodedPrologue;
        }
    }

    return 0;
}

ZyanBool __zyntercept_cdecl ZynterceptFindReplaceableInstructions(
    __zyntercept_in ZydisMachineMode MachineMode,
    __zyntercept_in ZydisStackWidth StackWidth,
    __zyntercept_in ZyanU8* Buffer,
    __zyntercept_in ZyanUSize BufferSize,
    __zyntercept_in ZyanU32 SizeOfDetour,
    __zyntercept_in ZyanU64 SizeOfDecodedBuffer,
    __zyntercept_out ZydisDecoded* DecodedBuffer,
    __zyntercept_out ZyanU64* NumberOfFoundInstructions,
    __zyntercept_out ZyanUSize* SizeOfFoundInstructions)
{
    ZyanUSize SizeOfDecodedInstructions = 0;
    ZyanU64 SizeOfDecodedPrologue = 0;
    ZyanU64 CountInstructions = 0;

    ZydisDecoder Decoder = {};
    ZydisDecoded Decoded = {};
    ZydisDecodedInstruction *Instruction = &Decoded.Instruction;
    ZydisDecodedOperand *Operands = Decoded.Operands;

    std::vector<ZydisDecoded> InstructionsVector = {};

    /* Initialize decoder with specified machine mode and stack width */
    if (ZYAN_FAILED(ZydisDecoderInit(&Decoder, MachineMode, StackWidth)))
    {
        return ZYAN_FALSE;
    }

    /* Decode prologue instructions until reach the size of detour */
    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(
        &Decoder,
        Buffer + SizeOfDecodedInstructions,
        BufferSize - SizeOfDecodedInstructions,
        Instruction,
        Operands)))
    {
        CountInstructions++;
        SizeOfDecodedPrologue += sizeof(ZydisDecoded);
        SizeOfDecodedInstructions += Instruction->length;

        InstructionsVector.push_back(Decoded);

        /* If the prologue size is enought to our use case, get the size of decoded prologue */
        if (SizeOfDecodedInstructions >= SizeOfDetour)
        {
            break;
        }
    }

    *SizeOfFoundInstructions = SizeOfDecodedInstructions;
    *NumberOfFoundInstructions = CountInstructions;

    ZyanUSize BytesToCopy = InstructionsVector.size() * sizeof(ZydisDecoded);
    
    if (BytesToCopy > SizeOfDecodedBuffer)
    {
        return ZYAN_FALSE;
    }

    if (SizeOfDecodedInstructions < SizeOfDetour)
    {
        return ZYAN_FALSE;
    }

    memcpy(DecodedBuffer, InstructionsVector.data(), BytesToCopy);

    return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptFindNextFunctionBranch(
    __zyntercept_in ZydisMachineMode MachineMode,
    __zyntercept_in ZydisStackWidth StackWidth,
    __zyntercept_in ZyanU8* Buffer,
    __zyntercept_in ZyanUSize BufferSize,
    __zyntercept_in ZyanU64 BaseAddress,
    __zyntercept_out ZydisDecoded* BranchInstruction,
    __zyntercept_out ZyanU64* InstructionAddress,
    __zyntercept_out ZyanU64* GreenBranchAddress,
    __zyntercept_out ZyanU64* RedBranchAddress)
{
    ZydisDecoder Decoder = {};
    ZydisDecoded Decoded = {};
    ZydisDecodedOperand *Operand = nullptr;
    ZyanUSize Offset = 0;
    ZyanUSize NextOffset = 0;

    /* Initialize decoder with specified machine mode and stack width */
    if (ZYAN_FAILED(ZydisDecoderInit(&Decoder, MachineMode, StackWidth)))
    {
        return ZYAN_FALSE;
    }

    /* Decode the instructions until find a jump */
    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(
        &Decoder,
        Buffer + NextOffset,
        BufferSize - NextOffset,
        &Decoded.Instruction,
        Decoded.Operands)))
    {
        /* This is the offset of the next instruction to be executed after current one */
        NextOffset += Decoded.Instruction.length;

        /* If current instruction is a <ret>, stop decoding instructions */
        if (ZynterceptIsRet(&Decoded))
        {
            *BranchInstruction = Decoded;
            *InstructionAddress = BaseAddress + Offset;
            *RedBranchAddress = 0;
            *GreenBranchAddress = 0;

            return ZYAN_FALSE;
        }

        /* Check if current instruction is a <jmp rel8/16/32> */
        if (ZynterceptIsJmp(&Decoded, &Operand) && Operand)
        {
            *BranchInstruction = Decoded;
            *InstructionAddress = BaseAddress + Offset;
            *GreenBranchAddress = BaseAddress + NextOffset + (Operand->imm.is_signed ? Operand->imm.value.s : Operand->imm.value.u);
            *RedBranchAddress = 0;

            return ZYAN_TRUE;
        }

        /* Check if current instruction is a <jcc rel8/16/32> */
        if (ZynterceptIsJcc(&Decoded, &Operand) && Operand)
        {
            *BranchInstruction = Decoded;
            *InstructionAddress = BaseAddress + Offset;
            *GreenBranchAddress = BaseAddress + NextOffset + (Operand->imm.is_signed ? Operand->imm.value.s : Operand->imm.value.u);
            *RedBranchAddress = BaseAddress + NextOffset;

            return ZYAN_TRUE;
        }

        /* This is the offset of the current instruction */
        Offset += Decoded.Instruction.length;
    }

    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptFindFunctionBranchs(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZydisMachineMode MachineMode,
    __zyntercept_in ZydisStackWidth StackWidth,
    __zyntercept_in ZyanU64 BaseAddress,
    __zyntercept_out ZydisBranch** FoundBranchs,
    __zyntercept_out ZyanU64* NumberOfFoundBranchs)
{
    /* Size of buffer used to fetch new instructions in memory */
    /* TODO: Review this line and check if this value could be a function argument */
    ZyanUSize BufferSize = 0x400;
    ZyanU8* Buffer = (ZyanU8*)malloc(BufferSize * sizeof(ZyanU8));

    /* Wtf?! Is the computer out of RAM? Are we running on a potato? */
    if (!Buffer)
    {
        return ZYAN_FALSE;
    }

    std::stack<ZydisBranch> TemporaryBranchs = {};
    std::vector<ZydisBranch> Branchs = {};
    ZynterceptPagedMemoryOperation Request = {0};
    ZydisDecoded Decoded = {};
    ZydisBranch Branch = {0};

    ZyanU64 Base = BaseAddress;
    ZyanU64 InstructionAddress = 0;
    ZyanU64 GreenBranchAddress = 0;
    ZyanU64 RedBranchAddress = 0;

    ZyanBool IsFirstIteration = ZYAN_TRUE;

    while (ZYAN_TRUE)
    {
        /* Zero Buffer memory to avoid trash instructions from previous iteration */
        memset(Buffer, 0, BufferSize);

        /* Check if stack is empty. If it's empty and isn't the first iteration, exit from the loop */
        if (TemporaryBranchs.empty() && !IsFirstIteration)
        {
            break;
        }

        /* Set flag as FALSE indicating that we aren't anymore in the first iteration */
        IsFirstIteration = ZYAN_FALSE;

        if (!TemporaryBranchs.empty())
        {
            Branch = TemporaryBranchs.top();
            TemporaryBranchs.pop();

            /* Set the base address as the destination of the current branch to follow him in memory */
            Base = Branch.Destination;
        }

        /* I know that it's not really possible but just for convenience, */
        /* check if the destination of the branch is different from zero */
        if (Base == 0)
        {
            goto FAILURE;
        }

        /* Read the target process memory and fetch the first 1024 bytes of the base address */
        Request.Address = Base;
        Request.Buffer = Buffer;
        Request.Size = BufferSize;

        if (!ZynterceptReadMemory(ProcessIdentifier, &Request))
        {
            goto FAILURE;
        }
         
        /* Fetch the next function branch (Jmp or Jcc) */
        /* If there's nothing to fetch anymore in this branch, the function returns FALSE */
        if (!ZynterceptFindNextFunctionBranch(
            MachineMode,
            StackWidth,
            Buffer,
            BufferSize,
            Base, /* Base address of where the instructions are stored */
            &Decoded,
            &InstructionAddress, /* Absolute address of Jmp/Jcc instruction in virtual memory */
            &GreenBranchAddress, /* Absolute address of the region that the jump points to in virtual memory */
            &RedBranchAddress))  /* Absolute address of the instruction immediately after found Jmp/Jcc instruction */
        {
            continue;
        }

        Branch.Base = Base;
        Branch.Address = InstructionAddress;
        Branch.Mnemonic = Decoded.Instruction.mnemonic;
        Branch.Flow = ZYDIS_BRANCH_FLOW_GREEN;
        Branch.Destination = GreenBranchAddress;

        /* Check if this branch already has followed and added to vector */
        if (std::find(Branchs.begin(), Branchs.end(), Branch) == Branchs.end())
        {
            TemporaryBranchs.push(Branch);
            Branchs.push_back(Branch);
        }

        /* If it's a unconditional jump, then red branch address is NULL */
        if (RedBranchAddress == 0)
        {
            /* When there's no red branch address, ignore it and follow the next branch code */
            continue;
        }

        Branch.Flow = ZYDIS_BRANCH_FLOW_RED;
        Branch.Destination = RedBranchAddress;

        /* Check if this branch already has followed and added to vector */
        if (std::find(Branchs.begin(), Branchs.end(), Branch) == Branchs.end())
        {
            TemporaryBranchs.push(Branch);
            Branchs.push_back(Branch);
        }
    }

    if (Branchs.empty()) {
        goto FAILURE;
    }

    *FoundBranchs = (ZydisBranch*)malloc(Branchs.size() * sizeof(ZydisBranch));
    *NumberOfFoundBranchs = Branchs.size();

    if (*FoundBranchs == nullptr)
    {
        goto FAILURE;
    }

    memset(*FoundBranchs, 0, Branchs.size() * sizeof(ZydisBranch));

    /* Copy values from std::vector<ZydisBranch> to new allocated FoundBranchs buffer as C-array style */
    memcpy(*FoundBranchs, Branchs.data(), Branchs.size() * sizeof(ZydisBranch));

    free(Buffer);
    return ZYAN_TRUE;

FAILURE:
    /* Cleanup the output pointers */
    *NumberOfFoundBranchs = 0;
    *FoundBranchs = nullptr;

    /* Release allocated memory of buffer instructions */
    free(Buffer);
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptHasFunctionBranchDestinationsBetween(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZydisMachineMode MachineMode,
    __zyntercept_in ZydisStackWidth StackWidth,
    __zyntercept_in ZyanU64 BaseAddress,
    __zyntercept_in ZyanU64 BeginAddress,
    __zyntercept_in ZyanU64 EndAddress)
{
    ZydisBranch* FoundBranchs = nullptr;
    ZyanU64 NumberOfFoundBranchs = 0;

    /* This function will follow all possible jumps in target function memory */
    /* and then create an array with branchs containing the address of the jump and his destination */
    if (!ZynterceptFindFunctionBranchs(
        ProcessIdentifier,
        MachineMode,
        StackWidth,
        BaseAddress,
        &FoundBranchs,
        &NumberOfFoundBranchs))
    {
        return ZYAN_FALSE;
    }

    /* Iterate over all found branchs */
    for (ZyanU64 Offset = 0; Offset < NumberOfFoundBranchs; Offset++)
    {
        ZydisBranch *Branch = &FoundBranchs[Offset];

        /* Check only the green paths (jumps and conditional jumps), not direct (red) paths */
        if (Branch->Flow != ZYDIS_BRANCH_FLOW_GREEN)
        {
            continue;
        }

        /* Check if destination is in prohibited region */
        if (Branch->Destination >= BeginAddress && Branch->Destination <= EndAddress)
        {
            /* Release the allocated memory used by ZynterceptFindFunctionBranchs */
            free(FoundBranchs);
            return ZYAN_TRUE;
        }
    }

    /* Release the allocated memory used by ZynterceptFindFunctionBranchs */
    free(FoundBranchs);
    return ZYAN_FALSE;
}
