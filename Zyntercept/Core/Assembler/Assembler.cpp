#include <Zyntercept/Core/Assembler/Assembler.h>

#include <map>
#include <memory>
#include <vector>

AssemblyBuilder::AssemblyBuilder(ZyanU64 BaseAddress) {
    this->BaseAddress = BaseAddress;
}

AssemblyBuilder::~AssemblyBuilder() {
    this->EncodedBuffer.clear();
}

void AssemblyBuilder::Jcc(ZydisDecoded* Reference, ZyanU64 Address) {
    ZydisEncoderRequest Instruction = {};
    ZyanU8 InstructionBuffer[ZYDIS_MAX_INSTRUCTION_LENGTH] = { 0 };
    ZyanUSize InstructionLength = ZYDIS_MAX_INSTRUCTION_LENGTH;
    ZyanU64 SourceAddress = this->GetBaseAddress() + this->Size();
    ZyanI64 Displacement = Difference(Address, SourceAddress + 6); // Target - (Source + SizeOfJump)

    /* Check if is bigger than 2^31 - 1 or lower than -2^31 to not overflow the signed int32 value */
    if ((0x7fffffffLL < Displacement) || (Displacement < -0x80000000LL)) {
        this->HasErrors = true;
        return;
    }

    if (ZYAN_FAILED(ZydisEncoderDecodedInstructionToEncoderRequest(
        &Reference->Instruction,
        Reference->Operands,
        Reference->Instruction.operand_count_visible,
        &Instruction)))
    {
        this->HasErrors = true;
        return;
    }

    /* Iterate over all operands in this instruction */
    for (ZyanU8 Offset = 0; Offset < Instruction.operand_count; Offset++)
    {
        ZydisEncoderOperand* Operand = &Instruction.operands[Offset];

        /* Find the immediate operand of this instruction */
        if (Operand->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            Operand->imm.s = Displacement;
            break;
        }
    }

    Instruction.branch_type = ZYDIS_BRANCH_TYPE_NEAR;
    Instruction.branch_width = ZYDIS_BRANCH_WIDTH_32;
    Instruction.address_size_hint = ZYDIS_ADDRESS_SIZE_HINT_32;
    Instruction.operand_size_hint = ZYDIS_OPERAND_SIZE_HINT_32;

    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&Instruction, &InstructionBuffer, &InstructionLength))) {
        this->HasErrors = true;
        return;
    }

    this->InstructionLength = InstructionLength;
    this->EncodedBuffer.insert(this->EncodedBuffer.end(), std::begin(InstructionBuffer), std::begin(InstructionBuffer) + InstructionLength);
}

void AssemblyBuilder::Jncc(ZydisMachineMode MachineMode, ZydisStackWidth StackWidth, ZydisDecoded* Reference, ZyanU64 Address) {
    ZydisDecoded Decoded = {};
    ZydisDecoder Decoder = {};
    ZydisEncoderRequest Instruction = {};
    ZyanUSize InstructionLength = ZYDIS_MAX_INSTRUCTION_LENGTH;
    ZyanU8 InstructionBuffer[ZYDIS_MAX_INSTRUCTION_LENGTH] = { 0 };

    /* Initialize decoder context */
    if (ZYAN_FAILED(ZydisDecoderInit(&Decoder, MachineMode, StackWidth))) {
        this->HasErrors = true;
        return;
    }

    /* For this map purposes, all LOOP's, LOOPcc's, JCXZ, JECXZ and JRCXZ mnemonics are unsupported */
    /* because these mnemonics doesn't have any antonym */
    std::map<ZydisMnemonic, ZydisMnemonic> AntonymMnemonics = {
        /* Antonym of jcc's */
        { ZYDIS_MNEMONIC_JB,    ZYDIS_MNEMONIC_JNB  },
        { ZYDIS_MNEMONIC_JO,    ZYDIS_MNEMONIC_JNO  },
        { ZYDIS_MNEMONIC_JP,    ZYDIS_MNEMONIC_JNP  },
        { ZYDIS_MNEMONIC_JS,    ZYDIS_MNEMONIC_JNS  },
        { ZYDIS_MNEMONIC_JZ,    ZYDIS_MNEMONIC_JNZ  },
        { ZYDIS_MNEMONIC_JL,    ZYDIS_MNEMONIC_JNL  },
        { ZYDIS_MNEMONIC_JBE,   ZYDIS_MNEMONIC_JNBE },
        { ZYDIS_MNEMONIC_JLE,   ZYDIS_MNEMONIC_JNLE },
        /* Antonym of negative jncc's */
        { ZYDIS_MNEMONIC_JNB,   ZYDIS_MNEMONIC_JB   },
        { ZYDIS_MNEMONIC_JNO,   ZYDIS_MNEMONIC_JO   },
        { ZYDIS_MNEMONIC_JNP,   ZYDIS_MNEMONIC_JP   },
        { ZYDIS_MNEMONIC_JNS,   ZYDIS_MNEMONIC_JS   },
        { ZYDIS_MNEMONIC_JNZ,   ZYDIS_MNEMONIC_JZ   },
        { ZYDIS_MNEMONIC_JNL,   ZYDIS_MNEMONIC_JL   },
        { ZYDIS_MNEMONIC_JNBE,  ZYDIS_MNEMONIC_JBE  },
        { ZYDIS_MNEMONIC_JNLE,  ZYDIS_MNEMONIC_JLE  }
    };

    /* Translate decoded instruction to encoder request */
    if (ZYAN_FAILED(ZydisEncoderDecodedInstructionToEncoderRequest(
        &Reference->Instruction,
        Reference->Operands,
        Reference->Instruction.operand_count_visible,
        &Instruction)))
    {
        this->HasErrors = true;
        return;
    }

    /* Check if mnemonic has an antonym */
    if (AntonymMnemonics.count(Instruction.mnemonic) == 0) {
        this->HasErrors = true;
        return;
    }

    /* Fetch the antonym of instruction mnemonic */
    Instruction.mnemonic = AntonymMnemonics[Instruction.mnemonic];

    /* Clear the old values of InstructionLength and InstructionBuffer variables to reencode the instruction */
    InstructionLength = ZYDIS_MAX_INSTRUCTION_LENGTH;
    memset(InstructionBuffer, 0, sizeof(InstructionBuffer));

    /* Encode the instruction with new mnemonic */
    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&Instruction, InstructionBuffer, &InstructionLength))) {
        this->HasErrors = true;
        return;
    }

    /* Decoded the rewrote instruction to the buffer */
    if (ZYAN_FAILED(ZydisDecoderDecodeFull(
        &Decoder,
        InstructionBuffer,
        InstructionLength,
        &Decoded.Instruction,
        Decoded.Operands)))
    {
        this->HasErrors = true;
        return;
    }

    this->Jcc(&Decoded, Address);
}

void AssemblyBuilder::Jmp64(ZyanU64 Address) {
    // jmp qword ptr [rip+0] 0xffffffffffffffff
    ZydisEncoderRequest Instruction = {};
    ZydisEncoderOperand* Operand = &Instruction.operands[0];

    Instruction.mnemonic = ZYDIS_MNEMONIC_JMP;
    Instruction.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    Instruction.operand_count = 1;

    Operand->type = ZYDIS_OPERAND_TYPE_MEMORY;
    Operand->mem.base = ZYDIS_REGISTER_RIP;
    Operand->mem.displacement = 0x00000000U;
    Operand->mem.size = sizeof(ZyanU64);

    ZyanU8 PointerBuffer[sizeof(ZyanU64)] = { 0 };

    memcpy(PointerBuffer, &Address, sizeof(PointerBuffer));

    std::vector<ZyanU8> Buffer = {};

    ZyanU8 InstructionBuffer[ZYDIS_MAX_INSTRUCTION_LENGTH] = { 0 };
    ZyanUSize InstructionLength = ZYDIS_MAX_INSTRUCTION_LENGTH;

    /* Encode the mega jump instruction */
    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&Instruction, &InstructionBuffer, &InstructionLength))) {
        this->HasErrors = true;
        return;
    }

    Buffer.insert(Buffer.end(), std::begin(InstructionBuffer), std::begin(InstructionBuffer) + InstructionLength);
    Buffer.insert(Buffer.end(), std::begin(PointerBuffer), std::end(PointerBuffer));

    this->InstructionLength = static_cast<ZyanU64>(Buffer.size()) * sizeof(ZyanU8);
    this->EncodedBuffer.insert(this->EncodedBuffer.end(), Buffer.begin(), Buffer.end());
}

void AssemblyBuilder::Jmp32(ZyanU64 Address) {
    ZydisEncoderRequest Instruction = {};
    ZydisEncoderOperand* Operand = &Instruction.operands[0];
    ZyanU8 InstructionBuffer[ZYDIS_MAX_INSTRUCTION_LENGTH] = { 0 };
    ZyanUSize InstructionLength = ZYDIS_MAX_INSTRUCTION_LENGTH;
    ZyanU64 SourceAddress = this->GetBaseAddress() + this->Size();
    ZyanI64 Displacement = Difference(Address, SourceAddress + 5); // Target - (Source + SizeOfJump)

    /* Check if is bigger than 2^31 - 1 or lower than -2^31 to not overflow the signed int32 value */
    if ((0x7fffffffLL < Displacement) || (Displacement < -0x80000000LL)) {
        this->HasErrors = true;
        return;
    }

    Instruction.mnemonic = ZYDIS_MNEMONIC_JMP;
    Instruction.machine_mode = ZYDIS_MACHINE_MODE_LEGACY_32;
    Instruction.operand_count = 1;

    Operand->type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
    Operand->imm.s = Displacement;

    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&Instruction, &InstructionBuffer, &InstructionLength))) {
        this->HasErrors = true;
        return;
    }

    this->InstructionLength = InstructionLength;
    this->EncodedBuffer.insert(this->EncodedBuffer.end(), std::begin(InstructionBuffer), std::begin(InstructionBuffer) + InstructionLength);
}

void AssemblyBuilder::Call64(ZyanU64 Address) {
    // call qword ptr [rip+0] 0xffffffffffffffff
    ZydisEncoderRequest Instruction = {};
    ZydisEncoderOperand* Operand = &Instruction.operands[0];
    ZyanU8 PointerBuffer[sizeof(ZyanU64)] = { 0 };
    ZyanU8 InstructionBuffer[ZYDIS_MAX_INSTRUCTION_LENGTH] = { 0 };
    ZyanUSize InstructionLength = ZYDIS_MAX_INSTRUCTION_LENGTH;
    std::vector<ZyanU8> Buffer = {};

    Instruction.mnemonic = ZYDIS_MNEMONIC_CALL;
    Instruction.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    Instruction.operand_count = 1;

    Operand->type = ZYDIS_OPERAND_TYPE_MEMORY;
    Operand->mem.base = ZYDIS_REGISTER_RIP;
    Operand->mem.displacement = 0x00000002U; // 0x2 bytes after the <jmp rel8> instructions
    Operand->mem.size = sizeof(ZyanU64);

    memcpy(PointerBuffer, &Address, sizeof(PointerBuffer));

    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&Instruction, &InstructionBuffer, &InstructionLength))) {
        this->HasErrors = true;
        return;
    }

    Buffer.insert(Buffer.end(), std::begin(InstructionBuffer), std::begin(InstructionBuffer) + InstructionLength);

    InstructionLength = ZYDIS_MAX_INSTRUCTION_LENGTH;

    memset(&Instruction, 0, sizeof(Instruction));
    memset(InstructionBuffer, 0, sizeof(InstructionBuffer));

    Instruction.mnemonic = ZYDIS_MNEMONIC_JMP;
    Instruction.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    Instruction.operand_size_hint = ZYDIS_OPERAND_SIZE_HINT_8;
    Instruction.operand_count = 1;

    Operand->type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
    // 0x08 bytes after the <call qword ptr [rip+0x02], jmp rel8> instructions
    // this jumps the invalid bytes due to write the absolute address in code page
    Operand->imm.s = 0x08;

    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&Instruction, &InstructionBuffer, &InstructionLength))) {
        this->HasErrors = true;
        return;
    }

    Buffer.insert(Buffer.end(), std::begin(InstructionBuffer), std::begin(InstructionBuffer) + InstructionLength);
    Buffer.insert(Buffer.end(), std::begin(PointerBuffer), std::end(PointerBuffer));

    this->InstructionLength = static_cast<ZyanU64>(Buffer.size()) * sizeof(ZyanU8);
    this->EncodedBuffer.insert(this->EncodedBuffer.end(), Buffer.begin(), Buffer.end());
}

void AssemblyBuilder::Call32(ZyanU64 Address) {
    ZydisEncoderRequest Instruction = {};
    ZydisEncoderOperand* Operand = &Instruction.operands[0];
    ZyanU64 SourceAddress = this->GetBaseAddress() + this->Size();
    ZyanI64 Displacement = Difference(Address, SourceAddress + 5); // Target - (Source + SizeOfCall)
    ZyanU8 InstructionBuffer[ZYDIS_MAX_INSTRUCTION_LENGTH] = { 0 };
    ZyanUSize InstructionLength = ZYDIS_MAX_INSTRUCTION_LENGTH;

    /* Check if is bigger than 2^31 - 1 or lower than -2^31 to not overflow the signed int32 value */
    if ((0x7fffffffLL < Displacement) || (Displacement < -0x80000000LL)) {
        this->HasErrors = true;
        return;
    }

    Instruction.mnemonic = ZYDIS_MNEMONIC_CALL;
    Instruction.machine_mode = ZYDIS_MACHINE_MODE_LEGACY_32;
    Instruction.operand_count = 1;

    Operand->type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
    Operand->imm.s = Displacement;

    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&Instruction, &InstructionBuffer, &InstructionLength))) {
        this->HasErrors = true;
        return;
    }

    this->InstructionLength = InstructionLength;
    this->EncodedBuffer.insert(this->EncodedBuffer.end(), std::begin(InstructionBuffer), std::begin(InstructionBuffer) + InstructionLength);
}

void AssemblyBuilder::Nop(ZyanU64 SizeOfBlock) {
    // Intel SDM Vol. 2B "Recommended Multi-Byte Sequence of NOP Instruction"
    static const ZyanU8 Nops[9][9] =
    {
        { 0x90 },
        { 0x66, 0x90 },
        { 0x0F, 0x1F, 0x00 },
        { 0x0F, 0x1F, 0x40, 0x00 },
        { 0x0F, 0x1F, 0x44, 0x00, 0x00 },
        { 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 },
        { 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 },
        { 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 },
    };

    ZyanU64 Length = SizeOfBlock;

    while (Length)
    {
        ZyanU64 NopSize = (Length > 9) ? 9 : Length;

        this->EncodedBuffer.insert(
            this->EncodedBuffer.end(), 
            std::begin(Nops[NopSize - 1]), 
            std::begin(Nops[NopSize - 1]) + NopSize);

        Length -= NopSize;
    }

    this->InstructionLength = SizeOfBlock;
}

void AssemblyBuilder::Encode(ZydisEncoderRequest* Instruction) {
    ZyanUSize InstructionLength = ZYDIS_MAX_INSTRUCTION_LENGTH;
    ZyanU8 InstructionBuffer[ZYDIS_MAX_INSTRUCTION_LENGTH] = { 0 };

    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(Instruction, InstructionBuffer, &InstructionLength))) {
        this->HasErrors = true;
        return;
    }

    this->InstructionLength = InstructionLength;
    this->EncodedBuffer.insert(this->EncodedBuffer.end(), std::begin(InstructionBuffer), std::begin(InstructionBuffer) + InstructionLength);
}

void AssemblyBuilder::Reencode(ZydisDecoded* Decoded) {
    ZydisEncoderRequest Encoder = {};

    /* Translate the decoded instruction to an encoder request with his operands */
    if (ZYAN_FAILED(ZydisEncoderDecodedInstructionToEncoderRequest(
        &Decoded->Instruction,
        Decoded->Operands,
        Decoded->Instruction.operand_count_visible,
        &Encoder)))
    {
        this->HasErrors = true;
        return;
    }

    this->Encode(&Encoder);
}

ZyanU64 AssemblyBuilder::GetBaseAddress() const {
    return this->BaseAddress;
}

ZyanU64 AssemblyBuilder::Offset() {
    if (this->Size() > 0) {
        return this->Size() - 1;
    }

    return 0;
}

ZyanU64 AssemblyBuilder::LastInstructionLength() const {
    return this->InstructionLength;
}

ZyanU64 AssemblyBuilder::Size() {
    return static_cast<ZyanU64>(this->EncodedBuffer.size()) * sizeof(ZyanU8);
}

ZyanBool AssemblyBuilder::CopyTo(void* Address, ZyanU64 SizeOfBuffer) {
    if (this->Size() > SizeOfBuffer) {
        return false;
    }

    memcpy(Address, this->EncodedBuffer.data(), this->EncodedBuffer.size() * sizeof(ZyanU8));

    return true;
}

ZyanBool AssemblyBuilder::Failed() const {
    return this->HasErrors ? ZYAN_TRUE : ZYAN_FALSE;
}

ZyanBool AssemblyBuilder::Success() const {
    return this->HasErrors ? ZYAN_FALSE : ZYAN_TRUE;
}
