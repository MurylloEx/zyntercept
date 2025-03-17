#ifndef ZYNTERCEPT_ASSEMBLER_H
#define ZYNTERCEPT_ASSEMBLER_H

#include <Zyntercept/Core/Common/Common.h>
#include <Zyntercept/Core/Disassembler/Disassembler.h>

#include <memory>
#include <vector>

class AssemblyBuilder {

protected:
    ZyanU64 BaseAddress;
    ZyanU64 InstructionLength = 0;
    bool HasErrors = false;
    std::vector<ZyanU8> EncodedBuffer = {};

public:
    AssemblyBuilder(ZyanU64 BaseAddress);
    ~AssemblyBuilder();

    void Jcc(ZydisDecoded* Reference, ZyanU64 Address);
    void Jncc(ZydisMachineMode MachineMode, ZydisStackWidth StackWidth, ZydisDecoded* Reference, ZyanU64 Address);
    void Jmp64(ZyanU64 Address);
    void Jmp32(ZyanU64 Address);
    void Call32(ZyanU64 Address);
    void Call64(ZyanU64 Address);
    void Nop(ZyanU64 SizeOfBlock);
    void Encode(ZydisEncoderRequest* Request);
    void Reencode(ZydisDecoded* Decoded);

    ZyanU64 GetBaseAddress() const;
    ZyanU64 Offset();
    ZyanU64 LastInstructionLength() const;
    ZyanU64 Size();
    ZyanBool CopyTo(void* Address, ZyanU64 SizeOfBuffer);
    ZyanBool Failed() const;
    ZyanBool Success() const;
};

#endif // ZYNTERCEPT_ASSEMBLER_H
