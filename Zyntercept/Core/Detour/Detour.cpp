#include <Zyntercept/Core/Detour/Detour.h>
#include <Zyntercept/Core/Allocator/Allocator.h>
#include <Zyntercept/Core/Trampoline/Trampoline.h>
#include <Zyntercept/Core/Assembler/Assembler.h>
#include <Zyntercept/Core/Disassembler/Disassembler.h>

/* Size of <jmp rel32> instruction */
#define ZYNTERCEPT_SIZE_OF_DETOUR_JUMP 5
#define ZYNTERCEPT_SIZE_OF_DETOUR_EXECUTABLE_BLOCK_64BIT 0x100
#define ZYNTERCEPT_SIZE_OF_DETOUR_EXECUTABLE_BLOCK_32BIT 0x80

ZyanBool __zyntercept_cdecl ZynterceptDetourFunction64(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier,
	__zyntercept_in ZyanU64 TargetFunction,
	__zyntercept_in ZyanU64 HookedFunction,
	__zyntercept_out ZyanU64* TrampolineFunction,
	__zyntercept_out ZyanU8** OriginalPrologue,
	__zyntercept_out ZyanU64* OriginalPrologueSize)
{
	std::vector<ZyanU8> PayloadBuffer = {};

	ZydisMachineMode MachineMode = ZYDIS_MACHINE_MODE_LONG_64;
	ZydisStackWidth StackWidth = ZYDIS_STACK_WIDTH_64;

	ZyanU8 PrologueBuffer[64] = { 0 };
	ZyanU8 RelayBuffer[64] = { 0 };
	ZyanU8 TrampolineBuffer[192] = { 0 };

	ZyanU64 NumberOfFoundInstructions = 0;
	ZyanUSize SizeOfFoundInstructions = 0;

	ZynterceptPagedMemory Page = { 0 };
	ZynterceptPagedMemoryOperation Request = { 0 };

	Request.Address = TargetFunction;
	Request.Buffer = PrologueBuffer;
	Request.Size = sizeof(PrologueBuffer);

	if (!ZynterceptReadMemory(ProcessIdentifier, &Request))
	{
		return ZYAN_FALSE;
	}

	ZyanU64 SizeOfDecodedInstructions = SizeOfDecodedDesiredInstructions(
		MachineMode,
		StackWidth,
		PrologueBuffer,
		sizeof(PrologueBuffer),
		ZYNTERCEPT_SIZE_OF_DETOUR_JUMP);

	if (!SizeOfDecodedInstructions)
	{
		return ZYAN_FALSE;
	}

	ZydisDecoded* ReplaceableInstructions = (ZydisDecoded*)malloc(SizeOfDecodedInstructions);

	if (!ReplaceableInstructions)
	{
		return ZYAN_FALSE;
	}

	if (!FindReplaceableInstructions(
		MachineMode,
		StackWidth,
		PrologueBuffer,
		sizeof(PrologueBuffer),
		ZYNTERCEPT_SIZE_OF_DETOUR_JUMP,
		SizeOfDecodedInstructions,
		ReplaceableInstructions,
		&NumberOfFoundInstructions,
		&SizeOfFoundInstructions))
	{
		free(ReplaceableInstructions);
		return ZYAN_FALSE;
	}

	if (HasFunctionBranchDestinationsBetween(
		ProcessIdentifier,
		MachineMode,
		StackWidth,
		TargetFunction,
		TargetFunction + 1,
		TargetFunction + SizeOfFoundInstructions))
	{
		free(ReplaceableInstructions);
		return ZYAN_FALSE;
	}

	ZyanU64 NearPageAddress = ZynterceptAllocateNearestAddress(
		ProcessIdentifier,
		TargetFunction,
		ZYNTERCEPT_SIZE_OF_DETOUR_EXECUTABLE_BLOCK_64BIT,
		ZYNTERCEPT_PAGE_STATE_RESERVED | ZYNTERCEPT_PAGE_STATE_COMMITTED,
		ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_WRITE);

	if (!NearPageAddress)
	{
		free(ReplaceableInstructions);
		return ZYAN_FALSE;
	}

	ZyanU64 TrampolineAddress = NearPageAddress;
	ZyanU64 RelayAddress = NearPageAddress + 192;

	std::shared_ptr<AssemblyBuilder> PrologueBuilder = std::make_shared<AssemblyBuilder>(TargetFunction);
	std::shared_ptr<AssemblyBuilder> RelayBuilder = std::make_shared<AssemblyBuilder>(RelayAddress);

	PrologueBuilder->Jmp32(RelayAddress);
	RelayBuilder->Jmp64(HookedFunction);

	if (!ZynterceptCompileTrampoline64(
		TargetFunction,
		TrampolineAddress,
		TrampolineBuffer,
		sizeof(TrampolineBuffer),
		ReplaceableInstructions,
		NumberOfFoundInstructions))
	{
		goto FAILURE;
	}

	if (PrologueBuilder->Failed() || RelayBuilder->Failed())
	{
		goto FAILURE;
	}

	if (SizeOfFoundInstructions > PrologueBuilder->Size())
	{
		PrologueBuilder->Nop(SizeOfFoundInstructions - PrologueBuilder->Size());
	}

	if (sizeof(RelayBuffer) > RelayBuilder->Size())
	{
		RelayBuilder->Nop(sizeof(RelayBuffer) - RelayBuilder->Size());
	}

	if (!PrologueBuilder->CopyTo(PrologueBuffer, sizeof(PrologueBuffer)) ||
		!RelayBuilder->CopyTo(RelayBuffer, sizeof(RelayBuffer)))
	{
		goto FAILURE;
	}

	Page.Address = TargetFunction;
	Page.Size = SizeOfFoundInstructions;
	Page.Protection = ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_WRITE;
	Page.State = 0;

	/* Turn the code page non-immutable from RX to RW */
	if (!ZynterceptProtectMemory(ProcessIdentifier, &Page))
	{
		goto FAILURE;
	}

	Request.Address = TargetFunction;
	Request.Buffer = PrologueBuffer;
	Request.Size = SizeOfFoundInstructions;

	/* Overwrite the prologue of function */
	if (!ZynterceptWriteMemory(ProcessIdentifier, &Request))
	{
		goto FAILURE;
	}

	/* Turn the code page back from RW to RX immutable */
	if (!ZynterceptProtectMemory(ProcessIdentifier, &Page))
	{
		goto FAILURE;
	}

	PayloadBuffer.insert(PayloadBuffer.end(), std::begin(TrampolineBuffer), std::begin(TrampolineBuffer) + sizeof(TrampolineBuffer));
	PayloadBuffer.insert(PayloadBuffer.end(), std::begin(RelayBuffer), std::begin(RelayBuffer) + sizeof(RelayBuffer));

	Request.Address = TrampolineAddress;
	Request.Buffer = PayloadBuffer.data();
	Request.Size = PayloadBuffer.size() * sizeof(ZyanU8);

	if (!ZynterceptWriteMemory(ProcessIdentifier, &Request))
	{
		goto FAILURE;
	}

	Page.Address = NearPageAddress;
	Page.Size = ZYNTERCEPT_SIZE_OF_DETOUR_EXECUTABLE_BLOCK_64BIT;
	Page.Protection = ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_EXECUTE;
	Page.State = 0;

	if (!ZynterceptProtectMemory(ProcessIdentifier, &Page))
	{
		goto FAILURE;
	}

	*TrampolineFunction = TrampolineAddress;

	return ZYAN_TRUE;

FAILURE:
	Page.Address = NearPageAddress;
	Page.Size = 0;
	Page.State = 0;
	Page.Protection = 0;

	free(ReplaceableInstructions);
	ZynterceptReleaseMemory(ProcessIdentifier, &Page);

	return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptDetourFunction32(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier,
	__zyntercept_in ZyanU64 TargetFunction,
	__zyntercept_in ZyanU64 HookedFunction,
	__zyntercept_out ZyanU64* TrampolineFunction,
	__zyntercept_out ZyanU8** OriginalPrologue,
	__zyntercept_out ZyanU64* OriginalPrologueSize)
{
	std::vector<ZyanU8> PayloadBuffer = {};

	ZydisMachineMode MachineMode = ZYDIS_MACHINE_MODE_LEGACY_32;
	ZydisStackWidth StackWidth = ZYDIS_STACK_WIDTH_32;

	ZyanU8 PrologueBuffer[64] = { 0 };
	ZyanU8 TrampolineBuffer[128] = { 0 };

	ZyanU64 NumberOfFoundInstructions = 0;
	ZyanUSize SizeOfFoundInstructions = 0;

	ZynterceptPagedMemory Page = { 0 };
	ZynterceptPagedMemoryOperation Request = { 0 };

	Request.Address = TargetFunction;
	Request.Buffer = PrologueBuffer;
	Request.Size = sizeof(PrologueBuffer);

	if (!ZynterceptReadMemory(ProcessIdentifier, &Request))
	{
		return ZYAN_FALSE;
	}

	ZyanU64 SizeOfDecodedInstructions = SizeOfDecodedDesiredInstructions(
		MachineMode,
		StackWidth,
		PrologueBuffer,
		sizeof(PrologueBuffer),
		ZYNTERCEPT_SIZE_OF_DETOUR_JUMP);

	if (!SizeOfDecodedInstructions)
	{
		return ZYAN_FALSE;
	}

	ZydisDecoded* ReplaceableInstructions = (ZydisDecoded*)malloc(SizeOfDecodedInstructions);

	if (!ReplaceableInstructions)
	{
		return ZYAN_FALSE;
	}

	if (!FindReplaceableInstructions(
		MachineMode,
		StackWidth,
		PrologueBuffer,
		sizeof(PrologueBuffer),
		ZYNTERCEPT_SIZE_OF_DETOUR_JUMP,
		SizeOfDecodedInstructions,
		ReplaceableInstructions,
		&NumberOfFoundInstructions,
		&SizeOfFoundInstructions))
	{
		free(ReplaceableInstructions);
		return ZYAN_FALSE;
	}

	if (HasFunctionBranchDestinationsBetween(
		ProcessIdentifier,
		MachineMode,
		StackWidth,
		TargetFunction,
		TargetFunction + 1,
		TargetFunction + SizeOfFoundInstructions))
	{
		free(ReplaceableInstructions);
		return ZYAN_FALSE;
	}

	ZyanU64 NearPageAddress = ZynterceptAllocateNearestAddress(
		ProcessIdentifier,
		TargetFunction,
		ZYNTERCEPT_SIZE_OF_DETOUR_EXECUTABLE_BLOCK_32BIT,
		ZYNTERCEPT_PAGE_STATE_RESERVED | ZYNTERCEPT_PAGE_STATE_COMMITTED,
		ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_WRITE);

	if (!NearPageAddress)
	{
		free(ReplaceableInstructions);
		return ZYAN_FALSE;
	}

	ZyanU64 TrampolineAddress = NearPageAddress;

	std::shared_ptr<AssemblyBuilder> PrologueBuilder = std::make_shared<AssemblyBuilder>(TargetFunction);

	PrologueBuilder->Jmp32(HookedFunction);

	if (!ZynterceptCompileTrampoline32(
		TargetFunction,
		TrampolineAddress,
		TrampolineBuffer,
		sizeof(TrampolineBuffer),
		ReplaceableInstructions,
		NumberOfFoundInstructions))
	{
		goto FAILURE;
	}

	if (PrologueBuilder->Failed())
	{
		goto FAILURE;
	}

	if (SizeOfFoundInstructions > PrologueBuilder->Size())
	{
		PrologueBuilder->Nop(SizeOfFoundInstructions - PrologueBuilder->Size());
	}

	if (!PrologueBuilder->CopyTo(PrologueBuffer, sizeof(PrologueBuffer)))
	{
		goto FAILURE;
	}

	Page.Address = TargetFunction;
	Page.Size = SizeOfFoundInstructions;
	Page.Protection = ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_WRITE;
	Page.State = 0;

	/* Turn the code page non-immutable from RX to RW */
	if (!ZynterceptProtectMemory(ProcessIdentifier, &Page))
	{
		goto FAILURE;
	}

	Request.Address = TargetFunction;
	Request.Buffer = PrologueBuffer;
	Request.Size = SizeOfFoundInstructions;

	if (!ZynterceptWriteMemory(ProcessIdentifier, &Request))
	{
		goto FAILURE;
	}

	/* Turn the code page back from RW to RX immutable */
	if (!ZynterceptProtectMemory(ProcessIdentifier, &Page))
	{
		goto FAILURE;
	}

	PayloadBuffer.insert(PayloadBuffer.end(), std::begin(TrampolineBuffer), std::begin(TrampolineBuffer) + sizeof(TrampolineBuffer));

	Request.Address = TrampolineAddress;
	Request.Buffer = PayloadBuffer.data();
	Request.Size = PayloadBuffer.size() * sizeof(ZyanU8);

	if (!ZynterceptWriteMemory(ProcessIdentifier, &Request))
	{
		goto FAILURE;
	}

	Page.Address = NearPageAddress;
	Page.Size = ZYNTERCEPT_SIZE_OF_DETOUR_EXECUTABLE_BLOCK_32BIT;
	Page.Protection = ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_EXECUTE;
	Page.State = 0;

	if (!ZynterceptProtectMemory(ProcessIdentifier, &Page))
	{
		goto FAILURE;
	}

	*TrampolineFunction = TrampolineAddress;

FAILURE:
	Page.Address = NearPageAddress;
	Page.Size = 0;
	Page.State = 0;
	Page.Protection = 0;

	free(ReplaceableInstructions);
	ZynterceptReleaseMemory(ProcessIdentifier, &Page);

	return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptRevertDetourFunction64(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier,
	__zyntercept_in ZyanU64 TargetFunction,
	__zyntercept_in ZyanU64 TrampolineFunction,
	__zyntercept_in ZyanU8* OriginalPrologue,
	__zyntercept_in ZyanU64 OriginalPrologueSize)
{
	ZynterceptPagedMemoryOperation Operations[1] = { 0 };

	Operations[0].Address = TargetFunction;
	Operations[0].Buffer = OriginalPrologue;
	Operations[0].Size = OriginalPrologueSize;

	if (!ZynterceptAtomicWriteMemory(ProcessIdentifier, Operations, 1)) {
		return ZYAN_FALSE;
	}

	ZynterceptPagedMemory TrampolinePage = { 0 };

	TrampolinePage.Address = TrampolineFunction;
	TrampolinePage.Size = ZYNTERCEPT_SIZE_OF_DETOUR_EXECUTABLE_BLOCK_64BIT;

	if (!ZynterceptReleaseMemory(ProcessIdentifier, &TrampolinePage)) {
		return ZYAN_FALSE;
	}

	return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptRevertDetourFunction32(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier,
	__zyntercept_in ZyanU64 TargetFunction,
	__zyntercept_in ZyanU64 TrampolineFunction,
	__zyntercept_in ZyanU8* OriginalPrologue,
	__zyntercept_in ZyanU64 OriginalPrologueSize)
{
	ZynterceptPagedMemoryOperation Operations[1] = { 0 };

	Operations[0].Address = TargetFunction;
	Operations[0].Buffer = OriginalPrologue;
	Operations[0].Size = OriginalPrologueSize;

	if (!ZynterceptAtomicWriteMemory(ProcessIdentifier, Operations, 1)) {
		return ZYAN_FALSE;
	}

	ZynterceptPagedMemory TrampolinePage = { 0 };

	TrampolinePage.Address = TrampolineFunction;
	TrampolinePage.Size = ZYNTERCEPT_SIZE_OF_DETOUR_EXECUTABLE_BLOCK_32BIT;

	if (!ZynterceptReleaseMemory(ProcessIdentifier, &TrampolinePage)) {
		return ZYAN_FALSE;
	}

	return ZYAN_TRUE;
}
