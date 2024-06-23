#ifndef ZYNTERCEPT_H
#define ZYNTERCEPT_H

typedef void* ZynterceptHandle;

typedef enum ZynterceptArchitecture_ {
	ZYNTERCEPT_ARCHITECTURE_32BIT,
	ZYNTERCEPT_ARCHITECTURE_64BIT,
} ZynterceptArchitecture;

typedef struct ZynterceptProcess_ {
	ZynterceptHandle Identifier;
	ZynterceptArchitecture Architecture;
} ZynterceptProcess;

bool ZynterceptTransactionBegin();
bool ZynterceptTransactionCommit();
bool ZynterceptAttachProcess(ZynterceptProcess* Process);
bool ZynterceptAttach(void** TargetRoutine, void* InterceptionRoutine);
bool ZynterceptDetach(void** TargetRoutine);

#endif // ZYNTERCEPT_H
