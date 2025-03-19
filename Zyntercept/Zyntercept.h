#ifndef ZYNTERCEPT_H
#define ZYNTERCEPT_H

#if defined(__cplusplus)
#define ROUTINE(Routine) &(void*&)Original##Routine
#define INTERCEPTION(Routine) &Intercept##Routine
#define TRAMPOLINE(Routine) static decltype(Routine)* Original##Routine = Routine
#endif

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
bool ZynterceptTransactionAbandon();
bool ZynterceptAttachProcess(ZynterceptProcess* Process);
bool ZynterceptAttach(void** TargetRoutine, void* InterceptionRoutine);
bool ZynterceptDetach(void** TargetRoutine);

#endif // ZYNTERCEPT_H
