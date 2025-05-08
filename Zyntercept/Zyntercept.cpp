#include <Zyntercept/Zyntercept.h>
#include <Zyntercept/Core/Core.h>

#include <mutex>
#include <atomic>
#include <vector>
#include <algorithm>

struct ZynterceptInterception {
    void** TargetRoutine;
    void* OriginalRoutine;
    void* InterceptionRoutine;
    void* TrampolineRoutine;
    uint8_t* OriginalPrologue;
    uint64_t OriginalPrologueSize;
    ZynterceptProcess Process;

    bool operator==(const ZynterceptInterception& Value) const 	{
        return Value.TargetRoutine == TargetRoutine &&
            Value.OriginalRoutine == OriginalRoutine &&
            Value.InterceptionRoutine == InterceptionRoutine;
    }
};

static std::vector<ZynterceptInterception> QueueOfAttachedRoutines = {};
static std::vector<ZynterceptInterception> QueueOfRoutinesToAttach = {};
static std::vector<ZynterceptInterception> QueueOfRoutinesToDetach = {};

static std::mutex TransactionMutex;
static std::atomic<bool> TransactionIsOpen(false);
static ZynterceptProcess TransactionCurrentProcess = { 0 };

bool ZynterceptTransactionBegin() {
    // Lock the transaction objects
    std::lock_guard<std::mutex> Guard(TransactionMutex);

    if (TransactionIsOpen) {
        return false;
    }

    TransactionIsOpen = true;

    return true;
}

bool ZynterceptTransactionCommit() {
    // Lock the transaction objects
    std::lock_guard<std::mutex> Guard(TransactionMutex);

    if (!TransactionIsOpen) {
        return false;
    }

    std::vector<ZynterceptInterception> AttachedRoutines = {};
    std::vector<ZynterceptInterception> DetachedRoutines = {};

    // Attach interception routines
    for (const auto& Reference : QueueOfRoutinesToAttach) {
        ZynterceptInterception Interception = Reference;

        ZyanBool Status = ZYAN_FALSE;

        ZynterceptHandle ProcessIdentifier = Interception.Process.Identifier;
        ZyanU8* OriginalPrologue = (ZyanU8*)Interception.OriginalPrologue;
        ZyanU64 OriginalPrologueSize = (ZyanU64)Interception.OriginalPrologueSize;
        ZyanU64 OriginalFunction = (ZyanU64)Interception.OriginalRoutine;
        ZyanU64 DetourFunction = (ZyanU64)Interception.InterceptionRoutine;
        ZyanU64 TrampolineFunction = (ZyanU64)Interception.TrampolineRoutine;

        if (Interception.Process.Architecture == ZYNTERCEPT_ARCHITECTURE_64BIT) {
            Status = ZynterceptDetourFunction64(
                ProcessIdentifier,
                OriginalFunction,
                DetourFunction,
                &TrampolineFunction,
                &OriginalPrologue,
                &OriginalPrologueSize);
        }

        if (Interception.Process.Architecture == ZYNTERCEPT_ARCHITECTURE_32BIT) {
            Status = ZynterceptDetourFunction32(
                ProcessIdentifier,
                OriginalFunction,
                DetourFunction,
                &TrampolineFunction,
                &OriginalPrologue,
                &OriginalPrologueSize);
        }

        if (!Status) {
            // Stop immediately, something bad was happened
            break;
        }

        Interception.OriginalPrologue = (uint8_t*)OriginalPrologue;
        Interception.OriginalPrologueSize = (uint64_t)OriginalPrologueSize;
        Interception.OriginalRoutine = (void*)OriginalFunction;
        Interception.InterceptionRoutine = (void*)DetourFunction;
        Interception.TrampolineRoutine = (void*)TrampolineFunction;

        AttachedRoutines.push_back(Interception);
    }

    // Revert partial interception routines
    if (AttachedRoutines.size() < QueueOfRoutinesToAttach.size()) {
        // One or more transactions failed and need to be reverted back
        for (const auto& Reference : AttachedRoutines) {
            ZynterceptInterception Interception = Reference;

            ZynterceptHandle ProcessIdentifier = Interception.Process.Identifier;
            ZyanU8* OriginalPrologue = (ZyanU8*)Interception.OriginalPrologue;
            ZyanU64 OriginalPrologueSize = (ZyanU64)Interception.OriginalPrologueSize;
            ZyanU64 OriginalFunction = (ZyanU64)Interception.OriginalRoutine;
            ZyanU64 TrampolineFunction = (ZyanU64)Interception.TrampolineRoutine;

            if (Interception.Process.Architecture == ZYNTERCEPT_ARCHITECTURE_64BIT) {
                ZYNTERCEPT_UNREFERENCED(ZynterceptRevertDetourFunction64(
                    ProcessIdentifier,
                    OriginalFunction,
                    TrampolineFunction,
                    OriginalPrologue,
                    OriginalPrologueSize));
            }

            if (Interception.Process.Architecture == ZYNTERCEPT_ARCHITECTURE_32BIT) {
                ZYNTERCEPT_UNREFERENCED(ZynterceptRevertDetourFunction32(
                    ProcessIdentifier,
                    OriginalFunction,
                    TrampolineFunction,
                    OriginalPrologue,
                    OriginalPrologueSize));
            }
        }

        QueueOfRoutinesToAttach.clear();
        QueueOfRoutinesToDetach.clear();

        std::vector<ZynterceptInterception>().swap(QueueOfRoutinesToAttach);
        std::vector<ZynterceptInterception>().swap(QueueOfRoutinesToDetach);

        return false;
    }
    else {
        // Push all attached routines to queue of attached routines
        QueueOfAttachedRoutines.insert(
            QueueOfAttachedRoutines.end(), 
            AttachedRoutines.begin(), 
            AttachedRoutines.end());

        // switch the pointers
        for (const auto& Reference : AttachedRoutines) {
            *Reference.TargetRoutine = Reference.TrampolineRoutine;
        }
    }

    // Detach interception routines
    for (const auto& Reference : QueueOfRoutinesToDetach) {
        ZynterceptInterception Interception = Reference;

        ZyanBool Status = ZYAN_FALSE;

        ZynterceptHandle ProcessIdentifier = Interception.Process.Identifier;
        ZyanU8* OriginalPrologue = (ZyanU8*)Interception.OriginalPrologue;
        ZyanU64 OriginalPrologueSize = (ZyanU64)Interception.OriginalPrologueSize;
        ZyanU64 OriginalFunction = (ZyanU64)Interception.OriginalRoutine;
        ZyanU64 TrampolineFunction = (ZyanU64)Interception.TrampolineRoutine;

        if (Interception.Process.Architecture == ZYNTERCEPT_ARCHITECTURE_64BIT) {
            Status = ZynterceptRevertDetourFunction64(
                ProcessIdentifier,
                OriginalFunction,
                TrampolineFunction,
                OriginalPrologue,
                OriginalPrologueSize);
        }

        if (Interception.Process.Architecture == ZYNTERCEPT_ARCHITECTURE_32BIT) {
            Status = ZynterceptRevertDetourFunction32(
                ProcessIdentifier,
                OriginalFunction,
                TrampolineFunction,
                OriginalPrologue,
                OriginalPrologueSize);
        }

        if (!Status) {
            // Stop immediately, something bad was happened
            break;
        }

        DetachedRoutines.push_back(Interception);
    }

    if (DetachedRoutines.size() < QueueOfRoutinesToDetach.size()) {
        //One or more functions was not reversed to original routine
        for (const auto& Reference : DetachedRoutines) {
            ZynterceptInterception Interception = Reference;

            ZynterceptHandle ProcessIdentifier = Interception.Process.Identifier;
            ZyanU8* OriginalPrologue = (ZyanU8*)Interception.OriginalPrologue;
            ZyanU64 OriginalPrologueSize = (ZyanU64)Interception.OriginalPrologueSize;
            ZyanU64 OriginalFunction = (ZyanU64)Interception.OriginalRoutine;
            ZyanU64 DetourFunction = (ZyanU64)Interception.InterceptionRoutine;
            ZyanU64 TrampolineFunction = (ZyanU64)Interception.TrampolineRoutine;

            if (Interception.Process.Architecture == ZYNTERCEPT_ARCHITECTURE_64BIT) {
                ZYNTERCEPT_UNREFERENCED(ZynterceptDetourFunction64(
                    ProcessIdentifier,
                    OriginalFunction,
                    DetourFunction,
                    &TrampolineFunction,
                    &OriginalPrologue,
                    &OriginalPrologueSize));
            }

            if (Interception.Process.Architecture == ZYNTERCEPT_ARCHITECTURE_32BIT) {
                ZYNTERCEPT_UNREFERENCED(ZynterceptDetourFunction32(
                    ProcessIdentifier,
                    OriginalFunction,
                    DetourFunction,
                    &TrampolineFunction,
                    &OriginalPrologue,
                    &OriginalPrologueSize));
            }

            Interception.OriginalPrologue = (uint8_t*)OriginalPrologue;
            Interception.OriginalPrologueSize = (uint64_t)OriginalPrologueSize;
            Interception.OriginalRoutine = (void*)OriginalFunction;
            Interception.InterceptionRoutine = (void*)DetourFunction;
            Interception.TrampolineRoutine = (void*)TrampolineFunction;

            std::vector<ZynterceptInterception>::iterator Iterator = std::remove(
                QueueOfAttachedRoutines.begin(), QueueOfAttachedRoutines.end(), Reference);

            QueueOfAttachedRoutines.erase(Iterator, QueueOfAttachedRoutines.end());

            QueueOfAttachedRoutines.push_back(Interception);
        }

        QueueOfRoutinesToAttach.clear();
        QueueOfRoutinesToDetach.clear();

        std::vector<ZynterceptInterception>().swap(QueueOfRoutinesToAttach);
        std::vector<ZynterceptInterception>().swap(QueueOfRoutinesToDetach);

        return false;
    }
    else {
        for (const auto& Reference : DetachedRoutines) {
            // Switch pointers back to original routine
            *Reference.TargetRoutine = Reference.OriginalRoutine;

            std::vector<ZynterceptInterception>::iterator Iterator = std::remove(
                QueueOfAttachedRoutines.begin(), QueueOfAttachedRoutines.end(), Reference);

            QueueOfAttachedRoutines.erase(Iterator,	QueueOfAttachedRoutines.end());
        }
    }

    QueueOfRoutinesToAttach.clear();
    QueueOfRoutinesToDetach.clear();

    std::vector<ZynterceptInterception>().swap(QueueOfRoutinesToAttach);
    std::vector<ZynterceptInterception>().swap(QueueOfRoutinesToDetach);

    TransactionIsOpen = false;
    TransactionCurrentProcess = { 0 };

    return true;
}

bool ZynterceptTransactionAbandon() {
    // Lock the transaction objects
    std::lock_guard<std::mutex> Guard(TransactionMutex);

    if (!TransactionIsOpen) {
        return false;
    }

    QueueOfRoutinesToAttach.clear();
    QueueOfRoutinesToDetach.clear();

    std::vector<ZynterceptInterception>().swap(QueueOfRoutinesToAttach);
    std::vector<ZynterceptInterception>().swap(QueueOfRoutinesToDetach);

    TransactionIsOpen = false;
    TransactionCurrentProcess = { 0 };

    return true;
}

bool ZynterceptAttachProcess(ZynterceptProcess* Process) {
    // Lock the transaction objects
    std::lock_guard<std::mutex> Guard(TransactionMutex);

    if (!TransactionIsOpen) {
        return false;
    }

    if (!Process || !Process->Identifier) {
        return false;
    }

    // Update current process being patched
    TransactionCurrentProcess = *Process;

    return true;
}

bool ZynterceptAttach(void** TargetRoutine, void* InterceptionRoutine) {
    // Lock the transaction objects
    std::lock_guard<std::mutex> Guard(TransactionMutex);

    if (!TransactionIsOpen) {
        return false;
    }

    ZynterceptInterception Interception = { 0 };

    Interception.Process = TransactionCurrentProcess;
    Interception.TargetRoutine = TargetRoutine;
    Interception.OriginalRoutine = *TargetRoutine;
    Interception.InterceptionRoutine = InterceptionRoutine;

    QueueOfRoutinesToAttach.push_back(Interception);

    return true;
}

bool ZynterceptDetach(void** TargetRoutine) {
    // Lock the transaction objects
    std::lock_guard<std::mutex> Guard(TransactionMutex);

    if (!TransactionIsOpen) {
        return false;
    }

    for (const auto& Interception : QueueOfAttachedRoutines) {
        if (Interception.TargetRoutine == TargetRoutine) {
            QueueOfRoutinesToDetach.push_back(Interception);
            return true;
        }
    }

    return false;
}
