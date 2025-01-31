#include <Zyntercept/Zyntercept.h>
#include <Zyntercept/Core/Syscall/Syscall.h>
#include <catch2/catch_test_macros.hpp>

#if defined(ZYNTERCEPT_WINDOWS)
#include <Windows.h>
static ZyanVoidPointer ProcessIdentifier = GetCurrentProcess();
#endif

#if defined(ZYNTERCEPT_UNIX)
#include <unistd.h>
static ZyanVoidPointer ProcessIdentifier = (ZyanVoidPointer)getpid();
#endif

// 1. Teste de gancho único na transação (com reversão total)
// 2. Teste de gancho duplo na transação (com reversão total)
// 3. Teste de gancho duplo na transação (com reversão parcial)
// 4. Teste de gancho de função com loop (com reversão total)
// 5. Teste de gancho de função recursiva e reentrante (com reversão total)
// 6. Teste de gancho de função previamente enganchada (gancho sobre gancho)
// 7. Teste de remoção de gancho inexistente
// 8. Teste de abertura de transação duplicada
// 9. Teste de tentativa de anexar gancho com transação fechada
// 10. Teste de tentativa de remover gancho com transação fechada
// 11. Teste de benchmark da função ZynterceptTransactionBegin
// 12. Teste de benchmark da função ZynterceptAttachProcess
// 13. Teste de benchmark da função ZynterceptAttach
// 14. Teste de benchmark da função ZynterceptDetach
// 15. Teste de benchmark da função ZynterceptTransactionCommit
