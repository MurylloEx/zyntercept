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

// 1. Teste de gancho �nico na transa��o (com revers�o total)
// 2. Teste de gancho duplo na transa��o (com revers�o total)
// 3. Teste de gancho duplo na transa��o (com revers�o parcial)
// 4. Teste de gancho de fun��o com loop (com revers�o total)
// 5. Teste de gancho de fun��o recursiva e reentrante (com revers�o total)
// 6. Teste de gancho de fun��o previamente enganchada (gancho sobre gancho)
// 7. Teste de remo��o de gancho inexistente
// 8. Teste de abertura de transa��o duplicada
// 9. Teste de tentativa de anexar gancho com transa��o fechada
// 10. Teste de tentativa de remover gancho com transa��o fechada
// 11. Teste de benchmark da fun��o ZynterceptTransactionBegin
// 12. Teste de benchmark da fun��o ZynterceptAttachProcess
// 13. Teste de benchmark da fun��o ZynterceptAttach
// 14. Teste de benchmark da fun��o ZynterceptDetach
// 15. Teste de benchmark da fun��o ZynterceptTransactionCommit
