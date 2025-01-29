#include <Windows.h>
#include <Zyntercept/Zyntercept.h>
#include <Zyntercept/Core/Syscall/Syscall.h>
#include <catch2/catch_test_macros.hpp>

TRAMPOLINE(IsMenu);
TRAMPOLINE(IsZoomed);
TRAMPOLINE(IsWindow);

BOOL WINAPI InterceptIsMenu(HMENU hMenu) {
    return TRUE;
}

BOOL WINAPI InterceptIsWindow(HWND hWnd) {
    return TRUE;
}

BOOL WINAPI InterceptIsZoomed(HWND hWnd) {
    return TRUE;
}

TEST_CASE("Should hook IsMenu, IsWindow and IsZoomed functions", "[zyntercept]")
{
    ZynterceptProcess Process = { 0 };

    Process.Identifier = GetCurrentProcess();
    Process.Architecture = ZynterceptIs64BitProcess(Process.Identifier)
        ? ZYNTERCEPT_ARCHITECTURE_64BIT 
        : ZYNTERCEPT_ARCHITECTURE_32BIT;

    ZynterceptTransactionBegin();
    ZynterceptAttachProcess(&Process);
    ZynterceptAttach(ROUTINE(IsMenu), INTERCEPTION(IsMenu));
    ZynterceptAttach(ROUTINE(IsWindow), INTERCEPTION(IsWindow));
    ZynterceptAttach(ROUTINE(IsZoomed), INTERCEPTION(IsZoomed));
    ZynterceptTransactionCommit();

    REQUIRE(IsMenu((HMENU)0xFFFFFFFF) == TRUE);
    REQUIRE(IsWindow((HWND)0xFFFFFFFF) == TRUE);
    REQUIRE(IsZoomed((HWND)0xFFFFFFFF) == TRUE);

    ZynterceptTransactionBegin();
    ZynterceptAttachProcess(&Process);
    ZynterceptDetach(ROUTINE(IsMenu));
    ZynterceptDetach(ROUTINE(IsWindow));
    ZynterceptDetach(ROUTINE(IsZoomed));
    ZynterceptTransactionCommit();

    REQUIRE(IsMenu((HMENU)0xFFFFFFFF) == FALSE);
    REQUIRE(IsWindow((HWND)0xFFFFFFFF) == FALSE);
    REQUIRE(IsZoomed((HWND)0xFFFFFFFF) == FALSE);
}
