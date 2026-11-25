/* A harmless GUI-subsystem program with a resource and several imports. */
#include <windows.h>
#include <stdio.h>

static const char note[] = "Barnacle UPX inventory: 4 pallets, 9 cartons, 21 folders.\n";

int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmd, int show)
{
    char user[64];
    DWORD size = sizeof(user);
    char buf[128];
    (void)prev; (void)cmd; (void)show;
    if (!GetUserNameA(user, &size)) {
        user[0] = 0;
    }
    LoadStringA(inst, 1, buf, sizeof(buf));
    snprintf(buf, sizeof(buf), "%s%s", note, user);
    OutputDebugStringA(buf);
    return GetSystemMetrics(SM_CXSCREEN) == 0;
}
