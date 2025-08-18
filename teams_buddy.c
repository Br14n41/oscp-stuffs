// keep_teams_available.c
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>

static int  MIN_SECONDS = 45;     // lower bound between actions
static int  MAX_SECONDS = 120;    // upper bound between actions
static int  IDLE_THRESHOLD = 60;  // only act if idle >= this many seconds
static int  MOUSE_JIGGLE_PCT = 10; // 0–100; rarity of mouse micro-jiggle

static volatile BOOL g_running = TRUE;

BOOL WINAPI ConsoleHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_CLOSE_EVENT) {
        g_running = FALSE;
        return TRUE;
    }
    return FALSE;
}

static unsigned int urand(void) {
    // Simple high-resolution seed mixed with rand(); fine for jitter
    LARGE_INTEGER qpc; QueryPerformanceCounter(&qpc);
    srand((unsigned)(qpc.QuadPart ^ GetTickCount()));
    return ((unsigned)rand() << 16) ^ (unsigned)rand();
}

static int rand_range(int lo, int hi_inclusive) {
    if (hi_inclusive <= lo) return lo;
    unsigned r = urand();
    return lo + (int)(r % (unsigned)(hi_inclusive - lo + 1));
}

static DWORD get_idle_seconds(void) {
    LASTINPUTINFO lii = {0};
    lii.cbSize = sizeof(lii);
    if (!GetLastInputInfo(&lii)) return 0;
    DWORD now = GetTickCount();
    return (now - lii.dwTime) / 1000;
}

static int icompare(const char* a, const char* b) {
    for (; *a && *b; a++, b++) {
        int da = tolower((unsigned char)*a);
        int db = tolower((unsigned char)*b);
        if (da != db) return da - db;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

static BOOL teams_is_running(void) {
    BOOL found = FALSE;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            const char *exe = pe.szExeFile;
            if (!exe) continue;
            if (icompare(exe, "Teams.exe") == 0 || icompare(exe, "ms-teams.exe") == 0) {
                found = TRUE; break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static void send_key_toggle(WORD vk) {
    // Press + release twice so the lock state ends unchanged
    INPUT in[4] = {0};
    for (int j = 0; j < 2; ++j) {
        in[2*j].type = INPUT_KEYBOARD;
        in[2*j].ki.wVk = vk;
        in[2*j].ki.dwFlags = 0;
        in[2*j+1].type = INPUT_KEYBOARD;
        in[2*j+1].ki.wVk = vk;
        in[2*j+1].ki.dwFlags = KEYEVENTF_KEYUP;
    }
    SendInput(4, in, sizeof(INPUT));
}

static void micro_mouse_jiggle(void) {
    INPUT in[2] = {0};
    in[0].type = INPUT_MOUSE;
    in[0].mi.dwFlags = MOUSEEVENTF_MOVE;
    in[0].mi.dx = 1; // +1 px
    in[1].type = INPUT_MOUSE;
    in[1].mi.dwFlags = MOUSEEVENTF_MOVE;
    in[1].mi.dx = -1; // back
    SendInput(2, in, sizeof(INPUT));
}

static void do_random_action(void) {
    int roll = rand_range(1, 100);
    if (roll <= MOUSE_JIGGLE_PCT) {
        micro_mouse_jiggle();
        return;
    }
    switch (rand_range(0, 2)) {
        case 0: send_key_toggle(VK_NUMLOCK); break;
        case 1: send_key_toggle(VK_SCROLL);  break;
        case 2: send_key_toggle(VK_CAPITAL); break;
    }
}

int main(int argc, char** argv) {
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    // Optional: adjust via args: keep_teams_available.exe 30 90 45 5
    if (argc >= 2) MIN_SECONDS     = max(10, atoi(argv[1]));
    if (argc >= 3) MAX_SECONDS     = max(MIN_SECONDS, atoi(argv[2]));
    if (argc >= 4) IDLE_THRESHOLD  = max(10, atoi(argv[3]));
    if (argc >= 5) MOUSE_JIGGLE_PCT = min(100, max(0, atoi(argv[4])));

    printf("Running... idle>=%ds, interval %d–%ds (+/- jitter), jiggle %d%%.\n",
           IDLE_THRESHOLD, MIN_SECONDS, MAX_SECONDS, MOUSE_JIGGLE_PCT);
    printf("Press Ctrl+C to stop.\n");

    while (g_running) {
        int base = rand_range(MIN_SECONDS, MAX_SECONDS);
        int jitter = rand_range(-10, 10); // +/- up to 10s
        int delay = base + jitter;
        if (delay < 10) delay = 10;
        for (int i = 0; g_running && i < delay; ++i) Sleep(1000);

        if (!g_running) break;
        if (!teams_is_running()) continue;

        if (get_idle_seconds() >= (DWORD)IDLE_THRESHOLD) {
            do_random_action();
        }
    }
    return 0;
}
