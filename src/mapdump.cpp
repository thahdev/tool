// mapdump.cpp - يحفظ نص الماب (المشفر + المفكوك) من رام لعبة LAC لملفات.
// الأوفستات RVA لنسخة com.MA.LAC 1.9.7 (64-bit) فقط. بعد أي تحديث للعبة لازم تتغير.
#include <android/log.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "dobby.h"

#define TAG "MapDump"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

// ---------------- إعدادات ----------------
#define PKG          "com.MA.LAC"
#define MIN_LEN      1000      // تجاهل النصوص القصيرة (الشات يمر من MapCrypto بعد). صغّره لو الماب صغير
#define MAX_FILES    60        // حد أقصى لعدد الأزواج المحفوظة
#define HOOK_READOBJ 0         // 1 = hook إضافي على ReadObjData

#define OFF_Decrypt  0xF5200CULL   // static string MapCrypto.Decrypt(string blob)
#define OFF_Encrypt  0xF51B78ULL   // static string MapCrypto.Encrypt(string plain)
#define OFF_ReadObj  0x10EB1D4ULL  // IEnumerator LACEditor.ReadObjData(string _data)

static const char* DIRS[] = {
    "/storage/emulated/0/Android/data/" PKG "/files/MapDump",
    "/sdcard/Android/data/" PKG "/files/MapDump",
    "/data/data/" PKG "/files/MapDump",
};
static const char* g_dir = nullptr;
static volatile int g_idx = 0;

// ---------------- مساعدات ----------------
static void mkdirs(const char* path) {
    char tmp[512]; snprintf(tmp, sizeof tmp, "%s", path);
    for (char* p = tmp + 1; *p; ++p)
        if (*p == '/') { *p = 0; mkdir(tmp, 0777); *p = '/'; }
    mkdir(tmp, 0777);
}

static size_t utf16_to_utf8(const uint16_t* s, int n, char* out) {
    size_t o = 0;
    for (int i = 0; i < n; i++) {
        uint32_t c = s[i];
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < n && s[i + 1] >= 0xDC00 && s[i + 1] < 0xE000) {
            c = 0x10000 + ((c - 0xD800) << 10) + (s[i + 1] - 0xDC00); i++;
        }
        if (c < 0x80) out[o++] = (char)c;
        else if (c < 0x800) { out[o++] = 0xC0 | (c >> 6); out[o++] = 0x80 | (c & 0x3F); }
        else if (c < 0x10000) { out[o++] = 0xE0 | (c >> 12); out[o++] = 0x80 | ((c >> 6) & 0x3F); out[o++] = 0x80 | (c & 0x3F); }
        else { out[o++] = 0xF0 | (c >> 18); out[o++] = 0x80 | ((c >> 12) & 0x3F); out[o++] = 0x80 | ((c >> 6) & 0x3F); out[o++] = 0x80 | (c & 0x3F); }
    }
    return o;
}

// Il2CppString (64-bit): length عند +0x10 ، حروف UTF-16 عند +0x14
static int il2cpp_len(void* s) { return s ? *(int*)((uintptr_t)s + 0x10) : 0; }

static void save_str(const char* tag, int idx, void* s) {
    int len = il2cpp_len(s);
    if (len <= 0 || len > 64 * 1024 * 1024 || !g_dir) return;
    const uint16_t* ch = (const uint16_t*)((uintptr_t)s + 0x14);
    char* buf = (char*)malloc((size_t)len * 4 + 1);
    if (!buf) return;
    size_t n = utf16_to_utf8(ch, len, buf);
    char path[600];
    snprintf(path, sizeof path, "%s/%s_%03d_len%d.txt", g_dir, tag, idx, len);
    if (FILE* f = fopen(path, "wb")) { fwrite(buf, 1, n, f); fclose(f); LOGI("saved %s (%zu bytes)", path, n); }
    else LOGI("fopen failed: %s", path);
    free(buf);
}

// ---------------- hooks ----------------
static void* (*old_Decrypt)(void*, void*);
static void* new_Decrypt(void* blob, void* mi) {
    void* r = old_Decrypt(blob, mi);
    if (il2cpp_len(blob) >= MIN_LEN || il2cpp_len(r) >= MIN_LEN) {
        int idx = __sync_add_and_fetch(&g_idx, 1);
        if (idx <= MAX_FILES) {
            save_str("encrypted_in", idx, blob);   // النص المشفر (blob)
            save_str("plain_out", idx, r);         // الماب المفكوك
        }
    }
    return r;
}

static void* (*old_Encrypt)(void*, void*);
static void* new_Encrypt(void* plain, void* mi) {
    if (il2cpp_len(plain) >= MIN_LEN) {
        int idx = __sync_add_and_fetch(&g_idx, 1);
        if (idx <= MAX_FILES) save_str("saved_plain", idx, plain);   // الماب لما تحفظه من المحرر
    }
    return old_Encrypt(plain, mi);
}

#if HOOK_READOBJ
static void* (*old_ReadObj)(void*, void*, void*);
static void* new_ReadObj(void* self, void* data, void* mi) {
    if (il2cpp_len(data) >= MIN_LEN) {
        int idx = __sync_add_and_fetch(&g_idx, 1);
        if (idx <= MAX_FILES) save_str("readobj", idx, data);
    }
    return old_ReadObj(self, data, mi);
}
#endif

// ---------------- تركيب الـ hooks ----------------
static uintptr_t lib_base(const char* lib) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[1024]; uintptr_t base = 0;
    while (fgets(line, sizeof line, f)) {
        if (!strstr(line, lib)) continue;
        unsigned long start = 0, off = 1;
        if (sscanf(line, "%lx-%*lx %*s %lx", &start, &off) == 2 && off == 0) { base = start; break; }
    }
    fclose(f);
    return base;
}

static void* install(void*) {
    uintptr_t base = 0;
    while (!(base = lib_base("libil2cpp.so"))) sleep(1);
    sleep(8);   // نخلي اللعبة تكمل تهيئة il2cpp

    for (const char* d : DIRS) { mkdirs(d); if (access(d, W_OK) == 0) { g_dir = d; break; } }
    LOGI("il2cpp base=%p dir=%s", (void*)base, g_dir ? g_dir : "(none!)");

    int r1 = DobbyHook((void*)(base + OFF_Decrypt), (void*)new_Decrypt, (void**)&old_Decrypt);
    int r2 = DobbyHook((void*)(base + OFF_Encrypt), (void*)new_Encrypt, (void**)&old_Encrypt);
#if HOOK_READOBJ
    int r3 = DobbyHook((void*)(base + OFF_ReadObj), (void*)new_ReadObj, (void**)&old_ReadObj);
    LOGI("hooks: Decrypt=%d Encrypt=%d ReadObj=%d", r1, r2, r3);
#else
    LOGI("hooks: Decrypt=%d Encrypt=%d", r1, r2);
#endif
    return nullptr;
}

__attribute__((constructor)) static void init() {
    pthread_t t;
    pthread_create(&t, nullptr, install, nullptr);
    pthread_detach(t);
}
