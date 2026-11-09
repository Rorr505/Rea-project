// espscan.m - dylib สแกนไบนารีของเกมทีเดียวจบ (images, symbol, native wrapper bytes, string, pattern)
// มีเมนูลอยบนหน้าจอ: สแกนทั้งหมด / เลือกหลายรายการหรือทั้งหมด / บันทึก / แชร์
// อ่านอย่างเดียว ไม่แก้หน่วยความจำของเกม
//
// build:
// xcrun -sdk iphoneos clang -arch arm64 -dynamiclib -fobjc-arc -miphoneos-version-min=14.0 -O2 \
//   -framework UIKit -framework Foundation -framework CoreGraphics -Wno-deprecated-declarations \
//   -o espscan.dylib espscan.m -install_name @executable_path/Frameworks/espscan.dylib

#import <UIKit/UIKit.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#define MAX_DUMP_SYMS 3000   // จำนวน symbol สูงสุดที่ดัมพ์ไบต์ (เดิม 60)
#define MAX_DUMP_LEN  1024   // ไบต์สูงสุดต่อ symbol (เดิม 400)
#define MAX_HITS 300000   // เพดานของโหมดสแกนปกติ/ค้นหา (เดิม 20000 ทำให้ล็อก "allsyms" ถูกตัดก่อนถึง scrWrapped_ ของ native) — ถ้าจะเอาทุกอย่างใช้ปุ่ม "แยกหมวด"

static FILE *L;

// คีย์เวิร์ดที่ผู้ใช้พิมพ์เอง (คั่นด้วยเว้นวรรค/คอมมา/ขึ้นบรรทัดใหม่) ไม่สนตัวพิมพ์เล็กใหญ่
#define MAX_UKW 32
static char g_ukw[MAX_UKW][64];
static int  g_ukw_n = 0;
static int  g_search_mode = 0;   // 1 = โหมดค้นหาเอง (ว่าง = แสดงทุก symbol)

static void set_user_keywords(NSString *text) {
    g_ukw_n = 0;
    NSCharacterSet *sep = [NSCharacterSet characterSetWithCharactersInString:@" ,;\n\t"];
    for (NSString *w in [text.lowercaseString componentsSeparatedByCharactersInSet:sep]) {
        if (!w.length || g_ukw_n >= MAX_UKW) continue;
        strlcpy(g_ukw[g_ukw_n++], w.UTF8String, sizeof g_ukw[0]);
    }
}

static const char *KW[] = {
    "scripthook", "posthook", "metalshade", "menyoo", "nativeinvo", "native_invoke",
    "nativehandler", "registerscript", "scriptregister", "get_screen_coord",
    "world_to_screen", "worldtoscreen", "draw_rect", "get_game_pool", "macportshv", NULL
};

// native ที่ ESP ต้องใช้: ตำแหน่งผู้เล่น/เอนทิตี, พูล ped กับ vehicle, สถานะ, วาดและแปลงพิกัด
static const char *NATIVE_KW[] = {
    "get_player_ped", "player_ped_id", "get_entity_coord", "get_entity_health",
    "is_ped_dead", "is_entity_dead", "is_entity_a_ped", "is_entity_a_vehicle",
    "nearby_ped", "nearby_vehicle", "get_gameplay_cam", "get_entity_model",
    "get_vehicle_ped_is_in", "draw_rect", "screen_coord_from_world", "get_ped_bone",
    "is_entity_on_screen", "get_distance_between", "get_entity_type",
    "get_entity_bone", "transformworldtoscreen", "get_entity_speed",
    "get_display_name", "get_random_ped", "get_closest", "ped_bone_coords", NULL
};

static int ci_contains(const char *hay, size_t n, const char *needle) {
    size_t m = strlen(needle);
    if (m == 0 || n < m) return 0;
    for (size_t i = 0; i + m <= n; i++) {
        size_t j = 0;
        while (j < m && tolower((unsigned char)hay[i + j]) == needle[j]) j++;
        if (j == m) return 1;
    }
    return 0;
}
static int matches_kw(const char *s, size_t n) {
    if (g_search_mode) {
        if (g_ukw_n == 0) return 1;   // ไม่ใส่คีย์เวิร์ด = เอาทั้งหมด
        for (int k = 0; k < g_ukw_n; k++) if (ci_contains(s, n, g_ukw[k])) return 1;
        return 0;
    }
    for (int k = 0; KW[k]; k++) if (ci_contains(s, n, KW[k])) return 1;
    return 0;
}
static int matches_native_kw(const char *s, size_t n) {
    for (int k = 0; NATIVE_KW[k]; k++) if (ci_contains(s, n, NATIVE_KW[k])) return 1;
    return 0;
}
static void san(char *out, const char *in, size_t n, size_t max) {
    size_t i = 0;
    for (; i < n && i < max; i++) { unsigned char c = in[i]; out[i] = (c >= 32 && c < 127) ? c : '?'; }
    out[i] = 0;
}

static NSString *docs_dir(void) {
    return NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
}

static void list_images(void) {
    fprintf(L, "\n== โหลดอิมเมจ ==\n");
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (strstr(name, "/usr/lib/") || strstr(name, "/System/")) continue;
        fprintf(L, "[%u] slide=0x%lx %s\n", i, (long)_dyld_get_image_vmaddr_slide(i), name);
    }
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

static void dump_symbols(const struct mach_header_64 *mh, intptr_t slide) {
    const struct load_command *lc = (const void *)(mh + 1);
    const struct symtab_command *st = NULL;
    const struct segment_command_64 *link = NULL;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_SYMTAB) st = (const void *)lc;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sc = (const void *)lc;
            if (!strcmp(sc->segname, "__LINKEDIT")) link = sc;
        }
        lc = (const void *)((const char *)lc + lc->cmdsize);
    }
    fprintf(L, "\n== สัญลักษณ์ที่ตรงคีย์เวิร์ดทั่วไป (แสดง address) ==\n");
    if (!st || !link) { fprintf(L, "ไม่มี symtab\n"); return; }
    uintptr_t base = link->vmaddr + slide - link->fileoff;
    const struct nlist_64 *nl = (const void *)(base + st->symoff);
    const char *strs = (const char *)(base + st->stroff);

    int hits = 0;
    for (uint32_t i = 0; i < st->nsyms && hits < MAX_HITS; i++) {
        if (nl[i].n_un.n_strx == 0 || (nl[i].n_type & N_STAB)) continue;
        const char *nm = strs + nl[i].n_un.n_strx;
        size_t n = strnlen(nm, 2048);
        if (matches_kw(nm, n)) {
            fprintf(L, "0x%llx  %s\n", (unsigned long long)nl[i].n_value, nm);
            hits++;
        }
    }
    fprintf(L, "(รวม %u สัญลักษณ์, ตรงคีย์เวิร์ดทั่วไป %d)\n", st->nsyms, hits);

    if (g_search_mode) return;   // โหมดค้นหา: แสดงเฉพาะรายชื่อ ไม่ดัมพ์ไบต์
    // ---- ดัมพ์ไบต์ของ symbol ที่เป็น native wrapper (scrWrapped_ + ชื่อ native ที่ ESP ต้องใช้) ----
    fprintf(L, "\n== ดัมพ์ไบต์ของ native wrapper ที่ ESP ต้องใช้ ==\n");
    // เก็บ address ของทุก symbol ใน section แล้วเรียง เพื่อหา "symbol ถัดไป" ด้วย binary search
    uint64_t *addrs = malloc(sizeof(uint64_t) * (st->nsyms ? st->nsyms : 1));
    uint32_t na = 0;
    for (uint32_t j = 0; j < st->nsyms; j++) {
        if (nl[j].n_un.n_strx == 0 || (nl[j].n_type & N_STAB) || (nl[j].n_type & N_TYPE) != N_SECT) continue;
        addrs[na++] = nl[j].n_value;
    }
    qsort(addrs, na, sizeof(uint64_t), cmp_u64);

    int dumped = 0;
    for (uint32_t i = 0; i < st->nsyms && dumped < MAX_DUMP_SYMS; i++) {
        if (nl[i].n_un.n_strx == 0 || (nl[i].n_type & N_STAB) || (nl[i].n_type & N_TYPE) != N_SECT) continue;
        const char *nm = strs + nl[i].n_un.n_strx;
        size_t n = strnlen(nm, 2048);
        int is_wrapper = ci_contains(nm, n, "scrwrapped_");
        int is_macport = ci_contains(nm, n, "macportshv");
        int is_w2s = ci_contains(nm, n, "transformworldtoscreen");
        if (!(is_macport || is_w2s || (is_wrapper && matches_native_kw(nm, n)))) continue;

        uint64_t a = nl[i].n_value;
        // หา address ของ symbol ถัดไปทั้งหมด เพื่อจำกัดความยาวไม่ให้ทับฟังก์ชันอื่น
        uint64_t next = 0;
        uint32_t lo = 0, hi = na;
        while (lo < hi) { uint32_t mid = (lo + hi) / 2; if (addrs[mid] > a) hi = mid; else lo = mid + 1; }
        if (lo < na) next = addrs[lo];
        uint64_t len = next ? (next - a) : 256;
        if (len > MAX_DUMP_LEN) len = MAX_DUMP_LEN;
        if (len < 4) continue;

        fprintf(L, "-- %s @0x%llx len=%llu --\n", nm, (unsigned long long)a, (unsigned long long)len);
        const uint8_t *p = (const uint8_t *)(a + slide);
        for (uint64_t o = 0; o < len; o += 16) {
            fprintf(L, "0x%llx:", (unsigned long long)(a + o));
            for (uint64_t k = 0; k < 16 && o + k < len; k++) fprintf(L, " %02x", p[o + k]);
            fputc('\n', L);
        }
        dumped++;
    }
    free(addrs);
    fprintf(L, "(ดัมพ์ไบต์ไป %d symbol)\n", dumped);
}

static void dump_strings(const struct mach_header_64 *mh, intptr_t slide) {
    fprintf(L, "\n== สตริงใน __cstring ที่ตรงคีย์เวิร์ด ==\n");
    const struct load_command *lc = (const void *)(mh + 1);
    int hits = 0;
    char tmp[130];
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sc = (const void *)lc;
            const struct section_64 *sec = (const void *)(sc + 1);
            for (uint32_t s = 0; s < sc->nsects; s++, sec++) {
                if (strcmp(sec->sectname, "__cstring")) continue;
                const char *p = (const char *)(sec->addr + slide);
                size_t off = 0;
                while (off < sec->size && hits < MAX_HITS) {
                    size_t n = strnlen(p + off, sec->size - off);
                    if (n > 3 && matches_kw(p + off, n)) {
                        san(tmp, p + off, n, 120);
                        fprintf(L, "0x%llx  \"%s\"\n", (unsigned long long)(sec->addr + off), tmp);
                        hits++;
                    }
                    off += n + 1;
                }
            }
        }
        lc = (const void *)((const char *)lc + lc->cmdsize);
    }
    fprintf(L, "(ตรง %d)\n", hits);
}

// Documents/patterns.txt  รูปแบบ:  ชื่อ=1F 20 03 D5 ?? ?? ?? ??
static int parse_pat(const char *s, int *bytes, int max) {
    int n = 0;
    while (*s && n < max) {
        while (*s == ' ') s++;
        if (!*s || *s == '\n' || *s == '\r') break;
        if (s[0] == '?') { bytes[n++] = -1; while (*s && *s != ' ') s++; continue; }
        char h[3] = { s[0], s[1], 0 };
        bytes[n++] = (int)strtol(h, NULL, 16);
        s += 2;
    }
    return n;
}

static void scan_patterns(const struct mach_header_64 *mh, intptr_t slide) {
    NSString *path = [docs_dir() stringByAppendingPathComponent:@"patterns.txt"];
    fprintf(L, "\n== สแกนแพตเทิร์น ==\n");
    FILE *f = fopen(path.UTF8String, "r");
    if (!f) { fprintf(L, "ไม่พบ Documents/patterns.txt ข้าม\n"); return; }
    char line[512];
    while (fgets(line, sizeof line, f)) {
        char *eq = strchr(line, '=');
        if (!eq || line[0] == '#') continue;
        *eq = 0;
        int pat[128];
        int pn = parse_pat(eq + 1, pat, 128);
        if (pn == 0) continue;
        fprintf(L, "%s:", line);
        int found = 0;
        const struct load_command *lc = (const void *)(mh + 1);
        for (uint32_t i = 0; i < mh->ncmds && found < 20; i++) {
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *sc = (const void *)lc;
                const struct section_64 *sec = (const void *)(sc + 1);
                for (uint32_t s = 0; s < sc->nsects; s++, sec++) {
                    if (strcmp(sec->segname, "__TEXT") || strcmp(sec->sectname, "__text")) continue;
                    const uint8_t *b = (const uint8_t *)(sec->addr + slide);
                    for (uint64_t o = 0; o + pn <= sec->size && found < 20; o += 4) {
                        int ok = 1;
                        for (int k = 0; k < pn; k++)
                            if (pat[k] >= 0 && b[o + k] != pat[k]) { ok = 0; break; }
                        if (ok) { fprintf(L, " 0x%llx", (unsigned long long)(sec->addr + o)); found++; }
                    }
                }
            }
            lc = (const void *)((const char *)lc + lc->cmdsize);
        }
        fprintf(L, found ? "\n" : " ไม่พบ\n");
    }
    fclose(f);
}

static NSString *run_scan(void) {
    char *buf = NULL; size_t size = 0;
    L = open_memstream(&buf, &size);
    if (!L) return @"เปิด memstream ไม่ได้";
    const struct mach_header_64 *mh = (const void *)_dyld_get_image_header(0);
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);
    fprintf(L, "espscan\nmain=%s\nheader=%p slide=0x%lx\n", _dyld_get_image_name(0), (const void *)mh, (long)slide);
    fprintf(L, "address ที่แสดงเป็นค่าก่อนบวก slide (ตรงกับที่เห็นใน Ghidra/Hopper)\n");
    list_images();
    dump_symbols(mh, slide);
    dump_strings(mh, slide);
    if (!g_search_mode) scan_patterns(mh, slide);
    fprintf(L, "\nเสร็จแล้ว\n");
    fclose(L); L = NULL;
    NSString *s = [[NSString alloc] initWithBytes:buf length:size encoding:NSUTF8StringEncoding];
    if (!s) s = [[NSString alloc] initWithBytes:buf length:size encoding:NSISOLatin1StringEncoding];
    free(buf);
    return s ?: @"";
}

static NSString *run_search(void) {
    g_search_mode = 1;
    NSString *r = run_scan();
    g_search_mode = 0;
    return r;
}

// ---------------- สแกนแยกหมวดหมู่ (ทุก symbol + native + สตริง) ----------------
// จัดหมวดด้วยชื่อ (heuristic) ทุก symbol ในไบนารีหลักแบบไม่ตัดจำนวน แล้วแยกเป็นหมวด
// NATIVE · xxx  = scrWrapped_<ชื่อ>::Call (ชื่อ native ตรงๆ ใช้ค้นหาใน Tweak ได้เลย)
// SYMBOL · xxx  = ฟังก์ชัน/คลาสอื่นของเกม     STRING · xxx = สตริงใน __cstring
// ใส่คีย์เวิร์ดในช่อง (หลายคำได้) = กรองเฉพาะที่ตรง, ว่าง = เอาทั้งหมด
typedef struct { const char *cat; const char *k[24]; } CatRule;
#define NR(a) (sizeof(a) / sizeof((a)[0]))

// ลำดับสำคัญ: กฎแรกที่ตรงชนะ (needle เป็นตัวพิมพ์เล็กเสมอ)
static const CatRule kNatRules[] = {
    { "NETWORK",   { "network", "net_", "participant", "script_host", "session", "lobby", "voice_chat", NULL } },
    { "ANIMATION", { "anim", "scenario", "_clip", NULL } },
    { "TASK-AI",   { "task_", "_task", "combat", "flee", "sequence", "navmesh", "waypoint_rec", NULL } },
    { "WEAPON",    { "weapon", "ammo", "bullet", "melee", "projectile", NULL } },
    { "VEHICLE",   { "vehicle", "_car_", "heli", "plane", "boat", "train", "trailer", "cargobob", NULL } },
    { "PLAYER",    { "player", "wanted", "stamina", "special_ability", "crime", NULL } },
    { "PED",       { "ped_", "_ped", "relationship", "group", "decision_maker", NULL } },
    { "ENTITY-OBJECT", { "entity", "object", "pickup", "door", "prop", "rope", "attach", NULL } },
    { "CAMERA",    { "cam_", "_cam", "cam_rot", "gameplay_cam", "render_script_cams", "cinematic", NULL } },
    { "GRAPHICS-DRAW", { "draw_", "graphics", "screen", "scaleform", "ptfx", "_fx", "light", "timecycle", "shader", "txd", "texture", "mirror", NULL } },
    { "AUDIO",     { "audio", "sound", "music", "radio", "speech", "voice", "ambient", "scene_", NULL } },
    { "STREAMING-MODEL", { "model", "stream", "request_", "ipl", "cutscene", "load_", NULL } },
    { "HUD-MAP-UI", { "hud", "blip", "map_", "_map", "text", "display", "minimap", "feed", "message", "print", "help", "menu", "ui_", NULL } },
    { "WORLD-ENV", { "weather", "clock", "time_", "water", "ground", "collision", "world", "zone", "interior", "road", "path", "pop_", "density", "fire", "explosion", "shapetest", "raycast", "wind", "rain", NULL } },
    { "STATS-PROGRESS", { "stat_", "money", "achievement", "profile", "social", "cash", "unlock", NULL } },
    { "SCRIPT-SYSTEM", { "script", "thread", "wait", "timer", "time_scale", "cheat", "bit", "global", "shutdown", NULL } },
    { "MATH-UTIL", { "vdist", "vmag", "sqrt", "sin", "cos", "tan", "abs", "round", "floor", "ceil", "to_float", "to_int", "hash", "string", "shift_", "random", "distance", NULL } },
};
static const CatRule kSymRules[] = {
    { "C++ STD/RUNTIME", { "__znst", "__zst", "__znks", "znst3", "libcpp", "cxxabi", NULL } },
    { "MEMORY-ALLOC",    { "_znwm", "_znam", "_zdlpv", "_zdapv", "heap", "alloc", "memory", "malloc", NULL } },
    { "NETWORK-ONLINE",  { "network", "netplayer", "netgame", "netobject", "netarray", "nethttp", "nettransport", "netconnection", "net", "msgscript", NULL } },
    { "SCRIPT-NATIVE",   { "scrthread", "scrprogram", "scrvalue", "scrinfo", "scripthandler", "script", "native", "scrwrapped_", NULL } },
    { "AUDIO",           { "audio", "audsound", "audentit", "audengine", "audmix", "audcategor", "sound", "music", "radio", "speech", "ambient", NULL } },
    { "PHYSICS",         { "physics", "phinst", "phbound", "phlevel", "phsim", "phcollider", "phmaterial", "fraginst", "fragment", "cloth", "verlet", "ragdoll", NULL } },
    { "ANIMATION",       { "anim", "crskel", "crclip", "crframe", "crik", "skeleton", "expression", "motiontree", NULL } },
    { "TASK-AI",         { "ctask", "task", "aitask", "behavio", "combat", "brain", NULL } },
    { "WEAPON-EXPLOSION", { "cweapon", "weapon", "ammo", "cprojectile", "explosion", "firingpattern", NULL } },
    { "VEHICLE",         { "cvehicle", "vehicle", "cautomobile", "cbike", "cheli", "cplane", "cboat", "ctrain", "handling", NULL } },
    { "PLAYER-WANTED",   { "cplayer", "playerinfo", "wanted", "crime", NULL } },
    { "PED",             { "cped", "pedmodel", "pedfactory", "pedinventory", "pedweapon", "pedintell", "pedcomp", "pedvariation", NULL } },
    { "CAMERA",          { "camera", "camcore", "camdirector", "gameplaycam", "camframe", "camfollow", "camcinematic", NULL } },
    { "WORLD-MAP",       { "cworld", "interior", "pathfind", "navmesh", "fwmap", "cobject", "cbuilding", "cdoor", "scenario", "population", "weather", "clock", "water", "timecycle", NULL } },
    { "STREAMING-MODEL", { "streaming", "cutscene", "fwarch", "archetype", "modelinfo", "rpf", "drawable", "txd", NULL } },
    { "GRAPHICS-RENDER", { "grc", "render", "shader", "metal", "texture", "vertex", "scaleform", "particle", "ptfx", "d3d", "dxgi", NULL } },
    { "UI-HUD-TEXT",     { "chud", "hud", "ctext", "cmenu", "pausemenu", "uiscreen", NULL } },
    { "CHEAT-DEBUG",     { "ccheat", "cheat", "debug", "diag", "assert", NULL } },
    { "RAGE UTIL/MATH",  { "rage2at", "atarray", "atmap", "atstring", "athash", "atorder", "atfixed", "atbinary", "atreferencecounter", "vector", "vec3", "matrix", "quaternion", "mat34", "mat44", NULL } },
    { "SYSTEM-IO-THREAD", { "sys", "thread", "mutex", "semaphore", "filedevice", "fidevice", "device", "rline", "socialclub", NULL } },
    { "OBJC-SWIFT-APPLE", { "objc", "_$s", "-[", "+[", NULL } },
};

static const char *classify(const CatRule *r, size_t nr, const char *s, size_t n, const char *def) {
    for (size_t i = 0; i < nr; i++)
        for (int j = 0; r[i].k[j]; j++)
            if (ci_contains(s, n, r[i].k[j])) return r[i].cat;
    return def;
}
static int matches_user(const char *s, size_t n) {
    if (g_ukw_n == 0) return 1;
    for (int k = 0; k < g_ukw_n; k++) if (ci_contains(s, n, g_ukw[k])) return 1;
    return 0;
}
static int cat_rank(NSString *k) { return [k hasPrefix:@"NATIVE"] ? 0 : [k hasPrefix:@"SYMBOL"] ? 1 : [k hasPrefix:@"STRING"] ? 2 : 3; }

#define MAX_CAT_STRINGS 40000
static NSString *run_categorized(void) {
    const struct mach_header_64 *mh = (const void *)_dyld_get_image_header(0);
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);
    const struct load_command *lc = (const void *)(mh + 1);
    const struct symtab_command *st = NULL; const struct segment_command_64 *link = NULL;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_SYMTAB) st = (const void *)lc;
        if (lc->cmd == LC_SEGMENT_64 && !strcmp(((const struct segment_command_64 *)lc)->segname, "__LINKEDIT")) link = (const void *)lc;
        lc = (const void *)((const char *)lc + lc->cmdsize);
    }
    if (!st || !link) return @"ไม่มี symtab";
    uintptr_t base = link->vmaddr + slide - link->fileoff;
    const struct nlist_64 *nl = (const void *)(base + st->symoff);
    const char *strs = (const char *)(base + st->stroff);

    NSMutableDictionary<NSString *, NSMutableArray<NSString *> *> *cats = [NSMutableDictionary new];
    uint32_t nNat = 0, nSym = 0, nStr = 0;
    for (uint32_t i = 0; i < st->nsyms; i++) {
        if (nl[i].n_un.n_strx == 0 || (nl[i].n_type & N_STAB)) continue;
        const char *nm = strs + nl[i].n_un.n_strx;
        size_t n = strnlen(nm, 2048);
        BOOL undef = (nl[i].n_type & N_TYPE) == N_UNDF;
        NSString *key, *line;
        const char *w = strstr(nm, "scrWrapped_"), *e = w ? strstr(w + 11, "4CallE") : NULL;
        if (w && e && e > w + 11 && !undef) {
            size_t ln = (size_t)(e - (w + 11));
            if (!matches_user(w + 11, ln)) continue;
            char nat[160]; size_t m = ln < 159 ? ln : 159; memcpy(nat, w + 11, m); nat[m] = 0;
            key = [NSString stringWithFormat:@"NATIVE · %s", classify(kNatRules, NR(kNatRules), nat, m, "OTHER")];
            line = [NSString stringWithFormat:@"%s  @0x%llx", nat, (unsigned long long)nl[i].n_value];
            nNat++;
        } else {
            if (!matches_user(nm, n)) continue;
            if (undef) { key = @"SYMBOL · IMPORT (ไลบรารีภายนอก)"; line = [NSString stringWithUTF8String:nm] ?: @"?"; }
            else {
                key = [NSString stringWithFormat:@"SYMBOL · %s", classify(kSymRules, NR(kSymRules), nm, n, "OTHER")];
                line = [NSString stringWithFormat:@"%s  @0x%llx", nm, (unsigned long long)nl[i].n_value];
            }
            nSym++;
        }
        NSMutableArray *a = cats[key]; if (!a) { a = [NSMutableArray new]; cats[key] = a; }
        [a addObject:line];
    }
    // ---- สตริง ----
    lc = (const void *)(mh + 1);
    char tmp[130];
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sc = (const void *)lc;
            const struct section_64 *sec = (const void *)(sc + 1);
            for (uint32_t s = 0; s < sc->nsects; s++, sec++) {
                if (strcmp(sec->sectname, "__cstring")) continue;
                const char *p = (const char *)(sec->addr + slide);
                size_t off = 0;
                while (off < sec->size && nStr < MAX_CAT_STRINGS) {
                    size_t n = strnlen(p + off, sec->size - off);
                    if (n >= 6 && matches_user(p + off, n)) {
                        san(tmp, p + off, n, 120);
                        NSString *key = [NSString stringWithFormat:@"STRING · %s", classify(kSymRules, NR(kSymRules), p + off, n, "OTHER")];
                        NSMutableArray *a = cats[key]; if (!a) { a = [NSMutableArray new]; cats[key] = a; }
                        [a addObject:[NSString stringWithFormat:@"\"%s\"  @0x%llx", tmp, (unsigned long long)(sec->addr + off)]];
                        nStr++;
                    }
                    off += n + 1;
                }
            }
        }
        lc = (const void *)((const char *)lc + lc->cmdsize);
    }
    NSArray *keys = [cats.allKeys sortedArrayUsingComparator:^NSComparisonResult(NSString *x, NSString *y) {
        int rx = cat_rank(x), ry = cat_rank(y);
        return rx != ry ? (rx < ry ? NSOrderedAscending : NSOrderedDescending) : [x compare:y];
    }];
    NSMutableString *out = [NSMutableString new];
    [out appendFormat:@"สรุป: native %u | symbol %u | string %u%@ | %lu หมวด  (แตะหัวหมวดเพื่อเลือกทั้งหมวด)\n",
        nNat, nSym, nStr, nStr >= MAX_CAT_STRINGS ? @" (ตัดที่เพดาน)" : @"", (unsigned long)keys.count];
    [out appendFormat:@"main=%s slide=0x%lx (address เป็นค่าก่อนบวก slide)\n", _dyld_get_image_name(0), (long)slide];
    for (NSString *k in keys) {
        NSMutableArray *a = cats[k];
        [a sortUsingSelector:@selector(compare:)];
        [out appendFormat:@"== %@ (%lu) ==\n", k, (unsigned long)a.count];
        [out appendString:[a componentsJoinedByString:@"\n"]];
        [out appendString:@"\n"];
    }
    return out;
}

// ---------------- UI ----------------

static NSArray<NSString *> *g_lines;   // ผลสแกน แยกเป็นบรรทัด (แต่ละบรรทัดคือ 1 รายการ)
static NSString *g_tag = @"scan";

@interface EspUI : NSObject <UITableViewDataSource, UITableViewDelegate, UITextFieldDelegate>
@property (nonatomic, strong) UIWindow *win;
@property (nonatomic, strong) UIButton *fab;
@property (nonatomic, strong) UIButton *allBtn;
@property (nonatomic, strong) UIView *panel;
@property (nonatomic, strong) UITableView *table;
@property (nonatomic, strong) UILabel *status;
@property (nonatomic, strong) UITextField *kwField;
@property (nonatomic, strong) NSMutableIndexSet *sel;
+ (instancetype)shared;
- (void)installIn:(UIWindow *)w;
@end

@implementation EspUI

+ (instancetype)shared {
    static EspUI *i; static dispatch_once_t t;
    dispatch_once(&t, ^{ i = [EspUI new]; });
    return i;
}

- (UIButton *)btn:(NSString *)title sel:(SEL)sel frame:(CGRect)f {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.frame = f;
    [b setTitle:title forState:UIControlStateNormal];
    [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont systemFontOfSize:13];
    b.titleLabel.adjustsFontSizeToFitWidth = YES;
    b.titleLabel.minimumScaleFactor = 0.6;
    b.backgroundColor = [UIColor colorWithWhite:0.25 alpha:1];
    b.layer.cornerRadius = 8;
    [b addTarget:self action:sel forControlEvents:UIControlEventTouchUpInside];
    return b;
}

- (void)installIn:(UIWindow *)w {
    if (self.win) return;
    self.win = w;
    self.sel = [NSMutableIndexSet new];
    g_lines = @[];

    self.fab = [UIButton buttonWithType:UIButtonTypeSystem];
    self.fab.frame = CGRectMake(20, w.safeAreaInsets.top + 60, 48, 48);
    self.fab.backgroundColor = [UIColor colorWithRed:0 green:0.6 blue:1 alpha:0.85];
    self.fab.layer.cornerRadius = 24;
    [self.fab setTitle:@"ESP" forState:UIControlStateNormal];
    [self.fab setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    self.fab.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    [self.fab addTarget:self action:@selector(toggle) forControlEvents:UIControlEventTouchUpInside];
    [self.fab addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(pan:)]];
    [w addSubview:self.fab];

    CGRect b = w.bounds;
    CGFloat pw = MIN(b.size.width - 20, 460);
    CGFloat ph = MIN(b.size.height - 40, b.size.height * 0.7);
    self.panel = [[UIView alloc] initWithFrame:CGRectMake((b.size.width - pw) / 2, w.safeAreaInsets.top + 10, pw, ph)];
    self.panel.backgroundColor = [UIColor colorWithWhite:0 alpha:0.88];
    self.panel.layer.cornerRadius = 14;
    self.panel.hidden = YES;

    CGFloat bw = (pw - 16 - 6 * 6) / 7;
    NSArray *titles = @[@"สแกนทั้งหมด", @"ค้นหา", @"แยกหมวด", @"เลือกทั้งหมด", @"บันทึก", @"แชร์", @"ปิด"];
    SEL sels[] = { @selector(doScanAll), @selector(doSearch), @selector(doCategorize), @selector(toggleAll), @selector(doSave), @selector(doShare), @selector(toggle) };
    for (int i = 0; i < 7; i++) {
        UIButton *bt = [self btn:titles[i] sel:sels[i] frame:CGRectMake(8 + i * (bw + 6), 8, bw, 36)];
        if (i == 3) self.allBtn = bt;
        [self.panel addSubview:bt];
    }

    self.kwField = [[UITextField alloc] initWithFrame:CGRectMake(8, 50, pw - 16, 32)];
    self.kwField.backgroundColor = [UIColor colorWithWhite:0.18 alpha:1];
    self.kwField.textColor = UIColor.whiteColor;
    self.kwField.font = [UIFont systemFontOfSize:13];
    self.kwField.layer.cornerRadius = 8;
    self.kwField.autocorrectionType = UITextAutocorrectionTypeNo;
    self.kwField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    self.kwField.returnKeyType = UIReturnKeySearch;
    self.kwField.clearButtonMode = UITextFieldViewModeWhileEditing;
    self.kwField.delegate = self;
    self.kwField.attributedPlaceholder = [[NSAttributedString alloc]
        initWithString:@" คีย์เวิร์ด เช่น ped health coord (เว้นวรรคได้หลายคำ / ว่าง = ทุก symbol)"
            attributes:@{NSForegroundColorAttributeName: UIColor.grayColor}];
    [self.panel addSubview:self.kwField];

    self.status = [[UILabel alloc] initWithFrame:CGRectMake(8, 86, pw - 16, 18)];
    self.status.font = [UIFont systemFontOfSize:11];
    self.status.textColor = UIColor.lightGrayColor;
    self.status.text = @"กด สแกน เพื่อเริ่ม";
    [self.panel addSubview:self.status];

    self.table = [[UITableView alloc] initWithFrame:CGRectMake(8, 108, pw - 16, ph - 116) style:UITableViewStylePlain];
    self.table.backgroundColor = [UIColor colorWithWhite:0.08 alpha:1];
    self.table.layer.cornerRadius = 8;
    self.table.dataSource = self;
    self.table.delegate = self;
    self.table.rowHeight = UITableViewAutomaticDimension;
    self.table.estimatedRowHeight = 18;
    self.table.separatorStyle = UITableViewCellSeparatorStyleNone;
    [self.table registerClass:UITableViewCell.class forCellReuseIdentifier:@"c"];
    [self.panel addSubview:self.table];

    [w addSubview:self.panel];
}

// ---- ตาราง ----
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return g_lines.count; }

- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:@"c" forIndexPath:ip];
    NSString *s = g_lines[ip.row];
    c.backgroundColor = UIColor.clearColor;
    c.selectionStyle = UITableViewCellSelectionStyleNone;
    c.textLabel.numberOfLines = 0;
    c.textLabel.font = [UIFont fontWithName:@"Menlo" size:10] ?: [UIFont systemFontOfSize:10];
    c.textLabel.text = s;
    c.textLabel.textColor = [s hasPrefix:@"=="] ? [UIColor colorWithRed:1 green:0.85 blue:0.3 alpha:1]
                                                : [UIColor colorWithRed:0.6 green:1 blue:0.6 alpha:1];
    c.accessoryType = [self.sel containsIndex:ip.row] ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
    return c;
}

- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    if ([g_lines[ip.row] hasPrefix:@"== "]) {          // แตะหัวหมวด = เลือก/ยกเลิกทั้งหมวด
        NSUInteger a = ip.row + 1, b = a;
        while (b < g_lines.count && ![g_lines[b] hasPrefix:@"== "]) b++;
        BOOL all = b > a;
        for (NSUInteger i = a; i < b && all; i++) if (![self.sel containsIndex:i]) all = NO;
        if (b > a) { if (all) [self.sel removeIndexesInRange:NSMakeRange(a, b - a)]; else [self.sel addIndexesInRange:NSMakeRange(a, b - a)]; }
        if (![self.sel containsIndex:ip.row]) [self.sel addIndex:ip.row]; else if (all) [self.sel removeIndex:ip.row];
        [tv reloadData]; [self updateStatus]; return;
    }
    if ([self.sel containsIndex:ip.row]) [self.sel removeIndex:ip.row]; else [self.sel addIndex:ip.row];
    [tv reloadRowsAtIndexPaths:@[ip] withRowAnimation:UITableViewRowAnimationNone];
    [self updateStatus];
}

- (void)updateStatus {
    self.status.text = [NSString stringWithFormat:@"เลือก %lu / %lu รายการ",
                        (unsigned long)self.sel.count, (unsigned long)g_lines.count];
    [self.allBtn setTitle:(g_lines.count && self.sel.count == g_lines.count) ? @"ยกเลิกเลือก" : @"เลือกทั้งหมด"
                 forState:UIControlStateNormal];
}

// ---- ปุ่ม ----
- (void)pan:(UIPanGestureRecognizer *)g {
    CGPoint t = [g translationInView:self.win];
    g.view.center = CGPointMake(g.view.center.x + t.x, g.view.center.y + t.y);
    [g setTranslation:CGPointMake(0, 0) inView:self.win];
}

- (void)toggle {
    self.panel.hidden = !self.panel.hidden;
    [self.win bringSubviewToFront:self.panel];
    [self.win bringSubviewToFront:self.fab];
}

- (void)toggleAll {
    if (!g_lines.count) return;
    if (self.sel.count == g_lines.count) [self.sel removeAllIndexes];
    else [self.sel addIndexesInRange:NSMakeRange(0, g_lines.count)];
    [self.table reloadData];
    [self updateStatus];
}

- (void)runJob:(NSString *(*)(void))fn tag:(NSString *)tag {
    self.status.text = @"กำลังทำงาน...";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *r = fn();
        NSMutableArray *a = [NSMutableArray new];
        NSCharacterSet *ws = NSCharacterSet.whitespaceCharacterSet;
        for (NSString *l in [r componentsSeparatedByString:@"\n"])
            if ([l stringByTrimmingCharactersInSet:ws].length) [a addObject:l];
        dispatch_async(dispatch_get_main_queue(), ^{
            g_lines = a;
            g_tag = tag;
            [self.sel removeAllIndexes];
            [self.table reloadData];
            [self updateStatus];
        });
    });
}

- (void)doScanAll { [self.kwField resignFirstResponder]; [self runJob:run_scan tag:@"scanall"]; }

- (void)doSearch {
    [self.kwField resignFirstResponder];
    set_user_keywords(self.kwField.text ?: @"");
    [self runJob:run_search tag:g_ukw_n ? @"search" : @"allsyms"];
}

- (void)doCategorize {
    [self.kwField resignFirstResponder];
    set_user_keywords(self.kwField.text ?: @"");
    [self runJob:run_categorized tag:g_ukw_n ? @"cat_filtered" : @"cat_all"];
}

- (BOOL)textFieldShouldReturn:(UITextField *)tf { [self doSearch]; return YES; }

// บันทึกเฉพาะรายการที่เลือก (เรียงตามลำดับเดิม)
- (NSString *)writeLog {
    if (!g_lines.count) { self.status.text = @"ยังไม่ได้สแกน"; return nil; }
    if (!self.sel.count) { self.status.text = @"ยังไม่ได้เลือกรายการ (กด เลือกทั้งหมด หรือแตะทีละบรรทัด)"; return nil; }
    NSMutableString *out = [NSMutableString new];
    [self.sel enumerateIndexesUsingBlock:^(NSUInteger i, BOOL *stop) {
        if (i < g_lines.count) [out appendFormat:@"%@\n", g_lines[i]];
    }];
    NSDateFormatter *df = [NSDateFormatter new];
    df.dateFormat = @"yyyyMMdd_HHmmss";
    NSString *name = [NSString stringWithFormat:@"espscan_%@_%@_%lu.log", g_tag,
                      [df stringFromDate:NSDate.date], (unsigned long)self.sel.count];
    NSString *p = [docs_dir() stringByAppendingPathComponent:name];
    NSError *e = nil;
    if ([out writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:&e]) {
        self.status.text = [NSString stringWithFormat:@"บันทึก %lu รายการ: Documents/%@",
                            (unsigned long)self.sel.count, name];
        return p;
    }
    self.status.text = [@"บันทึกไม่สำเร็จ: " stringByAppendingString:e.localizedDescription ?: @"?"];
    return nil;
}

- (void)doSave { [self writeLog]; }

- (void)doShare {
    NSString *p = [self writeLog];
    if (!p) return;
    UIViewController *top = self.win.rootViewController;
    while (top.presentedViewController) top = top.presentedViewController;
    if (!top) { self.status.text = @"ไม่พบหน้าจอสำหรับแชร์ (ไฟล์ถูกบันทึกแล้ว)"; return; }
    UIActivityViewController *vc =
        [[UIActivityViewController alloc] initWithActivityItems:@[[NSURL fileURLWithPath:p]] applicationActivities:nil];
    vc.popoverPresentationController.sourceView = self.panel;
    [top presentViewController:vc animated:YES completion:nil];
}

@end

static UIWindow *find_window(void) {
    for (UIScene *sc in UIApplication.sharedApplication.connectedScenes) {
        if (![sc isKindOfClass:UIWindowScene.class]) continue;
        UIWindowScene *ws = (UIWindowScene *)sc;
        for (UIWindow *w in ws.windows) if (w.isKeyWindow) return w;
        if (ws.windows.firstObject) return ws.windows.firstObject;
    }
    return UIApplication.sharedApplication.windows.firstObject;
}

static void try_install(int n) {
    UIWindow *w = find_window();
    if (w) { [[EspUI shared] installIn:w]; return; }
    if (n < 60)
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{ try_install(n + 1); });
}

__attribute__((constructor)) static void espscan_init(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{ try_install(0); });
    });
}
