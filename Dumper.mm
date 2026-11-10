#import "Dumper.h"
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#include <string.h>
#include <vector>

typedef void *P;
#define FN(r, n, ...) static r (*n)(__VA_ARGS__)

FN(P, il2cpp_domain_get);
FN(P *, il2cpp_domain_get_assemblies, P, size_t *);
FN(P, il2cpp_assembly_get_image, P);
FN(const char *, il2cpp_image_get_name, P);
FN(size_t, il2cpp_image_get_class_count, P);
FN(P, il2cpp_image_get_class, P, size_t);
FN(P, il2cpp_get_corlib);
FN(const char *, il2cpp_class_get_name, P);
FN(const char *, il2cpp_class_get_namespace, P);
FN(P, il2cpp_class_get_fields, P, void **);
FN(P, il2cpp_class_get_methods, P, void **);
FN(P, il2cpp_class_from_name, P, const char *, const char *);
FN(int, il2cpp_class_instance_size, P);
FN(const char *, il2cpp_field_get_name, P);
FN(size_t, il2cpp_field_get_offset, P);
FN(int, il2cpp_field_get_flags, P);
FN(const char *, il2cpp_method_get_name, P);
FN(uint32_t, il2cpp_method_get_flags, P, uint32_t *);
FN(P, il2cpp_resolve_icall, const char *);
FN(P, il2cpp_thread_attach, P);
FN(P, il2cpp_field_get_type, P);
FN(char *, il2cpp_type_get_name, P);
FN(void, il2cpp_free, void *);
FN(P, il2cpp_class_get_parent, P);
FN(bool, il2cpp_class_is_enum, P);
FN(bool, il2cpp_class_is_valuetype, P);

static BOOL gReady = NO;
static uintptr_t gBase = 0;
static const int kCap = 30000;   // กันผลลัพธ์ใหญ่เกิน

#define RVA(x) ((unsigned long)((uintptr_t)(x) - gBase))

static void *gHandle = RTLD_DEFAULT;   // Unity 6: UnityFramework มักถูกโหลดแบบ RTLD_LOCAL → ต้อง dlsym ผ่าน handle

static BOOL loadSyms(void) {
#define L(n) n = (decltype(n))dlsym(gHandle, #n); if (!n) return NO;
    L(il2cpp_domain_get) L(il2cpp_domain_get_assemblies) L(il2cpp_assembly_get_image)
    L(il2cpp_image_get_name) L(il2cpp_image_get_class_count) L(il2cpp_image_get_class)
    L(il2cpp_get_corlib) L(il2cpp_class_get_name) L(il2cpp_class_get_namespace)
    L(il2cpp_class_get_fields) L(il2cpp_class_get_methods) L(il2cpp_class_from_name)
    L(il2cpp_class_instance_size) L(il2cpp_field_get_name) L(il2cpp_field_get_offset)
    L(il2cpp_field_get_flags) L(il2cpp_method_get_name) L(il2cpp_method_get_flags)
    L(il2cpp_resolve_icall) L(il2cpp_thread_attach)
    L(il2cpp_field_get_type) L(il2cpp_type_get_name) L(il2cpp_free)
#define O(n) n = (decltype(n))dlsym(gHandle, #n);
    O(il2cpp_class_get_parent) O(il2cpp_class_is_enum) O(il2cpp_class_is_valuetype)
#undef O
#undef L
    return YES;
}

// MethodInfo layout ต่างกันตามเวอร์ชัน Unity:
//  ≤2021.1 : token@0x40 flags@0x44 iflags@0x46 slot@0x48
//  2021.2+ / 2022 / Unity 6 (มี virtualMethodPointer) : token@0x48 flags@0x4C iflags@0x4E slot@0x50
// หา offset จริงโดยเทียบ flags/iflags จาก il2cpp_method_get_flags กับค่าใน struct
static int gSlotOff = 0x50;
static void calibrateMethodInfo(void) {
    int v50 = 0, v48 = 0;
    P k = il2cpp_get_corlib() ? il2cpp_class_from_name(il2cpp_get_corlib(), "System", "String") : NULL;
    if (!k) return;
    void *it = NULL; P m; int n = 0;
    while ((m = il2cpp_class_get_methods(k, &it)) && n++ < 200) {
        uint32_t ifl = 0;
        uint32_t fl = il2cpp_method_get_flags(m, &ifl);
        uint16_t *u = (uint16_t *)m;
        if (u[0x4C / 2] == (uint16_t)fl && u[0x4E / 2] == (uint16_t)ifl) v50++;
        if (u[0x44 / 2] == (uint16_t)fl && u[0x46 / 2] == (uint16_t)ifl) v48++;
    }
    gSlotOff = (v48 > v50) ? 0x48 : 0x50;
}
static inline uint16_t methodSlot(P m) { return *(uint16_t *)((char *)m + gSlotOff); }

static P findClass(const char *ns, const char *nm) {
    size_t c = 0;
    P *a = il2cpp_domain_get_assemblies(il2cpp_domain_get(), &c);
    for (size_t i = 0; i < c; i++) {
        P k = il2cpp_class_from_name(il2cpp_assembly_get_image(a[i]), ns, nm);
        if (k) return k;
    }
    return NULL;
}

static NSString *fullName(P k) {
    const char *ns = il2cpp_class_get_namespace(k), *n = il2cpp_class_get_name(k);
    return (ns && *ns) ? [NSString stringWithFormat:@"%s.%s", ns, n] : [NSString stringWithUTF8String:n];
}

static void forEachClass(NSString *f, void (^cb)(P, NSString *, const char *, BOOL *)) {
    size_t ac = 0;
    P *asms = il2cpp_domain_get_assemblies(il2cpp_domain_get(), &ac);
    BOOL stop = NO;
    for (size_t i = 0; i < ac && !stop; i++) {
        P img = il2cpp_assembly_get_image(asms[i]);
        size_t cc = il2cpp_image_get_class_count(img);
        for (size_t j = 0; j < cc && !stop; j++) {
            P k = il2cpp_image_get_class(img, j);
            if (!k) continue;
            NSString *fn = fullName(k);
            if (f.length && ![fn localizedCaseInsensitiveContainsString:f]) continue;
            cb(k, fn, il2cpp_image_get_name(img), &stop);
        }
    }
}

// ---------- 1 & 3 : Field / Static Field ----------
static NSString *fieldDump(NSString *f, BOOL wantStatic) {
    NSMutableString *o = [NSMutableString new];
    __block int n = 0;
    forEachClass(f, ^(P k, NSString *full, const char *img, BOOL *stop) {
        void *it = NULL; P fld;
        NSMutableString *b = [NSMutableString new];
        while ((fld = il2cpp_class_get_fields(k, &it))) {
            int fl = il2cpp_field_get_flags(fld);
            if (fl & 0x40) continue;                       // literal/const
            if (((fl & 0x10) != 0) != wantStatic) continue;
            [b appendFormat:@"  %s = 0x%zX;\n", il2cpp_field_get_name(fld), il2cpp_field_get_offset(fld)];
            n++;
        }
        if (b.length) [o appendFormat:@"// %@  [%s]\n%@", full, img, b];
        if (n > kCap) *stop = YES;
    });
    return o.length ? o : @"ไม่พบข้อมูล (ลองพิมพ์ชื่อคลาสในช่อง filter)";
}

// ---------- 2 & 9 : Method pointer / VTable slot ----------
static void methodsOf(NSMutableString *o, P k, NSString *nameFilter, BOOL virtOnly, int *n) {
    void *it = NULL; P m;
    while ((m = il2cpp_class_get_methods(k, &it))) {
        const char *mn = il2cpp_method_get_name(m);
        if (nameFilter.length && ![[NSString stringWithUTF8String:mn] localizedCaseInsensitiveContainsString:nameFilter]) continue;
        uint32_t ifl = 0;
        uint32_t fl = il2cpp_method_get_flags(m, &ifl);
        BOOL isVirt = fl & 0x40;
        if (virtOnly && !isVirt) continue;
        P ptr = *(P *)m;                                   // MethodInfo->methodPointer
        if (virtOnly) {
            // MethodInfo.slot (u16) — offset หาอัตโนมัติ (0x50 บน Unity 2021.2+/Unity 6, 0x48 บนรุ่นเก่า)
            uint16_t slot = methodSlot(m);
            [o appendFormat:@"  slot %-4u %s  ptr=0x%lX\n", slot, mn, ptr ? RVA(ptr) : 0];
        } else {
            [o appendFormat:@"  %s = 0x%lX;%s\n", mn, ptr ? RVA(ptr) : 0, isVirt ? @" // virtual".UTF8String : ""];
        }
        (*n)++;
    }
}

static NSString *methodDump(NSString *f, BOOL virtOnly) {
    NSMutableString *o = [NSMutableString new];
    __block int n = 0;
    forEachClass(f, ^(P k, NSString *full, const char *img, BOOL *stop) {
        NSMutableString *b = [NSMutableString new];
        int c = 0;
        methodsOf(b, k, nil, virtOnly, &c);
        if (c) { [o appendFormat:@"// %@  [%s]\n%@", full, img, b]; n += c; }
        if (n > kCap) *stop = YES;
    });
    return o.length ? o : @"ไม่พบข้อมูล (ลองพิมพ์ชื่อคลาสในช่อง filter)";
}

// ---------- 4 & 5 : Collection / String ----------
static void instFields(NSMutableString *o, P corlib, const char *ns, const char *nm) {
    P k = il2cpp_class_from_name(corlib, ns, nm);
    if (!k) { [o appendFormat:@"// %s.%s  ✖ not found\n", ns, nm]; return; }
    [o appendFormat:@"// %s.%s  (size 0x%X)\n", ns, nm, il2cpp_class_instance_size(k)];
    void *it = NULL; P fld;
    while ((fld = il2cpp_class_get_fields(k, &it))) {
        int fl = il2cpp_field_get_flags(fld);
        if (fl & (0x10 | 0x40)) continue;
        [o appendFormat:@"  %s = 0x%zX;\n", il2cpp_field_get_name(fld), il2cpp_field_get_offset(fld)];
    }
}

static NSString *collectionDump(void) {
    NSMutableString *o = [NSMutableString new];
    P c = il2cpp_get_corlib();
    const char *ns = "System.Collections.Generic";
    for (const char *n : {"List`1", "Dictionary`2", "HashSet`1", "Queue`1", "Stack`1"})
        instFields(o, c, ns, n);
    [o appendString:@"\n// Il2CppArray (64-bit)\n  max_length = 0x18;\n  first_element = 0x20;\n"];
    return o;
}

static NSString *stringDump(void) {
    NSMutableString *o = [NSMutableString new];
    instFields(o, il2cpp_get_corlib(), "System", "String");
    [o appendString:@"\n// Il2CppString (64-bit)\n  length = 0x10;\n  chars(UTF-16) = 0x14;\n"];
    return o;
}

// ---------- 6 & 7 : Transform / Matrix / Camera ----------
static void icalls(NSMutableString *o, std::initializer_list<const char *> names) {
    for (const char *n : names) {
        // รองรับชื่อสำรอง คั่นด้วย '|' (Unity 6 เปลี่ยนชื่อ icall บางตัว)
        NSArray<NSString *> *alts = [@(n) componentsSeparatedByString:@"|"];
        P p = NULL; NSString *used = alts.firstObject;
        for (NSString *a in alts) { p = il2cpp_resolve_icall(a.UTF8String); if (p) { used = a; break; } }
        [o appendFormat:@"  %-58s = %@\n", used.UTF8String, p ? [NSString stringWithFormat:@"0x%lX", RVA(p)] : @"✖"];
    }
}

static NSString *transformDump(NSString *f) {
    NSMutableString *o = [NSMutableString stringWithString:@"// icall (native) addresses\n"];
    icalls(o, {"UnityEngine.Transform::get_position_Injected", "UnityEngine.Transform::set_position_Injected",
               "UnityEngine.Transform::get_rotation_Injected", "UnityEngine.Transform::get_localPosition_Injected",
               "UnityEngine.Transform::get_localScale_Injected", "UnityEngine.Transform::get_localRotation_Injected",
               "UnityEngine.Transform::set_localPosition_Injected", "UnityEngine.Transform::set_rotation_Injected", "UnityEngine.Transform::get_parentInternal|UnityEngine.Transform::get_parent",
               "UnityEngine.Transform::GetChild", "UnityEngine.Transform::get_childCount",
               "UnityEngine.Transform::get_localToWorldMatrix_Injected",
               "UnityEngine.Transform::get_worldToLocalMatrix_Injected"});
    P k = findClass("UnityEngine", "Transform");
    [o appendString:@"\n// managed methods UnityEngine.Transform\n"];
    int n = 0;
    if (k) methodsOf(o, k, f, NO, &n); else [o appendString:@"  ✖ class not found\n"];
    return o;
}

static NSString *cameraDump(NSString *f) {
    NSMutableString *o = [NSMutableString stringWithString:@"// icall (native) addresses\n"];
    icalls(o, {"UnityEngine.Camera::get_main", "UnityEngine.Camera::get_current",
               "UnityEngine.Camera::WorldToScreenPoint_Injected", "UnityEngine.Camera::WorldToViewportPoint_Injected",
               "UnityEngine.Camera::ScreenToWorldPoint_Injected", "UnityEngine.Camera::get_worldToCameraMatrix_Injected",
               "UnityEngine.Camera::get_projectionMatrix_Injected", "UnityEngine.Camera::get_fieldOfView",
               "UnityEngine.Camera::get_nearClipPlane", "UnityEngine.Camera::get_farClipPlane",
               "UnityEngine.Screen::get_width", "UnityEngine.Screen::get_height",
               "UnityEngine.Camera::get_pixelWidth", "UnityEngine.Camera::get_pixelHeight",
               "UnityEngine.Camera::get_allCamerasCount", "UnityEngine.Camera::GetAllCameras"});
    P k = findClass("UnityEngine", "Camera");
    [o appendString:@"\n// managed methods UnityEngine.Camera\n"];
    int n = 0;
    if (k) methodsOf(o, k, f, NO, &n); else [o appendString:@"  ✖ class not found\n"];
    return o;
}

// ---------- 8 : Class pointer ----------
static NSString *classPtrDump(NSString *f) {
    NSMutableString *o = [NSMutableString stringWithString:@"// runtime pointers (เปลี่ยนทุกครั้งที่รัน — ใช้ผ่าน il2cpp_class_from_name)\n"];
    __block int n = 0;
    forEachClass(f, ^(P k, NSString *full, const char *img, BOOL *stop) {
        [o appendFormat:@"%@  klass=%p  size=0x%X  [%s]\n", full, k, il2cpp_class_instance_size(k), img];
        if (++n >= (f.length ? kCap : 500)) *stop = YES;
    });
    if (!f.length) [o appendString:@"\n(แสดง 500 คลาสแรก — ใส่ filter เพื่อค้นหา)\n"];
    return o;
}

// ---------- 10 : GOT / PLT ----------
static NSString *gotplt(NSString *f) {
    uint32_t cnt = _dyld_image_count();
    int idx = -1;
    for (uint32_t i = 0; i < cnt; i++)
        if (strcasestr(_dyld_get_image_name(i), "UnityFramework")) { idx = i; break; }
    if (idx < 0) idx = 0;
    auto *mh = (const struct mach_header_64 *)_dyld_get_image_header(idx);
    intptr_t slide = _dyld_get_image_vmaddr_slide(idx);

    const symtab_command *st = NULL; const dysymtab_command *ds = NULL;
    const segment_command_64 *le = NULL; uint64_t textVm = 0;
    const uint8_t *p = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        auto *lc = (const load_command *)p;
        if (lc->cmd == LC_SYMTAB) st = (const symtab_command *)lc;
        else if (lc->cmd == LC_DYSYMTAB) ds = (const dysymtab_command *)lc;
        else if (lc->cmd == LC_SEGMENT_64) {
            auto *s = (const segment_command_64 *)lc;
            if (!strcmp(s->segname, "__LINKEDIT")) le = s;
            if (!strcmp(s->segname, "__TEXT")) textVm = s->vmaddr;
        }
        p += lc->cmdsize;
    }
    if (!st || !ds || !le) return @"✖ อ่าน Mach-O header ไม่ได้";

    uintptr_t leBase = slide + le->vmaddr - le->fileoff;
    auto *syms = (const nlist_64 *)(leBase + st->symoff);
    auto *str = (const char *)(leBase + st->stroff);
    auto *ind = (const uint32_t *)(leBase + ds->indirectsymoff);

    NSMutableString *o = [NSMutableString stringWithFormat:@"// image: %s\n", _dyld_get_image_name(idx)];
    int n = 0;
    p = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        auto *lc = (const load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            auto *s = (const segment_command_64 *)lc;
            auto *sec = (const section_64 *)(s + 1);
            for (uint32_t j = 0; j < s->nsects; j++, sec++) {
                uint32_t type = sec->flags & SECTION_TYPE;
                if (type != S_NON_LAZY_SYMBOL_POINTERS && type != S_LAZY_SYMBOL_POINTERS) continue;
                [o appendFormat:@"\n// %s,%s\n", sec->segname, sec->sectname];
                uint32_t count = (uint32_t)(sec->size / 8);
                for (uint32_t k = 0; k < count && n < kCap; k++) {
                    uint32_t si = ind[sec->reserved1 + k];
                    if (si & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;
                    const char *nm = str + syms[si].n_un.n_strx;
                    if (f.length && ![[NSString stringWithUTF8String:nm] localizedCaseInsensitiveContainsString:f]) continue;
                    [o appendFormat:@"  0x%llX  %s\n", sec->addr + k * 8 - textVm, nm];
                    n++;
                }
            }
        }
        p += lc->cmdsize;
    }
    return o;
}


// ---------- 11 : Analyze (heuristic guess) ----------
struct Rule { const char *label; std::vector<const char *> keys; std::vector<const char *> types; };
#define NUM "single", "int32", "int64", "int16", "double", "byte"

static const std::vector<Rule> &fieldRules() {
    static std::vector<Rule> r = {
        {"HP / เลือด",            {"hp", "health", "hitpoint", "life", "blood"},               {NUM}},
        {"HP สูงสุด",             {"maxhp", "maxhealth", "hpmax"},                              {NUM}},
        {"กระสุน / แมกกาซีน",     {"ammo", "bullet", "magazine", "clip", "reload"},            {NUM}},
        {"เงิน / ทรัพยากร",       {"gold", "coin", "money", "cash", "gem", "diamond", "currency", "credit"}, {NUM}},
        {"EXP / เลเวล / คะแนน",   {"exp", "xp", "level", "score", "rank", "point"},            {NUM}},
        {"ความเร็ว / การเคลื่อนที่", {"speed", "velocity", "move", "walk", "sprint", "run"},   {NUM, "vector3"}},
        {"ดาเมจ / พลังโจมตี",     {"damage", "dmg", "atk", "attack", "power", "crit"},         {NUM}},
        {"เกราะ / ป้องกัน",       {"defense", "defence", "armor", "shield", "def"},            {NUM}},
        {"คูลดาวน์ / เวลา",       {"cooldown", "timer", "delay", "interval", "duration", "time"}, {"single", "double", "int32"}},
        {"พิกัด / ทิศทาง",        {"position", "pos", "rotation", "scale", "forward", "direction", "offset"}, {"vector3", "quaternion", "transform"}},
        {"กล้อง / เมทริกซ์",      {"camera", "matrix", "projection", "view", "fov", "viewport"}, {"matrix4x4", "camera", "single"}},
        {"ตัวระบุ (ID/ทีม)",      {"id", "uid", "guid", "team", "faction", "owner"},          {"int32", "int64", "string"}},
        {"สวิตช์สถานะ",           {"dead", "alive", "active", "enabled", "locked", "visible", "invincible", "grounded"}, {"boolean"}},
        {"ชื่อ / ข้อความ",        {"name", "title", "text", "desc", "label", "nick"},         {"string"}},
        {"รายการ / คอลเลกชัน",    {"list", "items", "inventory", "array", "queue", "dict", "slots"}, {"list", "dictionary", "[]", "hashset"}},
        {"อาวุธ / สกิล / ไอเทม",  {"weapon", "gun", "skill", "item", "equip", "ability"},     {}},
        {"UI",                    {"button", "image", "panel", "canvas", "slider", "popup", "icon"}, {"unityengine"}},
        {"เครือข่าย",             {"photon", "network", "server", "socket", "rpc", "client", "room"}, {}},
        {"ตัวละคร / ผู้เล่น",     {"player", "character", "hero", "enemy", "monster", "npc", "pawn"}, {}},
    };
    return r;
}

static NSArray<NSString *> *tokens(NSString *n) {
    NSMutableArray *t = [NSMutableArray new];
    NSMutableString *cur = [NSMutableString new];
    NSCharacterSet *up = NSCharacterSet.uppercaseLetterCharacterSet, *al = NSCharacterSet.alphanumericCharacterSet;
    for (NSUInteger i = 0; i < n.length; i++) {
        unichar c = [n characterAtIndex:i];
        if (![al characterIsMember:c]) { if (cur.length) [t addObject:cur.lowercaseString]; cur = [NSMutableString new]; continue; }
        if ([up characterIsMember:c] && cur.length && ![up characterIsMember:[cur characterAtIndex:cur.length - 1]]) {
            [t addObject:cur.lowercaseString]; cur = [NSMutableString new];
        }
        [cur appendFormat:@"%C", c];
    }
    if (cur.length) [t addObject:cur.lowercaseString];
    return t;
}

struct Guess { NSString *label; int stars; };

// stars: 3 = ชื่อตรง+ชนิดตรง, 2 = ชื่อตรง ชนิดไม่ตรง, 1 = เดาจากชนิดอย่างเดียว
static Guess guessField(NSString *name, NSString *type) {
    NSString *low = name.lowercaseString, *tl = type.lowercaseString;
    NSArray *tk = tokens(name);
    Guess best = {nil, 0};
    for (auto &r : fieldRules()) {
        BOOL hit = NO;
        for (auto k : r.keys) {
            NSString *ks = @(k);
            if (ks.length <= 3 ? [tk containsObject:ks] : [low containsString:ks]) { hit = YES; break; }
        }
        if (!hit) continue;
        BOOL tOk = r.types.empty();
        for (auto t : r.types) if ([tl containsString:@(t)]) tOk = YES;
        int s = tOk ? 3 : 2;
        if (s > best.stars) best = {@(r.label), s};
    }
    if (best.stars) return best;
    if ([tl containsString:@"vector3"])    return {@"พิกัด/ทิศทาง (x,y,z) — เดาจากชนิด", 1};
    if ([tl containsString:@"quaternion"]) return {@"การหมุน (x,y,z,w) — เดาจากชนิด", 1};
    if ([tl containsString:@"matrix4x4"])  return {@"เมทริกซ์ 4x4 (view/proj) — เดาจากชนิด", 1};
    if ([tl containsString:@"boolean"])    return {@"สวิตช์ true/false — เดาจากชนิด", 1};
    if ([tl containsString:@"transform"] || [tl containsString:@"gameobject"])
        return {@"อ้างอิง object ในฉาก — เดาจากชนิด", 1};
    return {nil, 0};
}

static NSString *stars(int s) { return s >= 3 ? @"★★★" : s == 2 ? @"★★☆" : @"★☆☆"; }

struct MRule { const char *label; std::vector<const char *> keys; };
static const std::vector<MRule> &methodRules() {
    static std::vector<MRule> r = {
        {"รับดาเมจ",              {"takedamage", "applydamage", "ondamage", "onhit", "hurt", "receivedamage"}},
        {"ตาย / ฆ่า",             {"die", "dead", "kill", "death", "ondeath"}},
        {"ยิง / โจมตี",           {"shoot", "fire", "attack", "castskill", "useskill"}},
        {"รีโหลด",                {"reload"}},
        {"เพิ่ม/ใช้ทรัพยากร",     {"addcoin", "addgold", "addmoney", "addgem", "spend", "consume", "purchase", "buy"}},
        {"เพิ่ม EXP / เลเวลอัป",  {"addexp", "addxp", "levelup", "gainexp"}},
        {"เลือด: รักษา/เปลี่ยนค่า", {"heal", "sethealth", "addhealth", "changehp", "sethp"}},
        {"ลูปทุกเฟรม",            {"update", "fixedupdate", "lateupdate"}},
        {"เริ่มต้น / init",       {"awake", "start", "onenable", "init", "initialize", "setup"}},
        {"เครือข่าย / RPC",       {"rpc", "sendmessage", "onphoton", "sync", "serialize"}},
        {"เช็ค/ตรวจสอบ (ผลลัพธ์ bool)", {"can", "check", "validate", "verify"}},
    };
    return r;
}

static NSString *guessMethod(NSString *name) {
    NSString *low = name.lowercaseString;
    for (auto &r : methodRules())
        for (auto k : r.keys)
            if ([low containsString:@(k)]) return @(r.label);
    return nil;
}

static NSString *analyzeDump(NSString *f) {
    NSMutableString *o = [NSMutableString stringWithString:
        @"// ★★★ ชื่อ+ชนิดตรง   ★★☆ ชื่อตรง   ★☆☆ เดาจากชนิด\n// เป็นการเดาจากชื่อ/ชนิด ต้องยืนยันด้วยค่าจริงในเกมเสมอ\n\n"];
    __block int n = 0;
    BOOL verbose = f.length > 0;      // มี filter → โชว์ทุกฟิลด์ / ไม่มี → เฉพาะที่มั่นใจ ★★+
    forEachClass(f, ^(P k, NSString *full, const char *img, BOOL *stop) {
        NSMutableString *fb = [NSMutableString new], *mb = [NSMutableString new];
        NSMutableDictionary<NSString *, NSNumber *> *tally = [NSMutableDictionary new];

        void *it = NULL; P fld;
        while ((fld = il2cpp_class_get_fields(k, &it))) {
            int fl = il2cpp_field_get_flags(fld);
            if (fl & 0x40) continue;
            BOOL st = fl & 0x10;
            char *tn = il2cpp_type_get_name(il2cpp_field_get_type(fld));
            NSString *ts = tn ? @(tn) : @"?";
            if (tn) il2cpp_free(tn);
            NSString *nm = @(il2cpp_field_get_name(fld));
            Guess g = guessField(nm, ts);
            if (g.stars >= (verbose ? 1 : 2) || verbose) {
                [fb appendFormat:@"  %@0x%zX  %-22s %@  → %@ %@\n", st ? @"[S] " : @"    ",
                    il2cpp_field_get_offset(fld), ts.UTF8String, nm,
                    g.label ?: @"(ไม่ทราบ)", g.label ? stars(g.stars) : @""];
            }
            if (g.label && g.stars >= 2) tally[g.label] = @(tally[g.label].intValue + 1);
        }

        it = NULL; P m;
        while ((m = il2cpp_class_get_methods(k, &it))) {
            NSString *mn = @(il2cpp_method_get_name(m));
            NSString *g = guessMethod(mn);
            if (!g) continue;
            P ptr = *(P *)m;
            [mb appendFormat:@"    fn 0x%lX  %@  → %@\n", ptr ? RVA(ptr) : 0, mn, g];
        }

        if (!fb.length && !mb.length) return;
        NSMutableString *sum = [NSMutableString new];
        for (NSString *key in [tally keysSortedByValueUsingComparator:^NSComparisonResult(NSNumber *a, NSNumber *b) { return [b compare:a]; }])
            [sum appendFormat:@"%@×%@ ", key, tally[key]];
        [o appendFormat:@"// %@  [%s]%@\n%@%@\n", full, img, sum.length ? [@"\n// น่าจะเกี่ยวกับ: " stringByAppendingString:sum] : @"", fb, mb];
        if (++n > 2000) *stop = YES;
    });
    return n ? o : @"ไม่พบคลาส/ฟิลด์ที่เดาได้ — ลองใส่ filter เช่น Player, Weapon, Camera";
}

// ---------- 12 : Full Scan (วิเคราะห์ทั้งเกม) ----------
static NSDictionary *gScan;
static NSString *gScanFilter;

static BOOL isFrameworkImage(const char *img) {
    static const char *pre[] = {"mscorlib", "System", "Mono", "UnityEngine", "Unity.", "netstandard",
                                "Newtonsoft", "I18N", "Accessibility", "nunit", "UnityFramework"};
    NSString *s = @(img ?: "");
    for (auto p : pre) if ([s hasPrefix:@(p)]) return YES;
    return NO;
}

static BOOL obfName(NSString *n) {
    if (n.length <= 2) return YES;
    for (NSUInteger i = 0; i < n.length; i++) if ([n characterAtIndex:i] > 127) return YES;
    return NO;
}

static BOOL isNumType(NSString *tl) {
    for (auto t : {"single", "int32", "int64", "int16", "double", "byte"}) if ([tl containsString:@(t)]) return YES;
    return NO;
}

static NSDictionary *scanModel(NSString *f) {
    BOOL all = f.length > 0;
    NSMutableArray *classes = [NSMutableArray new], *singles = [NSMutableArray new], *loops = [NSMutableArray new];
    NSMutableDictionary<NSString *, NSMutableArray *> *cats = [NSMutableDictionary new];
    __block size_t nCls = 0, nFld = 0, nMeth = 0, nObf = 0, nEnum = 0;
    NSMutableSet *imgs = [NSMutableSet new];
    NSSet *generic = [NSSet setWithObjects:@"ลูปทุกเฟรม", @"เริ่มต้น / init", @"เช็ค/ตรวจสอบ (ผลลัพธ์ bool)", nil];
    NSSet *singNames = [NSSet setWithObjects:@"instance", @"_instance", @"s_instance", @"sinstance",
                                              @"singleton", @"current", @"_current", @"m_instance", nil];

    forEachClass(f, ^(P k, NSString *full, const char *img, BOOL *stop) {
        if (!all && isFrameworkImage(img)) return;
        nCls++;
        [imgs addObject:@(img ?: "")];
        NSString *nm = @(il2cpp_class_get_name(k));
        BOOL obf = obfName(nm);
        if (obf) nObf++;
        if (il2cpp_class_is_enum && il2cpp_class_is_enum(k)) { nEnum++; return; }
        BOOL isVal = il2cpp_class_is_valuetype ? il2cpp_class_is_valuetype(k) : NO;

        // inheritance chain
        NSMutableArray *chain = [NSMutableArray new];
        if (il2cpp_class_get_parent) {
            P pk = il2cpp_class_get_parent(k);
            for (int dep = 0; pk && dep < 10; dep++, pk = il2cpp_class_get_parent(pk)) [chain addObject:fullName(pk)];
        }
        BOOL isMono = [chain containsObject:@"UnityEngine.MonoBehaviour"];
        BOOL isSO = [chain containsObject:@"UnityEngine.ScriptableObject"];

        NSMutableArray *fields = [NSMutableArray new], *methods = [NSMutableArray new], *notes = [NSMutableArray new];
        NSMutableDictionary<NSString *, NSNumber *> *tally = [NSMutableDictionary new];
        NSMutableDictionary<NSString *, NSMutableArray *> *pair = [NSMutableDictionary new];
        NSMutableString *types = [NSMutableString new];
        int score = 0, numFields = 0;

        void *it = NULL; P fld;
        while ((fld = il2cpp_class_get_fields(k, &it))) {
            int fl = il2cpp_field_get_flags(fld);
            if (fl & 0x40) continue;
            BOOL st = fl & 0x10;
            char *tn = il2cpp_type_get_name(il2cpp_field_get_type(fld));
            NSString *ts = tn ? @(tn) : @"?";
            if (tn) il2cpp_free(tn);
            NSString *tl = ts.lowercaseString;
            [types appendFormat:@"%@|", tl];
            if (!st && isNumType(tl)) numFields++;
            NSString *fn = @(il2cpp_field_get_name(fld));
            Guess g = guessField(fn, ts);
            nFld++;
            NSString *off = [NSString stringWithFormat:@"0x%zX", il2cpp_field_get_offset(fld)];
            NSMutableDictionary *e = [@{@"name": fn, @"offset": off, @"type": ts, @"static": @(st)} mutableCopy];
            if (g.label) { e[@"guess"] = g.label; e[@"confidence"] = @(g.stars); }
            [fields addObject:e];

            if (g.label && g.stars >= 2) {
                score += g.stars;
                tally[g.label] = @(tally[g.label].intValue + 1);
                NSMutableDictionary *c = [@{@"class": full, @"field": fn, @"offset": off, @"type": ts,
                                            @"static": @(st), @"confidence": @(g.stars)} mutableCopy];
                if (!cats[g.label]) cats[g.label] = [NSMutableArray new];
                [cats[g.label] addObject:c];
                BOOL hasMax = [fn.lowercaseString containsString:@"max"];
                if (!pair[g.label]) pair[g.label] = [@[@NO, @NO] mutableCopy];
                pair[g.label][hasMax ? 0 : 1] = @YES;
            }
            // singleton
            if (st && ([ts isEqualToString:full] || [singNames containsObject:fn.lowercaseString]))
                [singles addObject:@{@"class": full, @"field": fn, @"staticOffset": off, @"type": ts}];
        }
        for (NSString *lab in pair)
            if ([pair[lab][0] boolValue] && [pair[lab][1] boolValue])
                [notes addObject:[NSString stringWithFormat:@"มีคู่ ปัจจุบัน/สูงสุด: %@", lab]];

        it = NULL; P m; BOOL hasLoop = NO; NSString *loopRva = nil;
        while ((m = il2cpp_class_get_methods(k, &it))) {
            nMeth++;
            NSString *mn = @(il2cpp_method_get_name(m));
            NSString *g = guessMethod(mn);
            if (!g) continue;
            P ptr = *(P *)m;
            uint32_t ifl = 0; uint32_t fl = il2cpp_method_get_flags(m, &ifl);
            NSMutableDictionary *e = [@{@"name": mn, @"guess": g,
                                         @"rva": ptr ? [NSString stringWithFormat:@"0x%lX", RVA(ptr)] : @"0x0",
                                         @"virtual": @((fl & 0x40) != 0)} mutableCopy];
            if (fl & 0x40) e[@"slot"] = @(methodSlot(m));
            [methods addObject:e];
            if ([g isEqualToString:@"ลูปทุกเฟรม"] && !hasLoop && ptr) { hasLoop = YES; loopRva = e[@"rva"]; }
            if (![generic containsObject:g]) { score += 2; tally[g] = @(tally[g].intValue + 1); }
        }
        if (isMono && hasLoop && (score > 0 || !obf))
            [loops addObject:@{@"class": full, @"updateRva": loopRva, @"score": @(score)}];

        // เดาจากโครงสร้าง (สำหรับคลาสที่ชื่อไม่บอกอะไร / ถูก obfuscate)
        NSString *structural = nil;
        if (!tally.count) {
            if (isMono && [types containsString:@"camera"]) structural = @"เกี่ยวกับกล้อง";
            else if (isMono && [types containsString:@"unityengine.ui"]) structural = @"คอมโพเนนต์ UI";
            else if (isMono && [types containsString:@"vector3"]) structural = @"ตำแหน่ง/การเคลื่อนที่";
            else if (isMono && numFields >= 6) structural = @"สถานะตัวละคร/วัตถุ (ตัวเลขเยอะ)";
            else if (!isMono && !isVal && numFields >= 5) structural = @"ข้อมูล/คอนฟิก (ตัวเลขเยอะ)";
            if (structural) [notes addObject:[structural stringByAppendingString:@" (เดาจากโครงสร้าง)"]];
        }

        NSMutableArray *role = [NSMutableArray new];
        for (NSString *key in [tally keysSortedByValueUsingComparator:^NSComparisonResult(NSNumber *a, NSNumber *b) { return [b compare:a]; }]) {
            if (role.count >= 3) break;
            [role addObject:[NSString stringWithFormat:@"%@×%@", key, tally[key]]];
        }

        [classes addObject:@{@"name": full, @"image": @(img ?: ""), @"parents": chain,
                             @"kind": isVal ? @"struct" : @"class", @"monoBehaviour": @(isMono),
                             @"scriptableObject": @(isSO), @"obfuscated": @(obf),
                             @"instanceSize": [NSString stringWithFormat:@"0x%X", il2cpp_class_instance_size(k)],
                             @"score": @(score), @"role": role, @"notes": notes,
                             @"fields": fields, @"methodHints": methods}];
    });

    for (NSString *key in cats)
        [cats[key] sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            return [b[@"confidence"] compare:a[@"confidence"]]; }];

    int pct = nCls ? (int)(nObf * 100 / nCls) : 0;
    NSMutableArray *warn = [NSMutableArray new];
    if (pct > 50) [warn addObject:@"คลาสส่วนใหญ่ถูก obfuscate — การเดาจากชื่อจะแม่นน้อย ให้ดูผลแบบ 'เดาจากโครงสร้าง' และยืนยันด้วยค่าจริง"];
    if (!nCls) [warn addObject:@"ไม่พบคลาสตาม filter/ขอบเขตนี้"];

    return @{@"stats": @{@"scope": all ? @"ทุก assembly ตาม filter" : @"เฉพาะ assembly ของเกม (ไม่รวม System/Unity)",
                         @"assemblies": @(imgs.count), @"classes": @(nCls), @"enums": @(nEnum),
                         @"fields": @(nFld), @"methods": @(nMeth), @"obfuscatedClassPercent": @(pct),
                         @"warnings": warn},
             @"classes": classes, @"categories": cats, @"singletons": singles, @"updateLoops": loops};
}

static NSString *renderScan(NSDictionary *m) {
    NSDictionary *s = m[@"stats"];
    NSMutableString *o = [NSMutableString stringWithFormat:
        @"// ===== FULL SCAN =====\n// ขอบเขต: %@\n// assemblies %@ · classes %@ · enums %@ · fields %@ · methods %@ · obfuscated %@%%\n",
        s[@"scope"], s[@"assemblies"], s[@"classes"], s[@"enums"], s[@"fields"], s[@"methods"], s[@"obfuscatedClassPercent"]];
    for (NSString *w in s[@"warnings"]) [o appendFormat:@"// ⚠ %@\n", w];
    [o appendString:@"// ★★★ ชื่อ+ชนิดตรง  ★★☆ ชื่อตรง  — เป็นการเดา ต้องยืนยันด้วยค่าจริง\n\n"];

    NSArray *classes = m[@"classes"];
    NSArray *sorted = [classes sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [b[@"score"] compare:a[@"score"]]; }];

    [o appendString:@"// ---------- 1) คลาสเด่น (เรียงตามคะแนนความเกี่ยวข้อง) ----------\n"];
    int shown = 0;
    for (NSDictionary *c in sorted) {
        if ([c[@"score"] intValue] <= 0 || shown >= 25) break;
        shown++;
        NSString *par = [c[@"parents"] count] ? [@" : " stringByAppendingString:[c[@"parents"] firstObject]] : @"";
        [o appendFormat:@"\n// #%d %@%@  [%@]  score=%@  size=%@%@\n", shown, c[@"name"], par, c[@"image"], c[@"score"], c[@"instanceSize"],
            [c[@"monoBehaviour"] boolValue] ? @"  (MonoBehaviour)" : @""];
        if ([c[@"role"] count]) [o appendFormat:@"// น่าจะเกี่ยวกับ: %@\n", [c[@"role"] componentsJoinedByString:@"  "]];
        for (NSString *n in c[@"notes"]) [o appendFormat:@"// note: %@\n", n];
        int lines = 0;
        for (NSDictionary *e in c[@"fields"]) {
            if (!e[@"guess"] || lines >= 25) continue;
            [o appendFormat:@"  %@%@  %-20s %@  → %@ %@\n", [e[@"static"] boolValue] ? @"[S] " : @"    ", e[@"offset"],
                [e[@"type"] UTF8String], e[@"name"], e[@"guess"], stars([e[@"confidence"] intValue])];
            lines++;
        }
        for (NSDictionary *e in c[@"methodHints"]) {
            if ([e[@"guess"] isEqualToString:@"ลูปทุกเฟรม"] || [e[@"guess"] isEqualToString:@"เริ่มต้น / init"]) continue;
            [o appendFormat:@"    fn %@  %@  → %@\n", e[@"rva"], e[@"name"], e[@"guess"]];
        }
    }
    if (!shown) [o appendString:@"(ไม่พบคลาสที่มีคะแนน — ลองใส่ filter เช่น Player)\n"];

    [o appendString:@"\n// ---------- 2) ดัชนีตามหมวด (ทั้งเกม) ----------\n"];
    NSDictionary *cats = m[@"categories"];
    for (NSString *label in [cats.allKeys sortedArrayUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
            return [@([cats[b] count]) compare:@([cats[a] count])]; }]) {
        NSArray *arr = cats[label];
        [o appendFormat:@"\n// %@  (%lu)\n", label, (unsigned long)arr.count];
        NSUInteger i = 0;
        for (NSDictionary *e in arr) {
            if (i++ >= 40) { [o appendFormat:@"  … อีก %lu รายการ (ดูใน JSON)\n", (unsigned long)arr.count - 40]; break; }
            [o appendFormat:@"  %@%@.%@ = %@  %@ %@\n", [e[@"static"] boolValue] ? @"[S] " : @"", e[@"class"], e[@"field"],
                e[@"offset"], e[@"type"], stars([e[@"confidence"] intValue])];
        }
    }

    NSArray *sg = m[@"singletons"];
    [o appendFormat:@"\n// ---------- 3) Singleton ที่น่าจะเป็น (%lu) ----------\n", (unsigned long)sg.count];
    NSUInteger i = 0;
    for (NSDictionary *e in sg) {
        if (i++ >= 60) break;
        [o appendFormat:@"  %@.%@  static@%@  (%@)\n", e[@"class"], e[@"field"], e[@"staticOffset"], e[@"type"]];
    }

    NSArray *lp = [m[@"updateLoops"] sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [b[@"score"] compare:a[@"score"]]; }];
    [o appendFormat:@"\n// ---------- 4) MonoBehaviour ที่มี Update loop (%lu) — จุดเกาะ/สังเกตค่า ----------\n", (unsigned long)lp.count];
    i = 0;
    for (NSDictionary *e in lp) {
        if (i++ >= 60) break;
        [o appendFormat:@"  Update@%@  %@  (score %@)\n", e[@"updateRva"], e[@"class"], e[@"score"]];
    }
    [o appendString:@"\n// ดูรายละเอียดครบทุกคลาส/ฟิลด์: Export → JSON\n"];
    return o;
}

static NSString *scanText(NSString *f) {
    NSDictionary *m = scanModel(f);
    gScan = m; gScanFilter = f;
    return renderScan(m);
}

static NSString *grp(NSTextCheckingResult *m, NSString *s, NSUInteger i) {
    return [s substringWithRange:[m rangeAtIndex:i]];
}

@implementation Dumper

+ (BOOL)attach {
    if (gReady) return YES;
    if (!loadSyms()) {
        NSString *path = [NSBundle.mainBundle.privateFrameworksPath
            stringByAppendingPathComponent:@"UnityFramework.framework/UnityFramework"];
        void *h = dlopen(path.UTF8String, RTLD_NOW);
        if (!h) h = dlopen(path.UTF8String, RTLD_NOW | RTLD_NOLOAD);
        if (h) gHandle = h;
        if (!loadSyms()) return NO;
    }
    Dl_info info;
    if (dladdr((void *)il2cpp_domain_get, &info)) gBase = (uintptr_t)info.dli_fbase;
    calibrateMethodInfo();
    gReady = YES;
    return YES;
}

+ (NSString *)run:(DumpKind)kind filter:(NSString *)f {
    f = [f stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
    if (kind == DumpGOTPLT) return gotplt(f);
    if (![self attach]) return @"✖ ไม่พบ il2cpp API — แอปนี้ไม่ใช่ Unity IL2CPP หรือยังโหลดไม่เสร็จ";
    il2cpp_thread_attach(il2cpp_domain_get());
    switch (kind) {
        case DumpFieldOffset:   return fieldDump(f, NO);
        case DumpMethodPtr:     return methodDump(f, NO);
        case DumpStaticField:   return fieldDump(f, YES);
        case DumpCollection:    return collectionDump();
        case DumpString:        return stringDump();
        case DumpTransform:     return transformDump(f);
        case DumpMatrixCamera:  return cameraDump(f);
        case DumpClassPointer:  return classPtrDump(f);
        case DumpVTable:        return methodDump(f, YES);
        case DumpAnalyze:       return analyzeDump(f);
        case DumpFullScan:      return scanText(f);
        default: return @"";
    }
}

// ---------- JSON export (same @implementation as the declarations in Dumper.h) ----------
+ (NSString *)fullScanJSON:(NSString *)f {
    f = [f stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
    if (!gScan || ![gScanFilter isEqualToString:f]) { if (![self attach]) return @"{}"; il2cpp_thread_attach(il2cpp_domain_get()); gScan = scanModel(f); gScanFilter = f; }
    NSData *j = [NSJSONSerialization dataWithJSONObject:@{@"tool": @"OffsetDumper", @"category": @"full_scan", @"filter": f, @"result": gScan}
                  options:NSJSONWritingPrettyPrinted | NSJSONWritingWithoutEscapingSlashes error:nil];
    return j ? [[NSString alloc] initWithData:j encoding:NSUTF8StringEncoding] : @"{}";
}

+ (NSString *)jsonFromText:(NSString *)text kindName:(NSString *)kn filter:(NSString *)f {
    auto RX = ^NSRegularExpression *(NSString *p) { return [NSRegularExpression regularExpressionWithPattern:p options:0 error:nil]; };
    NSRegularExpression *rAna  = RX(@"0x([0-9A-Fa-f]+)\\s+(\\S+)\\s+(\\S+)\\s+→\\s+(.+?)\\s*(★[★☆]*)?\\s*$");
    NSRegularExpression *rFn   = RX(@"^\\s*fn\\s+(0x[0-9A-Fa-f]+)\\s+(\\S+)\\s+→\\s+(.+)$");
    NSRegularExpression *rSlot = RX(@"slot\\s+(\\d+)\\s+(\\S+)\\s+ptr=(0x[0-9A-Fa-f]+)");
    NSRegularExpression *rCls  = RX(@"^(\\S+)\\s+klass=(0x[0-9A-Fa-f]+)\\s+size=(0x[0-9A-Fa-f]+)");
    NSRegularExpression *rGot  = RX(@"^\\s*(0x[0-9A-Fa-f]+)\\s+(\\S+)\\s*$");
    NSRegularExpression *rEq   = RX(@"^\\s*([^\\s=]+)\\s*=\\s*(0x[0-9A-Fa-f]+)");
    NSRegularExpression *rHex  = RX(@"0x[0-9A-Fa-f]+");

    NSMutableArray *groups = [NSMutableArray new];
    __block NSMutableDictionary *cur = nil;
    auto newGroup = ^(NSString *name) {
        cur = [@{@"name": name, @"entries": [NSMutableArray new]} mutableCopy];
        [groups addObject:cur];
    };
    newGroup(@"(root)");

    for (NSString *raw in [text componentsSeparatedByString:@"\n"]) {
        NSString *line = [raw stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if (!line.length) continue;
        if ([line hasPrefix:@"//"]) {
            NSString *g = [[line substringFromIndex:2] stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
            if (g.length) newGroup(g);
            continue;
        }
        NSMutableDictionary *e = [NSMutableDictionary new];
        NSRange all = NSMakeRange(0, raw.length);
        NSTextCheckingResult *m;
        if ((m = [rAna firstMatchInString:raw options:0 range:all])) {
            e[@"offset"] = [@"0x" stringByAppendingString:grp(m, raw, 1)];
            e[@"type"] = grp(m, raw, 2); e[@"name"] = grp(m, raw, 3); e[@"guess"] = grp(m, raw, 4);
            if ([m rangeAtIndex:5].location != NSNotFound) e[@"confidence"] = @(grp(m, raw, 5).length);
        } else if ((m = [rFn firstMatchInString:raw options:0 range:all])) {
            e[@"offset"] = grp(m, raw, 1); e[@"name"] = grp(m, raw, 2); e[@"guess"] = grp(m, raw, 3); e[@"kind"] = @"method";
        } else if ((m = [rSlot firstMatchInString:raw options:0 range:all])) {
            e[@"slot"] = @(grp(m, raw, 1).intValue); e[@"name"] = grp(m, raw, 2); e[@"offset"] = grp(m, raw, 3);
        } else if ((m = [rCls firstMatchInString:raw options:0 range:all])) {
            e[@"name"] = grp(m, raw, 1); e[@"klass"] = grp(m, raw, 2); e[@"size"] = grp(m, raw, 3);
        } else if ((m = [rGot firstMatchInString:raw options:0 range:all])) {
            e[@"offset"] = grp(m, raw, 1); e[@"name"] = grp(m, raw, 2);
        } else if ((m = [rEq firstMatchInString:raw options:0 range:all])) {
            e[@"name"] = grp(m, raw, 1); e[@"offset"] = grp(m, raw, 2);
            if ([raw containsString:@"virtual"]) e[@"virtual"] = @YES;
        } else if ((m = [rHex firstMatchInString:raw options:0 range:all])) {
            e[@"offset"] = grp(m, raw, 0);
        }
        if ([raw containsString:@"[S]"]) e[@"static"] = @YES;
        e[@"raw"] = line;
        [cur[@"entries"] addObject:e];
    }
    NSMutableArray *out = [NSMutableArray new];
    for (NSDictionary *g in groups) if ([g[@"entries"] count]) [out addObject:g];

    NSDictionary *root = @{@"tool": @"OffsetDumper", @"category": kn ?: @"", @"filter": f ?: @"",
                           @"date": [NSISO8601DateFormatter stringFromDate:NSDate.date
                                     timeZone:NSTimeZone.localTimeZone formatOptions:NSISO8601DateFormatWithInternetDateTime],
                           @"groups": out};
    NSData *j = [NSJSONSerialization dataWithJSONObject:root
                  options:NSJSONWritingPrettyPrinted | NSJSONWritingWithoutEscapingSlashes error:nil];
    return j ? [[NSString alloc] initWithData:j encoding:NSUTF8StringEncoding] : @"{}";
}
@end
