#include <dlfcn.h>
#include <filesystem>
#include <set>
#include <stdio.h>
#include <stdlib.h>
#include <map>
#include <vector>

#include "PFishHook.h"
#include "dep.h"

#include "StaticHook.h"

struct hook_defs {
  void *hook, **original;
};

namespace fs = std::filesystem;

static std::vector<void *> mods;
static std::map<void *, hook_defs> *hooks;

struct BedrockLog {
  static void log(uint area, uint level, char const *tag, int prip, char const *content, ...);
};

extern "C" void mcpelauncher_log(uint level, char const *tag, char const *content) {
  BedrockLog::log(0x800, level, tag, -1, "%s", content);
}

int mcpelauncher_hook_internal(void *sym, void *func, void **rev) {
  auto ret = HookIt(sym, rev, func);
  switch (ret) {
  case FHSuccess: return 0;
  case FHAllocFailed: mcpelauncher_log(5, "hook", "Hook failed: AllocFailed\n"); return -ret;
  case FHDecodeFailed: mcpelauncher_log(5, "hook", "Hook failed: DecodeFailed\n"); return -ret;
  case FHMprotectFail: mcpelauncher_log(5, "hook", "Hook failed: MProtectFailed\n"); return -ret;
  case FHPatchFailed: mcpelauncher_log(5, "hook", "Hook failed: PatchFailed\n"); return -ret;
  case FHTooManyPatches: mcpelauncher_log(5, "hook", "Hook failed: TooManyPatches\n"); return -ret;
  case FHUnrecognizedRIP: mcpelauncher_log(5, "hook", "Hook failed: UnrecognizedRIP\n"); return -ret;
  default: mcpelauncher_log(5, "hook", "Hook failed: Unknown error\n"); return -ret;
  }
}

extern "C" int mcpelauncher_hook(void *symbol, void *hook, void **original) {
  auto def = hooks->find(symbol);
  if (def == hooks->end()) {
    auto result = mcpelauncher_hook_internal(symbol, hook, original);
    hooks->insert({ symbol, { hook, original } });
    return result;
  } else {
    *original             = *def->second.original;
    *def->second.original = hook;
    def->second           = { hook, original };
    return 0;
  }
}

TClasslessInstanceHook(void *, _ZN15DedicatedServer5startEv) { return original(this); }

void loadMods(fs::path path, std::set<fs::path> &others) {
  auto deps = getDependencies(path);
  for (auto const &dep : deps) {
    if (others.count(dep) > 0) {
      auto name = path.parent_path();
      name /= dep;
      others.erase(dep);
      loadMods(name, others);
      others.erase(dep);
    }
  }
  printf("Loading mod: %s\n", path.stem().c_str());
  void *mod = dlopen(path.c_str(), RTLD_LAZY);
  if (mod) { mods.emplace_back(mod); }
}

void loadModsFromDirectory(fs::path base) {
  if (fs::exists(base) && fs::is_directory(base)) {
    std::set<fs::path> modsToLoad;
    for (auto mod : fs::directory_iterator{ base }) {
      if (mod.path().extension() == ".so") { modsToLoad.insert(mod.path()); }
    }
    while (!modsToLoad.empty()) {
      auto it   = modsToLoad.begin();
      auto path = *it;
      modsToLoad.erase(it);

      loadMods(path, modsToLoad);
    }
  }
}

void mod_init(void) __attribute__((constructor));

void mod_init(void) {
  hooks = new std::map<void *, hook_defs>();
  printf("ModLoader Loading...\n");
  loadModsFromDirectory("mods");
}