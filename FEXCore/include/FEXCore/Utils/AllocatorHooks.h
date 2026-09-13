// SPDX-License-Identifier: MIT
#pragma once
#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Utils/EnumOperators.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/TypeDefines.h>

#ifndef _WIN32
#include <stdlib.h>
#ifdef __APPLE__
#include <malloc/malloc.h>
#include <pthread.h>
#include <TargetConditionals.h>
#include <dlfcn.h>
#include <FEXCore/Utils/JIT26.h>
#else
#include <malloc.h>
#endif
#include <sys/mman.h>
#else
#define NTDDI_VERSION 0x0A000005
#include <memoryapi.h>
#endif

#include <new>
#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <sys/types.h>

namespace FEXCore::Allocator {
enum class ProtectOptions : uint32_t {
  None = 0,
  Read = (1U << 0),
  Write = (1U << 1),
  Exec = (1U << 2),
};
FEX_DEF_NUM_OPS(ProtectOptions)

enum class THPControl {
  Enable,
  Disable,
};

#ifndef _WIN32
FEX_DEFAULT_VISIBILITY void SetupHooks(size_t PageSize);
#else
using VirtualNamePtr = void (*)(const char*, const void*, size_t);
using VirtualTHPPtr = void (*)(const void*, size_t, THPControl);
struct HookPtrs {
  VirtualNamePtr VirtualName;
  VirtualTHPPtr VirtualTHPControl;
};
FEX_DEFAULT_VISIBILITY void SetupHooks(size_t PageSize, HookPtrs Ptrs);
#endif
FEX_DEFAULT_VISIBILITY void ClearHooks();

#ifdef _WIN32
inline void* VirtualAlloc(void* Base, size_t Size, bool Execute = false, bool Commit = true) {
  // Allocate top-down to avoid polluting the lower VA space, as even on 64-bit some programs (i.e. LuaJIT) require allocations below 4GB.
  DWORD Flags = (Commit ? MEM_COMMIT : 0) | MEM_RESERVE | MEM_TOP_DOWN;
#ifdef ARCHITECTURE_arm64ec
  MEM_EXTENDED_PARAMETER Parameter {};
  if (Execute) {
    Parameter.Type = MemExtendedParameterAttributeFlags;
    Parameter.ULong64 = MEM_EXTENDED_PARAMETER_EC_CODE;
  };
  return ::VirtualAlloc2(nullptr, Base, Size, Flags, Execute ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE, Execute ? &Parameter : nullptr,
                         Execute ? 1 : 0);
#else
  return ::VirtualAlloc(Base, Size, Flags, Execute ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE);
#endif
}

inline void* VirtualAlloc(size_t Size, bool Execute = false, bool Commit = true) {
  return VirtualAlloc(nullptr, Size, Execute, Commit);
}

inline void VirtualFree(void* Ptr, size_t Size) {
  ::VirtualFree(Ptr, 0, MEM_RELEASE);
}

inline void VirtualDontNeed(void* Ptr, size_t Size, bool Recommit = true) {
  // Zero the page-aligned region, preserving permissions.
  MEMORY_BASIC_INFORMATION Info;
  ::VirtualQuery(Ptr, &Info, sizeof(Info));
  ::VirtualFree(Ptr, Size, MEM_DECOMMIT);
  if (Recommit) {
    ::VirtualAlloc(Ptr, Size, MEM_COMMIT, Info.Protect);
  }
}

inline bool VirtualProtect(void* Ptr, size_t Size, ProtectOptions options) {
  DWORD prot {PAGE_NOACCESS};

  if (options == ProtectOptions::None) {
    prot = PAGE_NOACCESS;
  } else if (options == ProtectOptions::Read) {
    prot = PAGE_READONLY;
  } else if (options == (ProtectOptions::Read | ProtectOptions::Write)) {
    prot = PAGE_READWRITE;
  } else if (options == (ProtectOptions::Read | ProtectOptions::Exec)) {
    prot = PAGE_EXECUTE_READ;
  } else if (options == (ProtectOptions::Read | ProtectOptions::Write | ProtectOptions::Exec)) {
    prot = PAGE_EXECUTE_READWRITE;
  } else {
    LOGMAN_MSG_A_FMT("Unknown VirtualProtect options combination");
  }

  return ::VirtualProtect(Ptr, Size, prot, nullptr) == 0;
}

FEX_DEFAULT_VISIBILITY extern VirtualNamePtr VirtualName;
FEX_DEFAULT_VISIBILITY extern VirtualTHPPtr VirtualTHPControl;
#else
using MMAP_Hook = void* (*)(void*, size_t, int, int, int, off_t);
using MUNMAP_Hook = int (*)(void*, size_t);
// Notified after an operation replaces the physical pages backing an existing VA range in place
// (fresh mmap(MAP_FIXED) over live memory). Embedders that mirror FEXCore-visible memory into a
// second mapping domain (e.g. a Hypervisor.framework guest, where hv_vm_map association survives
// such a replacement and would keep translating to the old pages) re-establish their mapping here.
using PAGES_REPLACED_Hook = void (*)(void*, size_t);

FEX_DEFAULT_VISIBILITY extern MMAP_Hook mmap;
FEX_DEFAULT_VISIBILITY extern MUNMAP_Hook munmap;
FEX_DEFAULT_VISIBILITY extern PAGES_REPLACED_Hook PagesReplaced;
FEX_DEFAULT_VISIBILITY extern void VirtualName(const char* Name, void* Ptr, size_t Size);

// All commit parameters are ignored here, they are unnecessary as Linux supports overcommit

#ifdef __APPLE__
// Apple's hardened runtime forbids RWX mappings outright: executable anonymous memory must be
// requested with MAP_JIT, and even then a thread may only write to it while that thread's JIT
// write-protection is explicitly disabled (see JITWriteScope below) - RWX from mmap() alone
// (what the generic path below does on Linux) is rejected.
inline int MapJitFlagIfExecutable(bool Execute) {
  return Execute ? MAP_JIT : 0;
}

#if TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
// Real iOS device rejects a plain mmap(MAP_JIT) executable mapping outright (EXC_BAD_ACCESS /
// KERN_PROTECTION_FAILURE, confirmed even under externally-granted CS_DEBUGGED - see the Unicorn
// backend's own JIT26 bring-up, src/common/utils/ios_device_jit_mmap_shim.cpp, for the full story).
// It needs QEMU's upstream "splitwx" (split write/execute) architecture instead:
// fexcore_jit26_prepare_region() hands back a genuinely executable (RX) region, and
// fexcore_jit26_writable_alias() maps a separate writable (RW) alias of the same physical pages.
// VirtualAlloc(..., Execute=true) below hands back the RW alias (what every existing caller
// already expects to write generated code through); anything that instead needs the real
// executable address, or needs to write through an address it only has in RX form (e.g. one
// derived from an actually-executing PC), must go through JIT26ToExecutable()/JIT26ToWritable()
// near the bottom of this file.
namespace JIT26Detail {
  // ToExecutable()/ToWritable() are called from CPUBackend::IsAddressInCodeBuffer, which real
  // signal handlers call (SignalDelegator.cpp, checking a faulting PC) - a signal can land on a
  // thread that is already inside a lock this table's own reader/writer path might take (e.g. mid-
  // VirtualAlloc while lazily compiling a new code buffer), and mutexes are not async-signal-safe
  // regardless of recursiveness, so a lock here can self-deadlock the interrupted thread. Regions
  // are only ever appended, never removed (VirtualFree only unmaps the writable alias - the table
  // entry, and the RX region it describes, is intentionally left in place, matching the Unicorn
  // backend's own JIT26 usage, which never frees its region either), so a lock-free, append-only
  // scheme works: each slot's Size field is the publish flag, written last with release ordering
  // once RWBase/RXBase are already in place, and read first with acquire ordering by every reader -
  // that ordering is what makes RWBase/RXBase visible together with a non-zero Size, so a reader
  // (including one running inside a signal handler) never blocks and never sees a torn entry.
  struct Region {
    uintptr_t RWBase = 0;
    uintptr_t RXBase = 0;
    std::atomic<size_t> Size {0};
  };

  // A handful of long-lived regions (the dispatcher, plus one CodeBuffer generation per guest
  // thread and any it outlives briefly for signal-handler safety) - registration is nowhere near
  // hot enough (once per allocation) to need more than a generous fixed capacity.
  inline constexpr size_t MaxRegions = 64;
  inline Region g_Regions[MaxRegions] {};
  inline std::atomic<size_t> g_NextRegionIndex {0};

  inline void RegisterRegion(void* RX, void* RW, size_t Size) {
    const size_t Index = g_NextRegionIndex.fetch_add(1, std::memory_order_relaxed);
    if (Index >= MaxRegions) {
      // A fresh JIT26 region would silently fall through ToExecutable()/ToWritable() as "not a
      // JIT26 region at all" (plain identity) from here on, reintroducing exactly the RX/RW bug
      // this table exists to fix - fail loudly rather than let that miscompile silently.
      LogMan::Msg::EFmt("JIT26: region table exhausted ({} regions already registered) - a fresh "
                        "writable alias will not convert to its executable address",
                        MaxRegions);
      assert(false && "JIT26Detail::g_Regions exhausted - raise MaxRegions");
      return;
    }
    Region& R = g_Regions[Index];
    R.RWBase = reinterpret_cast<uintptr_t>(RW);
    R.RXBase = reinterpret_cast<uintptr_t>(RX);
    R.Size.store(Size, std::memory_order_release);

    // Temporary device-debugging aid: a fault PC that falls in [RW, RW+Size) rather than
    // [RX, RX+Size) means something branched to this region's writable alias instead of
    // converting through ToExecutable() first - this line makes both sides of every registered
    // region visible so that comparison can be made directly against a captured fault address.
    LogMan::Msg::IFmt("JIT26: registered region RW=[0x{:x}, 0x{:x}) RX=[0x{:x}, 0x{:x})", R.RWBase, R.RWBase + Size, R.RXBase,
                      R.RXBase + Size);
  }

  inline void* ToExecutable(void* Ptr) {
    const auto Addr = reinterpret_cast<uintptr_t>(Ptr);
    for (auto& R : g_Regions) {
      const size_t Size = R.Size.load(std::memory_order_acquire);
      if (Size != 0 && Addr >= R.RWBase && Addr < R.RWBase + Size) {
        return reinterpret_cast<void*>(R.RXBase + (Addr - R.RWBase));
      }
    }
    // Already executable (or not a JIT26 region at all) - identity.
    return Ptr;
  }

  inline void* ToWritable(void* Ptr) {
    const auto Addr = reinterpret_cast<uintptr_t>(Ptr);
    for (auto& R : g_Regions) {
      const size_t Size = R.Size.load(std::memory_order_acquire);
      if (Size != 0 && Addr >= R.RXBase && Addr < R.RXBase + Size) {
        return reinterpret_cast<void*>(R.RWBase + (Addr - R.RXBase));
      }
    }
    // Already writable (or not a JIT26 region at all) - identity.
    return Ptr;
  }

  inline void* AllocateExecutable(void* Hint, size_t Size) {
    void* const RX = fexcore_jit26_prepare_region(Hint, Size);
    if (RX == nullptr) {
      return nullptr;
    }
    int KernReturn = 0;
    unsigned int CurProt = 0, MaxProt = 0;
    void* const RW = fexcore_jit26_writable_alias(RX, Size, &KernReturn, &CurProt, &MaxProt);
    if (RW == nullptr) {
      // No writable alias - handing back the RX region directly means the first attempt to write
      // generated code through it will fault, but that's no worse than returning nullptr here and
      // having every caller's null-check fire instead.
      return RX;
    }
    RegisterRegion(RX, RW, Size);
    return RW;
  }
} // namespace JIT26Detail
#endif
#endif

inline void* VirtualAlloc(size_t Size, bool Execute = false, bool Commit = true) {
#ifdef __APPLE__
#if TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
  if (Execute) {
    return JIT26Detail::AllocateExecutable(nullptr, Size);
  }
#endif
  return FEXCore::Allocator::mmap(nullptr, Size, PROT_READ | PROT_WRITE | (Execute ? PROT_EXEC : 0),
                                  MAP_PRIVATE | MAP_ANONYMOUS | MapJitFlagIfExecutable(Execute), -1, 0);
#else
  return FEXCore::Allocator::mmap(nullptr, Size, PROT_READ | PROT_WRITE | (Execute ? PROT_EXEC : 0), MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
}

inline void* VirtualAlloc(void* Base, size_t Size, bool Execute = false, bool Commit = true) {
#ifdef __APPLE__
#if TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
  if (Execute) {
    return JIT26Detail::AllocateExecutable(Base, Size);
  }
#endif
  return FEXCore::Allocator::mmap(Base, Size, PROT_READ | PROT_WRITE | (Execute ? PROT_EXEC : 0),
                                  MAP_PRIVATE | MAP_ANONYMOUS | MapJitFlagIfExecutable(Execute), -1, 0);
#else
  return FEXCore::Allocator::mmap(Base, Size, PROT_READ | PROT_WRITE | (Execute ? PROT_EXEC : 0), MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
}

#ifdef __APPLE__
// Toggles the calling thread's JIT write-protection (Apple Silicon's W^X enforcement is
// per-thread, not per-mapping): writable-and-not-executable while `false`, executable-and-not-
// writable while `true`. Must bracket any code that writes into a MAP_JIT region - wrap the
// coarse "compile one block" / "emit one stub" boundary, not individual instruction emits, since
// toggling has real per-call overhead.
struct JITWriteScope {
  // Real iOS device has no per-thread JIT-write-protect API at all (pthread_jit_write_protect_np
  // doesn't exist there) - real device write/execute control instead needs the JIT26
  // breakpoint-protocol split-mapping technique, wired into this allocator separately. The
  // Simulator is a plain macOS process (same kernel, same libpthread), so Apple Silicon's
  // per-thread MAP_JIT W^X model applies there exactly as it does on desktop macOS, and skipping
  // the toggle faults the very first JIT write with EXC_BAD_ACCESS/SIGBUS (confirmed empirically).
  // The iOS SDK headers mark the symbol `unavailable` for both iOS targets regardless (it links
  // fine on the Simulator, which really is the host macOS kernel), so it's resolved via dlsym
  // instead of calling it directly - that sidesteps the compile-time availability annotation, and
  // naturally no-ops on real device too (dlsym returns null there, matching the intended no-op).
  JITWriteScope() {
#if defined(__APPLE__) && !TARGET_OS_IPHONE
    ::pthread_jit_write_protect_np(0);
#elif defined(__APPLE__)
    JITWriteScope::CallJitWriteProtect(0);
#endif
  }
  ~JITWriteScope() {
#if defined(__APPLE__) && !TARGET_OS_IPHONE
    ::pthread_jit_write_protect_np(1);
#elif defined(__APPLE__)
    JITWriteScope::CallJitWriteProtect(1);
#endif
  }
  JITWriteScope(const JITWriteScope&) = delete;
  JITWriteScope& operator=(const JITWriteScope&) = delete;

#if defined(__APPLE__) && TARGET_OS_IPHONE
private:
  static void CallJitWriteProtect(int Enabled) {
    using JitWriteProtectNpFn = void (*)(int);
    static auto* const Fn = reinterpret_cast<JitWriteProtectNpFn>(::dlsym(RTLD_DEFAULT, "pthread_jit_write_protect_np"));
    if (Fn != nullptr) {
      Fn(Enabled);
    }
  }
#endif
};
#endif

inline void VirtualFree(void* Ptr, size_t Size) {
  // If Ptr is a JIT26 writable alias (i.e. it came from VirtualAlloc(..., Execute=true) on real
  // iOS device), this is an ordinary mach_vm_remap() mapping and munmap()-ing it here as usual is
  // fine. Its JIT26Detail table entry is deliberately left in place, not removed: the RX region it
  // aliases has no "unprepare" counterpart to JIT26's blessing anyway (so it's left mapped too,
  // matching the Unicorn backend's own JIT26 usage), and the table is append-only/lock-free
  // specifically so ToExecutable()/ToWritable() never block a signal handler - removing entries
  // would need synchronization that reintroduces that hazard for no real benefit.
  FEXCore::Allocator::munmap(Ptr, Size);
}
inline void VirtualDontNeed(void* Ptr, size_t Size, bool Recommit = true) {
#ifdef __APPLE__
  // Darwin's madvise(MADV_DONTNEED) does NOT zero-fill anonymous pages the way Linux does - it is
  // effectively advisory - so every caller that relies on VirtualDontNeed to *clear* memory would
  // silently keep stale data on macOS. The critical one is LookupCache::ClearThreadLocalCaches, run on
  // each JIT code-buffer switch (ChangeGuestToHostMapping) to drop the per-thread L1/L2 block lookup
  // cache: with the clear silently no-op'ing, a stale entry mapping a guest RIP to an older buffer's
  // host code survives, and once that buffer is freed the dispatcher jumps into it - inaccessible
  // (PROT_NONE) on Apple - and faults. Honour the zero-on-reuse contract explicitly: for page-aligned
  // regions replace them with fresh, zero-filled, decommitted anonymous pages (mmap MAP_FIXED, the
  // Darwin equivalent of Linux's MADV_DONTNEED on anonymous memory - this also keeps the large, sparsely
  // populated L2 page table from being fully committed by a plain memset); zero the rare sub-page
  // caller in place (__builtin_memset avoids pulling <string.h> into this widely-included header).
  const uintptr_t Addr = reinterpret_cast<uintptr_t>(Ptr);
  if ((Addr & (FEXCore::Utils::FEX_HOST_PAGE_SIZE - 1)) == 0 && (Size & (FEXCore::Utils::FEX_HOST_PAGE_SIZE - 1)) == 0) {
    ::mmap(Ptr, Size, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (PagesReplaced) {
      PagesReplaced(Ptr, Size);
    }
  } else {
    __builtin_memset(Ptr, 0, Size);
  }
#else
  ::madvise(reinterpret_cast<void*>(Ptr), Size, MADV_DONTNEED);
#endif
}
inline bool VirtualProtect(void* Ptr, size_t Size, ProtectOptions options) {
  int prot {PROT_NONE};
  if ((options & ProtectOptions::Read) == ProtectOptions::Read) {
    prot |= PROT_READ;
  }
  if ((options & ProtectOptions::Write) == ProtectOptions::Write) {
    prot |= PROT_WRITE;
  }
  if ((options & ProtectOptions::Exec) == ProtectOptions::Exec) {
    prot |= PROT_EXEC;
  }

  return ::mprotect(Ptr, Size, prot) == 0;
}

inline void VirtualTHPControl(const void* Ptr, size_t Size, THPControl Control) {
#ifdef __APPLE__
  // Darwin has no per-mapping transparent-huge-page madvise hint; the VM system manages this itself.
  (void)Ptr;
  (void)Size;
  (void)Control;
#else
  ::madvise(const_cast<void*>(Ptr), Size, Control == THPControl::Enable ? MADV_HUGEPAGE : MADV_NOHUGEPAGE);
#endif
}

#endif

// Splitwx (execute-only / write-only split mapping) address conversion. Identity on every
// configuration except real iOS device, where VirtualAlloc(..., Execute=true) hands back a JIT26
// writable alias rather than the real executable address (see JIT26Detail::AllocateExecutable
// above): anything that needs to actually branch to, call, or icache-invalidate a JIT-generated
// address must convert it with JIT26ToExecutable() first; anything that needs to write through an
// address it only has in executable form (e.g. one derived from an actually-executing PC, which
// can only ever be the real RX address) must convert the other way with JIT26ToWritable() first.
inline void* JIT26ToExecutable(void* Ptr) {
#if defined(__APPLE__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
  return JIT26Detail::ToExecutable(Ptr);
#else
  return Ptr;
#endif
}

inline void* JIT26ToWritable(void* Ptr) {
#if defined(__APPLE__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
  return JIT26Detail::ToWritable(Ptr);
#else
  return Ptr;
#endif
}

// Memory allocation routines to be defined externally.
// This allows to use jemalloc for emulation while using the normal allocator
// for host tools without building FEXCore twice.
void* malloc(size_t size);
void* calloc(size_t n, size_t size);
void* memalign(size_t align, size_t s);
void* valloc(size_t size);
int posix_memalign(void** r, size_t a, size_t s);
void* realloc(void* ptr, size_t size);
void free(void* ptr);
size_t malloc_usable_size(void* ptr);
void* aligned_alloc(size_t a, size_t s);
void aligned_free(void* ptr);

FEX_DEFAULT_VISIBILITY extern void InitializeThread();

#ifndef _WIN32
void SetupAllocatorHooks(void* (*)(void* addr, size_t length, int prot, int flags, int fd, off_t offset), int (*)(void* addr, size_t length));
#endif

struct FEXAllocOperators {
  FEXAllocOperators() = default;

  void* operator new(size_t size) {
    return FEXCore::Allocator::malloc(size);
  }

  void* operator new(size_t size, std::align_val_t align) {
    return FEXCore::Allocator::aligned_alloc(static_cast<size_t>(align), size);
  }

  void operator delete(void* ptr) {
    return FEXCore::Allocator::free(ptr);
  }

  void operator delete(void* ptr, std::align_val_t align) {
    return FEXCore::Allocator::aligned_free(ptr);
  }
};
} // namespace FEXCore::Allocator
