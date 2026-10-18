// SPDX-License-Identifier: MIT
#pragma once

#include "Interface/IR/IR.h"
#include <cstdint>

namespace FEXCore::IR {
class IREmitter;

// Embedder-specific (sogen) constant: on Apple Silicon macOS, every process has a mandatory,
// unshrinkable 4GB __PAGEZERO segment - the entire guest address range a real 32-bit x86 process
// needs (image base, stack, heap, both 32-bit ntdll/kernel32) is permanently unmappable there.
// When the embedder opts in (Context::Config.NeedsWow64GuestRebase), LoadEffectiveAddress/
// SelectAddressMode (Addressing.cpp) and Decoder::AdjustAddrForSpecialRegion (Frontend.cpp) add this
// to every sub-4GB guest memory dereference/instruction fetch so the embedder can back that memory at
// real host addresses (guest_addr + this), while the guest itself only ever sees ordinary, unrebased
// address values. Without the opt-in, guest and host addresses are identical in both modes. See
// OpDispatchBuilder::GuestMemoryRebase() (OpcodeDispatcher.h) for the call-site helper.
//
// This is only the DEFAULT (Context::Config.Wow64GuestRebaseValue's initial value, for embedders
// that never call SetWow64GuestRebaseValue - public Context.h) - not necessarily what actually gets
// used. A fixed compile-time value here is fragile in practice: on Apple Silicon macOS, the actual
// host VA a real embedder can safely rebase into depends on what else this specific process has
// already mapped (other frameworks' own dyld-load-time reservations, scaled to this machine's
// physical RAM in ways that vary a lot from host to host), which no single constant can account
// for. sogen calls SetWow64GuestRebaseValue with a value it probes for at runtime instead of
// relying on this default - see fex_x86_64_emulator.cpp's reserve_wow64_host_window.
inline constexpr uint64_t WOW64_GUEST_REBASE = 0x400000000ULL;

// A 32-bit x86 guest's entire architectural address space is bounded by its 32-bit pointers -
// this is the only range that ever needs WOW64_GUEST_REBASE applied. Kept separate from
// WOW64_GUEST_REBASE itself (the unrelated offset actually added) - see GuestRebaseInfo's doc
// comment for why the two must not be conflated.
inline constexpr uint64_t WOW64_GUEST_ADDRESS_SPACE_SIZE = 0x100000000ULL;

// Describes how LoadEffectiveAddress/SelectAddressMode should apply WOW64_GUEST_REBASE, returned
// by OpDispatchBuilder::GuestMemoryRebase() (OpcodeDispatcher.h):
//  - Rebase == 0: no rebase at all (the embedder did not opt in).
//  - Rebase != 0, Conditional == false: unconditionally add Rebase (a 32-bit-mode block - every
//    address it computes is inherently below WOW64_GUEST_ADDRESS_SPACE_SIZE already, so an
//    unconditional add is correct and cheaper than a runtime check).
//  - Rebase != 0, Conditional == true: add Rebase only if the computed address is below
//    WOW64_GUEST_ADDRESS_SPACE_SIZE (a genuine runtime check, emitted as an IR Select) - a
//    64-bit-mode block of a wow64 process, where some real 64-bit-executed content (the wow64 TEB
//    pair, wow64cpu.dll, the heaven's-gate trampoline) lives below 4GB for 32-bit-pointer
//    reachability, but ordinary 64-bit addresses (heap/stack/module data) are not restricted to any
//    particular range and must NOT be blanket-rebased.
struct GuestRebaseInfo {
  uint64_t Rebase {0};
  bool Conditional {false};
};

struct AddressMode {
  Ref Segment {nullptr};
  Ref Base {nullptr};
  Ref Index {nullptr};
  int64_t Offset = 0;

  MemOffsetType IndexType = MemOffsetType::SXTX;
  uint8_t IndexScale = 1;

  // Size in bytes for the address calculation. 8 for an arm64 hardware mode.
  IR::OpSize AddrSize;
  bool NonTSO;
};

Ref LoadEffectiveAddress(IREmitter* IREmit, const AddressMode& A, IR::OpSize GPRSize, bool AddSegmentBase, bool AllowUpperGarbage = false,
                         GuestRebaseInfo Rebase = {});
AddressMode SelectAddressMode(IREmitter* IREmit, const AddressMode& A, IR::OpSize GPRSize, bool HostSupportsTSOImm9, bool AtomicTSO,
                              bool Vector, IR::OpSize AccessSize, GuestRebaseInfo Rebase = {});

} // namespace FEXCore::IR