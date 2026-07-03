// SPDX-License-Identifier: MIT
#pragma once
#include <cstddef>

namespace FEXCore::Utils {
// FEX assumes an operating page size of 4096
// To work around build systems that build on a 16k/64k page size, define our page size here
// Don't use the system provided PAGE_SIZE define because of this.
//
// This is the x86 GUEST's page size, an architectural constant that must stay 4096 regardless of
// host page size. It is NOT the granularity the host kernel's mprotect() actually operates at -
// see FEX_HOST_PAGE_SIZE below for that.
constexpr size_t FEX_PAGE_SIZE = 4096;
constexpr size_t FEX_PAGE_SHIFT = 12;
constexpr size_t FEX_PAGE_MASK = ~(FEX_PAGE_SIZE - 1);

// The host's actual mprotect()/mmap() granularity, used for pages that need independent host-side
// protection (e.g. guard pages, InterruptFaultPage) rather than guest VA bookkeeping. On Linux
// this coincides with FEX_PAGE_SIZE; Apple Silicon's XNU kernel fixes this at 16KB with no way to
// get 4KB host pages, so protecting a FEX_PAGE_SIZE-sized region at a FEX_PAGE_SIZE-aligned
// address would operate on the wrong granularity (or fail outright: mprotect requires the start
// address to be host-page-aligned).
#ifdef __APPLE__
constexpr size_t FEX_HOST_PAGE_SIZE = 16384;
#else
constexpr size_t FEX_HOST_PAGE_SIZE = FEX_PAGE_SIZE;
#endif
} // namespace FEXCore::Utils
