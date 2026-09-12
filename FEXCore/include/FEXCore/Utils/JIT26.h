// SPDX-License-Identifier: MIT
// Prefixed fexcore_ rather than reusing the plain jit26_* names: this project's own
// tools/sogen-ios/Sources/JIT/JIT26.c (the SogenIOS app target) defines the same-named C
// functions, and both this file's implementation and that one end up as strong symbols in the
// same final SogenIOS binary once FEXCore's allocator actually calls these - unprefixed, that's a
// duplicate-symbol link error.
#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void fexcore_jit26_detach(void);
void *fexcore_jit26_prepare_region(void *address, size_t length);
bool fexcore_jit26_is_debugged(void);
void *fexcore_jit26_writable_alias(void *rx_address, size_t length, int *out_kern_return, unsigned int *out_cur_prot,
                                    unsigned int *out_max_prot);

#ifdef __cplusplus
}
#endif
