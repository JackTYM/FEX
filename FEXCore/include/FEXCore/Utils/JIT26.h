// SPDX-License-Identifier: MIT
#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void jit26_detach(void);
void *jit26_prepare_region(void *address, size_t length);
bool jit26_is_debugged(void);
void *jit26_writable_alias(void *rx_address, size_t length, int *out_kern_return, unsigned int *out_cur_prot,
                            unsigned int *out_max_prot);

#ifdef __cplusplus
}
#endif
