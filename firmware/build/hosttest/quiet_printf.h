/* Force-included into the host mbedtls objects only: the SDK's ctr_drbg.c prints a debug line on every
 * seed ("mbedtls_ctr_drbg_seed: line is 457"). The tests' own printf calls are not affected. */
#pragma once
#include <stdio.h>
#define printf(...) ((void)0)
