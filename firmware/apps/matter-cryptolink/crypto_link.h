// Link test for the Matter crypto set. crypto_link_keep() calls crypto_link_run() only if the
// volatile flag is set (never), so the linker keeps every referenced mbedtls function.
#pragma once

extern volatile int crypto_link_enable;
int crypto_link_run(void); // returns the number of failed self-checks
const void *libs_link_keep(void); // libs_link.c: address table of every Matter lib function
void crypto_link_keep(void);
