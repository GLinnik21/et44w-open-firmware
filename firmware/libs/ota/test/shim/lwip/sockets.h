/* Host test shim: the upload is read from a buffer (fake.c). */
#pragma once
#include <stddef.h>
int recv(int sock, void* buf, size_t n, int flags);
