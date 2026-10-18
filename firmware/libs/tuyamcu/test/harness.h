/* Tiny assert harness. */
#ifndef HARNESS_H
#define HARNESS_H

#include <stdio.h>
#include <string.h>

extern int t_checks, t_fails;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        t_checks++;                                                                                \
        if (!(cond)) {                                                                             \
            t_fails++;                                                                             \
            printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                               \
        }                                                                                          \
    } while (0)
#define CHECK_EQ(a, b) CHECK((long)(a) == (long)(b))
#define CHECK_MEM(a, b, n) CHECK(memcmp((a), (b), (n)) == 0)

#define RUN(fn)                                                                                    \
    do {                                                                                           \
        int before = t_fails;                                                                      \
        fn();                                                                                      \
        printf("%s %s\n", t_fails == before ? "ok  " : "FAIL", #fn);                               \
    } while (0)

#endif
