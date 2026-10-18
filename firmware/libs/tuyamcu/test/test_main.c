#include "harness.h"
#include "tests.h"

int t_checks, t_fails;

int main(void)
{
    run_codec_tests();
    run_proto_tests();
    printf("%d checks, %d failed\n", t_checks, t_fails);
    return t_fails ? 1 : 0;
}
