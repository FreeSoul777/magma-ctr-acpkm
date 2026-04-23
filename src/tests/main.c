#include "benchmark.h"
#include "test_ctr_acpkm.h"
#include "test_magma.h"

#include <stdint.h>
#include <stdio.h>

int main(void)
{
    printf("Magma ACPKM Test Suite\n");

    int magma_ok = test_magma_rfc8891();
    int ctr_ok   = test_ctr_acpkm();

    printf("\nCryptographic tests: %s\n\n", (magma_ok && ctr_ok) ? "PASSED" : "FAILED");

    if (magma_ok && ctr_ok)
    {
        uint8_t  key[32] = {0};
        uint64_t iv      = 0x1234567890ABCDEFULL;
        run_all_benchmarks(key, iv);
    }

    printf("\nDone.\n");
    return (magma_ok && ctr_ok) ? 0 : 1;
}