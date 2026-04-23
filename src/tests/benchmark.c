#include "core/ctr_acpkm.h"
#include "utils/utils.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

static double get_time_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

static void create_test_file(const char* filename, size_t size_mb)
{
    FILE* f = fopen(filename, "wb");
    if (!f)
        return;

    uint8_t* buf = malloc(1024 * 1024);
    memset(buf, 0xAA, 1024 * 1024);

    for (size_t i = 0; i < size_mb; i++)
        fwrite(buf, 1, 1024 * 1024, f);

    free(buf);
    fclose(f);
}

void benchmark_file_encryption(uint8_t* key, uint64_t iv)
{
    printf("--- 3.1 File Encryption/Decryption ---\n");
    printf("| %-7s | %-11s | %-11s | %-13s | %-13s |\n", "Size", "Encrypt(ms)", "Decrypt(ms)", "Encrypt(MB/s)",
           "Decrypt(MB/s)");
    printf("|---------|-------------|-------------|---------------|---------------|\n");

    const int sizes[] = {1, 100, 1000};

    for (int i = 0; i < 3; i++)
    {
        char name[32];
        snprintf(name, sizeof(name), "test_%dmb", sizes[i]);
        create_test_file(name, sizes[i]);

        char enc_name[64], dec_name[64];
        snprintf(enc_name, sizeof(enc_name), "%s.enc", name);
        snprintf(dec_name, sizeof(dec_name), "%s.dec", name);

        double start    = get_time_ms();
        int    ok       = encrypt_file(name, enc_name, key, iv, 1000000);
        double enc_time = get_time_ms() - start;

        if (ok != 0)
        {
            printf("| %-7d | %-11s | %-11s | %-13s | %-13s |\n", sizes[i], "ERROR", "-", "-", "-");
            unlink(name);
            continue;
        }

        start           = get_time_ms();
        ok              = decrypt_file(enc_name, dec_name, key, iv, 1000000);
        double dec_time = get_time_ms() - start;

        double size_mb   = sizes[i];
        double enc_speed = size_mb / (enc_time / 1000.0);
        double dec_speed = size_mb / (dec_time / 1000.0);

        printf("| %-7d | %-11.2f | %-11.2f | %-13.2f | %-13.2f |\n", sizes[i], enc_time, dec_time, enc_speed,
               dec_speed);

        unlink(name);
        unlink(enc_name);
        unlink(dec_name);
    }
}

void benchmark_rekey_blocks(uint8_t* key)
{
    printf("--- 3.2 Rekey Benchmark (1,000,000 blocks = 8 MB) ---\n");
    printf("| %-8s | %-8s | %-11s | %-6s | %-6s |\n", "Interval", "Time(ms)", "Speed(MB/s)", "Rekeys", "Status");
    printf("|----------|----------|-------------|--------|--------|\n");

    const uint64_t blocks      = 1000000;
    const uint64_t intervals[] = {10, 100, 1000};
    uint8_t        data[8]     = {0};
    uint8_t        out[8];

    for (int i = 0; i < 3; i++)
    {
        ctr_acpkm_ctx ctx;
        ctr_acpkm_init(&ctx, key, 0, intervals[i], 0);

        double start = get_time_ms();
        for (uint64_t j = 0; j < blocks; j++)
            ctr_acpkm_crypt(&ctx, data, out, 8);
        double elapsed = get_time_ms() - start;

        double   data_mb = (blocks * 8) / (1024.0 * 1024.0);
        double   speed   = data_mb / (elapsed / 1000.0);
        uint64_t rekeys  = blocks / intervals[i];

        printf("| %-8llu | %-8.2f | %-11.2f | %-6llu | %-6s |\n", (unsigned long long)intervals[i], elapsed, speed,
               (unsigned long long)rekeys, "OK");

        ctr_acpkm_destroy(&ctx);
    }
}

void benchmark_memory_cpu(uint8_t* key, uint64_t iv)
{
    printf("--- 3.3 Memory/CPU Usage (during 100 MB encryption) ---\n");

    create_test_file("test_mem", 100);

    struct rusage ru_before, ru_after;
    double        realtime_start = get_time_ms();

    getrusage(RUSAGE_SELF, &ru_before);
    encrypt_file("test_mem", "test_mem.enc", key, iv, 1000000);
    getrusage(RUSAGE_SELF, &ru_after);
    double realtime_end = get_time_ms();

    double realtime_ms = realtime_end - realtime_start;
    double user_time   = (ru_after.ru_utime.tv_sec - ru_before.ru_utime.tv_sec) * 1000.0
                       + (ru_after.ru_utime.tv_usec - ru_before.ru_utime.tv_usec) / 1000.0;
    double sys_time = (ru_after.ru_stime.tv_sec - ru_before.ru_stime.tv_sec) * 1000.0
                      + (ru_after.ru_stime.tv_usec - ru_before.ru_stime.tv_usec) / 1000.0;
    long max_rss = ru_after.ru_maxrss;

    printf("  Real time:       %-12.2f ms\n", realtime_ms);
    printf("  CPU user time:   %-12.2f ms\n", user_time);
    printf("  CPU system time: %-12.2f ms\n", sys_time);
    printf("  Max RSS:         %-12.2f MB (%ld KB)\n", max_rss / 1024.0, max_rss);

    unlink("test_mem");
    unlink("test_mem.enc");
}

void run_all_benchmarks(uint8_t* key, uint64_t iv)
{
    printf("=== Test 3: BENCHMARK ===\n\n");

    benchmark_file_encryption(key, iv);
    printf("\n");
    benchmark_rekey_blocks(key);
    printf("\n");
    benchmark_memory_cpu(key, iv);
}