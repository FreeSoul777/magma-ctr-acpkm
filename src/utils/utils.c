#include "utils.h"

#include "logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/mman.h>
#include <sys/stat.h>
#endif

void secure_zero(void* ptr, size_t len)
{
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (len--)
        *p++ = 0;
}

void secure_free(void* ptr, size_t len)
{
    if (ptr && len)
    {
        secure_zero(ptr, len);
        free(ptr);
    }
}

int secure_lock_memory(void* ptr, size_t len)
{
#ifdef __linux__
    return mlock(ptr, len);
#else
    return -1;
#endif
}

void secure_unlock_memory(void* ptr, size_t len)
{
#ifdef __linux__
    munlock(ptr, len);
#endif
}

void print_hex(const char* label, const uint8_t* data, int len)
{
    printf("%s: ", label);
    for (int i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

void pad_block(uint8_t* block, size_t data_len, size_t block_size)
{
    if (data_len >= block_size)
        return;
    block[data_len] = 0x80;
    for (size_t i = data_len + 1; i < block_size; i++)
        block[i] = 0;
}

int unpad_block(uint8_t* block, size_t block_size, size_t* data_len)
{
    int last_one = -1;
    for (int i = (int)block_size - 1; i >= 0; i--)
        if (block[i] == 0x80)
        {
            last_one = i;
            break;
        }
    if (last_one == -1)
        return -1;
    for (int i = last_one + 1; i < (int)block_size; i++)
        if (block[i] != 0)
            return -1;
    *data_len = last_one;
    return 0;
}

int load_key_from_file(const char* filename, uint8_t* key, size_t key_size)
{
    FILE* f = fopen(filename, "rb");
    if (!f)
    {
        char msg[256];
        snprintf(msg, sizeof(msg), "Failed to open key file: %s", filename);
        LOG("KEY", msg);
        return -1;
    }

#ifdef __linux__
    struct stat st;
    if (fstat(fileno(f), &st) != 0)
    {
        LOG("KEY", "Failed to get key file stats");
        fclose(f);
        return -1;
    }

    if (st.st_uid != getuid())
    {
        LOG("KEY", "Key file owned by another user");
        fclose(f);
        return -1;
    }

    if ((st.st_mode & 0777) != 0600)
    {
        char msg[256];
        snprintf(msg, sizeof(msg), "Insecure permissions on %s: expected 600, got %03o", filename, st.st_mode & 0777);
        LOG("KEY", msg);
        fclose(f);
        return -1;
    }
#endif

    size_t read = fread(key, 1, key_size, f);
    fclose(f);

    if (read != key_size)
    {
        char msg[256];
        snprintf(msg, sizeof(msg), "Key file size mismatch: expected %zu, got %zu", key_size, read);
        LOG("KEY", msg);
        return -1;
    }

    char msg[256];
    snprintf(msg, sizeof(msg), "Key loaded from %s", filename);
    LOG("KEY", msg);
    return 0;
}

static uint32_t crc32_table[256];
static int      crc32_initialized = 0;

static void crc32_init_table(void)
{
    if (crc32_initialized)
        return;
    for (uint32_t i = 0; i < 256; i++)
    {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320 : 0);
        crc32_table[i] = crc;
    }
    crc32_initialized = 1;
}

static uint32_t crc32_calc(const uint8_t* data, size_t len)
{
    crc32_init_table();
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++)
        crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFF];
    return crc ^ 0xFFFFFFFF;
}

static uint32_t get_file_crc(const char* filename)
{
    FILE* f = fopen(filename, "rb");
    if (!f)
        return 0;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t* buf = malloc(size);
    if (!buf)
    {
        fclose(f);
        return 0;
    }

    size_t read = fread(buf, 1, size, f);
    fclose(f);

    uint32_t crc = crc32_calc(buf, read);
    free(buf);
    return crc;
}

static uint32_t    stored_crc       = 0;
static const char* crc_storage_file = ".magma_crc";

int integrity_check(const char* filename)
{
#ifdef DEV_MODE
    LOG("INTEGRITY", "Check skipped (DEV_MODE)");
    return 1;
#endif

    uint32_t current_crc = get_file_crc(filename);
    if (current_crc == 0)
    {
        LOG("INTEGRITY", "Failed to read executable file");
        return 0;
    }

    FILE* f = fopen(crc_storage_file, "r");
    if (f)
    {
        if (fscanf(f, "%08X", &stored_crc) != 1)
            stored_crc = 0;
        fclose(f);
    }

    if (stored_crc == 0)
    {
        stored_crc = current_crc;
        f          = fopen(crc_storage_file, "w");
        if (f)
        {
            fprintf(f, "%08X\n", stored_crc);
            fclose(f);
        }
        char msg[256];
        snprintf(msg, sizeof(msg), "Initial CRC stored: 0x%08X (first run)", stored_crc);
        LOG("INTEGRITY", msg);
        return 1;
    }

    if (current_crc != stored_crc)
    {
        char msg[256];
        snprintf(msg, sizeof(msg), "FAILED! File modified: CRC was 0x%08X, now 0x%08X", stored_crc, current_crc);
        LOG("INTEGRITY", msg);
        return 0;
    }

    LOG("INTEGRITY", "Check passed");
    return 1;
}