#include "ctr_acpkm.h"

#include "magma.h"

#include "utils/logging.h"
#include "utils/utils.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int ctr_acpkm_is_expired(const ctr_acpkm_ctx* ctx)
{
    if (ctx->expires_at == 0)
        return 0;
    return time(NULL) > ctx->expires_at;
}

static void acpkm_transform(const uint32_t current_keys[32], uint32_t next_keys[32])
{
    static const uint8_t constants[4][8] = {{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
                                            {0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02},
                                            {0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03},
                                            {0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04}};

    uint8_t encrypted[8];
    uint8_t new_key[32] = {0};

    for (int i = 0; i < 4; i++)
    {
        magma_encrypt_block(constants[i], current_keys, encrypted);
        memcpy(new_key + i * 8, encrypted, 8);
    }

    magma_expand_key(new_key, next_keys);
    secure_zero(new_key, sizeof(new_key));
}

void ctr_acpkm_init(ctr_acpkm_ctx* ctx, const uint8_t master_key[32], uint64_t iv, uint64_t max_blocks,
                    time_t lifetime_seconds)
{
    char log_msg[256];

    uint32_t round_keys[32];
    magma_expand_key(master_key, round_keys);
    memcpy(ctx->round_keys, round_keys, sizeof(ctx->round_keys));
    secure_zero(round_keys, sizeof(round_keys));

    ctx->key_locked         = (secure_lock_memory(ctx->round_keys, sizeof(ctx->round_keys)) == 0);
    ctx->counter            = iv;
    ctx->blocks_processed   = 0;
    ctx->max_blocks_per_key = max_blocks ? max_blocks : (1ULL << 20);
    ctx->expires_at         = (lifetime_seconds == 0) ? 0 : time(NULL) + lifetime_seconds;

    snprintf(log_msg, sizeof(log_msg), "Key created, max_blocks=%llu, expires_at=%ld, mlock=%s",
             (unsigned long long)max_blocks, (long)ctx->expires_at, ctx->key_locked ? "yes" : "no");
    LOG("KEY", log_msg);
}

void ctr_acpkm_destroy(ctr_acpkm_ctx* ctx)
{
    LOG("KEY", "Key destroyed");
    if (ctx->key_locked)
        secure_unlock_memory(ctx->round_keys, sizeof(ctx->round_keys));
    secure_zero(ctx->round_keys, sizeof(ctx->round_keys));
    ctx->key_locked = 0;
}

static void ctr_acpkm_rekey(ctr_acpkm_ctx* ctx)
{
    LOG("REKEY", "Re-keying triggered");

    uint32_t next_keys[32];
    acpkm_transform(ctx->round_keys, next_keys);

    secure_zero(ctx->round_keys, sizeof(ctx->round_keys));
    if (ctx->key_locked)
        secure_unlock_memory(ctx->round_keys, sizeof(ctx->round_keys));

    memcpy(ctx->round_keys, next_keys, sizeof(ctx->round_keys));
    secure_zero(next_keys, sizeof(next_keys));

    if (secure_lock_memory(ctx->round_keys, sizeof(ctx->round_keys)) == 0)
        ctx->key_locked = 1;
    ctx->blocks_processed = 0;

    LOG("REKEY", "New key installed");
}

int ctr_acpkm_crypt(ctr_acpkm_ctx* ctx, const uint8_t* input, uint8_t* output, size_t length)
{
    if (ctr_acpkm_is_expired(ctx))
    {
        LOG("EXPIRY", "Key expired - encryption rejected");
        return -1;
    }

    uint8_t counter_block[8];
    uint8_t keystream[8];
    size_t  processed = 0;

    while (processed < length)
    {
        if (ctx->blocks_processed >= ctx->max_blocks_per_key)
        {
            ctr_acpkm_rekey(ctx);
            if (ctr_acpkm_is_expired(ctx))
            {
                LOG("EXPIRY", "Key expired - encryption rejected");
                return -1;
            }
        }

        uint64_t counter_val = ctx->counter++;
        counter_block[0]     = (counter_val >> 56) & 0xFF;
        counter_block[1]     = (counter_val >> 48) & 0xFF;
        counter_block[2]     = (counter_val >> 40) & 0xFF;
        counter_block[3]     = (counter_val >> 32) & 0xFF;
        counter_block[4]     = (counter_val >> 24) & 0xFF;
        counter_block[5]     = (counter_val >> 16) & 0xFF;
        counter_block[6]     = (counter_val >> 8) & 0xFF;
        counter_block[7]     = counter_val & 0xFF;

        magma_encrypt_block(counter_block, ctx->round_keys, keystream);

        size_t remaining  = length - processed;
        size_t block_size = (remaining < 8) ? remaining : 8;

        for (size_t i = 0; i < block_size; i++)
        {
            output[processed + i] = input[processed + i] ^ keystream[i];
        }

        processed += block_size;
        ctx->blocks_processed++;
    }
    return 0;
}

int encrypt_file(const char* input_file, const char* output_file, uint8_t* key, uint64_t iv, uint64_t max_blocks)
{
    FILE* in = fopen(input_file, "rb");
    if (!in)
    {
        LOG("FILE", "Cannot open input file");
        return -1;
    }

    FILE* out = fopen(output_file, "wb");
    if (!out)
    {
        fclose(in);
        LOG("FILE", "Cannot open output file");
        return -1;
    }

    ctr_acpkm_ctx ctx;
    ctr_acpkm_init(&ctx, key, iv, max_blocks, 3600);
    secure_zero(key, 32);

    uint8_t  buffer[8];
    uint8_t  encrypted[8];
    size_t   bytes_read;
    uint64_t total_bytes = 0;

    while ((bytes_read = fread(buffer, 1, 8, in)) > 0)
    {
        if (ctr_acpkm_crypt(&ctx, buffer, encrypted, bytes_read) != 0)
        {
            LOG("FILE", "Encryption failed (key expired?)");
            fclose(in);
            fclose(out);
            ctr_acpkm_destroy(&ctx);
            return -1;
        }
        fwrite(encrypted, 1, bytes_read, out);
        total_bytes += bytes_read;
    }

    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Encrypted %llu bytes from %s to %s", (unsigned long long)total_bytes,
             input_file, output_file);
    LOG("FILE", log_msg);

    fclose(in);
    fclose(out);
    ctr_acpkm_destroy(&ctx);
    return 0;
}

int decrypt_file(const char* input_file, const char* output_file, uint8_t* key, uint64_t iv, uint64_t max_blocks)
{
    FILE* in = fopen(input_file, "rb");
    if (!in)
    {
        LOG("FILE", "Cannot open input file");
        return -1;
    }

    FILE* out = fopen(output_file, "wb");
    if (!out)
    {
        fclose(in);
        LOG("FILE", "Cannot open output file");
        return -1;
    }

    ctr_acpkm_ctx ctx;
    ctr_acpkm_init(&ctx, key, iv, max_blocks, 3600);
    secure_zero(key, 32);

    uint8_t  buffer[8];
    uint8_t  decrypted[8];
    size_t   bytes_read;
    uint64_t total_bytes = 0;

    while ((bytes_read = fread(buffer, 1, 8, in)) > 0)
    {
        if (ctr_acpkm_crypt(&ctx, buffer, decrypted, bytes_read) != 0)
        {
            LOG("FILE", "Decryption failed");
            fclose(in);
            fclose(out);
            ctr_acpkm_destroy(&ctx);
            return -1;
        }
        fwrite(decrypted, 1, bytes_read, out);
        total_bytes += bytes_read;
    }

    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Decrypted %llu bytes from %s to %s", (unsigned long long)total_bytes,
             input_file, output_file);
    LOG("FILE", log_msg);

    fclose(in);
    fclose(out);
    ctr_acpkm_destroy(&ctx);
    return 0;
}