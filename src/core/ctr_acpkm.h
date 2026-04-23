#ifndef CTR_ACPKM_H
#define CTR_ACPKM_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef struct
{
    uint64_t counter;
    uint32_t round_keys[32];
    uint64_t blocks_processed;
    uint64_t max_blocks_per_key;
    int      key_locked;
    time_t   expires_at;
} ctr_acpkm_ctx;

void ctr_acpkm_init(ctr_acpkm_ctx* ctx, const uint8_t master_key[32], uint64_t iv, uint64_t max_blocks,
                    time_t lifetime_seconds);
void ctr_acpkm_destroy(ctr_acpkm_ctx* ctx);
int  ctr_acpkm_crypt(ctr_acpkm_ctx* ctx, const uint8_t* input, uint8_t* output, size_t length);

int encrypt_file(const char* input_file, const char* output_file, uint8_t* key, uint64_t iv, uint64_t max_blocks);
int decrypt_file(const char* input_file, const char* output_file, uint8_t* key, uint64_t iv, uint64_t max_blocks);

#endif