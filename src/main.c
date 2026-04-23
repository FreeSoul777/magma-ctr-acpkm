#include "core/ctr_acpkm.h"
#include "utils/logging.h"
#include "utils/utils.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char* argv[])
{
    atexit(log_close);

    log_init();
    LOG("SYSTEM", "Program started");

    if (!self_test())
    {
        printf("FATAL: Self-test FAILED!\n");
        LOG("SYSTEM", "FATAL: Self-test FAILED");
        return 1;
    }
    printf("Self-test PASSED\n\n");

    if (!integrity_check(argv[0]))
    {
        printf("FATAL: Integrity check FAILED!\n");
        LOG("SYSTEM", "FATAL: Integrity check FAILED");
        return 1;
    }
    printf("Integrity check PASSED\n\n");

    if (argc < 3)
    {
        printf("ERROR: Key file required\n");
        printf("\nUsage:\n");
        printf("  %s --key-file KEYFILE enc|dec input output\n", argv[0]);
        printf("\nExample:\n");
        printf("  %s --key-file key.bin enc plain.txt encrypted.bin\n", argv[0]);
        printf("  %s --key-file key.bin dec encrypted.bin decrypted.txt\n", argv[0]);
        LOG("SYSTEM", "FATAL: No key file provided");
        return 1;
    }

    if (strcmp(argv[1], "--key-file") != 0)
    {
        printf("ERROR: First argument must be --key-file\n");
        return 1;
    }

    const char* keyfile = argv[2];
    uint8_t     key[32];

    if (load_key_from_file(keyfile, key, 32) != 0)
    {
        printf("ERROR: Failed to load key from file: %s\n", keyfile);
        return 1;
    }
    printf("Key loaded from: %s\n", keyfile);

    if (secure_lock_memory(key, 32) != 0)
    {
        LOG("KEY", "Warning: Could not lock key memory");
    }

    int    remaining_argc = argc - 3;
    char** remaining_argv = &argv[3];

    if (remaining_argc < 3)
    {
        printf("ERROR: Missing mode or input/output files\n");
        printf("Usage: %s --key-file KEYFILE enc|dec input output\n", argv[0]);
        secure_zero(key, 32);
        secure_unlock_memory(key, 32);
        return 1;
    }

    const char* mode   = remaining_argv[0];
    const char* input  = remaining_argv[1];
    const char* output = remaining_argv[2];

    uint64_t iv         = 0x1234567890ABCDEFULL;
    uint64_t max_blocks = 1000000;

    int result = 0;

    if (strcmp(mode, "enc") == 0)
    {
        printf("Encrypting %s -> %s\n", input, output);
        result = encrypt_file(input, output, key, iv, max_blocks);
        if (result == 0)
        {
            printf("Encryption completed successfully\n");
            LOG("SYSTEM", "File encryption completed");
        }
        else
        {
            printf("Encryption failed\n");
            LOG("SYSTEM", "File encryption FAILED");
        }
    }
    else if (strcmp(mode, "dec") == 0)
    {
        printf("Decrypting %s -> %s\n", input, output);
        result = decrypt_file(input, output, key, iv, max_blocks);
        if (result == 0)
        {
            printf("Decryption completed successfully\n");
            LOG("SYSTEM", "File decryption completed");
        }
        else
        {
            printf("Decryption failed\n");
            LOG("SYSTEM", "File decryption FAILED");
        }
    }
    else
    {
        printf("ERROR: Unknown mode '%s'. Use 'enc' or 'dec'\n", mode);
        result = 1;
    }

    secure_zero(key, 32);
    secure_unlock_memory(key, 32);

    LOG("SYSTEM", "Program finished");
    return result;
}