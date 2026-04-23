#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>

void secure_zero(void* ptr, size_t len);
void secure_free(void* ptr, size_t len);
int  secure_lock_memory(void* ptr, size_t len);
void secure_unlock_memory(void* ptr, size_t len);
void print_hex(const char* label, const uint8_t* data, int len);

void pad_block(uint8_t* block, size_t data_len, size_t block_size);
int  unpad_block(uint8_t* block, size_t block_size, size_t* data_len);

int load_key_from_file(const char* filename, uint8_t* key, size_t key_size);
int integrity_check(const char* filename);

#endif