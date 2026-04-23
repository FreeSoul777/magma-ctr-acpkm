#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <stdint.h>

void benchmark_file_encryption(uint8_t* key, uint64_t iv);
void benchmark_rekey_blocks(uint8_t* key);
void benchmark_memory_cpu(uint8_t* key, uint64_t iv);
void run_all_benchmarks(uint8_t* key, uint64_t iv);

#endif