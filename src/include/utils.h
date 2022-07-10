#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct file_load {
  void* map_addr;
  char* path;
  uintptr_t map_end;
  off_t map_size;
} file_load_t;

bool ends_with(const char* str, const char* suffix);
int load_file(file_load_t* context, const char* pathname);
int unload_file(file_load_t* context);
bool is_elf(file_load_t* file_ctx);
bool is_macho(file_load_t* file_ctx);
bool is_fat_macho(file_load_t* file_ctx);
uint32_t swap_uint32(uint32_t val);

#endif