#include "utils.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "elf_def.h"
#include "macho.h"

bool ends_with(const char* str, const char* suffix) {
  if (!str || !suffix) return 0;
  size_t lenstr = strlen(str);
  size_t lensuffix = strlen(suffix);
  if (lensuffix > lenstr) return 0;
  return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

int load_file(file_load_t* context, const char* pathname) {
  memset(context, 0, sizeof(void));

  context->path = strdup(pathname);
  if (context->path == NULL) return -1;

  const int fd = open(pathname, O_RDONLY);
  if (fd < 0) return -2;

  struct stat stat;
  int ret = fstat(fd, &stat);

  if (ret == -1) {
    close(fd);
    return -3;
  }

  if (!S_ISREG(stat.st_mode)) {
    close(fd);
    return -4;
  }
  context->map_size = stat.st_size;

  context->map_addr =
      mmap(NULL, context->map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  if (context->map_addr == MAP_FAILED) {
    close(fd);
    return -5;
  }
  return 0;
}

int unload_file(file_load_t* context) {
  if (context->path != NULL) free(context->path);

  if (context->map_addr != NULL) {
    int ret = munmap(context->map_addr, context->map_size);
    if (ret != 0) {
      // perror("munmap");
      return -1;
    }
  }

  memset(context, 0, sizeof(file_load_t));
  return 0;
}

bool is_elf(file_load_t* file_ctx) {
  if (memcmp(file_ctx->map_addr, ELFMAG, SELFMAG) != 0)
    return false;
  else
    return true;
}

bool is_macho(file_load_t* file_ctx) {
  uint32_t magic = *(uint32_t*)file_ctx->map_addr;
  if (magic == MH_MAGIC || magic == MH_CIGAM || magic == MH_MAGIC_64 ||
      magic == MH_CIGAM_64)
    return true;
  else
    return false;
}

bool is_fat_macho(file_load_t* file_ctx) {
  uint32_t magic = *(uint32_t*)file_ctx->map_addr;
  if (magic == FAT_MAGIC || magic == FAT_CIGAM)
    return true;
  else
    return false;
}

uint32_t swap_uint32(uint32_t val) {
  val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
  return (val << 16) | (val >> 16);
}

// uint64_t swap_uint64(uint64_t val) {
//   val = ((val << 8) & 0xFF00FF00FF00FF00ULL) |
//         ((val >> 8) & 0x00FF00FF00FF00FFULL);
//   val = ((val << 16) & 0xFFFF0000FFFF0000ULL) |
//         ((val >> 16) & 0x0000FFFF0000FFFFULL);
//   return (val << 32) | (val >> 32);
// }