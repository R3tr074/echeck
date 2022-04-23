/**
 * Elf parser
 */

#include "elf.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "macros.h"

int elf_load_file(elf_ctx_t *context, const char *pathname) {
  memset(context, 0, sizeof(elf_ctx_t));

  context->path = strdup(pathname);
  if (context->path == NULL) return -1;

  const int fd = open(context->path, O_RDONLY);
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

int elf_unload_file(elf_ctx_t *context) {
  if (context->path != NULL) free(context->path);

  if (context->map_addr != NULL) {
    int ret = munmap(context->map_addr, context->map_size);
    if (ret != 0) {
      // perror("munmap");
      return -1;
    }
  }

  memset(context, 0, sizeof(elf_ctx_t));
  return 0;
}

bool is_pointer_valid(void *p) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  void *basex = (void *)((((size_t)p) / page_size) * page_size);
  return msync(basex, page_size, MS_ASYNC) == 0;
}

int elf32_parse(elf_ctx_t *context) {
  // elf base header
  Elf32_Ehdr *elf_ehdr = (Elf32_Ehdr *)context->map_addr;
  // Section header table file offset
  Elf32_Shdr *elf_shdr = (Elf32_Shdr *)(context->map_addr + elf_ehdr->e_shoff);
  // Program header table file offset
  Elf32_Phdr *elf_phdr = (Elf32_Phdr *)(context->map_addr + elf_ehdr->e_phoff);

  context->arch.e_machine = elf_ehdr->e_machine;
  context->arch.e_classtype = elf_ehdr->e_ident[EI_CLASS];
  context->arch.endian = elf_ehdr->e_ident[EI_DATA];

  // https://github.com/torvalds/linux/blob/v4.9/fs/binfmt_elf.c#L784-L789
  size_t i, j;
  for (i = 0; i < elf_ehdr->e_phnum; i++) {
    if (elf_phdr[i].p_type == PT_GNU_STACK && !(elf_phdr[i].p_flags & PF_X)) {
      context->elf_prot.nx = true;
      break;
    }
  }

  // if binary type is DYN, pie is enable
  if (elf_ehdr->e_type == ET_DYN) {
    context->elf_prot.pie = true;
  } else {
    // Address base
    for (i = 0; i < elf_ehdr->e_phnum; i++) {
      if (elf_phdr[i].p_type == PT_LOAD) {
        context->elf_prot.pie = elf_phdr[i].p_vaddr;
        break;
      }
    }
  }

  // relro
  for (i = 0; i < elf_ehdr->e_phnum; i++) {
    if (elf_phdr[i].p_type == PT_GNU_RELRO) {
      context->elf_prot.relro = RELRO_PARTIAL;
      break;
    }
  }
  for (i = 0; i < elf_ehdr->e_shnum; i++) {
    if (elf_shdr[i].sh_type == SHT_DYNAMIC) {
      Elf32_Dyn *dot_dynamic =
          (Elf32_Dyn *)((void *)elf_ehdr + elf_shdr[i].sh_offset);
      int num = elf_shdr[i].sh_size / elf_shdr[i].sh_entsize, flags;

      for (j = 0; j < num; j++) {
        if (dot_dynamic[j].d_tag == DT_FLAGS) {
          flags = dot_dynamic[j].d_un.d_val;
          if (flags & DF_BIND_NOW) {
            context->elf_prot.relro = RELRO_FULL;
            break;
          }
        }

        if (dot_dynamic[j].d_tag == DT_FLAGS_1) {
          flags = dot_dynamic[j].d_un.d_val;
          if (flags & DF_1_NOW) {
            context->elf_prot.relro = RELRO_FULL;
            break;
          }
        }
      }
    }
  }

  // rwx segments
  for (i = 0; i < elf_ehdr->e_phnum; i++) {
    int rwx = PF_X | PF_W;
    if ((elf_phdr[i].p_flags & rwx) == rwx) {
      context->elf_prot.rwx_seg = true;
      break;
    }
  }

  // writable segments
  for (i = 0; i < elf_ehdr->e_phnum; i++) {
    int rw = PF_W;
    if ((elf_phdr[i].p_flags & rw) == rw) {
      context->elf_prot.writable_seg = true;
      break;
    }
  }

  return 0;
}

int elf64_parse(elf_ctx_t *context) {
  // elf base header
  Elf64_Ehdr *elf_ehdr = (Elf64_Ehdr *)context->map_addr;
  // Section header table file offset
  Elf64_Shdr *elf_shdr = (Elf64_Shdr *)(context->map_addr + elf_ehdr->e_shoff);
  // Program header table file offset
  Elf64_Phdr *elf_phdr = (Elf64_Phdr *)(context->map_addr + elf_ehdr->e_phoff);

  context->arch.e_machine = elf_ehdr->e_machine;
  context->arch.e_classtype = elf_ehdr->e_ident[EI_CLASS];
  context->arch.endian = elf_ehdr->e_ident[EI_DATA];

  // https://github.com/torvalds/linux/blob/v4.9/fs/binfmt_elf.c#L784-L789
  size_t i, j;
  for (i = 0; i < elf_ehdr->e_phnum; i++) {
    if (elf_phdr[i].p_type == PT_GNU_STACK && !(elf_phdr[i].p_flags & PF_X)) {
      context->elf_prot.nx = true;
      break;
    }
  }

  // if binary type is DYN, pie is enable
  if (elf_ehdr->e_type == ET_DYN) {
    context->elf_prot.pie = true;
  } else {
    // Address base
    for (i = 0; i < elf_ehdr->e_phnum; i++) {
      if (elf_phdr[i].p_type == PT_LOAD) {
        context->elf_prot.pie = elf_phdr[i].p_vaddr;
        break;
      }
    }
  }

  // canary
  for (i = 0; i < elf_ehdr->e_phnum; i++) {
    if (elf_shdr[i].sh_type == SHT_DYNSYM) {
      Elf64_Sym *dot_sym =
          (Elf64_Sym *)((void *)elf_ehdr + elf_shdr[i].sh_offset);
      int num = elf_shdr[i].sh_size / elf_shdr[i].sh_entsize;
      void *sdata = (void *)elf_ehdr + elf_shdr[elf_shdr[i].sh_link].sh_offset;
      for (j = 0; j < num; j++) {
        if (sdata + dot_sym[j].st_name == NULL ||
            !is_pointer_valid(sdata + dot_sym[j].st_name))
          continue;

        if (strcmp((char *)(sdata + dot_sym[j].st_name), CANARY_STR_1) == 0 ||
            strcmp((char *)(sdata + dot_sym[j].st_name), CANARY_STR_2) == 0) {
          context->elf_prot.canary = true;
          break;
        }
      }
    }
  }

  // relro
  for (i = 0; i < elf_ehdr->e_phnum; i++) {
    if (elf_phdr[i].p_type == PT_GNU_RELRO) {
      context->elf_prot.relro = RELRO_PARTIAL;
      break;
    }
  }
  for (i = 0; i < elf_ehdr->e_shnum; i++) {
    if (elf_shdr[i].sh_type == SHT_DYNAMIC) {
      Elf64_Dyn *dot_dynamic =
          (Elf64_Dyn *)((void *)elf_ehdr + elf_shdr[i].sh_offset);
      int num = elf_shdr[i].sh_size / elf_shdr[i].sh_entsize, flags;

      for (j = 0; j < num; j++) {
        if (dot_dynamic[j].d_tag == DT_FLAGS) {
          flags = dot_dynamic[j].d_un.d_val;
          if (flags & DF_BIND_NOW) {
            context->elf_prot.relro = RELRO_FULL;
            break;
          }
        }

        if (dot_dynamic[j].d_tag == DT_FLAGS_1) {
          flags = dot_dynamic[j].d_un.d_val;
          if (flags & DF_1_NOW) {
            context->elf_prot.relro = RELRO_FULL;
            break;
          }
        }
      }
    }
  }

  // rwx segments
  for (i = 0; i < elf_ehdr->e_phnum; i++) {
    int rwx = PF_X | PF_W;
    if ((elf_phdr[i].p_flags & rwx) == rwx) {
      context->elf_prot.rwx_seg = true;
      break;
    }
  }

  // writable segments
  for (i = 0; i < elf_ehdr->e_phnum; i++) {
    int rw = PF_W;
    if ((elf_phdr[i].p_flags & rw) == rw) {
      context->elf_prot.writable_seg = true;
      break;
    }
  }

  return 0;
}

int elf_parse(elf_ctx_t *context) {
  // check magic
  if (memcmp(context->map_addr, ELFMAG, SELFMAG) != 0) return -1;
  int ret;

  context->elf_prot.relro = RELRO_NONE;
  context->elf_prot.canary = false;
  context->elf_prot.nx = false;
  context->elf_prot.pie = false;

  int8_t *class_ptr = context->map_addr + EI_CLASS;  // e_type
  // int8_t *e_machine = context->map_addr + EI_CLASS + 4;  // e_machine
  // context->arch = *e_machine;

  if (*class_ptr == ELFCLASS64) {
    ret = elf64_parse(context);
  } else if (*class_ptr == ELFCLASS32) {
    ret = elf32_parse(context);
  } else {
    fprintf(stderr, "Unknow class\n");
    ret = -2;
  }

  return ret;
}