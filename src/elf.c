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
#include "utils.h"
#include "view.h"

#define Elf_PROP(bits, prop) Elf##bits##prop

#define NX_CHECK(_context, elf_ehdr, elf_phdr)                                 \
  for (size_t i = 0; i < elf_ehdr->e_phnum; i++) {                             \
    if (elf_phdr[i].p_type == PT_GNU_STACK && !(elf_phdr[i].p_flags & PF_X)) { \
      _context->elf_prot.nx = true;                                            \
      break;                                                                   \
    }                                                                          \
  }

#define PIE_CHECK(_context, elf_ehdr, elf_phdr)       \
  if (elf_ehdr->e_type == ET_DYN) {                   \
    _context->elf_prot.pie = true;                    \
  } else {                                            \
    for (size_t i = 0; i < elf_ehdr->e_phnum; i++) {  \
      if (elf_phdr[i].p_type == PT_LOAD) {            \
        _context->elf_prot.pie = elf_phdr[i].p_vaddr; \
        break;                                        \
      }                                               \
    }                                                 \
  }

#define RELRO_CHECK(BITS, _context, elf_ehdr, elf_phdr, elf_shdr)             \
  for (size_t i = 0; i < elf_ehdr->e_phnum; i++) {                            \
    if (elf_phdr[i].p_type == PT_GNU_RELRO) {                                 \
      _context->elf_prot.relro = RELRO_PARTIAL;                               \
      break;                                                                  \
    }                                                                         \
  }                                                                           \
  for (size_t i = 0; i < elf_ehdr->e_shnum; i++) {                            \
    if (elf_shdr[i].sh_type == SHT_DYNAMIC) {                                 \
      Elf_PROP(BITS, _Dyn) *dot_dynamic =                                     \
          (Elf_PROP(BITS, _Dyn) *)((void *)elf_ehdr + elf_shdr[i].sh_offset); \
      int num = elf_shdr[i].sh_size / elf_shdr[i].sh_entsize, flags;          \
      for (size_t j = 0; j < num; j++) {                                      \
        if (dot_dynamic[j].d_tag == DT_FLAGS) {                               \
          flags = dot_dynamic[j].d_un.d_val;                                  \
          if (flags & DF_BIND_NOW) {                                          \
            _context->elf_prot.relro = RELRO_FULL;                            \
            break;                                                            \
          }                                                                   \
        }                                                                     \
        if (dot_dynamic[j].d_tag == DT_FLAGS_1) {                             \
          flags = dot_dynamic[j].d_un.d_val;                                  \
          if (flags & DF_1_NOW) {                                             \
            _context->elf_prot.relro = RELRO_FULL;                            \
            break;                                                            \
          }                                                                   \
        }                                                                     \
      }                                                                       \
    }                                                                         \
  }

#define RWX_CHECK(_context, elf_ehdr, elf_phdr)    \
  for (size_t i = 0; i < elf_ehdr->e_phnum; i++) { \
    int rwx = PF_X | PF_W;                         \
    if ((elf_phdr[i].p_flags & rwx) == rwx) {      \
      _context->elf_prot.rwx_seg = true;           \
      break;                                       \
    }                                              \
  }

#define WRITEABLE_CHECK(_context, elf_ehdr, elf_phdr) \
  for (size_t i = 0; i < elf_ehdr->e_phnum; i++) {    \
    int rw = PF_W;                                    \
    if ((elf_phdr[i].p_flags & rw) == rw) {           \
      _context->elf_prot.writable_seg = true;         \
      break;                                          \
    }                                                 \
  }

#define CANARY_CHECK(BITS, _context, elf_ehdr, elf_shdr)                      \
  for (size_t i = 0; i < elf_ehdr->e_phnum; i++) {                            \
    if (elf_shdr[i].sh_type == SHT_DYNSYM) {                                  \
      Elf_PROP(BITS, _Sym) *dot_sym =                                         \
          (Elf_PROP(BITS, _Sym) *)((void *)elf_ehdr + elf_shdr[i].sh_offset); \
      int num = elf_shdr[i].sh_size / elf_shdr[i].sh_entsize;                 \
      void *sdata =                                                           \
          (void *)elf_ehdr + elf_shdr[elf_shdr[i].sh_link].sh_offset;         \
      for (size_t j = 0; j < num; j++) {                                      \
        char *func_name = sdata + dot_sym[j].st_name;                         \
        if (func_name == NULL || !is_pointer_valid(func_name)) continue;      \
        if (strcmp(func_name, CANARY_STR_1) == 0 ||                           \
            strcmp(func_name, CANARY_STR_2) == 0) {                           \
          _context->elf_prot.canary = true;                                   \
          break;                                                              \
        }                                                                     \
      }                                                                       \
    }                                                                         \
  }

#define FORTIFY_CHECK(BITS, _context, elf_ehdr, elf_shdr)                     \
  for (size_t i = 0; i < elf_ehdr->e_phnum; i++) {                            \
    if (elf_shdr[i].sh_type == SHT_DYNSYM) {                                  \
      Elf_PROP(BITS, _Sym) *dot_sym =                                         \
          (Elf_PROP(BITS, _Sym) *)((void *)elf_ehdr + elf_shdr[i].sh_offset); \
      int num = elf_shdr[i].sh_size / elf_shdr[i].sh_entsize;                 \
      void *sdata =                                                           \
          (void *)elf_ehdr + elf_shdr[elf_shdr[i].sh_link].sh_offset;         \
      for (size_t j = 0; j < num; j++) {                                      \
        char *func_name = sdata + dot_sym[j].st_name;                         \
        if (func_name == NULL || !is_pointer_valid(func_name)) continue;      \
        if (ends_with(func_name, FORTIFY_SUFFIX)) {                           \
          _context->elf_prot.fortify++;                                       \
        }                                                                     \
      }                                                                       \
    }                                                                         \
  }

bool is_pointer_valid(void *p) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  void *basex = (void *)((((size_t)p) / page_size) * page_size);
  return msync(basex, page_size, MS_ASYNC) == 0;
}

int elf32_parse(elf_ctx_t *context) {
  // elf base header
  Elf32_Ehdr *elf_ehdr = (Elf32_Ehdr *)context->file_load->map_addr;
  // Section header table file offset
  Elf32_Shdr *elf_shdr =
      (Elf32_Shdr *)(context->file_load->map_addr + elf_ehdr->e_shoff);
  // Program header table file offset
  Elf32_Phdr *elf_phdr =
      (Elf32_Phdr *)(context->file_load->map_addr + elf_ehdr->e_phoff);

  context->arch.e_machine = elf_ehdr->e_machine;
  context->arch.e_classtype = elf_ehdr->e_ident[EI_CLASS];
  context->arch.endian = elf_ehdr->e_ident[EI_DATA];

  // https://github.com/torvalds/linux/blob/v4.9/fs/binfmt_elf.c#L784-L789
  NX_CHECK(context, elf_ehdr, elf_phdr)
  // if binary type is DYN, pie is enable
  PIE_CHECK(context, elf_ehdr, elf_phdr)
  // relro
  RELRO_CHECK(32, context, elf_ehdr, elf_phdr, elf_shdr)
  // rwx segments
  RWX_CHECK(context, elf_ehdr, elf_phdr)
  // writable segments
  WRITEABLE_CHECK(context, elf_ehdr, elf_phdr)
  // canary
  CANARY_CHECK(32, context, elf_ehdr, elf_shdr)
  // fortify
  FORTIFY_CHECK(32, context, elf_ehdr, elf_shdr)
  return 0;
}

int elf64_parse(elf_ctx_t *context) {
  // elf base header
  Elf64_Ehdr *elf_ehdr = (Elf64_Ehdr *)context->file_load->map_addr;
  // Section header table file offset
  Elf64_Shdr *elf_shdr =
      (Elf64_Shdr *)(context->file_load->map_addr + elf_ehdr->e_shoff);
  // Program header table file offset
  Elf64_Phdr *elf_phdr =
      (Elf64_Phdr *)(context->file_load->map_addr + elf_ehdr->e_phoff);

  context->arch.e_machine = elf_ehdr->e_machine;
  context->arch.e_classtype = elf_ehdr->e_ident[EI_CLASS];
  context->arch.endian = elf_ehdr->e_ident[EI_DATA];

  // https://github.com/torvalds/linux/blob/v4.9/fs/binfmt_elf.c#L784-L789
  NX_CHECK(context, elf_ehdr, elf_phdr)
  // if binary type is DYN, pie is enable
  PIE_CHECK(context, elf_ehdr, elf_phdr)
  // relro
  RELRO_CHECK(64, context, elf_ehdr, elf_phdr, elf_shdr)
  // rwx segments
  RWX_CHECK(context, elf_ehdr, elf_phdr)
  // writable segments
  WRITEABLE_CHECK(context, elf_ehdr, elf_phdr)
  // canary
  CANARY_CHECK(64, context, elf_ehdr, elf_shdr)

  // fortify
  FORTIFY_CHECK(64, context, elf_ehdr, elf_shdr)
  return 0;
}

int elf_parse(elf_ctx_t *context) {
  // check magic
  if (memcmp(context->file_load->map_addr, ELFMAG, SELFMAG) != 0) return -1;
  int ret;

  context->elf_prot.relro = RELRO_NONE;
  context->elf_prot.canary = false;
  context->elf_prot.nx = false;
  context->elf_prot.pie = false;
  context->elf_prot.fortify = false;
  context->elf_prot.rwx_seg = false;

  int8_t *class_ptr = context->file_load->map_addr + EI_CLASS;  // e_type
  if (*class_ptr == ELFCLASS64)
    ret = elf64_parse(context);
  else if (*class_ptr == ELFCLASS32)
    ret = elf32_parse(context);
  else {
    fprintf(stderr, "Unknow class\n");
    ret = -2;
  }

  return ret;
}

int elf_load(file_load_t *file_ctx) {
  elf_ctx_t context;
  context.file_load = file_ctx;
  if (elf_parse(&context) != 0) {
    fprintf(stderr, "Error to parse \"%s\" file\nthis is really a elf?\n",
            file_ctx->path);
    return -1;
  }
  elf_format_context(&context);
  unload_file(file_ctx);
  return 0;
}