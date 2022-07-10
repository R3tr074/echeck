#include "macho.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"
#include "view.h"

#define CANARY_CHECK(context, func)            \
  if (strcmp(func, CANARY_MACHO_STR_1) == 0 || \
      strcmp(func, CANARY_MACHO_STR_2) == 0) { \
    context->macho_prot.canary = true;         \
  }

#define ARC_CHECK(context, func)    \
  if (strcmp(func, ARC_STR) == 0) { \
    context->macho_prot.arc = true; \
  }

#define CMD_SETUP(context, mach_hdr, load_cmd, symtab, dysymtab)           \
  for (size_t i = 0; i < mach_hdr->ncmds; i++) {                           \
    switch (load_cmd->cmd) {                                               \
      case LC_SYMTAB:                                                      \
        symtab = (symtab_command_t *)load_cmd;                             \
        break;                                                             \
      case LC_DYSYMTAB:                                                    \
        dysymtab = (dysymtab_command_t *)load_cmd;                         \
        break;                                                             \
      case LC_ENCRYPTION_INFO:                                             \
      case LC_ENCRYPTION_INFO_64:                                          \
        context->macho_prot.encrypted = true;                              \
        break;                                                             \
      case LC_CODE_SIGNATURE:                                              \
        context->macho_prot.code_signature = true;                         \
        break;                                                             \
      case LC_RPATH:                                                       \
        context->macho_prot.rpath =                                        \
            (void *)load_cmd + ((rpath_command_t *)load_cmd)->path.offset; \
        break;                                                             \
    }                                                                      \
    load_cmd = (void *)load_cmd + load_cmd->cmdsize;                       \
  }

int macho32_parse(macho_ctx_t *context) { puts("32 bits"); }
int macho64_parse(macho_ctx_t *context) {
  void *base_addr = context->file_load->map_addr;
  mach_header_64_t *macho_hdr = (mach_header_64_t *)base_addr;
  load_command_t *load_cmd =
      (load_command_t *)(base_addr + sizeof(mach_header_64_t));
  symtab_command_t *symtab = NULL;
  dysymtab_command_t *dysymtab = NULL;

  CMD_SETUP(context, macho_hdr, load_cmd, symtab, dysymtab)

  const char *string_table = base_addr + symtab->stroff;
  nlist_64_t *nlist = base_addr + symtab->symoff;
  nlist_64_t *nlist_imports = nlist + dysymtab->iundefsym;
  // all symbols
  for (size_t i = 0; i < symtab->nsyms; ++i) {
    const char *symbol = string_table + nlist[i].n_un.n_strx;
    if (ends_with(symbol, FORTIFY_SUFFIX)) {
      context->macho_prot.fortify++;
    }
  }
  // imports
  for (size_t i = 0; i < dysymtab->nundefsym; ++i) {
    char *func_name = string_table + nlist_imports[i].n_un.n_strx;
    CANARY_CHECK(context, func_name)
    ARC_CHECK(context, func_name)
  }
  return 0;
}

int macho_parse(macho_ctx_t *context) {
  int ret = 0;
  context->macho_prot.canary = false;
  context->macho_prot.fortify = false;
  context->macho_prot.code_signature = false;
  context->macho_prot.arc = false;
  context->macho_prot.encrypted = false;
  context->macho_prot.rpath = NULL;

  mach_header_t *macho_hdr = (mach_header_t *)context->file_load->map_addr;
  context->macho_prot.nx = !(macho_hdr->flags & MH_ALLOW_STACK_EXECUTION);
  context->macho_prot.pie = !!(macho_hdr->flags & MH_PIE);
  context->macho_arch.cputype = macho_hdr->cputype;
  context->macho_arch.cpusubtype = macho_hdr->cpusubtype;

  if ((context->macho_arch.cputype & CPU_ARCH_MASK) == CPU_ARCH_ABI64)
    ret = macho64_parse(context);
  else
    ret = macho32_parse(context);

  return ret;
}

int macho_load(file_load_t *file_ctx) {
  macho_ctx_t context;
  context.file_load = file_ctx;
  if (macho_parse(&context) != 0) {
    fprintf(stderr, "Error to parse \"%s\" file\nthis is really a mach-o?\n",
            file_ctx->path);
    return -1;
  }
  macho_format_context(&context);
  unload_file(file_ctx);
  return 0;
}

int macho_fat_load(file_load_t *file_ctx) {
  fat_header_t *fat_header = (fat_header_t *)file_ctx->map_addr;
  fat_arch_t *fat_arch = file_ctx->map_addr + sizeof(fat_header_t);
  macho_ctx_t context;
  void *fat_base = file_ctx->map_addr;

  for (size_t i = 0; i < swap_uint32(fat_header->nfat_arch); i++) {
    context.file_load = file_ctx;
    void *base = fat_base + swap_uint32(fat_arch[i].offset);
    file_ctx->map_addr = base;
    if (macho_parse(&context) != 0) {
      fprintf(stderr, "Error to parse \"%s\" file\nthis is really a mach-o?\n",
              file_ctx->path);
      return -1;
    }
    macho_format_context(&context);
    memset(&context, 0, sizeof(macho_ctx_t));
  }
  return 0;
}