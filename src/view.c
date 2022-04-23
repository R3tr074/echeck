// Context print formater

#include "view.h"

#include <stdlib.h>
#include <string.h>

#include "elf.h"
#define SPACE "    "

char *join_arch_string(elf_ctx_t *context) {
  char *arch_name, *arch_bits, *arch_endian;
  size_t string_len;

  switch (context->arch.e_machine) {
    case EM_386:
    case EM_860:
      arch_name = "i386";
      break;
    case EM_ARM:
      arch_name = "arm";
      break;
    case EM_X86_64:
      arch_name = "amd64";
      break;
    default:
      arch_name = "unknown";
  }

  switch (context->arch.e_classtype) {
    case ELFCLASS32:
      arch_bits = "32";
      break;
    case ELFCLASS64:
      arch_bits = "64";
      break;
    default:
      arch_bits = "unknown";
  }

  switch (context->arch.endian) {
    case ELFDATA2LSB:
      arch_endian = "little";
      break;
    case ELFDATA2MSB:
      arch_endian = "big";
      break;
    default:
      arch_endian = "unknown";
  }

  string_len = strlen(arch_name) + strlen(arch_endian) + strlen(arch_bits) + 3;
  char *arch_full = malloc(string_len);

  snprintf(arch_full, string_len, "%s-%s-%s", arch_name, arch_bits,
           arch_endian);
  return arch_full;
}

void format_context(elf_ctx_t *context) {
  printf("%s '%s'\n", INFO_MSG, context->path);

  char *arch_name = join_arch_string(context);
  printf(SPACE "Arch: " SPACE "%s\n", arch_name);

  printf(SPACE "RELRO:" SPACE);
  switch (context->elf_prot.relro) {
    case RELRO_NONE:
      printf(RED "No RELRO\n" NO_COLOR);
      break;
    case RELRO_PARTIAL:
      printf(YELLOW "Partial RELRO\n" NO_COLOR);
      break;
    case RELRO_FULL:
      printf(GREEN "Full RELRO\n" NO_COLOR);
      break;
  }

  printf(SPACE "Stack:" SPACE);
  if (context->elf_prot.canary) {
    printf(GREEN "Canary found\n" NO_COLOR);
  } else {
    printf(RED "No canary found\n" NO_COLOR);
  }

  printf(SPACE "NX:   " SPACE);
  if (context->elf_prot.nx) {
    printf(GREEN "NX enabled\n" NO_COLOR);
  } else {
    printf(RED "NX disabled\n" NO_COLOR);
  }

  printf(SPACE "PIE:  " SPACE);
  if (context->elf_prot.pie == true) {
    printf(GREEN "PIE enabled\n" NO_COLOR);
  } else {
    printf(RED "No PIE (0x%x)\n" NO_COLOR, context->elf_prot.pie);
  }

  if (context->elf_prot.rwx_seg ||
      (!(context->elf_prot.nx) && context->elf_prot.writable_seg)) {
    printf(SPACE "RWX:  " SPACE RED "Has RWX segments\n" NO_COLOR);
  }

  free(arch_name);
  return;
}
