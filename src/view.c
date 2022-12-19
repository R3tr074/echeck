// Context print formater

#include "view.h"

#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "elf_def.h"
#include "macho.h"
#define SPACE "    "

char *elf_join_arch_string(elf_ctx_t *context) {
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
    case EM_AARCH64:
      arch_name = "aarch";
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

char *mach_join_arch_string(macho_ctx_t *context) {
  char *arch_name, *arch_bits, *arch_endian;
  size_t string_len;

  if (context->macho_arch.cputype == CPU_TYPE_I386)
    arch_name = "i386";
  else if (context->macho_arch.cputype == CPU_TYPE_X86_64)
    arch_name = "amd64";
  else if (context->macho_arch.cputype == CPU_TYPE_ARM)
    arch_name = "arm";
  else if (context->macho_arch.cputype == CPU_TYPE_ARM64)
    arch_name = "aarch";
  else
    arch_name = "unknown";

  if ((context->macho_arch.cputype & CPU_ARCH_MASK) == CPU_ARCH_ABI64)
    arch_bits = "64";
  else
    arch_bits = "32";

  if ((context->macho_arch.cputype & ~CPU_ARCH_MASK) == CPU_TYPE_ANY) {
    if ((context->macho_arch.cpusubtype & ~CPU_SUBTYPE_MASK) ==
        CPU_SUBTYPE_LITTLE_ENDIAN)
      arch_endian = "little";
    else if ((context->macho_arch.cpusubtype & ~CPU_SUBTYPE_MASK) ==
             CPU_SUBTYPE_BIG_ENDIAN)
      arch_endian = "big";
  } else {
    arch_endian = "little";
  }

  string_len = strlen(arch_name) + strlen(arch_endian) + strlen(arch_bits) + 3;
  char *arch_full = malloc(string_len);
  snprintf(arch_full, string_len, "%s-%s-%s", arch_name, arch_bits,
           arch_endian);
  return arch_full;
}

void elf_format_context(elf_ctx_t *context) {
  printf("%s '%s'\n", INFO_MSG, context->file_load->path);

  char *arch_name = elf_join_arch_string(context);
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

  if (context->elf_prot.fortify != false) {
    printf(SPACE "FORTIFY:  ");
    printf(GREEN "Enabled" NO_COLOR " (%d functions)\n" NO_COLOR,
           context->elf_prot.fortify);
  }
  if (context->elf_prot.rwx_seg ||
      (!(context->elf_prot.nx) && context->elf_prot.writable_seg)) {
    printf(SPACE "RWX:  " SPACE RED "Has RWX segments\n" NO_COLOR);
  }
  if (context->elf_prot.rpath != NULL) {
    printf(SPACE "RUNPATH:  " RED "b'%s'\n" NO_COLOR, context->elf_prot.rpath);
    free(context->elf_prot.rpath);
  }

  bool some_inter_func = false;
  for (size_t i = 0; i < INTERESTING_FUNCS_LEN; i++) {
    if (context->elf_prot.inter_func[i] == NULL) continue;

    if (!some_inter_func) {
      printf(SPACE "FUNCS:" SPACE);
      some_inter_func = true;
    }
    // only "dangerous" deliberate function
    const char *color = strcmp(context->elf_prot.inter_func[i], "gets") == 0
                            ? BOLD RED
                            : BOLD YELLOW;
    printf("%s%s" NO_COLOR, color, context->elf_prot.inter_func[i]);

    free(context->elf_prot.inter_func[i]);
    printf(" ");
  }
  if (some_inter_func) puts("");
  free(arch_name);
  return;
}

void macho_format_context(macho_ctx_t *context) {
  printf("%s '%s'\n", INFO_MSG, context->file_load->path);

  char *arch_name = mach_join_arch_string(context);
  printf(SPACE "Arch:  " SPACE "%s\n", arch_name);

  printf(SPACE "Stack: " SPACE);
  if (context->macho_prot.canary) {
    printf(GREEN "Canary found\n" NO_COLOR);
  } else {
    printf(RED "No canary found\n" NO_COLOR);
  }

  printf(SPACE "NX:    " SPACE);
  if (context->macho_prot.nx) {
    printf(GREEN "NX enabled\n" NO_COLOR);
  } else {
    printf(RED "NX disabled\n" NO_COLOR);
  }

  printf(SPACE "PIE:   " SPACE);
  if (context->macho_prot.pie == true) {
    printf(GREEN "PIE enabled\n" NO_COLOR);
  } else {
    printf(RED "No PIE\n" NO_COLOR);
  }

  if (context->macho_prot.fortify != false) {
    printf(SPACE "FORTIFY:   ");
    printf(GREEN "Enabled" NO_COLOR " (%d functions)\n" NO_COLOR,
           context->macho_prot.fortify);
  }

  printf(SPACE "ARC:   " SPACE);
  if (context->macho_prot.arc == true) {
    printf(GREEN "ARC enabled\n" NO_COLOR);
  } else {
    printf(RED "No ARC\n" NO_COLOR);
  }
  printf(SPACE "ENCRYPTED: ");
  if (context->macho_prot.encrypted == true) {
    printf(GREEN "Encrypted\n" NO_COLOR);
  } else {
    printf(RED "No encrypted\n" NO_COLOR);
  }
  printf(SPACE "CODE SIGN: ");
  if (context->macho_prot.code_signature == true) {
    printf(GREEN "Signed\n" NO_COLOR);
  } else {
    printf(RED "No signed\n" NO_COLOR);
  }

  if (context->macho_prot.rpath != NULL) {
    printf(SPACE "RUNPATH:  ");
    printf(RED "%s\n" NO_COLOR, context->macho_prot.rpath);
  }
  free(arch_name);
  return;
}