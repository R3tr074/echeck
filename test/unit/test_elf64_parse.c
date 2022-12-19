#include <stdlib.h>

#include "elf_def.h"
#include "minunit.h"

int test_aarch64_full_prot(void) {
  file_load_t *file_ctx = malloc(sizeof(file_load_t));
  elf_ctx_t *context = malloc(sizeof(elf_ctx_t));
  context->file_load = file_ctx;

  mu_assert(
      "Load elf64",
      !load_file(file_ctx, "./bins/elf/aarch64_pie_nx_canary_relrofull"));
  mu_assert("Validate ELF format", is_elf(file_ctx));
  mu_assert("Parse elf64", !elf_parse(context));
  mu_assert("Arch aarch64", context->arch.e_machine == EM_AARCH64);
  mu_assert("64 bits", context->arch.e_classtype == ELFCLASS64);
  mu_assert("NX enable", context->elf_prot.nx == true);
  mu_assert("Canary enable", context->elf_prot.canary == true);
  mu_assert("PIE enable", context->elf_prot.pie == true);
  mu_assert("Relro full", context->elf_prot.relro == RELRO_FULL);

  free(context);
  unload_file(file_ctx);
  mu_end;
}

int all_tests(void) {
  mu_run_test(test_aarch64_full_prot);
  return tests_passed != tests_run;
}

int main(int argc, char **argv) { return all_tests(); }