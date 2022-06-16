#include <stdio.h>
#include <stdlib.h>

#include "elf.h"
#include "usage.h"
#include "view.h"

int main(int argc, char *argv[]) {
  if (argc < 2) {
    USAGE();
    exit(0);
  }

  int prog_ret = EXIT_SUCCESS;
  for (int i = 1; i < argc; i++) {
    elf_ctx_t context;
    int ret;

    ret = elf_load_file(&context, argv[i]);
    if (ret != 0) {
      fprintf(stderr, "Error to open \"%s\" file\n", argv[1]);
      prog_ret = EXIT_FAILURE;
      continue;
    }

    ret = elf_parse(&context);
    if (ret != 0) {
      fprintf(stderr, "Error to parse \"%s\" file\nthis is really a elf?\n",
              argv[1]);
      prog_ret = EXIT_FAILURE;
      continue;
    }

    format_context(&context);

    elf_unload_file(&context);
  }
  return prog_ret;
}