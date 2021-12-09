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

  elf_ctx_t context;
  int ret;

  ret = elf_load_file(&context, argv[1]);
  if (ret != 0) {
    fprintf(stderr, "Error to open \"%s\" file\n", argv[1]);
    return EXIT_FAILURE;
  }

  ret = elf_parse(&context);
  if (ret != 0) {
    fprintf(stderr, "Error to parse \"%s\" file\nthis is really a elf?\n",
            argv[1]);
    return EXIT_FAILURE;
  }

  format_context(&context);

  elf_unload_file(&context);
  return EXIT_SUCCESS;
}