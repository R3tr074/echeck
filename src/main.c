#include <stdio.h>
#include <stdlib.h>

#include "elf_def.h"
#include "macho.h"
#include "usage.h"
#include "utils.h"
#include "view.h"

int main(int argc, char *argv[]) {
  if (argc < 2) {
    USAGE();
    exit(0);
  }

  int prog_ret = EXIT_SUCCESS;
  for (int i = 1; i < argc; i++) {
    file_load_t file_ctx;
    int ret;

    ret = load_file(&file_ctx, argv[i]);
    if (ret != 0) {
      fprintf(stderr, "Error to open \"%s\" file\n", argv[1]);
      prog_ret = EXIT_FAILURE;
      continue;
    }

    if (is_elf(&file_ctx)) {
      ret = elf_load(&file_ctx);
    } else if (is_macho(&file_ctx)) {
      ret = macho_load(&file_ctx);
    } else if (is_fat_macho(&file_ctx)) {
      ret = macho_fat_load(&file_ctx);
    } else {
      fprintf(stderr, "Error to parse \"%s\" file\nNot recognized file type\n",
              argv[1]);
      prog_ret = EXIT_FAILURE;
      continue;
    }
    if (ret != 0) {
      prog_ret = EXIT_FAILURE;
    }
  }
  return prog_ret;
}