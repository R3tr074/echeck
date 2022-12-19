#ifndef VIEW_H
#define VIEW_H

#include "elf_def.h"
#include "macho.h"

#define BLUE "\e[34m"
#define RED "\e[31m"
#define YELLOW "\e[33m"
#define GREEN "\e[32m"
#define NO_COLOR "\e[0m"
#define BOLD "\e[1m"

#define INFO_MSG "[" BOLD BLUE "*" NO_COLOR "]"

void elf_format_context(elf_ctx_t *context);
void macho_format_context(macho_ctx_t *context);

#endif