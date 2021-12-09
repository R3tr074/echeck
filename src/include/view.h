#ifndef VIEW_H
#define VIEW_H

#include "elf.h"

#define BLUE "\e[34m"
#define RED "\e[31m"
#define YELLOW "\e[33m"
#define GREEN "\e[32m"
#define NO_COLOR "\e[0m"
#define BOLD "\e[1m"

#define INFO_MSG "[" BOLD BLUE "*" NO_COLOR "]"

void format_context(elf_ctx_t *context);

#endif