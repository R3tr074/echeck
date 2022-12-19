#ifndef COMMON_H
#define COMMON_H

static const char *interesting_funcs[] = {"gets",  "system", "popen", "exec",
                                   "execl", "execve", "execvp"};
#define INTERESTING_FUNCS_LEN (sizeof(interesting_funcs) / sizeof(interesting_funcs[0]))

#endif