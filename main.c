#include <stdio.h>

#include "skinwalker.h"

// command-line entry point: just validates arguments and forwards to
// the lib. all the ELF-loading logic lives in skinwalker.c.
int main(int argc, char **argv, char **envp)
{
    if (argc < 2)
    {
        fprintf(stderr, "usage: %s <program> [args...]\n", argv[0]);
        return 2;
    }

    // forward everything after the loader's own name (argv[1] = target,
    // argv[2..] = target's args).
    int target_argc = argc - 1;
    char **target_argv = argv + 1;

    if (skinwalker_exec(target_argc, target_argv, envp) != 0)
    {
        fprintf(stderr, "failed to load/execute %s\n", target_argv[0]);
        return -1;
    }

    // skinwalker_exec only returns on error; if we got here, something
    // went wrong before the jump to the target.
    return -1;
}
