# skinwalker

A vibe-coded, userland execve()-like ELF loader.

Maps a binary (and ld.so, if needed) straight
into the current process's memory, builds a fresh stack/auxv from
scratch, and jumps to the entry point, without going through
`execve`.

After the jump, it wipes its own memory (code, most of the heap, old
stack), so the result looks like a brand new process: same PID, the
loader's shell on the outside (`/proc/PID/exe`, name in `ps`), the
target's contents on the inside.

## build

```
make
./skinwalker <program> [args...]
```

## as a library

`skinwalker.c`/`skinwalker.h` can be used standalone, without the CLI
wrapper in `main.c`. Entry points:

- `skinwalker_load_elf_mem(data, size, label, &image)` — maps an ELF
  straight out of a buffer already in memory. Never touches a file
  descriptor. The binary doesn't have to exist on disk at all — a
  downloaded blob, a decrypted payload, whatever's already in RAM works.
  `label` is only used in error messages. Doesn't jump anywhere, only
  loads — useful if you want to inspect the result first.
- `skinwalker_load_elf(path, &image)` — convenience wrapper: mmaps the
  file at `path` and hands it to `skinwalker_load_elf_mem`.
- `skinwalker_exec(argc, argv, envp)` — loads `argv[0]` (and its
  interpreter, if any) from disk and transfers execution to it. Never
  returns on success.

```c
#include <unistd.h>
#include "skinwalker.h"

extern char **environ;

int main(void)
{
    char *target_argv[] = {"/bin/ls", "-la", NULL};

    // never returns on success — this process becomes /bin/ls -la.
    skinwalker_exec(2, target_argv, environ);

    // only reached if something failed before the jump.
    _exit(1);
}
```

Loading straight from a buffer, no path involved:

```c
#include "skinwalker.h"

// buf/len come from wherever: a download, a decrypted blob, bytes
// assembled by hand — nothing here ever touches disk.
loaded_image_t image;
if (skinwalker_load_elf_mem(buf, len, "payload", &image) != 0)
{
    // handle error
}
// image.entry, image.phdr_addr, etc. are now ready to use.
```

## test/

Small ELF binaries used to exercise the loader:
- `sample.c` — static binary, loops printing its own PID.
- `dynsample.c` — same, but dynamically linked (exercises the
  PT_INTERP / ld.so path).
