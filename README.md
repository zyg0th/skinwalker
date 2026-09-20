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

**Disclaimer**: built for exploratory/educational purposes. Licensed
under GPLv3 (see `LICENSE`), which comes with no warranty of any kind.
No responsibility is taken for how this code is used or any damage
resulting from its use.

## what this is

`skinwalker.c`/`skinwalker.h` is the library. That's the actual
project — everything else (`main.c`, the HTTPS download path) is
just a CLI wrapper built on top of it, to demonstrate the library
being used. Any real integration should link against `skinwalker.c`
directly and call the API below; it doesn't need `main.c` at all.

## API

The whole public surface is one function:

```c
int skinwalker_exec(const void *data, size_t size, int argc, char **argv, char **envp);
```

Loads the ELF already sitting at `data`/`size` — any origin: a file
you read yourself, a download, a decrypted blob, doesn't matter — and
transfers execution to it, resolving its PT_INTERP (loaded from disk,
since that's the system's `ld.so`) if it needs one.

**Never returns on success.** The process becomes the target: same
PID, loader's own memory wiped. Only returns (with `-1`) if something
fails before the jump — invalid image, out of memory, etc.

- `argv[0]` is used only as a label in error messages.
- `argv[1..argc-1]` are forwarded as the target's own argv
  (`argv[argc]` must be NULL, same convention as `main`'s argv).

Getting bytes onto disk-or-not is entirely the caller's job — read a
file, download over HTTPS, decrypt something, whatever. skinwalker
only cares about the buffer you hand it.

```c
#include <unistd.h>
#include "skinwalker.h"

extern char **environ;

int main(void)
{
    // caller's responsibility: get the bytes from wherever.
    unsigned char *buf; size_t len;
    read_file_to_mem("/bin/ls", &buf, &len); // or download, decrypt, etc.

    char *target_argv[] = {"/bin/ls", "-la", NULL};

    // never returns on success — this process becomes /bin/ls -la.
    skinwalker_exec(buf, len, 2, target_argv, environ);

    // only reached if something failed before the jump.
    _exit(1);
}
```

## build

```
make
./skinwalker <program-path-or-https-url> [args...]
```

`main.c` is the example/demo wrapper: it reads a local path or
downloads over HTTPS into a buffer, then calls `skinwalker_exec`.
It's a reference for how to feed the library, not part of the API
itself.

## test/

Small ELF binaries used to exercise the loader:
- `sample.c` — static binary, loops printing its own PID.
- `dynsample.c` — same, but dynamically linked (exercises the
  PT_INTERP / ld.so path).
