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

## test/

Small ELF binaries used to exercise the loader:
- `sample.c` — static binary, loops printing its own PID.
- `dynsample.c` — same, but dynamically linked (exercises the
  PT_INTERP / ld.so path).
