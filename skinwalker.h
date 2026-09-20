#ifndef SKINWALKER_H
#define SKINWALKER_H

#include <elf.h>
#include <stddef.h>

// everything we need to remember after loading an ELF into memory, so
// we can build the auxv and decide where to jump.
typedef struct
{
    Elf64_Addr load_bias; // 0 for ET_EXEC, chosen address for ET_DYN
    Elf64_Addr entry;      // e_entry already shifted by load_bias
    Elf64_Addr phdr_addr;  // address of the program header table in memory
    Elf64_Half phentsize;
    Elf64_Half phnum;
    int has_interp;
    char interp_path[256]; // PT_INTERP path, if present
} loaded_image_t;

// loads an entire ELF straight from a buffer already in memory: maps
// every PT_LOAD with the correct permissions. does not require the
// binary to exist on disk anywhere. applies no relocation at all
// (reason explained in the .c). returns 0 on success, -1 on error,
// filling *image_out. `label` is only used in error messages.
//
// doesn't jump anywhere — only loads. useful on its own if you want to
// inspect the result before deciding to execute it.
int skinwalker_load_elf_mem(const void *data, size_t size, const char *label,
                             loaded_image_t *image_out);

// convenience wrapper: mmaps the file at `path` and loads it via
// skinwalker_load_elf_mem.
int skinwalker_load_elf(const char *path, loaded_image_t *image_out);

// loads the binary at target_path (and its interpreter, if it needs
// one) and transfers execution to it. NEVER RETURNS on success — the
// process starts executing the target. only returns if something fails
// before the jump (invalid file, out of memory, etc), returning -1.
//
// argv[0] is the target's path and argv[1..argc-1] are forwarded as its
// arguments (argv[argc] must be NULL, same as in main).
int skinwalker_exec(int argc, char **argv, char **envp);

#endif // SKINWALKER_H
