// skinwalker - userland execve()-like ELF loader
// Copyright (C) 2025  zygoth <core.zyg0th@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// Written for exploratory/educational purposes. No responsibility is
// taken for how this code is used downstream.

#include "skinwalker.h"

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/auxv.h>

// everything we need to remember after loading an ELF into memory, so
// we can build the auxv and decide where to jump. internal only — the
// public API (skinwalker_exec) never hands this back to the caller.
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

// x86_64 page alignment. in production we'd use sysconf(_SC_PAGESIZE).
#define PAGE_SIZE 4096ul

// max number of PT_LOAD segments we know how to handle per file.
// enough for any normal ELF (real ld.so/libc have 4-5).
#define MAX_LOAD_REGIONS 64

// ---- ELF header validation ----
//
// checks the magic, class (64-bit), architecture (x86_64) and type
// (ET_EXEC or ET_DYN). anything else is rejected.
static int validate_elf_header(const char *label, const Elf64_Ehdr *elf_header)
{
    if (memcmp(elf_header->e_ident, ELFMAG, SELFMAG) != 0)
    {
        fprintf(stderr, "%s: ELF64 signature not found\n", label);
        return -1;
    }

    if (elf_header->e_ident[EI_CLASS] != ELFCLASS64 ||
        elf_header->e_machine != EM_X86_64)
    {
        fprintf(stderr, "%s: not ELF64 x86_64\n", label);
        return -1;
    }

    if (elf_header->e_type != ET_EXEC && elf_header->e_type != ET_DYN)
    {
        fprintf(stderr, "%s: unsupported type (expected EXEC or DYN)\n", label);
        return -1;
    }

    return 0;
}

// ---- looks up the PT_INTERP entry in the program header table ----
//
// if present, copies the interpreter path (e.g. "/lib64/ld-linux-
// x86-64.so.2") out and returns 1. if absent, returns 0. reads straight
// out of the in-memory buffer, no file I/O.
static int read_interpreter(const unsigned char *data, size_t size,
                             const Elf64_Phdr *program_header_table,
                             Elf64_Half entry_total, char *interp_path_out,
                             size_t out_buffer_size)
{
    for (int i = 0; i < entry_total; i++)
    {
        const Elf64_Phdr *program_header_entry = &program_header_table[i];

        if (program_header_entry->p_type != PT_INTERP)
            continue;

        size_t string_len = program_header_entry->p_filesz;
        if (string_len >= out_buffer_size)
            string_len = out_buffer_size - 1;
        if (program_header_entry->p_offset + string_len > size)
            string_len = (program_header_entry->p_offset < size)
                             ? size - program_header_entry->p_offset
                             : 0;

        memcpy(interp_path_out, data + program_header_entry->p_offset, string_len);
        interp_path_out[string_len] = '\0';

        return 1;
    }

    return 0;
}

// ---- computes load_bias for an ET_DYN (PIE) binary ----
//
// the p_vaddr values of an ET_DYN are relative to an imaginary base of
// 0: whoever loads it picks where the real image goes. we scan the
// PT_LOAD entries just to find the total image size (from the lowest
// vaddr to the highest vaddr+memsz), reserve that range with a
// "placeholder" mmap (PROT_NONE, just reserves address space), and the
// returned address minus the lowest vaddr is the load_bias.
//
// for ET_EXEC (addresses already absolute), load_bias is 0, but we
// still reserve the fixed range with MAP_FIXED_NOREPLACE to detect an
// address conflict.
static int calculate_load_bias(const Elf64_Ehdr *elf_header,
                                const Elf64_Phdr *program_header_table,
                                Elf64_Half entry_total, Elf64_Addr *load_bias_out)
{
    Elf64_Addr min_vaddr = (Elf64_Addr)-1;
    Elf64_Addr max_vaddr = 0;

    for (int i = 0; i < entry_total; i++)
    {
        const Elf64_Phdr *program_header_entry = &program_header_table[i];
        if (program_header_entry->p_type != PT_LOAD)
            continue;

        Elf64_Addr page_start = program_header_entry->p_vaddr & ~(PAGE_SIZE - 1);
        Elf64_Addr end = program_header_entry->p_vaddr + program_header_entry->p_memsz;
        end = (end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1); // round up

        if (page_start < min_vaddr)
            min_vaddr = page_start;
        if (end > max_vaddr)
            max_vaddr = end;
    }

    size_t total_image_size = max_vaddr - min_vaddr;

    if (elf_header->e_type == ET_EXEC)
    {
        // absolute addresses: the target requires exactly
        // [min_vaddr, max_vaddr). MAP_FIXED_NOREPLACE fails instead of
        // overwriting if something is already there (e.g. the loader
        // itself, if it was linked without PIE at the same address).
        // without this check, MAP_FIXED would wipe out the loader's own
        // code while it's still running, and the result would be an
        // unexplained segfault.
        void *fixed_region = mmap((void *)min_vaddr, total_image_size, PROT_NONE,
                                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                                   -1, 0);
        if (fixed_region == MAP_FAILED || (Elf64_Addr)fixed_region != min_vaddr)
        {
            fprintf(stderr,
                    "skinwalker: target ET_EXEC needs 0x%lx-0x%lx, but that "
                    "range is already in use (likely conflict with the loader "
                    "itself; link the loader with -static-pie)\n",
                    (unsigned long)min_vaddr,
                    (unsigned long)(min_vaddr + total_image_size));
            if (fixed_region != MAP_FAILED)
                munmap(fixed_region, total_image_size);
            return -1;
        }

        *load_bias_out = 0;
        return 0;
    }

    void *reserved_region = mmap(NULL, total_image_size, PROT_NONE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reserved_region == MAP_FAILED)
    {
        perror("mmap reserve");
        return -1;
    }

    *load_bias_out = (Elf64_Addr)reserved_region - min_vaddr;
    return 0;
}

// ---- maps a single PT_LOAD segment into memory ----
//
// reserves the page(s) with mmap (always RW, so the segment contents
// can be written next), copies the bytes straight out of the in-memory
// ELF buffer, and returns the final protection this segment should
// have (applied later, by apply_final_protections).
static int map_load_segment(const unsigned char *data, size_t size, const char *label,
                             const Elf64_Phdr *program_header_entry, Elf64_Addr load_bias,
                             Elf64_Addr *page_align_out, size_t *map_size_out,
                             int *protection_out)
{
    Elf64_Addr vaddr = load_bias + program_header_entry->p_vaddr;
    Elf64_Addr page_align = vaddr & ~(PAGE_SIZE - 1);
    Elf64_Addr delta = vaddr - page_align;
    size_t map_size = program_header_entry->p_memsz + delta;

    int protection = 0;
    if (program_header_entry->p_flags & PF_R)
        protection |= PROT_READ;
    if (program_header_entry->p_flags & PF_W)
        protection |= PROT_WRITE;
    if (program_header_entry->p_flags & PF_X)
        protection |= PROT_EXEC;

    // an anonymous mmap already hands back zeroed memory: the "hole"
    // between filesz and memsz (the .bss) is zeroed for free.
    void *mapped = mmap((void *)page_align, map_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if (mapped == MAP_FAILED)
    {
        perror("mmap");
        return -1;
    }

    if (program_header_entry->p_filesz > 0)
    {
        if (program_header_entry->p_offset + program_header_entry->p_filesz > size)
        {
            fprintf(stderr, "%s: segment reaches past the end of the buffer\n", label);
            return -1;
        }

        memcpy((void *)vaddr, data + program_header_entry->p_offset,
               program_header_entry->p_filesz);
    }

    *page_align_out = page_align;
    *map_size_out = map_size;
    *protection_out = protection;
    return 0;
}

typedef struct
{
    Elf64_Addr page_align;
    size_t map_size;
    int protection;
} mapped_region_t;

// ---- applies the final protection (mprotect) to each mapped segment ----
//
// done as a separate pass, after all PT_LOAD segments have been copied,
// because no segment can lose PROT_WRITE before the copy is finished.
static int apply_final_protections(const mapped_region_t *regions, int region_count)
{
    for (int i = 0; i < region_count; i++)
    {
        if (mprotect((void *)regions[i].page_align, regions[i].map_size,
                      regions[i].protection) != 0)
        {
            perror("mprotect");
            return -1;
        }
    }
    return 0;
}

// ---- loads an entire ELF from an in-memory buffer (maps every PT_LOAD) ----
//
// this is the real workhorse: it never touches a file descriptor, only
// the bytes already sitting at `data`. that means the ELF doesn't have
// to come from disk at all — a buffer downloaded over the network,
// decrypted in place, or assembled by hand works just as well as one
// read from a file.
//
// no relocation is applied. that's intentional: both a normal ET_DYN
// binary (PIE) and the dynamic linker (ld.so) carry inside themselves a
// small bootstrap (_dl_relocate_static_pie in the first case, _dl_start
// in the second) that self-relocates as soon as execution reaches
// e_entry. that's exactly what the real kernel does: it only maps the
// segments, never touches relocation at all.
//
// `label` is only used in error messages (a path, a description,
// whatever makes sense for the caller) — it plays no role in loading.
static int skinwalker_load_elf(const void *data_v, size_t size, const char *label,
                             loaded_image_t *image_out)
{
    const unsigned char *data = data_v;
    memset(image_out, 0, sizeof(*image_out));

    if (size < sizeof(Elf64_Ehdr))
    {
        fprintf(stderr, "%s: buffer too small\n", label);
        return -1;
    }

    Elf64_Ehdr elf_header;
    memcpy(&elf_header, data, sizeof(elf_header));

    if (validate_elf_header(label, &elf_header) != 0)
        return -1;

    Elf64_Half entry_total = elf_header.e_phnum;
    Elf64_Half entry_size = elf_header.e_phentsize;

    size_t phdr_table_size = (size_t)entry_total * sizeof(Elf64_Phdr);
    if (elf_header.e_phoff + phdr_table_size > size)
    {
        fprintf(stderr, "%s: program header table reaches past the buffer\n", label);
        return -1;
    }

    Elf64_Phdr *program_header_table = malloc(phdr_table_size);
    memcpy(program_header_table, data + elf_header.e_phoff, phdr_table_size);

    char interp_path[256] = {0};
    int has_interp = read_interpreter(data, size, program_header_table, entry_total,
                                       interp_path, sizeof(interp_path));

    Elf64_Addr load_bias = 0;
    if (calculate_load_bias(&elf_header, program_header_table, entry_total, &load_bias) != 0)
    {
        free(program_header_table);
        return -1;
    }

    Elf64_Addr image_base = 0; // (shifted) p_vaddr of the segment holding offset 0
    mapped_region_t regions[MAX_LOAD_REGIONS];
    int region_count = 0;

    for (int i = 0; i < entry_total; i++)
    {
        const Elf64_Phdr *program_header_entry = &program_header_table[i];

        if (program_header_entry->p_type != PT_LOAD)
            continue;

        if (program_header_entry->p_offset == 0)
            image_base = load_bias + program_header_entry->p_vaddr;

        if (region_count >= MAX_LOAD_REGIONS)
        {
            fprintf(stderr, "%s: more PT_LOAD segments than the loader supports\n", label);
            free(program_header_table);
            return -1;
        }

        Elf64_Addr page_align;
        size_t map_size;
        int protection;

        if (map_load_segment(data, size, label, program_header_entry, load_bias,
                              &page_align, &map_size, &protection) != 0)
        {
            free(program_header_table);
            return -1;
        }

        regions[region_count].page_align = page_align;
        regions[region_count].map_size = map_size;
        regions[region_count].protection = protection;
        region_count++;
    }

    free(program_header_table);

    if (apply_final_protections(regions, region_count) != 0)
        return -1;

    image_out->load_bias = load_bias;
    image_out->entry = load_bias + elf_header.e_entry;
    image_out->phdr_addr = image_base + elf_header.e_phoff;
    image_out->phentsize = entry_size;
    image_out->phnum = entry_total;
    image_out->has_interp = has_interp;
    if (has_interp)
        memcpy(image_out->interp_path, interp_path, sizeof(interp_path));

    return 0;
}

// ---- convenience wrapper: loads an ELF straight from a path on disk ----
//
// mmaps the file read-only and hands the resulting view to
// skinwalker_load_elf — no heap copy of the whole file, and the
// source mapping is dropped again once loading is done (the segment
// contents were already copied out into their own PT_LOAD mappings by
// then). this is purely a convenience: skinwalker doesn't require the
// binary to live on disk at all, see skinwalker_load_elf above.
static int skinwalker_load_elf_file(const char *path, loaded_image_t *image_out)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        fprintf(stderr, "failed to open %s\n", path);
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0)
    {
        perror("fstat");
        close(fd);
        return -1;
    }

    void *file_view = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd); // the mapping stays valid after the fd is closed
    if (file_view == MAP_FAILED)
    {
        perror("mmap file");
        return -1;
    }

    int rc = skinwalker_load_elf(file_view, (size_t)st.st_size, path, image_out);

    munmap(file_view, (size_t)st.st_size);
    return rc;
}

// ---- freeing the loader's own memory before the jump ----
//
// by default, after the final jmp, the loader's code/data/heap/stack
// stay mapped forever (the target is only mapped OVER free parts of the
// address space; nothing belonging to the loader is ever given back to
// the kernel). this section unmaps all of that before the jump, so the
// process's memory footprint ends up matching a real execve().
//
// the problem: the loader can't munmap its own code while it's still
// executing it (the next instruction would have to come from a page
// that just vanished). the fix is a small "stub" of a few instructions,
// copied to a NEW, separate page, that does the dirty work:
//   1. walks a table of regions (addr, size) and calls munmap() on each
//      one via a direct syscall (no libc — libc is also one of the
//      regions being removed).
//   2. only after everything is unmapped does it swap rsp and jump to
//      the target.
//
// this stub also can't live in the middle of an ordinary C function: if
// it did, it would itself be part of the region unmapped in step 1. so
// it's written as a block of global assembly (outside any function),
// copied by value into fresh memory at runtime.

#define MAX_UNMAP_REGIONS 32

typedef struct
{
    uint64_t addr;
    uint64_t len;
} unmap_region_t;

// global assembly block: lives inside the loader's OWN .text (which is
// why it's copied out before use), with two symbols marking start/end
// so we know the exact size to copy.
//
// register convention on entry (defined by us, not a normal C calling
// ABI — that's why it's entered with an asm jmp, not a regular C call):
//   r8  = pointer to a table of unmap_region_t, terminated by addr==0
//         (loader binary + original stack — NEVER the heap, see below)
//   r9  = new rsp value (target stack, already built)
//   r10 = entry point to jump to at the end
//   r11 = start of the loader's heap (from /proc/self/maps), or 0 if none
//
// the heap is handled separately, with brk(), not a generic munmap():
// the heap comes from brk()/sbrk(), and the kernel keeps an internal
// "program break" for the process. a manual munmap unmaps the pages but
// does NOT tell the kernel the break should move back — the recorded
// break keeps pointing into thin air. we tested this: it leaves the
// process in an inconsistent state, and the next related access
// (glibc/TLS fixing things up via brk internally) suffers a general
// protection fault. brk(heap_start) is the right call: besides freeing
// the pages, it updates the process's break consistently.
__asm__(
    ".globl skinwalker_stub_begin\n"
    "skinwalker_stub_begin:\n"
    "   testq %r11, %r11\n"      // heap_start == 0 -> no heap, skip
    "   jz 3f\n"
    "   movq %r11, %rdi\n"       // brk(heap_start): give the whole heap back
    "   movq $12, %rax\n"        // SYS_brk
    "   syscall\n"
    "3:\n"
    "1:\n"
    "   movq (%r8), %rdi\n"      // addr = table->addr
    "   testq %rdi, %rdi\n"      // addr == 0 -> end of table
    "   jz 2f\n"
    "   movq 8(%r8), %rsi\n"     // len = table->len
    "   movq $11, %rax\n"        // SYS_munmap
    "   syscall\n"
    "   addq $16, %r8\n"         // next table entry
    "   jmp 1b\n"
    "2:\n"
    "   movq %r9, %rsp\n"        // stack swap happens only now
    "   xorq %rdx, %rdx\n"       // rtld_fini = NULL
    "   jmp *%r10\n"             // never returns to the loader again
    ".globl skinwalker_stub_end\n"
    "skinwalker_stub_end:\n");

extern char skinwalker_stub_begin[];
extern char skinwalker_stub_end[];

// reads /proc/self/maps and collects, into the output table, every
// range that belongs to the LOADER ITSELF: the executable binary (every
// region mapped from the loader's own file) and the process's original
// stack ("[stack]"). the heap ("[heap]") goes out through a separate
// path (*heap_start_out), because it needs brk(), not a generic
// munmap() (see the comment next to the stub). vDSO/vvar/vsyscall NEVER
// end up here (different pathname) because they're still needed after
// the jump (e.g. AT_SYSINFO_EHDR). the target/interpreter regions also
// don't end up here: they were created by our own anonymous mmaps, with
// no pathname matching any of the filters.
static int collect_unmap_regions(unmap_region_t *out, int max_regions, int *count_out,
                                  uint64_t *heap_start_out)
{
    char self_exe[4096] = {0};
    ssize_t n = readlink("/proc/self/exe", self_exe, sizeof(self_exe) - 1);
    if (n <= 0)
    {
        perror("readlink /proc/self/exe");
        return -1;
    }
    self_exe[n] = '\0';

    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps)
    {
        perror("fopen /proc/self/maps");
        return -1;
    }

    int count = 0;
    *heap_start_out = 0;
    char line[512];
    while (fgets(line, sizeof(line), maps))
    {
        unsigned long start, end;
        char pathname[400] = {0};

        // format: "start-end perms offset dev inode  pathname"
        // pathname may be missing (anonymous mapping) — sscanf handles
        // that by leaving pathname[0] == '\0'.
        sscanf(line, "%lx-%lx %*s %*s %*s %*s %399[^\n]", &start, &end, pathname);

        // strip the indentation spaces that /proc/self/maps puts before
        // the pathname.
        char *trimmed = pathname;
        while (*trimmed == ' ')
            trimmed++;

        if (strcmp(trimmed, "[heap]") == 0)
        {
            *heap_start_out = start;
            continue;
        }

        int matches = (strcmp(trimmed, self_exe) == 0) ||
                      (strcmp(trimmed, "[stack]") == 0);

        if (!matches)
            continue;

        if (count >= max_regions)
        {
            fprintf(stderr, "skinwalker: more regions to unmap than supported\n");
            fclose(maps);
            return -1;
        }

        out[count].addr = start;
        out[count].len = end - start;
        count++;
    }

    fclose(maps);
    *count_out = count;
    return 0;
}

// ---- builds the target process's new stack and jumps to it ----
//
// expected layout at the top of the stack, from bottom to top:
//   [argc]
//   [argv[0..argc-1]]
//   [NULL]
//   [envp[0..]]
//   [NULL]
//   [auxv: (type, value) pairs...]
//   [AT_NULL, 0]
//
// since we're going to unmap the process's ORIGINAL stack (where
// argv/envp and their strings live) and the loader's .data (where a
// static AT_RANDOM would sit), all of that needs to be copied first
// into an "arena": a fresh anonymous mmap that doesn't match any of
// collect_unmap_regions' filters and therefore survives the unmap.
static int build_stack_and_jump(int target_argc, char **target_argv, char **envp,
                                 const loaded_image_t *target_image,
                                 const loaded_image_t *interp_image,
                                 int use_interp)
{
    int envc = 0;
    while (envp[envc] != NULL)
        envc++;

    // arena: fresh memory, outside the loader binary and outside the
    // original stack, to host everything that needs to survive the
    // final unmap (argv/envp strings, AT_RANDOM, the region table and
    // the stub). generous size — fits even a huge environment/command
    // line.
    size_t arena_size = 1 * 1024 * 1024;
    unsigned char *arena = mmap(NULL, arena_size, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (arena == MAP_FAILED)
    {
        perror("mmap arena");
        return -1;
    }
    unsigned char *arena_cursor = arena;
    unsigned char *arena_end = arena + arena_size;

#define ARENA_ALLOC(n) ({                         \
    unsigned char *p_ = arena_cursor;             \
    arena_cursor += (n);                          \
    if (arena_cursor > arena_end)                 \
    {                                              \
        fprintf(stderr, "skinwalker: arena overflow\n"); \
        return -1;                                \
    }                                              \
    p_; })

    // copy every argv/envp string into the arena: the original pointers
    // point into the process's old stack, which we're about to unmap.
    char **arena_argv = (char **)ARENA_ALLOC((target_argc + 1) * sizeof(char *));
    for (int i = 0; i < target_argc; i++)
    {
        size_t len = strlen(target_argv[i]) + 1;
        char *copy = (char *)ARENA_ALLOC(len);
        memcpy(copy, target_argv[i], len);
        arena_argv[i] = copy;
    }
    arena_argv[target_argc] = NULL;

    char **arena_envp = (char **)ARENA_ALLOC((envc + 1) * sizeof(char *));
    for (int i = 0; i < envc; i++)
    {
        size_t len = strlen(envp[i]) + 1;
        char *copy = (char *)ARENA_ALLOC(len);
        memcpy(copy, envp[i], len);
        arena_envp[i] = copy;
    }
    arena_envp[envc] = NULL;

    target_argv = arena_argv;
    envp = arena_envp;

    // AT_RANDOM requires a pointer to 16 valid bytes, used by libc to
    // seed the stack canary. doesn't need to be strong for this study
    // project. it lives in the arena (no longer "static", which would
    // land in the loader's .data, unmapped at the end).
    unsigned char *at_random_value = ARENA_ALLOC(16);
    memcpy(at_random_value, (unsigned char[16]){1, 2, 3, 4, 5, 6, 7, 8,
                                                 9, 10, 11, 12, 13, 14, 15, 16},
           16);

    // auxv always describes the TARGET program, never the interpreter.
    // that's how ld.so, once we jump to it, finds out where the real
    // program is.
    Elf64_auxv_t auxv[] = {
        {.a_type = AT_PHDR, .a_un.a_val = target_image->phdr_addr},
        {.a_type = AT_PHENT, .a_un.a_val = target_image->phentsize},
        {.a_type = AT_PHNUM, .a_un.a_val = target_image->phnum},
        {.a_type = AT_PAGESZ, .a_un.a_val = PAGE_SIZE},
        {.a_type = AT_BASE, .a_un.a_val = use_interp ? interp_image->load_bias : 0},
        {.a_type = AT_ENTRY, .a_un.a_val = target_image->entry},
        {.a_type = AT_RANDOM, .a_un.a_val = (Elf64_Addr)at_random_value},
        {.a_type = AT_SECURE, .a_un.a_val = 0},
        {.a_type = AT_EXECFN, .a_un.a_val = (Elf64_Addr)target_argv[0]},
        {.a_type = AT_UID, .a_un.a_val = getuid()},
        {.a_type = AT_EUID, .a_un.a_val = geteuid()},
        {.a_type = AT_GID, .a_un.a_val = getgid()},
        {.a_type = AT_EGID, .a_un.a_val = getegid()},
        // we forward the vDSO and HWCAP the real kernel already gave
        // OUR OWN process when it started — they're still mapped.
        {.a_type = AT_SYSINFO_EHDR, .a_un.a_val = getauxval(AT_SYSINFO_EHDR)},
        {.a_type = AT_HWCAP, .a_un.a_val = getauxval(AT_HWCAP)},
        {.a_type = AT_CLKTCK, .a_un.a_val = getauxval(AT_CLKTCK)},
        {.a_type = AT_NULL, .a_un.a_val = 0},
    };
    int auxc = sizeof(auxv) / sizeof(auxv[0]);

    size_t total_words = 1                          // argc
                          + (size_t)(target_argc + 1) // argv[] + NULL
                          + (size_t)(envc + 1)        // envp[] + NULL
                          + (size_t)auxc * 2;         // auxv pairs

    size_t stack_size = 8 * 1024 * 1024; // 8 MB
    void *stack_mem = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack_mem == MAP_FAILED)
    {
        perror("mmap stack");
        return -1;
    }

    uint64_t stack_top = (uint64_t)stack_mem + stack_size;

    // reserve room for the words and align to 16 bytes (required by the
    // ABI at the process entry point).
    uint64_t stack_pointer = stack_top - (total_words * sizeof(uint64_t));
    stack_pointer &= ~0xFul;

    uint64_t *writer = (uint64_t *)stack_pointer;
    *writer++ = (uint64_t)target_argc;
    for (int i = 0; i < target_argc; i++)
        *writer++ = (uint64_t)target_argv[i];
    *writer++ = 0; // NULL after argv

    for (int i = 0; i < envc; i++)
        *writer++ = (uint64_t)envp[i];
    *writer++ = 0; // NULL after envp

    for (int i = 0; i < auxc; i++)
    {
        *writer++ = (uint64_t)auxv[i].a_type;
        *writer++ = (uint64_t)auxv[i].a_un.a_val;
    }

    // jump to ld.so if present; otherwise straight to the target. we
    // never come back to our own code after this.
    void *entry_point = (void *)(use_interp ? interp_image->entry : target_image->entry);

    // table of the LOADER's OWN regions (binary + original stack), for
    // the stub to unmap before the jump. lives in the arena.
    //
    // the heap is DELIBERATELY left out (we don't pass heap_start to
    // the stub, it always arrives as 0). we tested this: a raw brk()
    // giving the whole heap back (even though it's the "correct" call,
    // unlike a manual munmap) leaves some internal reference inside
    // ld.so to memory it was still going to allocate, and the process
    // dies on a bogus munmap()/mmap() further down, already inside
    // ld.so. we didn't chase the exact mechanism down to the bottom —
    // probably related to how the new process (ld.so) starts managing
    // its OWN heap from the "program break" it inherits from the
    // process, which we messed with along the way. practical result:
    // the loader's heap (typically small) is left behind, not given
    // back — a trade-off we accept in exchange for not breaking the
    // dynamic case.
    unmap_region_t *region_table =
        (unmap_region_t *)ARENA_ALLOC((MAX_UNMAP_REGIONS + 1) * sizeof(unmap_region_t));
    int region_count = 0;
    uint64_t heap_start_unused = 0;
    if (collect_unmap_regions(region_table, MAX_UNMAP_REGIONS, &region_count, &heap_start_unused) != 0)
        return -1;
    uint64_t heap_start = 0; // always 0: see comment above
    region_table[region_count].addr = 0; // terminator (addr == 0)
    region_table[region_count].len = 0;

    // copy the stub into a new page, separate from the loader's own
    // .text (which IS in the region list above and is about to vanish).
    // after the copy, the original stub (inside the loader) is no
    // longer needed.
    size_t stub_len = (size_t)(skinwalker_stub_end - skinwalker_stub_begin);
    unsigned char *stub_copy = mmap(NULL, stub_len, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stub_copy == MAP_FAILED)
    {
        perror("mmap stub");
        return -1;
    }
    memcpy(stub_copy, skinwalker_stub_begin, stub_len);
    if (mprotect(stub_copy, stub_len, PROT_READ | PROT_EXEC) != 0)
    {
        perror("mprotect stub");
        return -1;
    }

    // jump to the stub (still inside the loader's own .text up to this
    // last instruction). from here on, execution runs entirely in the
    // copy: the stub unmaps the loader/old stack, and only then swaps
    // rsp and jumps to the target.
    //
    // r8/r9/r10/r11 carry the stub's arguments by our own convention
    // (this isn't a C call, it's a jmp; that's why the operands go into
    // fixed registers chosen by us, and stay in the clobber list so the
    // compiler doesn't try to use them for anything else).
    __asm__ volatile(
        "mov %0, %%r8\n"
        "mov %1, %%r9\n"
        "mov %2, %%r10\n"
        "mov %4, %%r11\n"
        "jmp *%3\n"
        :
        : "r"(region_table), "r"(stack_pointer), "r"(entry_point), "r"(stub_copy),
          "r"(heap_start)
        : "memory", "r8", "r9", "r10", "r11");

    __builtin_unreachable();
}

int skinwalker_exec(const void *data, size_t size, int argc, char **argv, char **envp)
{
    if (data == NULL || size == 0 || argc < 1 || argv == NULL || argv[0] == NULL)
        return -1;

    // argv[0] is used only as a label for error messages here — the
    // actual bytes to load come from `data`/`size`, supplied by the
    // caller (read from disk, downloaded, decrypted, whatever).
    loaded_image_t target_image;
    if (skinwalker_load_elf(data, size, argv[0], &target_image) != 0)
        return -1;

    // if the target has a PT_INTERP, we need to load ld.so too, and
    // jump to ITS entry, not the target's — it's ld.so that, after
    // resolving libraries and symbols, jumps to the real program.
    loaded_image_t interp_image;
    int use_interp = target_image.has_interp;

    if (use_interp)
    {
        if (skinwalker_load_elf_file(target_image.interp_path, &interp_image) != 0)
            return -1;
    }

    // on success, build_stack_and_jump never returns.
    return build_stack_and_jump(argc, argv, envp, &target_image, &interp_image, use_interp);
}
