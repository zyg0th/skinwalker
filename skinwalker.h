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

#ifndef SKINWALKER_H
#define SKINWALKER_H

#include <stddef.h>

// loads the ELF already sitting in `data`/`size` (any origin — disk,
// download, decrypted blob, whatever the caller assembled) and
// transfers execution to it, resolving its PT_INTERP (loaded from disk,
// since that's the system's ld.so) if it needs one. NEVER RETURNS on
// success — the process starts executing the target. only returns if
// something fails before the jump (invalid image, out of memory, etc),
// returning -1.
//
// argv[0] is used only as a label in error messages; argv[1..argc-1]
// are forwarded as the target's own argv (argv[argc] must be NULL,
// same convention as main's argv).
int skinwalker_exec(const void *data, size_t size, int argc, char **argv, char **envp);

#endif // SKINWALKER_H
