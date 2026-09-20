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

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <curl/curl.h>

#include "skinwalker.h"

// reads the whole file at `path` into a malloc'd buffer. caller frees.
// returns 0 on success, -1 on error.
static int read_file_to_mem(const char *path, unsigned char **out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0;

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

    unsigned char *buf = malloc((size_t)st.st_size);
    if (!buf)
    {
        close(fd);
        return -1;
    }

    ssize_t total = 0;
    while (total < st.st_size)
    {
        ssize_t n = read(fd, buf + total, (size_t)(st.st_size - total));
        if (n <= 0)
        {
            perror("read");
            free(buf);
            close(fd);
            return -1;
        }
        total += n;
    }
    close(fd);

    *out = buf;
    *out_len = (size_t)st.st_size;
    return 0;
}

typedef struct
{
    unsigned char *data;
    size_t len;
    size_t cap; /* hard limit, 0 = unlimited */
} membuf;

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    membuf *b = userdata;
    size_t n = size * nmemb;

    if (nmemb && n / nmemb != size)
        return 0; /* overflow */
    if (b->cap && b->len + n > b->cap)
        return 0; /* too big, abort */

    unsigned char *p = realloc(b->data, b->len + n + 1); /* +1 for NUL */
    if (!p)
        return 0;
    b->data = p;
    memcpy(b->data + b->len, ptr, n);
    b->len += n;
    b->data[b->len] = '\0'; /* safe to treat as C string if text */
    return n;
}

/* Download `url` (https only) into memory.
 * On success: returns 0, *out = malloc'd buffer (caller free()s), *out_len = size.
 * On failure: returns -1, *out = NULL.
 * max_bytes: abort if body exceeds this (0 = no limit). */
int download_to_mem(const char *url, unsigned char **out, size_t *out_len,
                    size_t max_bytes)
{
    membuf b = {NULL, 0, max_bytes};
    char errbuf[CURL_ERROR_SIZE] = {0};
    *out = NULL;
    *out_len = 0;

    CURL *curl = curl_easy_init();
    if (!curl)
        return -1;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &b);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // DEMO ONLY, revert before real use
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L); // DEMO ONLY, revert before real use
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);

    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1024L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 30L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK)
    {
        fprintf(stderr, "download failed: %s\n",
                errbuf[0] ? errbuf : curl_easy_strerror(res));
        free(b.data);
        return -1;
    }

    /* empty body: give caller a valid 1-byte buffer */
    if (!b.data)
    {
        b.data = calloc(1, 1);
        if (!b.data)
            return -1;
    }
    *out = b.data;
    *out_len = b.len;
    return 0;
}

static bool starts_with(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

// command-line entry point: just validates arguments and forwards to
// the lib. all the ELF-loading logic lives in skinwalker.c.
int main(int argc, char **argv, char **envp)
{
    if (argc < 2)
    {
        fprintf(stderr, "usage: %s <program/url> [args...]\n", argv[0]);
        return 2;
    }

    // forward everything after the loader's own name (argv[1] = target,
    // argv[2..] = target's args).
    int target_argc = argc - 1;
    char **target_argv = argv + 1;

    unsigned char *buf = NULL;
    size_t len = 0;

    if (starts_with(argv[1], "https://"))
    {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        int rc = download_to_mem(argv[1], &buf, &len, 10u << 20);
        curl_global_cleanup();

        if (rc != 0)
            return -1;
    }
    else if (starts_with(argv[1], "./") || starts_with(argv[1], "/"))
    {
        if (read_file_to_mem(argv[1], &buf, &len) != 0)
            return -1;
    }
    else
    {
        fprintf(stderr, "usage: %s <program/url> [args...]\n", argv[0]);
        return 2;
    }

    // skinwalker_exec only returns on error; if we got here, something
    // went wrong before the jump to the target.
    int rc = skinwalker_exec(buf, len, target_argc, target_argv, envp);
    fprintf(stderr, "failed to load/execute %s\n", target_argv[0]);
    free(buf);
    return rc;
}
