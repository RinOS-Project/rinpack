/* SPDX-License-Identifier: Apache-2.0 */
/* Deterministically replace the manifest root before a source open. */
#define _GNU_SOURCE

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef int (*openat_fn)(int, const char *, int, ...);

static const char replacement_manifest[] =
    "[package]\n"
    "package_id = \"org.rinos.attacker\"\n"
    "display_name = \"Replacement Manifest\"\n"
    "version = \"9.9.9\"\n"
    "architecture = \"any\"\n"
    "package_type = \"application\"\n"
    "description = \"attacker manifest\"\n"
    "license = \"MIT\"\n"
    "homepage = \"https://example.invalid\"\n"
    "min_rinos_version = \"1.0\"\n"
    "max_rinos_version = \"\"\n"
    "dependencies = []\n"
    "optional_dependencies = []\n"
    "conflicts = []\n"
    "provides = []\n"
    "entry_points = []\n"
    "flags = []\n"
    "capabilities = []\n"
    "\n[[files]]\n"
    "path = \"data/payload.bin\"\n"
    "source = \"payload.bin\"\n";

static int write_file(const char *path, const char *contents)
{
    int descriptor = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    size_t length = strlen(contents);
    size_t offset = 0u;
    if (descriptor < 0) return -1;
    while (offset < length) {
        ssize_t count = write(descriptor, contents + offset, length - offset);
        if (count <= 0) {
            (void)close(descriptor);
            return -1;
        }
        offset += (size_t)count;
    }
    return close(descriptor);
}

int openat(int directory, const char *path, int flags, ...)
{
    static openat_fn real_openat;
    static int swapped;
    mode_t mode = 0;
    int has_mode = (flags & O_CREAT) != 0;
#ifdef O_TMPFILE
    has_mode = has_mode || (flags & O_TMPFILE) == O_TMPFILE;
#endif
    if (has_mode) {
        va_list arguments;
        va_start(arguments, flags);
        mode = (mode_t)va_arg(arguments, int);
        va_end(arguments);
    }
    if (!real_openat)
        real_openat = (openat_fn)dlsym(RTLD_NEXT, "openat");
    if (!real_openat) return -1;
    {
        const char *swap_component = getenv("RINPACK_TEST_SWAP_COMPONENT");
        if (!swap_component) swap_component = "payload.bin";
        if (strcmp(path, swap_component) == 0 && !swapped) {
            const char *root = getenv("RINPACK_TEST_SOURCE_ROOT");
            const char *marker = getenv("RINPACK_TEST_SWAP_MARKER");
            char moved[4096];
            char attacker_root[4096];
            char replacement[4096];
            int length;
            swapped = 1;
            if (!root || !marker) return -1;
            length = snprintf(moved, sizeof(moved), "%s.held", root);
            if (length < 0 || (size_t)length >= sizeof(moved) ||
                rename(root, moved) != 0 || mkdir(root, 0700) != 0)
                return -1;
            length = snprintf(attacker_root, sizeof(attacker_root),
                              "%s.attacker", root);
            if (length < 0 || (size_t)length >= sizeof(attacker_root))
                return -1;
            length = snprintf(replacement, sizeof(replacement), "%s/%s", root,
                              swap_component);
            if (length < 0 || (size_t)length >= sizeof(replacement) ||
                write_file(replacement,
                           strcmp(swap_component, "package.toml") == 0
                               ? replacement_manifest
                               : "attacker-controlled replacement\n") != 0 ||
                write_file(marker, "root path replaced\n") != 0)
                return -1;
            {
                int descriptor = has_mode
                    ? real_openat(directory, path, flags, mode)
                    : real_openat(directory, path, flags);
                if (rename(root, attacker_root) != 0 ||
                    rename(moved, root) != 0) {
                    if (descriptor >= 0) (void)close(descriptor);
                    return -1;
                }
                return descriptor;
            }
        }
    }
    return has_mode ? real_openat(directory, path, flags, mode)
                    : real_openat(directory, path, flags);
}
