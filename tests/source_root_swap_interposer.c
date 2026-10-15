/* SPDX-License-Identifier: Apache-2.0 */
/* Deterministically replace the manifest root before a source open. */
#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef int (*openat_fn)(int, const char *, int, ...);
typedef int (*fstat_fn)(int, struct stat *);

static int watched_descriptor = -1;
static int watched_directory = -1;
static unsigned watched_fstat_count;
static int hardlink_attempted;
static char watched_component[256];
static char watched_alias[4096];
static char watched_marker[4096];

static int is_expected_root(int descriptor)
{
    const char *path = getenv("RINPACK_TEST_HARDLINK_ROOT");
    struct stat actual;
    struct stat expected;
    return path && fstat(descriptor, &actual) == 0 && stat(path, &expected) == 0 &&
           actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino;
}

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

static void create_hardlink_after_read(void)
{
    char error_message[64];
    int error_number;
    if (hardlink_attempted || watched_directory < 0)
        return;
    hardlink_attempted = 1;
    if (linkat(watched_directory, watched_component, AT_FDCWD,
               watched_alias, 0) == 0) {
        (void)write_file(watched_marker, "created\n");
    } else {
        error_number = errno;
        (void)snprintf(error_message, sizeof(error_message), "error=%d\n",
                       error_number);
        (void)write_file(watched_marker, error_message);
    }
    (void)close(watched_directory);
    watched_directory = -1;
}

int fstat(int descriptor, struct stat *information)
{
    static fstat_fn real_fstat;
    if (!real_fstat) real_fstat = (fstat_fn)dlsym(RTLD_NEXT, "fstat");
    if (!real_fstat) return -1;
    /* The first fstat validates the open; inject the race at the post-read check. */
    if (descriptor == watched_descriptor && !hardlink_attempted &&
        ++watched_fstat_count == 2u)
        create_hardlink_after_read();
    return real_fstat(descriptor, information);
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
        const char *swap_style = getenv("RINPACK_TEST_SWAP_STYLE");
        const char *swap_component = getenv("RINPACK_TEST_SWAP_COMPONENT");
        const char *swap_target = getenv("RINPACK_TEST_SWAP_TARGET");
        const char *marker = getenv("RINPACK_TEST_SWAP_MARKER");
        if (swap_style && strcmp(swap_style, "component-symlink") == 0 &&
            swap_component && swap_target && marker &&
            strcmp(path, swap_component) == 0) {
            char held[4096];
            int length = snprintf(held, sizeof(held), "%s.rinpack-held", path);
            if (length < 0 || (size_t)length >= sizeof(held)) return -1;
            if (renameat(directory, path, directory, held) != 0) {
                char message[64];
                (void)snprintf(message, sizeof(message), "error=%d\n", errno);
                (void)write_file(marker, message);
                return -1;
            }
            if (symlinkat(swap_target, directory, path) != 0) {
                const int failure = errno;
                (void)renameat(directory, held, directory, path);
                {
                    char message[64];
                    (void)snprintf(message, sizeof(message), "error=%d\n",
                                   failure);
                    (void)write_file(marker, message);
                }
                errno = failure;
                return -1;
            }
            (void)write_file(marker, "created\n");
            {
                int descriptor = has_mode
                    ? real_openat(directory, path, flags, mode)
                    : real_openat(directory, path, flags);
                const int open_error = errno;
                if (unlinkat(directory, path, 0) != 0 ||
                    renameat(directory, held, directory, path) != 0) {
                    if (descriptor >= 0) (void)close(descriptor);
                    return -1;
                }
                errno = open_error;
                return descriptor;
            }
        }
    }
    {
        const char *hardlink_component =
            getenv("RINPACK_TEST_HARDLINK_COMPONENT");
        const char *hardlink_alias = getenv("RINPACK_TEST_HARDLINK_ALIAS");
        const char *hardlink_marker = getenv("RINPACK_TEST_HARDLINK_MARKER");
        const char *hardlink_root = getenv("RINPACK_TEST_HARDLINK_ROOT");
        if (hardlink_component && hardlink_alias && hardlink_marker &&
            hardlink_root && is_expected_root(directory) &&
            watched_descriptor < 0 &&
            strcmp(path, hardlink_component) == 0) {
            int descriptor = has_mode
                ? real_openat(directory, path, flags, mode)
                : real_openat(directory, path, flags);
            if (descriptor >= 0) {
                struct stat opened;
                struct stat named;
                int opened_ok = fstat(descriptor, &opened) == 0;
                int named_ok = fstatat(directory, path, &named,
                                       AT_SYMLINK_NOFOLLOW) == 0;
                if (!opened_ok || !named_ok ||
                    !S_ISREG(opened.st_mode) ||
                    opened.st_dev != named.st_dev ||
                    opened.st_ino != named.st_ino)
                    return descriptor;
                int component_length = snprintf(
                    watched_component, sizeof(watched_component), "%s", path);
                int alias_length = snprintf(
                    watched_alias, sizeof(watched_alias), "%s", hardlink_alias);
                int marker_length = snprintf(
                    watched_marker, sizeof(watched_marker), "%s", hardlink_marker);
                watched_directory = dup(directory);
                if (component_length < 0 ||
                    (size_t)component_length >= sizeof(watched_component) ||
                    alias_length < 0 ||
                    (size_t)alias_length >= sizeof(watched_alias) ||
                    marker_length < 0 ||
                    (size_t)marker_length >= sizeof(watched_marker) ||
                    watched_directory < 0) {
                    if (watched_directory >= 0) close(watched_directory);
                    watched_directory = -1;
                    close(descriptor);
                    return -1;
                }
                watched_descriptor = descriptor;
            }
            return descriptor;
        }
    }
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
