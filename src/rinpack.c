/* SPDX-License-Identifier: Apache-2.0 */
/* Native RinOS .rpk package builder and verifier. */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <zlib.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <windows.h>
#define mkdir_one(path) _mkdir(path)
#define unlink_file _unlink
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define strtok_s strtok_s
typedef struct _stat RinStat;
#define rin_stat _stat
#define resolve_full_path _fullpath
#define rin_stat_is_regular(stat_value) (((stat_value).st_mode & _S_IFREG) != 0)
#else
#include <unistd.h>
#include <strings.h>
#define mkdir_one(path) mkdir(path, 0777)
#define unlink_file unlink
#define strtok_s strtok_r
typedef struct stat RinStat;
#define rin_stat stat
#define rin_stat_is_regular(stat_value) S_ISREG((stat_value).st_mode)
#endif

#define PKG_MAGIC UINT32_C(0x474b5052)
#define PKG_HEADER_SIZE 256u
#define PKG_ENTRY_SIZE 224u
#define PKG_VERSION_UNSIGNED 1u
#define PKG_VERSION_SIGNED 2u
#define PKG_VERSION_PUBLISHER_SIGNED 3u
#define PKG_FLAG_SIGNED 1u
#define PKG_MAX_FILES 64u
#define PKG_MAX_DEPS 8u
#define PKG_MAX_CAPABILITIES 31u
#define PKG_MAX_TOTAL_SIZE (256u * 1024u * 1024u)
#define PKG_MAX_FILE_SIZE (32u * 1024u * 1024u)
#define PKG_PATH_MAX 192u
#define PKG_NAME_MAX 64u
#define PKG_VERSION_MAX 32u
#define PKG_DESC_MAX 256u
#define PKG_DISPLAY_NAME_MAX 64u
#define PKG_LICENSE_MAX 64u
#define PKG_HOMEPAGE_MAX 192u
#define PKG_MANIFEST_HEADER_SIZE 848u
#define PKG_MANIFEST_MAX_SIZE 32768u

#define PKG_FILE_FLAG_METADATA 1u
#define PKG_DEPENDENCY_MAGIC UINT32_C(0x50454452)
#define PKG_CAPABILITY_MAGIC UINT32_C(0x50414352)
#define PKG_FILE_IDENTITY_MAGIC UINT32_C(0x4d494652)
#define PKG_MANIFEST_MAGIC UINT32_C(0x314d5052)
#define RIN_SIGNATURE_MAGIC UINT32_C(0x31534452)

#define RIN_IMAGE_MAGIC UINT32_C(0x004e4952)
#define RIN_IMAGE_VERSION_V3 UINT32_C(0x00030000)
#define RIN_IMAGE_HEADER_SIZE 256u
#define RIN_IMAGE_EXECUTABLE UINT32_C(1)

#define MAX_LINE 8192u
#define MAX_ARRAY_ITEMS PKG_MAX_CAPABILITIES
#define MAX_INLINE_VALUE 512u

typedef struct {
    uint8_t *data;
    size_t size;
    size_t capacity;
} Buffer;

#ifndef _WIN32
static char *resolve_full_path(char *destination, const char *path,
                               size_t destination_size) {
    char *resolved;
    size_t length;
    if (!destination || !path || destination_size == 0u) return NULL;
    resolved = realpath(path, NULL);
    if (!resolved) return NULL;
    length = strlen(resolved);
    if (length + 1u > destination_size) {
        free(resolved);
        return NULL;
    }
    memcpy(destination, resolved, length + 1u);
    free(resolved);
    return destination;
}
#endif

typedef struct {
    char name[PKG_NAME_MAX];
    char min_version[PKG_VERSION_MAX];
    char max_version[PKG_VERSION_MAX];
} Dependency;

typedef struct {
    char name[PKG_NAME_MAX];
    char path[PKG_PATH_MAX];
} EntryPoint;

typedef struct {
    char path[PKG_PATH_MAX];
    char source[PKG_PATH_MAX];
    uint8_t *data;
    size_t size;
    unsigned seen;
} PackageFile;

typedef struct {
    char package_id[PKG_NAME_MAX];
    char display_name[PKG_DISPLAY_NAME_MAX];
    char version[PKG_VERSION_MAX];
    char architecture[16];
    char package_type[32];
    char description[PKG_DESC_MAX];
    char license[PKG_LICENSE_MAX];
    char homepage[PKG_HOMEPAGE_MAX];
    char min_rinos_version[PKG_VERSION_MAX];
    char max_rinos_version[PKG_VERSION_MAX];
    char flags[3][32];
    size_t flag_count;
    char capabilities[PKG_MAX_CAPABILITIES][32];
    size_t capability_count;
    char conflicts[PKG_MAX_DEPS][PKG_NAME_MAX];
    size_t conflict_count;
    char provides[PKG_MAX_DEPS][PKG_NAME_MAX];
    size_t provides_count;
    Dependency dependencies[PKG_MAX_DEPS];
    size_t dependency_count;
    Dependency optional_dependencies[PKG_MAX_DEPS];
    size_t optional_dependency_count;
    EntryPoint entry_points[PKG_MAX_DEPS];
    size_t entry_point_count;
    PackageFile files[PKG_MAX_FILES];
    size_t file_count;
    char root[1024];
} Manifest;

typedef struct {
    char path[PKG_PATH_MAX];
    Buffer data;
} Metadata;

typedef struct {
    int json;
    const char *manifest;
    const char *output;
    const char *package;
    const char *sign_key;
    const char *public_key;
    unsigned publisher_generation;
    int generation_set;
} Options;

static int failf(const char *message) {
    fprintf(stderr, "rinpack: %s\n", message);
    return -1;
}

static int failf2(const char *prefix, const char *value) {
    fprintf(stderr, "rinpack: %s: %s\n", prefix, value);
    return -1;
}

static void buffer_free(Buffer *buffer) {
    if (buffer) {
        free(buffer->data);
        buffer->data = NULL;
        buffer->size = 0;
        buffer->capacity = 0;
    }
}

static int buffer_reserve(Buffer *buffer, size_t additional) {
    size_t needed;
    size_t capacity;
    uint8_t *grown;
    if (additional > SIZE_MAX - buffer->size) return failf("buffer size overflow");
    needed = buffer->size + additional;
    if (needed <= buffer->capacity) return 0;
    capacity = buffer->capacity ? buffer->capacity : 4096u;
    while (capacity < needed) {
        if (capacity > SIZE_MAX / 2u) return failf("buffer capacity overflow");
        capacity *= 2u;
    }
    grown = (uint8_t *)realloc(buffer->data, capacity);
    if (!grown) return failf("out of memory");
    buffer->data = grown;
    buffer->capacity = capacity;
    return 0;
}

static int buffer_append(Buffer *buffer, const void *data, size_t size) {
    if (buffer_reserve(buffer, size) != 0) return -1;
    if (size) memcpy(buffer->data + buffer->size, data, size);
    buffer->size += size;
    return 0;
}

static uint16_t get16(const uint8_t *data, size_t offset) {
    return (uint16_t)data[offset] | ((uint16_t)data[offset + 1u] << 8);
}

static uint32_t get32(const uint8_t *data, size_t offset) {
    return (uint32_t)data[offset] | ((uint32_t)data[offset + 1u] << 8) |
           ((uint32_t)data[offset + 2u] << 16) | ((uint32_t)data[offset + 3u] << 24);
}

static uint64_t get64(const uint8_t *data, size_t offset) {
    return (uint64_t)get32(data, offset) | ((uint64_t)get32(data, offset + 4u) << 32);
}

static void put16(uint8_t *data, size_t offset, uint16_t value) {
    data[offset] = (uint8_t)value;
    data[offset + 1u] = (uint8_t)(value >> 8);
}

static void put32(uint8_t *data, size_t offset, uint32_t value) {
    data[offset] = (uint8_t)value;
    data[offset + 1u] = (uint8_t)(value >> 8);
    data[offset + 2u] = (uint8_t)(value >> 16);
    data[offset + 3u] = (uint8_t)(value >> 24);
}

static void put64(uint8_t *data, size_t offset, uint64_t value) {
    put32(data, offset, (uint32_t)value);
    put32(data, offset + 4u, (uint32_t)(value >> 32));
}

static uint32_t crc32_bytes(const uint8_t *data, size_t size) {
    return (uint32_t)crc32(0L, data, (uInt)size);
}

static char *trim(char *value) {
    char *end;
    while (*value && isspace((unsigned char)*value)) ++value;
    end = value + strlen(value);
    while (end > value && isspace((unsigned char)end[-1])) --end;
    *end = '\0';
    return value;
}

static void strip_comment(char *line) {
    int quoted = 0;
    int escaped = 0;
    unsigned braces = 0;
    size_t index;
    for (index = 0; line[index]; ++index) {
        char c = line[index];
        if (quoted) {
            if (escaped) escaped = 0;
            else if (c == '\\') escaped = 1;
            else if (c == '"') quoted = 0;
        } else if (c == '"') quoted = 1;
        else if (c == '{') ++braces;
        else if (c == '}' && braces) --braces;
        else if (c == '#' && braces == 0u) {
            line[index] = '\0';
            return;
        }
    }
}

static int copy_text(char *destination, size_t capacity, const char *value,
                     const char *field, int allow_empty) {
    size_t length = strlen(value);
    size_t index;
    if ((!allow_empty && length == 0u) || length >= capacity) {
        fprintf(stderr, "rinpack: %s is outside its bounded text policy\n", field);
        return -1;
    }
    for (index = 0; index < length; ++index) {
        unsigned char c = (unsigned char)value[index];
        if (c == 0u || c < 0x20u || c == 0x7fu) {
            fprintf(stderr, "rinpack: %s contains a forbidden byte\n", field);
            return -1;
        }
    }
    memcpy(destination, value, length + 1u);
    return 0;
}

static int parse_string_token(const char *input, char *output, size_t capacity,
                              const char *field) {
    size_t in = 0;
    size_t out = 0;
    if (input[in++] != '"') {
        fprintf(stderr, "rinpack: %s must be a double-quoted TOML string\n", field);
        return -1;
    }
    while (input[in] && input[in] != '"') {
        unsigned char c = (unsigned char)input[in++];
        if (c == '\\') {
            c = (unsigned char)input[in++];
            if (c == 'n') c = '\n';
            else if (c == 'r') c = '\r';
            else if (c == 't') c = '\t';
            else if (c == 'b') c = '\b';
            else if (c == 'f') c = '\f';
            else if (c != '\\' && c != '"') {
                fprintf(stderr, "rinpack: unsupported escape in %s\n", field);
                return -1;
            }
        }
        if (out + 1u >= capacity) {
            fprintf(stderr, "rinpack: %s is too long\n", field);
            return -1;
        }
        output[out++] = (char)c;
    }
    if (input[in] != '"') {
        fprintf(stderr, "rinpack: unterminated string in %s\n", field);
        return -1;
    }
    ++in;
    while (input[in] && isspace((unsigned char)input[in])) ++in;
    if (input[in] != '\0') {
        fprintf(stderr, "rinpack: trailing data in %s\n", field);
        return -1;
    }
    output[out] = '\0';
    return 0;
}

static int split_array(const char *input, char items[MAX_ARRAY_ITEMS][MAX_INLINE_VALUE],
                       size_t *count, const char *field) {
    size_t length = strlen(input);
    size_t index = 0;
    size_t start;
    size_t item_length;
    int quoted = 0;
    int escaped = 0;
    unsigned braces = 0;
    *count = 0;
    if (length < 2u || input[0] != '[' || input[length - 1u] != ']') {
        fprintf(stderr, "rinpack: %s must be an array\n", field);
        return -1;
    }
    index = 1u;
    while (index < length - 1u) {
        while (index < length - 1u && isspace((unsigned char)input[index])) ++index;
        if (index == length - 1u) break;
        if (*count >= MAX_ARRAY_ITEMS) {
            fprintf(stderr, "rinpack: %s contains too many values\n", field);
            return -1;
        }
        start = index;
        quoted = 0;
        escaped = 0;
        braces = 0;
        while (index < length - 1u) {
            char c = input[index];
            if (quoted) {
                if (escaped) escaped = 0;
                else if (c == '\\') escaped = 1;
                else if (c == '"') quoted = 0;
            } else if (c == '"') quoted = 1;
            else if (c == '{') ++braces;
            else if (c == '}' && braces) --braces;
            else if (c == ',' && braces == 0u) break;
            ++index;
        }
        item_length = index - start;
        while (item_length && isspace((unsigned char)input[start + item_length - 1u])) --item_length;
        if (item_length == 0u || item_length >= MAX_INLINE_VALUE) {
            fprintf(stderr, "rinpack: empty or oversized value in %s\n", field);
            return -1;
        }
        memcpy(items[*count], input + start, item_length);
        items[*count][item_length] = '\0';
        ++*count;
        while (index < length - 1u && isspace((unsigned char)input[index])) ++index;
        if (index < length - 1u) {
            if (input[index] != ',') {
                fprintf(stderr, "rinpack: malformed array %s\n", field);
                return -1;
            }
            ++index;
        }
    }
    if (quoted || braces != 0u) return failf2("malformed array", field);
    return 0;
}

static int parse_string_array(const char *input, char values[][32], size_t capacity,
                              size_t *count, const char *field) {
    char items[MAX_ARRAY_ITEMS][MAX_INLINE_VALUE];
    size_t index;
    if (split_array(input, items, count, field) != 0 || *count > capacity) return -1;
    for (index = 0; index < *count; ++index) {
        char value[256];
        if (parse_string_token(items[index], value, sizeof(value), field) != 0 ||
            copy_text(values[index], 32u, value, field, 1) != 0) return -1;
    }
    return 0;
}

static int parse_name_array(const char *input, char values[][PKG_NAME_MAX], size_t capacity,
                            size_t *count, const char *field) {
    char items[MAX_ARRAY_ITEMS][MAX_INLINE_VALUE];
    size_t index;
    if (split_array(input, items, count, field) != 0 || *count > capacity) return -1;
    for (index = 0; index < *count; ++index) {
        char value[256];
        if (parse_string_token(items[index], value, sizeof(value), field) != 0 ||
            copy_text(values[index], PKG_NAME_MAX, value, field, 0) != 0) return -1;
    }
    return 0;
}

static int parse_inline_fields(const char *input, char values[][MAX_INLINE_VALUE],
                               const char *keys[], size_t key_count, const char *field) {
    size_t length = strlen(input);
    size_t position = 0;
    unsigned found = 0;
    if (length < 2u || input[0] != '{' || input[length - 1u] != '}') {
        fprintf(stderr, "rinpack: %s must be an inline table\n", field);
        return -1;
    }
    position = 1u;
    while (position < length - 1u) {
        char part[MAX_INLINE_VALUE];
        size_t start = position;
        size_t end;
        size_t index;
        while (position < length - 1u && isspace((unsigned char)input[position])) ++position;
        start = position;
        while (position < length - 1u && input[position] != '=' && input[position] != ',') ++position;
        if (position >= length - 1u || input[position] != '=') return failf2("malformed inline table", field);
        end = position;
        while (end > start && isspace((unsigned char)input[end - 1u])) --end;
        if (end <= start || end - start >= sizeof(part)) return failf2("invalid inline key", field);
        memcpy(part, input + start, end - start);
        part[end - start] = '\0';
        ++position;
        start = position;
        {
            int quoted = 0;
            int escaped = 0;
            while (position < length - 1u) {
                char c = input[position];
                if (quoted) {
                    if (escaped) escaped = 0;
                    else if (c == '\\') escaped = 1;
                    else if (c == '"') quoted = 0;
                } else if (c == '"') quoted = 1;
                else if (c == ',') break;
                ++position;
            }
        }
        end = position;
        while (end > start && isspace((unsigned char)input[end - 1u])) --end;
        while (start < end && isspace((unsigned char)input[start])) ++start;
        if (end <= start || end - start >= MAX_INLINE_VALUE) return failf2("invalid inline value", field);
        for (index = 0; index < key_count; ++index) {
            if (strcmp(part, keys[index]) == 0) {
                if (found & (1u << index)) return failf2("duplicate inline field", field);
                memcpy(values[index], input + start, end - start);
                values[index][end - start] = '\0';
                found |= 1u << index;
                break;
            }
        }
        if (index == key_count) return failf2("unknown inline field", part);
        if (position < length - 1u && input[position] == ',') ++position;
    }
    if (found != ((1u << key_count) - 1u)) return failf2("missing inline field", field);
    return 0;
}

static int parse_dependency_array(const char *input, Dependency *values, size_t *count,
                                  const char *field) {
    char items[MAX_ARRAY_ITEMS][MAX_INLINE_VALUE];
    const char *keys[] = {"name", "min_version", "max_version"};
    size_t index;
    if (split_array(input, items, count, field) != 0 || *count > PKG_MAX_DEPS) return -1;
    for (index = 0; index < *count; ++index) {
        char raw[3][MAX_INLINE_VALUE];
        char value[256];
        if (parse_inline_fields(items[index], raw, keys, 3u, field) != 0) return -1;
        if (parse_string_token(raw[0], value, sizeof(value), field) != 0 ||
            copy_text(values[index].name, PKG_NAME_MAX, value, field, 0) != 0 ||
            parse_string_token(raw[1], value, sizeof(value), field) != 0 ||
            copy_text(values[index].min_version, PKG_VERSION_MAX, value, field, 1) != 0 ||
            parse_string_token(raw[2], value, sizeof(value), field) != 0 ||
            copy_text(values[index].max_version, PKG_VERSION_MAX, value, field, 1) != 0) return -1;
    }
    return 0;
}

static int parse_entry_point_array(const char *input, EntryPoint *values, size_t *count,
                                   const char *field) {
    char items[MAX_ARRAY_ITEMS][MAX_INLINE_VALUE];
    const char *keys[] = {"name", "path"};
    size_t index;
    if (split_array(input, items, count, field) != 0 || *count > PKG_MAX_DEPS) return -1;
    for (index = 0; index < *count; ++index) {
        char raw[2][MAX_INLINE_VALUE];
        char value[256];
        if (parse_inline_fields(items[index], raw, keys, 2u, field) != 0) return -1;
        if (parse_string_token(raw[0], value, sizeof(value), field) != 0 ||
            copy_text(values[index].name, PKG_NAME_MAX, value, field, 0) != 0 ||
            parse_string_token(raw[1], value, sizeof(value), field) != 0 ||
            copy_text(values[index].path, PKG_PATH_MAX, value, field, 0) != 0) return -1;
    }
    return 0;
}

static int find_assignment(char *line, char **key, char **value) {
    char *equals = strchr(line, '=');
    if (!equals) return -1;
    *equals = '\0';
    *key = trim(line);
    *value = trim(equals + 1);
    if (!**key || !**value) return -1;
    return 0;
}

static int set_package_field(Manifest *manifest, unsigned *seen, const char *key,
                             const char *value) {
    char parsed[512];
    unsigned bit = 0;
    size_t index;
    const char *required[] = {
        "package_id", "display_name", "version", "architecture", "package_type",
        "description", "license", "homepage", "min_rinos_version", "max_rinos_version",
        "dependencies", "optional_dependencies", "conflicts", "provides", "entry_points",
        "flags", "capabilities"
    };
    for (index = 0; index < sizeof(required) / sizeof(required[0]); ++index)
        if (strcmp(key, required[index]) == 0) bit = 1u << index;
    if (!bit) return failf2("unknown [package] field", key);
    if (*seen & bit) return failf2("duplicate [package] field", key);
    *seen |= bit;
    if (strcmp(key, "dependencies") == 0)
        return parse_dependency_array(value, manifest->dependencies, &manifest->dependency_count, key);
    if (strcmp(key, "optional_dependencies") == 0)
        return parse_dependency_array(value, manifest->optional_dependencies, &manifest->optional_dependency_count, key);
    if (strcmp(key, "entry_points") == 0)
        return parse_entry_point_array(value, manifest->entry_points, &manifest->entry_point_count, key);
    if (strcmp(key, "conflicts") == 0)
        return parse_name_array(value, manifest->conflicts, PKG_MAX_DEPS, &manifest->conflict_count, key);
    if (strcmp(key, "provides") == 0)
        return parse_name_array(value, manifest->provides, PKG_MAX_DEPS, &manifest->provides_count, key);
    if (strcmp(key, "flags") == 0)
        return parse_string_array(value, manifest->flags, 3u, &manifest->flag_count, key);
    if (strcmp(key, "capabilities") == 0)
        return parse_string_array(value, manifest->capabilities,
                                  PKG_MAX_CAPABILITIES,
                                  &manifest->capability_count, key);
    if (parse_string_token(value, parsed, sizeof(parsed), key) != 0) return -1;
    if (strcmp(key, "package_id") == 0) return copy_text(manifest->package_id, sizeof(manifest->package_id), parsed, key, 0);
    if (strcmp(key, "display_name") == 0) return copy_text(manifest->display_name, sizeof(manifest->display_name), parsed, key, 0);
    if (strcmp(key, "version") == 0) return copy_text(manifest->version, sizeof(manifest->version), parsed, key, 0);
    if (strcmp(key, "architecture") == 0) return copy_text(manifest->architecture, sizeof(manifest->architecture), parsed, key, 0);
    if (strcmp(key, "package_type") == 0) return copy_text(manifest->package_type, sizeof(manifest->package_type), parsed, key, 0);
    if (strcmp(key, "description") == 0) return copy_text(manifest->description, sizeof(manifest->description), parsed, key, 1);
    if (strcmp(key, "license") == 0) return copy_text(manifest->license, sizeof(manifest->license), parsed, key, 0);
    if (strcmp(key, "homepage") == 0) return copy_text(manifest->homepage, sizeof(manifest->homepage), parsed, key, 1);
    if (strcmp(key, "min_rinos_version") == 0) return copy_text(manifest->min_rinos_version, sizeof(manifest->min_rinos_version), parsed, key, 1);
    return copy_text(manifest->max_rinos_version, sizeof(manifest->max_rinos_version), parsed, key, 1);
}

static int set_file_field(PackageFile *file, const char *key, const char *value) {
    char parsed[512];
    if (strcmp(key, "path") != 0 && strcmp(key, "source") != 0) return failf2("unknown [[files]] field", key);
    if ((strcmp(key, "path") == 0 && (file->seen & 1u)) || (strcmp(key, "source") == 0 && (file->seen & 2u)))
        return failf2("duplicate [[files]] field", key);
    if (parse_string_token(value, parsed, sizeof(parsed), key) != 0) return -1;
    if (strcmp(key, "path") == 0) {
        file->seen |= 1u;
        return copy_text(file->path, sizeof(file->path), parsed, key, 0);
    }
    file->seen |= 2u;
    return copy_text(file->source, sizeof(file->source), parsed, key, 0);
}

static int parse_manifest(const char *path, Manifest *manifest) {
    FILE *stream;
    char line[MAX_LINE];
    unsigned table = 0;
    unsigned package_seen = 0;
    PackageFile *current_file = NULL;
    char full_path[1024];
    char *slash;
    size_t index;
    memset(manifest, 0, sizeof(*manifest));
    if (!path || !resolve_full_path(full_path, path, sizeof(full_path))) return failf2("manifest path is invalid", path);
    memcpy(manifest->root, full_path, strlen(full_path) + 1u);
    slash = strrchr(manifest->root, '/');
    {
        char *backslash = strrchr(manifest->root, '\\');
        if (!slash || (backslash && backslash > slash)) slash = backslash;
    }
    if (!slash) return failf2("manifest has no parent directory", path);
    *slash = '\0';
    stream = fopen(full_path, "rb");
    if (!stream) return failf2("cannot open manifest", path);
    while (fgets(line, sizeof(line), stream)) {
        char *content;
        char *key;
        char *value;
        strip_comment(line);
        content = trim(line);
        if (!*content) continue;
        if (strcmp(content, "[package]") == 0) {
            if (table != 0u) { fclose(stream); return failf("manifest table order is invalid"); }
            table = 1u;
            continue;
        }
        if (strcmp(content, "[[files]]") == 0) {
            if (table == 0u || manifest->file_count >= PKG_MAX_FILES) {
                fclose(stream); return failf("file table count or order is invalid");
            }
            table = 2u;
            current_file = &manifest->files[manifest->file_count++];
            current_file->seen = 0;
            continue;
        }
        if (content[0] == '[') { fclose(stream); return failf2("unknown manifest table", content); }
        if (find_assignment(content, &key, &value) != 0) {
            fclose(stream); return failf("manifest assignment is malformed");
        }
        if (table == 1u) {
            if (set_package_field(manifest, &package_seen, key, value) != 0) { fclose(stream); return -1; }
        } else if (table == 2u && current_file) {
            if (set_file_field(current_file, key, value) != 0) { fclose(stream); return -1; }
        } else {
            fclose(stream); return failf("manifest assignment is outside a table");
        }
    }
    if (ferror(stream)) { fclose(stream); return failf2("cannot read manifest", path); }
    fclose(stream);
    if (package_seen != ((1u << 17u) - 1u) || manifest->file_count == 0u) return failf("manifest is missing required fields or files");
    for (index = 0; index < manifest->file_count; ++index) {
        if (strchr(manifest->files[index].path, '\\') || manifest->files[index].path[0] == '/' ||
            manifest->files[index].path[strlen(manifest->files[index].path) - 1u] == '/')
            return failf("file destination is not relative");
        if (manifest->files[index].seen != 3u) return failf("file record is missing path or source");
    }
    return 0;
}

static int canonical_name(const char *value, const char *field) {
    size_t index;
    size_t length = strlen(value);
    if (!length || length >= PKG_NAME_MAX || strcmp(value, ".") == 0 || strcmp(value, "..") == 0) return failf2("invalid package name", field);
    for (index = 0; index < length; ++index) {
        unsigned char c = (unsigned char)value[index];
        if (c < 0x20u || c == 0x7fu || c == '/' || c == '\\' || c == ':') return failf2("invalid package name", field);
    }
    return 0;
}

static int canonical_version(const char *value, const char *field, int allow_empty) {
    const char *cursor = value;
    unsigned components = 0;
    if (!*value && allow_empty) return 0;
    if (!*value || strlen(value) >= PKG_VERSION_MAX) return failf2("invalid version", field);
    while (*cursor) {
        unsigned long long number = 0;
        const char *start = cursor;
        if (++components > 4u) return failf2("invalid version", field);
        while (*cursor && *cursor != '.') {
            if (!isdigit((unsigned char)*cursor)) return failf2("invalid version", field);
            number = number * 10u + (unsigned)(*cursor - '0');
            if (number > UINT32_MAX) return failf2("invalid version", field);
            ++cursor;
        }
        if (cursor == start || (cursor - start > 1 && start[0] == '0')) return failf2("invalid version", field);
        if (*cursor == '.') {
            ++cursor;
            if (!*cursor) return failf2("invalid version", field);
        }
    }
    return 0;
}

static int canonical_relative(const char *value, const char *field, int allow_reserved) {
    char copy[PKG_PATH_MAX];
    char *part;
    char *save = NULL;
    if (copy_text(copy, sizeof(copy), value, field, 0) != 0 || value[0] == '/' || value[strlen(value) - 1u] == '/') return -1;
    part = strtok_s(copy, "/", &save);
    while (part) {
        if (!*part || strcmp(part, ".") == 0 || strcmp(part, "..") == 0) return failf2("non-canonical relative path", field);
        part = strtok_s(NULL, "/", &save);
    }
    if (!allow_reserved && strncmp(value, ".rinpkg/", 8u) == 0) return failf2("reserved relative path", field);
    return 0;
}

static int version_compare(const char *left, const char *right) {
    const char *a = left;
    const char *b = right;
    unsigned index;
    for (index = 0; index < 4u; ++index) {
        unsigned long long av = 0;
        unsigned long long bv = 0;
        while (*a && *a != '.') { av = av * 10u + (unsigned)(*a - '0'); ++a; }
        while (*b && *b != '.') { bv = bv * 10u + (unsigned)(*b - '0'); ++b; }
        if (av < bv) return -1;
        if (av > bv) return 1;
        if (*a == '.') ++a;
        if (*b == '.') ++b;
    }
    return 0;
}

static int source_is_link(const char *path) {
#ifdef _WIN32
    DWORD attributes = GetFileAttributesA(path);
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
    struct stat st;
    return lstat(path, &st) == 0 && S_ISLNK(st.st_mode);
#endif
}

static int validate_manifest(Manifest *manifest) {
    size_t index;
    size_t other;
    static const char *capabilities[] = {
        "dac-override", "chown", "system-admin", "driver-broker",
        "service-control", "gui-control", "process-control", "network-admin",
        "crash-diagnostic", "storage-manage", "package-manage", "rin-pass",
        "keyring-master", "power-control", "system-info", "network-access",
        "clipboard", "notification", "gpu-access", "microphone", "camera",
        "midi", "location", "file-portal", "theme-control", "accessibility",
        "display", "desktop", "audio-output", "debugging", "profiling",
    };
    const char *flags[] = {"system", "reboot-required", "security"};
    if (canonical_name(manifest->package_id, "package_id") != 0 ||
        canonical_version(manifest->version, "version", 0) != 0 ||
        canonical_version(manifest->min_rinos_version, "min_rinos_version", 1) != 0 ||
        canonical_version(manifest->max_rinos_version, "max_rinos_version", 1) != 0) return -1;
    if (strcmp(manifest->architecture, "x86_64") != 0 && strcmp(manifest->architecture, "i686") != 0 && strcmp(manifest->architecture, "any") != 0)
        return failf2("unknown architecture", manifest->architecture);
    if (strcmp(manifest->package_type, "application") != 0 && strcmp(manifest->package_type, "runtime") != 0 && strcmp(manifest->package_type, "library") != 0 && strcmp(manifest->package_type, "driver") != 0 && strcmp(manifest->package_type, "system-component") != 0 && strcmp(manifest->package_type, "language-pack") != 0 && strcmp(manifest->package_type, "theme") != 0 && strcmp(manifest->package_type, "developer-tool") != 0)
        return failf2("unknown package type", manifest->package_type);
    for (index = 0; index < manifest->flag_count; ++index) {
        size_t found = 0;
        for (other = 0; other < 3u; ++other) if (strcmp(manifest->flags[index], flags[other]) == 0) found = 1;
        if (!found) return failf2("unknown package flag", manifest->flags[index]);
        for (other = 0; other < index; ++other) if (strcmp(manifest->flags[index], manifest->flags[other]) == 0) return failf("duplicate package flag");
    }
    for (index = 0; index < manifest->capability_count; ++index) {
        size_t found = 0;
        for (other = 0; other < sizeof(capabilities) / sizeof(capabilities[0]); ++other)
            if (strcmp(manifest->capabilities[index], capabilities[other]) == 0) found = 1;
        if (!found) return failf2("unknown capability", manifest->capabilities[index]);
        for (other = 0; other < index; ++other) if (strcmp(manifest->capabilities[index], manifest->capabilities[other]) == 0) return failf("duplicate capability");
    }
    for (index = 0; index < manifest->file_count; ++index) {
        char source_path[2048];
        char resolved[2048];
        RinStat st;
        if (canonical_relative(manifest->files[index].path, "files.path", 0) != 0 ||
            copy_text(manifest->files[index].source, sizeof(manifest->files[index].source), manifest->files[index].source, "files.source", 0) != 0) return -1;
        for (other = 0; other < index; ++other) if (strcmp(manifest->files[index].path, manifest->files[other].path) == 0) return failf("duplicate package destination path");
        if (snprintf(source_path, sizeof(source_path), "%s/%s", manifest->root, manifest->files[index].source) >= (int)sizeof(source_path) || !resolve_full_path(resolved, source_path, sizeof(resolved))) return failf("source path is too long");
        {
            size_t root_length = strlen(manifest->root);
            if (strlen(resolved) <= root_length || strncasecmp(resolved, manifest->root, root_length) != 0 || (resolved[root_length] != '/' && resolved[root_length] != '\\')) return failf("file source escapes manifest directory");
        }
        if (source_is_link(resolved) || rin_stat(resolved, &st) != 0 || !rin_stat_is_regular(st)) return failf2("source is not a regular non-symlink file", resolved);
        if ((uint64_t)st.st_size > PKG_MAX_FILE_SIZE) return failf2("source exceeds per-file limit", resolved);
        manifest->files[index].data = (uint8_t *)malloc(st.st_size ? (size_t)st.st_size : 1u);
        manifest->files[index].size = (size_t)st.st_size;
        if (!manifest->files[index].data) return failf("out of memory reading source");
        {
            FILE *source = fopen(resolved, "rb");
            if (!source || (st.st_size && fread(manifest->files[index].data, 1, (size_t)st.st_size, source) != (size_t)st.st_size)) {
                if (source) fclose(source);
                return failf2("cannot read source", resolved);
            }
            fclose(source);
        }
    }
    return 0;
}

static void manifest_free(Manifest *manifest) {
    size_t index;
    for (index = 0; index < manifest->file_count; ++index) free(manifest->files[index].data);
}

static int compare_file(const void *left, const void *right) {
    const PackageFile *a = (const PackageFile *)left;
    const PackageFile *b = (const PackageFile *)right;
    return strcmp(a->path, b->path);
}

static int compare_dependency(const void *left, const void *right) {
    return strcmp(((const Dependency *)left)->name, ((const Dependency *)right)->name);
}

static int compare_name64(const void *left, const void *right) {
    return strcmp((const char *)left, (const char *)right);
}

static int compare_entry_point(const void *left, const void *right) {
    return strcmp(((const EntryPoint *)left)->name, ((const EntryPoint *)right)->name);
}

static int validate_dependency_ranges(const Dependency *dependencies, size_t count,
                                      const char *owner) {
    size_t index;
    for (index = 0; index < count; ++index) {
        if (canonical_name(dependencies[index].name, "dependency name") != 0 ||
            strcmp(dependencies[index].name, owner) == 0 ||
            canonical_version(dependencies[index].min_version, "dependency min_version", 1) != 0 ||
            canonical_version(dependencies[index].max_version, "dependency max_version", 1) != 0) return -1;
        if (index && strcmp(dependencies[index - 1u].name, dependencies[index].name) == 0) return failf("duplicate dependency name");
        if (dependencies[index].min_version[0] && dependencies[index].max_version[0] &&
            version_compare(dependencies[index].min_version, dependencies[index].max_version) >= 0) return failf("dependency version range is empty");
    }
    return 0;
}

static int make_base_package(const Manifest *manifest, uint8_t header[PKG_HEADER_SIZE],
                             uint8_t entries[PKG_MAX_FILES * PKG_ENTRY_SIZE], Buffer *payload) {
    size_t index;
    uint32_t type;
    memset(header, 0, PKG_HEADER_SIZE);
    memset(entries, 0, PKG_MAX_FILES * PKG_ENTRY_SIZE);
    if (strcmp(manifest->package_type, "application") == 0) type = 0;
    else if (strcmp(manifest->package_type, "runtime") == 0 || strcmp(manifest->package_type, "library") == 0) type = 1;
    else if (strcmp(manifest->package_type, "driver") == 0) type = 2;
    else type = 3;
    put32(header, 0, PKG_MAGIC);
    put16(header, 4, PKG_VERSION_UNSIGNED);
    put16(header, 6, (uint16_t)type);
    memcpy(header + 8, manifest->package_id, strlen(manifest->package_id));
    memcpy(header + 72, manifest->version, strlen(manifest->version));
    memcpy(header + 104, manifest->display_name, strlen(manifest->display_name));
    for (index = 0; index < manifest->file_count; ++index) {
        uint8_t *entry = entries + index * PKG_ENTRY_SIZE;
        size_t path_length = strlen(manifest->files[index].path);
        if (path_length >= PKG_PATH_MAX || payload->size > UINT32_MAX || manifest->files[index].size > UINT32_MAX) return failf("package entry is too large");
        memcpy(entry, manifest->files[index].path, path_length);
        put32(entry, 192, (uint32_t)payload->size);
        put32(entry, 196, (uint32_t)manifest->files[index].size);
        put32(entry, 200, crc32_bytes(manifest->files[index].data, manifest->files[index].size));
        if (buffer_append(payload, manifest->files[index].data, manifest->files[index].size) != 0) return -1;
    }
    put32(header, 168, (uint32_t)manifest->file_count);
    put32(header, 172, (uint32_t)payload->size);
    put32(header, 180, crc32_bytes(header, PKG_HEADER_SIZE));
    return 0;
}

static int metadata_init(Metadata *metadata, const char *path, const void *data, size_t size) {
    memset(metadata, 0, sizeof(*metadata));
    if (strlen(path) >= PKG_PATH_MAX || copy_text(metadata->path, sizeof(metadata->path), path, "metadata path", 0) != 0 || buffer_append(&metadata->data, data, size) != 0) return -1;
    return 0;
}

static void metadata_free(Metadata *metadata, size_t count) {
    size_t index;
    for (index = 0; index < count; ++index) buffer_free(&metadata[index].data);
}

static int make_dependency_metadata(const Manifest *manifest, Buffer *out) {
    uint8_t header[32];
    size_t index;
    memset(header, 0, sizeof(header));
    put32(header, 0, PKG_DEPENDENCY_MAGIC);
    put16(header, 4, 1);
    put16(header, 6, 32);
    put32(header, 8, (uint32_t)manifest->dependency_count);
    put32(header, 12, 128);
    if (buffer_append(out, header, sizeof(header)) != 0) return -1;
    for (index = 0; index < manifest->dependency_count; ++index) {
        uint8_t record[128];
        memset(record, 0, sizeof(record));
        memcpy(record, manifest->dependencies[index].name, strlen(manifest->dependencies[index].name));
        memcpy(record + 64, manifest->dependencies[index].min_version, strlen(manifest->dependencies[index].min_version));
        memcpy(record + 96, manifest->dependencies[index].max_version, strlen(manifest->dependencies[index].max_version));
        if (buffer_append(out, record, sizeof(record)) != 0) return -1;
    }
    put32(out->data, 16, crc32_bytes(out->data, out->size));
    return 0;
}

static uint64_t capability_bit(const char *name) {
    static const char *names[] = {
        "dac-override", "chown", "system-admin", "driver-broker",
        "service-control", "gui-control", "process-control", "network-admin",
        "crash-diagnostic", "storage-manage", "package-manage", "rin-pass",
        "keyring-master", "power-control", "system-info", "network-access",
        "clipboard", "notification", "gpu-access", "microphone", "camera",
        "midi", "location", "file-portal", "theme-control", "accessibility",
        "display", "desktop", "audio-output", "debugging", "profiling",
    };
    size_t index;
    for (index = 0; index < sizeof(names) / sizeof(names[0]); ++index) if (strcmp(name, names[index]) == 0) return UINT64_C(1) << index;
    return 0;
}

static uint32_t manifest_flag(const char *name) {
    if (strcmp(name, "system") == 0) return 1u;
    if (strcmp(name, "reboot-required") == 0) return 2u;
    if (strcmp(name, "security") == 0) return 4u;
    return 0;
}

static int make_capability_metadata(const Manifest *manifest, const uint8_t key_id[32], unsigned generation, Buffer *out) {
    uint8_t data[96];
    size_t index;
    uint64_t declared = 0;
    memset(data, 0, sizeof(data));
    for (index = 0; index < manifest->capability_count; ++index) declared |= capability_bit(manifest->capabilities[index]);
    put32(data, 0, PKG_CAPABILITY_MAGIC);
    put16(data, 4, 2);
    put16(data, 6, 96);
    put64(data, 8, declared);
    memcpy(data + 24, key_id, 32);
    put32(data, 56, generation);
    put32(data, 20, crc32_bytes(data, sizeof(data)));
    return buffer_append(out, data, sizeof(data));
}

static int make_file_identity_metadata(const Manifest *manifest, Buffer *out) {
    uint8_t header[32];
    size_t index;
    memset(header, 0, sizeof(header));
    put32(header, 0, PKG_FILE_IDENTITY_MAGIC);
    put16(header, 4, 1);
    put16(header, 6, 32);
    put32(header, 8, (uint32_t)manifest->file_count);
    put32(header, 12, 264);
    if (buffer_append(out, header, sizeof(header)) != 0) return -1;
    for (index = 0; index < manifest->file_count; ++index) {
        uint8_t record[264];
        uint8_t digest[32];
        memset(record, 0, sizeof(record));
        memcpy(record, manifest->files[index].path, strlen(manifest->files[index].path));
        put64(record, 192, manifest->files[index].size);
        EVP_Digest(manifest->files[index].data, manifest->files[index].size, digest, NULL, EVP_sha256(), NULL);
        memcpy(record + 200, digest, sizeof(digest));
        if (manifest->files[index].size >= RIN_IMAGE_HEADER_SIZE && get32(manifest->files[index].data, 0) == RIN_IMAGE_MAGIC && get32(manifest->files[index].data, 4) == RIN_IMAGE_VERSION_V3 && get16(manifest->files[index].data, 8) == RIN_IMAGE_HEADER_SIZE && (get32(manifest->files[index].data, 16) & RIN_IMAGE_EXECUTABLE) != 0u)
            memcpy(record + 232, manifest->files[index].data + 116, 32);
        if (buffer_append(out, record, sizeof(record)) != 0) return -1;
    }
    put32(out->data, 16, crc32_bytes(out->data, out->size));
    return 0;
}

static uint16_t manifest_architecture(const char *value) {
    if (strcmp(value, "x86_64") == 0) return 1;
    if (strcmp(value, "i686") == 0) return 2;
    return 3;
}

static uint16_t manifest_class(const char *value) {
    static const char *names[] = {"application", "runtime", "library", "driver", "system-component", "language-pack", "theme", "developer-tool"};
    size_t index;
    for (index = 0; index < sizeof(names) / sizeof(names[0]); ++index) if (strcmp(value, names[index]) == 0) return (uint16_t)(index + 1u);
    return 0;
}

static int make_package_manifest(const Manifest *manifest, const uint8_t key_id[32], unsigned generation,
                                 uint32_t final_total_size, Buffer *out) {
    uint8_t header[PKG_MANIFEST_HEADER_SIZE];
    size_t index;
    uint32_t flags = 0;
    for (index = 0; index < manifest->flag_count; ++index) flags |= manifest_flag(manifest->flags[index]);
    memset(header, 0, sizeof(header));
    put32(header, 0, PKG_MANIFEST_MAGIC);
    put16(header, 4, 1);
    put16(header, 6, PKG_MANIFEST_HEADER_SIZE);
    put32(header, 8, final_total_size);
    memcpy(header + 12, manifest->package_id, strlen(manifest->package_id));
    memcpy(header + 76, manifest->display_name, strlen(manifest->display_name));
    memcpy(header + 140, manifest->version, strlen(manifest->version));
    put16(header, 172, manifest_architecture(manifest->architecture));
    put16(header, 174, manifest_class(manifest->package_type));
    put32(header, 176, flags);
    memcpy(header + 180, key_id, 32);
    put32(header, 212, generation);
    memcpy(header + 216, manifest->description, strlen(manifest->description));
    memcpy(header + 472, manifest->license, strlen(manifest->license));
    memcpy(header + 536, manifest->homepage, strlen(manifest->homepage));
    memcpy(header + 728, manifest->min_rinos_version, strlen(manifest->min_rinos_version));
    memcpy(header + 760, manifest->max_rinos_version, strlen(manifest->max_rinos_version));
    {
        uint64_t installed = 0;
        for (index = 0; index < manifest->file_count; ++index) installed += manifest->files[index].size;
        put64(header, 792, installed);
    }
    put32(header, 800, (uint32_t)manifest->dependency_count);
    put32(header, 804, (uint32_t)manifest->optional_dependency_count);
    put32(header, 808, (uint32_t)manifest->conflict_count);
    put32(header, 812, (uint32_t)manifest->provides_count);
    put32(header, 816, (uint32_t)manifest->entry_point_count);
    put32(header, 820, (uint32_t)manifest->file_count);
    if (buffer_append(out, header, sizeof(header)) != 0) return -1;
    for (index = 0; index < manifest->dependency_count; ++index) {
        uint8_t record[128]; memset(record, 0, sizeof(record));
        memcpy(record, manifest->dependencies[index].name, strlen(manifest->dependencies[index].name));
        memcpy(record + 64, manifest->dependencies[index].min_version, strlen(manifest->dependencies[index].min_version));
        memcpy(record + 96, manifest->dependencies[index].max_version, strlen(manifest->dependencies[index].max_version));
        if (buffer_append(out, record, sizeof(record)) != 0) return -1;
    }
    for (index = 0; index < manifest->optional_dependency_count; ++index) {
        uint8_t record[128]; memset(record, 0, sizeof(record));
        memcpy(record, manifest->optional_dependencies[index].name, strlen(manifest->optional_dependencies[index].name));
        memcpy(record + 64, manifest->optional_dependencies[index].min_version, strlen(manifest->optional_dependencies[index].min_version));
        memcpy(record + 96, manifest->optional_dependencies[index].max_version, strlen(manifest->optional_dependencies[index].max_version));
        if (buffer_append(out, record, sizeof(record)) != 0) return -1;
    }
    for (index = 0; index < manifest->conflict_count; ++index) {
        uint8_t record[64]; memset(record, 0, sizeof(record)); memcpy(record, manifest->conflicts[index], strlen(manifest->conflicts[index]));
        if (buffer_append(out, record, sizeof(record)) != 0) return -1;
    }
    for (index = 0; index < manifest->provides_count; ++index) {
        uint8_t record[64]; memset(record, 0, sizeof(record)); memcpy(record, manifest->provides[index], strlen(manifest->provides[index]));
        if (buffer_append(out, record, sizeof(record)) != 0) return -1;
    }
    for (index = 0; index < manifest->entry_point_count; ++index) {
        uint8_t record[256]; memset(record, 0, sizeof(record));
        memcpy(record, manifest->entry_points[index].name, strlen(manifest->entry_points[index].name));
        memcpy(record + 64, manifest->entry_points[index].path, strlen(manifest->entry_points[index].path));
        if (buffer_append(out, record, sizeof(record)) != 0) return -1;
    }
    for (index = 0; index < manifest->file_count; ++index) {
        uint8_t record[64]; memset(record, 0, sizeof(record)); memcpy(record, manifest->files[index].path, strlen(manifest->files[index].path));
        if (buffer_append(out, record, sizeof(record)) != 0) return -1;
    }
    if (out->size > PKG_MANIFEST_MAX_SIZE) return failf("package manifest exceeds its size limit");
    put32(out->data, 824, crc32_bytes(out->data, out->size));
    return 0;
}

static int build_image(const Manifest *manifest, const uint8_t key_id[32], unsigned generation,
                       int signed_package, Buffer *image) {
    uint8_t base_header[PKG_HEADER_SIZE];
    uint8_t base_entries[PKG_MAX_FILES * PKG_ENTRY_SIZE];
    Buffer payload = {0};
    Metadata metadata[4];
    size_t metadata_count = 0;
    size_t index;
    size_t metadata_payload_size = 0;
    uint32_t base_total;
    uint32_t final_file_count;
    uint32_t final_total;
    memset(metadata, 0, sizeof(metadata));
    if (make_base_package(manifest, base_header, base_entries, &payload) != 0) goto error;
    base_total = (uint32_t)payload.size;
    if (signed_package) {
        Buffer value = {0};
        if (manifest->dependency_count) {
            if (make_dependency_metadata(manifest, &value) != 0 || metadata_init(&metadata[metadata_count++], ".rinpkg/dependencies.rdep", value.data, value.size) != 0) { buffer_free(&value); goto error; }
            buffer_free(&value);
        }
        if (manifest->capability_count) {
            if (generation == 0u || make_capability_metadata(manifest, key_id, generation, &value) != 0 || metadata_init(&metadata[metadata_count++], ".rinpkg/capabilities.rcap", value.data, value.size) != 0) { buffer_free(&value); goto error; }
            buffer_free(&value);
        }
        if (make_file_identity_metadata(manifest, &value) != 0 || metadata_init(&metadata[metadata_count++], ".rinpkg/file-identities.rfim", value.data, value.size) != 0) { buffer_free(&value); goto error; }
        buffer_free(&value);
        if (make_package_manifest(manifest, (generation ? key_id : (const uint8_t[32]){0}), generation, 0, &value) != 0) goto error;
        metadata_payload_size = value.size;
        for (index = 0; index < metadata_count; ++index) metadata_payload_size += metadata[index].data.size;
        final_total = base_total + (uint32_t)metadata_payload_size;
        {
            Buffer final_manifest = {0};
            if (make_package_manifest(manifest, (generation ? key_id : (const uint8_t[32]){0}), generation, final_total, &final_manifest) != 0 || metadata_init(&metadata[metadata_count++], ".rinpkg/manifest.rman", final_manifest.data, final_manifest.size) != 0) { buffer_free(&value); buffer_free(&final_manifest); goto error; }
            buffer_free(&final_manifest);
        }
        buffer_free(&value);
    }
    final_file_count = (uint32_t)manifest->file_count + (uint32_t)metadata_count;
    if (final_file_count == 0u || final_file_count > PKG_MAX_FILES) { failf("package file count exceeds limit"); goto error; }
    metadata_payload_size = 0;
    for (index = 0; index < metadata_count; ++index) metadata_payload_size += metadata[index].data.size;
    final_total = base_total + (uint32_t)metadata_payload_size;
    if (final_total > PKG_MAX_TOTAL_SIZE) { failf("package exceeds total payload limit"); goto error; }
    memset(image, 0, sizeof(*image));
    if (buffer_append(image, base_header, PKG_HEADER_SIZE) != 0 || buffer_append(image, base_entries, manifest->file_count * PKG_ENTRY_SIZE) != 0) goto error;
    for (index = 0; index < metadata_count; ++index) {
        uint8_t entry[PKG_ENTRY_SIZE];
        memset(entry, 0, sizeof(entry));
        memcpy(entry, metadata[index].path, strlen(metadata[index].path));
        put32(entry, 192, base_total);
        for (size_t previous = 0; previous < index; ++previous) put32(entry, 192, get32(entry, 192) + (uint32_t)metadata[previous].data.size);
        put32(entry, 196, (uint32_t)metadata[index].data.size);
        put32(entry, 200, crc32_bytes(metadata[index].data.data, metadata[index].data.size));
        put16(entry, 204, PKG_FILE_FLAG_METADATA);
        if (buffer_append(image, entry, sizeof(entry)) != 0) goto error;
    }
    if (buffer_append(image, payload.data, payload.size) != 0) goto error;
    for (index = 0; index < metadata_count; ++index) if (buffer_append(image, metadata[index].data.data, metadata[index].data.size) != 0) goto error;
    put32(image->data, 168, final_file_count);
    put32(image->data, 172, final_total);
    put32(image->data, 180, 0);
    put32(image->data, 180, crc32_bytes(image->data, PKG_HEADER_SIZE));
    metadata_free(metadata, metadata_count);
    buffer_free(&payload);
    return 0;
error:
    metadata_free(metadata, metadata_count);
    buffer_free(&payload);
    buffer_free(image);
    return -1;
}

static int read_file(const char *path, Buffer *out) {
    FILE *stream;
    long length;
    memset(out, 0, sizeof(*out));
    stream = fopen(path, "rb");
    if (!stream) return failf2("cannot open file", path);
    if (fseek(stream, 0, SEEK_END) != 0 || (length = ftell(stream)) < 0 || fseek(stream, 0, SEEK_SET) != 0) { fclose(stream); return failf2("cannot determine file size", path); }
    if ((uint64_t)length > SIZE_MAX || buffer_reserve(out, (size_t)length) != 0 || (length && fread(out->data, 1, (size_t)length, stream) != (size_t)length)) { fclose(stream); buffer_free(out); return failf2("cannot read file", path); }
    out->size = (size_t)length;
    fclose(stream);
    return 0;
}

static int header_crc_valid(const uint8_t *header) {
    uint8_t checked[PKG_HEADER_SIZE];
    memcpy(checked, header, sizeof(checked));
    put32(checked, 180, 0);
    return crc32_bytes(checked, sizeof(checked)) == get32(header, 180);
}

static int canonical_field(const uint8_t *field, size_t capacity, int allow_empty) {
    size_t length = 0;
    while (length < capacity && field[length]) ++length;
    if (length == capacity || (!allow_empty && length == 0u)) return -1;
    while (++length < capacity) if (field[length]) return -1;
    return 0;
}

static int validate_package(const Buffer *package, size_t *data_offset, size_t *file_count) {
    const uint8_t *header = package->data;
    uint32_t count;
    uint32_t total;
    size_t index;
    size_t end_max = 0;
    if (package->size < PKG_HEADER_SIZE) return failf("package is shorter than its header");
    if (get32(header, 0) != PKG_MAGIC) return failf("package magic is invalid");
    if (get16(header, 4) < 1u || get16(header, 4) > 3u) return failf("package version is invalid");
    if (get16(header, 6) > 3u) return failf("package type is invalid");
    if (!header_crc_valid(header)) return failf("package header CRC32 is invalid");
    if (canonical_field(header + 8, 64, 0) != 0) return failf("package name is invalid");
    if (canonical_field(header + 72, 32, 0) != 0) return failf("package version string is invalid");
    if (canonical_field(header + 104, 64, 1) != 0) return failf("package display name is invalid");
    for (index = 236u; index < PKG_HEADER_SIZE; ++index) if (header[index]) return failf("package header reserved bytes are not zero");
    count = get32(header, 168);
    total = get32(header, 172);
    if (count == 0u || count > PKG_MAX_FILES || total > PKG_MAX_TOTAL_SIZE) return failf("package header limits are invalid");
    *data_offset = PKG_HEADER_SIZE + (size_t)count * PKG_ENTRY_SIZE;
    if (*data_offset > package->size) return failf("package entry table is truncated");
    for (index = 0; index < count; ++index) {
        const uint8_t *entry = package->data + PKG_HEADER_SIZE + index * PKG_ENTRY_SIZE;
        size_t path_length = 0;
        uint32_t offset;
        uint32_t size;
        while (path_length < PKG_PATH_MAX && entry[path_length]) ++path_length;
        if (path_length == PKG_PATH_MAX || canonical_relative((const char *)entry, "package entry path", 1) != 0 || (get16(entry, 204) != 0u && get16(entry, 204) != PKG_FILE_FLAG_METADATA)) return -1;
        for (size_t reserved = 206u; reserved < PKG_ENTRY_SIZE; ++reserved) if (entry[reserved]) return failf("package entry reserved bytes are not zero");
        if (strncmp((const char *)entry, ".rinpkg/", 8u) == 0 && get16(entry, 204) == 0u) return failf("reserved package entry is not metadata");
        offset = get32(entry, 192); size = get32(entry, 196);
        if ((uint64_t)offset + size > total || (uint64_t)*data_offset + offset + size > package->size) return failf("package entry exceeds payload");
        if (crc32_bytes(package->data + *data_offset + offset, size) != get32(entry, 200)) return failf("package entry CRC32 is invalid");
        if ((size_t)offset + size > end_max) end_max = (size_t)offset + size;
        for (size_t previous = 0; previous < index; ++previous) {
            const uint8_t *old = package->data + PKG_HEADER_SIZE + previous * PKG_ENTRY_SIZE;
            uint32_t old_offset = get32(old, 192), old_size = get32(old, 196);
            if (size && old_size && offset < old_offset + old_size && old_offset < offset + size) return failf("package entries overlap");
            if (strncmp((const char *)entry, (const char *)old, PKG_PATH_MAX) == 0) return failf("package contains duplicate paths");
        }
    }
    if (end_max != total) return failf("package payload is not dense");
    if (get16(header, 4) == PKG_VERSION_UNSIGNED) {
        if (get32(header, 176) || get64(header, 184) || get32(header, 192) || get32(header, 196) || package->size != *data_offset + total) return failf("unsigned package contains signed metadata");
    } else {
        uint64_t signature_offset = get64(header, 184);
        uint32_t signature_size = get32(header, 192);
        if (get32(header, 176) != PKG_FLAG_SIGNED || get32(header, 196) != 0u || signature_offset != *data_offset + total || signature_size < 48u || signature_offset + signature_size != package->size) return failf("signed package layout is invalid");
        if (get16(header, 4) == PKG_VERSION_PUBLISHER_SIGNED && (get32(header, 232) == 0u || !memcmp(header + 200, (const uint8_t[32]){0}, 32))) return failf("publisher identity is invalid");
    }
    *file_count = count;
    return 0;
}

static int load_public_der(const char *path, Buffer *der, RSA **rsa_out) {
    const unsigned char *cursor;
    RSA *rsa;
    if (read_file(path, der) != 0) return -1;
    cursor = der->data;
    rsa = d2i_RSAPublicKey(NULL, &cursor, (long)der->size);
    if (!rsa || cursor != der->data + der->size) { RSA_free(rsa); buffer_free(der); return failf2("public key DER is invalid", path); }
    *rsa_out = rsa;
    return 0;
}

static int load_private_key(const char *path, EVP_PKEY **key_out) {
    FILE *stream = fopen(path, "rb");
    EVP_PKEY *key;
    if (!stream) return failf2("cannot open private key", path);
    key = PEM_read_PrivateKey(stream, NULL, NULL, NULL);
    fclose(stream);
    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA || EVP_PKEY_get_bits(key) < 2048 || EVP_PKEY_get_bits(key) > 4096) { EVP_PKEY_free(key); return failf("private key must be RSA 2048..4096 bits"); }
    *key_out = key;
    return 0;
}

static int public_der_matches(EVP_PKEY *private_key, const Buffer *trusted_der) {
    RSA *rsa = EVP_PKEY_get1_RSA(private_key);
    unsigned char *encoded = NULL;
    int length;
    int matches;
    if (!rsa) return failf("cannot extract RSA public key");
    length = i2d_RSAPublicKey(rsa, &encoded);
    RSA_free(rsa);
    matches = length > 0 && (size_t)length == trusted_der->size && memcmp(encoded, trusted_der->data, trusted_der->size) == 0;
    OPENSSL_free(encoded);
    return matches ? 0 : failf("private signing key does not match public key");
}

static int digest_sign(EVP_PKEY *key, const uint8_t *data, size_t size, uint8_t **signature, size_t *signature_size) {
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    size_t length = 0;
    uint8_t *value;
    if (!context || EVP_DigestSignInit(context, NULL, EVP_sha256(), NULL, key) != 1 || EVP_DigestSignUpdate(context, data, size) != 1 || EVP_DigestSignFinal(context, NULL, &length) != 1) { EVP_MD_CTX_free(context); return failf("RSA SHA-256 signing setup failed"); }
    value = (uint8_t *)malloc(length ? length : 1u);
    if (!value || EVP_DigestSignFinal(context, value, &length) != 1) { free(value); EVP_MD_CTX_free(context); return failf("RSA SHA-256 signing failed"); }
    EVP_MD_CTX_free(context);
    *signature = value;
    *signature_size = length;
    return 0;
}

static int sign_package(Buffer *image, const char *private_path, const char *public_path, unsigned generation) {
    Buffer public_der = {0};
    RSA *trusted_rsa = NULL;
    EVP_PKEY *private_key = NULL;
    uint8_t key_id[32];
    uint8_t *probe = NULL;
    uint8_t *signature = NULL;
    size_t probe_size = 0;
    size_t signature_size = 0;
    uint8_t envelope[48];
    if (load_public_der(public_path, &public_der, &trusted_rsa) != 0 || load_private_key(private_path, &private_key) != 0) goto error;
    RSA_free(trusted_rsa); trusted_rsa = NULL;
    if (public_der_matches(private_key, &public_der) != 0 || digest_sign(private_key, image->data, image->size, &probe, &probe_size) != 0 || probe_size < 256u || probe_size > 512u) goto error;
    EVP_Digest(public_der.data, public_der.size, key_id, NULL, EVP_sha256(), NULL);
    put16(image->data, 4, generation ? PKG_VERSION_PUBLISHER_SIGNED : PKG_VERSION_SIGNED);
    put32(image->data, 176, PKG_FLAG_SIGNED);
    put64(image->data, 184, image->size);
    put32(image->data, 192, (uint32_t)(48u + probe_size));
    put32(image->data, 196, 0);
    if (generation) { memcpy(image->data + 200, key_id, 32); put32(image->data, 232, generation); }
    else { memset(image->data + 200, 0, 32); put32(image->data, 232, 0); }
    put32(image->data, 180, 0);
    put32(image->data, 180, crc32_bytes(image->data, PKG_HEADER_SIZE));
    free(probe); probe = NULL;
    if (digest_sign(private_key, image->data, image->size, &signature, &signature_size) != 0 || signature_size != (size_t)get32(image->data, 192) - 48u) goto error;
    memset(envelope, 0, sizeof(envelope));
    put32(envelope, 0, RIN_SIGNATURE_MAGIC);
    put16(envelope, 4, 1);
    put16(envelope, 6, 48);
    put16(envelope, 8, 1);
    put16(envelope, 10, (uint16_t)signature_size);
    memcpy(envelope + 12, key_id, 32);
    if (buffer_append(image, envelope, sizeof(envelope)) != 0 || buffer_append(image, signature, signature_size) != 0) goto error;
    EVP_PKEY_free(private_key); buffer_free(&public_der); free(signature); return 0;
error:
    RSA_free(trusted_rsa); EVP_PKEY_free(private_key); buffer_free(&public_der); free(probe); free(signature); return -1;
}

static int verify_signature(const Buffer *package, const char *public_path) {
    Buffer der = {0};
    RSA *rsa = NULL;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *context = NULL;
    size_t offset = (size_t)get64(package->data, 184);
    size_t total = package->size - offset;
    const uint8_t *envelope = package->data + offset;
    uint8_t key_id[32];
    int result = -1;
    if (load_public_der(public_path, &der, &rsa) != 0) goto done;
    if (total < 48u || get32(envelope, 0) != RIN_SIGNATURE_MAGIC || get16(envelope, 4) != 1u || get16(envelope, 6) != 48u || get16(envelope, 8) != 1u || get16(envelope, 10) + 48u != get32(package->data, 192)) goto done;
    EVP_Digest(der.data, der.size, key_id, NULL, EVP_sha256(), NULL);
    if (memcmp(envelope + 12, key_id, 32) != 0) goto done;
    key = EVP_PKEY_new();
    if (!key || EVP_PKEY_assign_RSA(key, rsa) != 1) goto done;
    rsa = NULL;
    context = EVP_MD_CTX_new();
    if (!context || EVP_DigestVerifyInit(context, NULL, EVP_sha256(), NULL, key) != 1 || EVP_DigestVerifyUpdate(context, package->data, offset) != 1) goto done;
    if (EVP_DigestVerifyFinal(context, envelope + 48, get16(envelope, 10)) != 1) goto done;
    result = 0;
done:
    if (result != 0) failf("package signature verification failed");
    EVP_MD_CTX_free(context); EVP_PKEY_free(key); RSA_free(rsa); buffer_free(&der);
    return result;
}

static int ensure_parent(const char *path) {
    char copy[2048];
    char *slash;
    char *cursor;
    if (strlen(path) >= sizeof(copy)) return failf("output path is too long");
    strcpy(copy, path);
    slash = strrchr(copy, '/');
    {
        char *backslash = strrchr(copy, '\\');
        if (!slash || (backslash && backslash > slash)) slash = backslash;
    }
    if (!slash) return 0;
    *slash = '\0';
    cursor = copy;
#ifdef _WIN32
    if (isalpha((unsigned char)cursor[0]) && cursor[1] == ':') cursor += 2;
#endif
    for (; *cursor; ++cursor) {
        if (*cursor == '/' || *cursor == '\\') {
            char saved = *cursor;
            *cursor = '\0';
            if (*copy && !(copy[1] == ':' && cursor == copy + 2) && mkdir_one(copy) != 0 && errno != EEXIST) return failf2("cannot create output directory", copy);
            *cursor = saved;
        }
    }
    if (*copy && mkdir_one(copy) != 0 && errno != EEXIST) return failf2("cannot create output directory", copy);
    return 0;
}

static int write_atomic(const char *path, const Buffer *image) {
    char temporary[2048];
    FILE *stream;
    if (ensure_parent(path) != 0 || snprintf(temporary, sizeof(temporary), "%s.tmp", path) >= (int)sizeof(temporary)) return -1;
    stream = fopen(temporary, "wb");
    if (!stream) return failf2("cannot open output", path);
    if ((image->size && fwrite(image->data, 1, image->size, stream) != image->size) || fflush(stream) != 0) { fclose(stream); unlink_file(temporary); return failf2("cannot write output", path); }
#ifdef _WIN32
    if (_commit(_fileno(stream)) != 0) { fclose(stream); unlink_file(temporary); return failf("cannot flush output"); }
#else
    if (fsync(fileno(stream)) != 0) { fclose(stream); unlink_file(temporary); return failf("cannot flush output"); }
#endif
    if (fclose(stream) != 0) { unlink_file(temporary); return failf("cannot close output"); }
#ifdef _WIN32
    if (!MoveFileExA(temporary, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) { unlink_file(temporary); return failf2("cannot publish output", path); }
#else
    if (rename(temporary, path) != 0) { unlink_file(temporary); return failf2("cannot publish output", path); }
#endif
    return 0;
}

static void json_string(const char *value) {
    const unsigned char *cursor = (const unsigned char *)value;
    putchar('"');
    while (*cursor) {
        if (*cursor == '"' || *cursor == '\\') { putchar('\\'); putchar(*cursor); }
        else if (*cursor == '\n') fputs("\\n", stdout);
        else if (*cursor == '\r') fputs("\\r", stdout);
        else if (*cursor == '\t') fputs("\\t", stdout);
        else if (*cursor < 0x20u) printf("\\u%04x", *cursor);
        else putchar(*cursor);
        ++cursor;
    }
    putchar('"');
}

static void print_hex(const uint8_t *value, size_t size) {
    size_t index;
    for (index = 0; index < size; ++index) printf("%02x", value[index]);
}

static void print_inspection(const Buffer *package, int json);

static void print_inspection(const Buffer *package, int json) {
    size_t data_offset, count, index;
    const uint8_t *header = package->data;
    uint8_t package_digest[32];
    if (validate_package(package, &data_offset, &count) != 0) return;
    if (!json) { printf("package %s %s (%llu files, %u bytes)\n", (const char *)(header + 8), (const char *)(header + 72), (unsigned long long)count, get32(header, 172)); return; }
    EVP_Digest(package->data, package->size, package_digest, NULL, EVP_sha256(), NULL);
    printf("{\"format\":\".rpk\",\"version\":%u,\"package_type\":%u,\"package_id\":", get16(header, 4), get16(header, 6)); json_string((const char *)(header + 8));
    printf(",\"package_version\":"); json_string((const char *)(header + 72));
    printf(",\"display_name\":"); json_string((const char *)(header + 104));
    printf(",\"file_count\":%llu,\"installed_size\":%u,\"signed\":%s,\"publisher_id\":\"", (unsigned long long)count, get32(header, 172), get16(header, 4) == PKG_VERSION_UNSIGNED ? "false" : "true");
    print_hex(header + 200, 32);
    printf("\",\"publisher_generation\":%u,\"package_sha256\":\"", get32(header, 232));
    print_hex(package_digest, sizeof(package_digest));
    printf("\",\"entries\":[");
    for (index = 0; index < count; ++index) {
        const uint8_t *entry = package->data + PKG_HEADER_SIZE + index * PKG_ENTRY_SIZE;
        if (index) putchar(',');
        uint8_t entry_digest[32];
        EVP_Digest(package->data + data_offset + get32(entry, 192), get32(entry, 196), entry_digest, NULL, EVP_sha256(), NULL);
        printf("{\"path\":"); json_string((const char *)entry); printf(",\"offset\":%u,\"size\":%u,\"sha256\":\"", get32(entry, 192), get32(entry, 196));
        print_hex(entry_digest, sizeof(entry_digest));
        printf("\",\"metadata\":%s}", get16(entry, 204) ? "true" : "false");
    }
    puts("]}");
}

static int build_command(const Options *options) {
    Manifest manifest;
    Buffer image = {0};
    uint8_t key_id[32] = {0};
    Buffer public_der = {0};
    int signed_package = options->sign_key != NULL || options->public_key != NULL;
    int result = -1;
    if (!options->manifest || !options->output) return failf("create requires --manifest and --output");
    if ((options->sign_key == NULL) != (options->public_key == NULL)) return failf("--sign-key and --public-key must be supplied together");
    if (options->generation_set && (!signed_package || options->publisher_generation == 0u)) return failf("publisher generation requires a positive signing identity");
    if (parse_manifest(options->manifest, &manifest) != 0 || validate_manifest(&manifest) != 0) goto done;
    qsort(manifest.files, manifest.file_count, sizeof(manifest.files[0]), compare_file);
    qsort(manifest.dependencies, manifest.dependency_count, sizeof(manifest.dependencies[0]), compare_dependency);
    qsort(manifest.optional_dependencies, manifest.optional_dependency_count, sizeof(manifest.optional_dependencies[0]), compare_dependency);
    qsort(manifest.conflicts, manifest.conflict_count, sizeof(manifest.conflicts[0]), compare_name64);
    qsort(manifest.provides, manifest.provides_count, sizeof(manifest.provides[0]), compare_name64);
    qsort(manifest.entry_points, manifest.entry_point_count, sizeof(manifest.entry_points[0]), compare_entry_point);
    if (validate_dependency_ranges(manifest.dependencies, manifest.dependency_count, manifest.package_id) != 0 || validate_dependency_ranges(manifest.optional_dependencies, manifest.optional_dependency_count, manifest.package_id) != 0) goto done;
    if (manifest.entry_point_count) for (size_t index = 0; index < manifest.entry_point_count; ++index) if (canonical_relative(manifest.entry_points[index].path, "entry point path", 0) != 0) goto done;
    if (signed_package && read_file(options->public_key, &public_der) != 0) goto done;
    if (signed_package) EVP_Digest(public_der.data, public_der.size, key_id, NULL, EVP_sha256(), NULL);
    if (build_image(&manifest, key_id, options->generation_set ? options->publisher_generation : 0u, signed_package, &image) != 0) goto done;
    if (signed_package && sign_package(&image, options->sign_key, options->public_key, options->generation_set ? options->publisher_generation : 0u) != 0) goto done;
    if (write_atomic(options->output, &image) != 0) goto done;
    if (options->json) {
        Buffer written = {0};
        if (read_file(options->output, &written) != 0) goto done;
        print_inspection(&written, 1);
        buffer_free(&written);
    } else {
        printf("created %s (%s %s%s)\n", options->output, manifest.package_id, manifest.version, signed_package ? ", signed" : ", unsigned");
    }
    result = 0;
done:
    manifest_free(&manifest);
    buffer_free(&public_der);
    buffer_free(&image);
    return result;
}

static int inspect_command(const Options *options) {
    Buffer package = {0};
    int result;
    if (!options->package || read_file(options->package, &package) != 0) return -1;
    result = validate_package(&package, &(size_t){0}, &(size_t){0});
    if (result == 0) print_inspection(&package, options->json);
    buffer_free(&package);
    return result;
}

static int verify_command(const Options *options) {
    Buffer package = {0};
    size_t data_offset, count;
    if (!options->package || !options->public_key) return failf("verify requires --package and --public-key");
    if (read_file(options->package, &package) != 0 || validate_package(&package, &data_offset, &count) != 0) { buffer_free(&package); return -1; }
    if (get16(package.data, 4) == PKG_VERSION_UNSIGNED || verify_signature(&package, options->public_key) != 0) { buffer_free(&package); return failf("package is not production-authenticated"); }
    if (options->json) printf("{\"format\":\".rpk\",\"verified\":true,\"file_count\":%llu}\n", (unsigned long long)count);
    else printf("verified %s\n", options->package);
    buffer_free(&package);
    (void)data_offset;
    return 0;
}

static void usage(void) {
    puts("usage: rinpack create --manifest package.toml --output app.rpk [--sign-key private.pem --public-key public.der --publisher-generation N]");
    puts("       rinpack inspect --package app.rpk [--json]");
    puts("       rinpack verify --package app.rpk --public-key public.der [--json]");
}

int main(int argc, char **argv) {
    Options options;
    const char *command;
    int index;
    memset(&options, 0, sizeof(options));
    if (argc < 2) { usage(); return 2; }
    command = argv[1];
    for (index = 2; index < argc; ++index) {
        if (strcmp(argv[index], "--json") == 0) options.json = 1;
        else if (strcmp(argv[index], "--manifest") == 0 && index + 1 < argc) options.manifest = argv[++index];
        else if (strcmp(argv[index], "--output") == 0 && index + 1 < argc) options.output = argv[++index];
        else if (strcmp(argv[index], "--package") == 0 && index + 1 < argc) options.package = argv[++index];
        else if (strcmp(argv[index], "--sign-key") == 0 && index + 1 < argc) options.sign_key = argv[++index];
        else if (strcmp(argv[index], "--public-key") == 0 && index + 1 < argc) options.public_key = argv[++index];
        else if (strcmp(argv[index], "--publisher-generation") == 0 && index + 1 < argc) {
            char *end;
            unsigned long value = strtoul(argv[++index], &end, 10);
            if (*end || value == 0u || value > UINT32_MAX) {
                failf("publisher generation is invalid");
                return 1;
            }
            options.publisher_generation = (unsigned)value;
            options.generation_set = 1;
        }
        else { usage(); return 2; }
    }
    if (strcmp(command, "create") == 0 || strcmp(command, "build") == 0) return build_command(&options) == 0 ? 0 : 1;
    if (strcmp(command, "inspect") == 0) return inspect_command(&options) == 0 ? 0 : 1;
    if (strcmp(command, "verify") == 0) return verify_command(&options) == 0 ? 0 : 1;
    usage();
    return 2;
}
