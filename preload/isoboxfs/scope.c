#define _GNU_SOURCE
#include "scope.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

static char *isoboxfs_strndup(const char *s, size_t n) {
    char *out = malloc(n + 1);
    if (out == NULL) {
        return NULL;
    }
    memcpy(out, s, n);
    out[n] = '\0';
    return out;
}

static int push_part(char ***parts, size_t *len, size_t *cap, const char *start, size_t n) {
    if (*len == *cap) {
        size_t next = *cap == 0 ? 8 : *cap * 2;
        if (next < *cap) {
            errno = ENOMEM;
            return -1;
        }
        char **grown = realloc(*parts, next * sizeof((*parts)[0]));
        if (grown == NULL) {
            return -1;
        }
        *parts = grown;
        *cap = next;
    }
    (*parts)[*len] = isoboxfs_strndup(start, n);
    if ((*parts)[*len] == NULL) {
        return -1;
    }
    (*len)++;
    return 0;
}

char *isoboxfs_normalize_lexical(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return strdup(".");
    }

    int absolute = path[0] == '/';
    char **parts = NULL;
    size_t len = 0;
    size_t cap = 0;

    const char *p = path;
    while (*p != '\0') {
        while (*p == '/') {
            p++;
        }
        if (*p == '\0') {
            break;
        }
        const char *start = p;
        while (*p != '\0' && *p != '/') {
            p++;
        }
        size_t n = (size_t)(p - start);
        if (n == 1 && start[0] == '.') {
            continue;
        }
        if (n == 2 && start[0] == '.' && start[1] == '.') {
            if (absolute) {
                if (len > 0) {
                    free(parts[--len]);
                }
            } else if (len > 0 && strcmp(parts[len - 1], "..") != 0) {
                free(parts[--len]);
            } else if (push_part(&parts, &len, &cap, start, n) != 0) {
                goto fail;
            }
            continue;
        }
        if (push_part(&parts, &len, &cap, start, n) != 0) {
            goto fail;
        }
    }

    if (len == 0) {
        free(parts);
        return strdup(absolute ? "/" : ".");
    }

    size_t total = absolute ? 1 : 0;
    for (size_t i = 0; i < len; i++) {
        total += strlen(parts[i]);
        if (i + 1 < len) {
            total++;
        }
    }

    char *out = malloc(total + 1);
    if (out == NULL) {
        goto fail;
    }
    char *cursor = out;
    if (absolute) {
        *cursor++ = '/';
    }
    for (size_t i = 0; i < len; i++) {
        size_t n = strlen(parts[i]);
        memcpy(cursor, parts[i], n);
        cursor += n;
        if (i + 1 < len) {
            *cursor++ = '/';
        }
    }
    *cursor = '\0';

    for (size_t i = 0; i < len; i++) {
        free(parts[i]);
    }
    free(parts);
    return out;

fail:
    for (size_t i = 0; i < len; i++) {
        free(parts[i]);
    }
    free(parts);
    return NULL;
}

void isoboxfs_scope_init(struct isoboxfs_scope_set *scope) {
    scope->roots = NULL;
    scope->len = 0;
    scope->cap = 0;
}

void isoboxfs_scope_free(struct isoboxfs_scope_set *scope) {
    if (scope == NULL) {
        return;
    }
    for (size_t i = 0; i < scope->len; i++) {
        free(scope->roots[i]);
    }
    free(scope->roots);
    isoboxfs_scope_init(scope);
}

static int scope_push_owned(struct isoboxfs_scope_set *scope, char *root) {
    if (scope->len == scope->cap) {
        size_t next = scope->cap == 0 ? 8 : scope->cap * 2;
        if (next < scope->cap) {
            errno = ENOMEM;
            return -1;
        }
        char **grown = realloc(scope->roots, next * sizeof(scope->roots[0]));
        if (grown == NULL) {
            return -1;
        }
        scope->roots = grown;
        scope->cap = next;
    }
    scope->roots[scope->len++] = root;
    return 0;
}

static char *trim_ascii(char *line) {
    while (isspace((unsigned char)*line)) {
        line++;
    }
    char *end = line + strlen(line);
    while (end > line && isspace((unsigned char)end[-1])) {
        *--end = '\0';
    }
    return line;
}

static int scope_add_line(struct isoboxfs_scope_set *scope, char *line) {
    char *trimmed = trim_ascii(line);
    if (trimmed[0] == '\0' || trimmed[0] == '#') {
        return 0;
    }
    if (trimmed[0] != '/') {
        errno = EINVAL;
        return -1;
    }
    char *normalized = isoboxfs_normalize_lexical(trimmed);
    if (normalized == NULL) {
        return -1;
    }
    if (scope_push_owned(scope, normalized) != 0) {
        free(normalized);
        return -1;
    }
    return 0;
}

static int cmp_string_ptr(const void *a, const void *b) {
    const char *const *sa = a;
    const char *const *sb = b;
    return strcmp(*sa, *sb);
}

static void scope_sort_dedup(struct isoboxfs_scope_set *scope) {
    if (scope->len == 0) {
        return;
    }
    qsort(scope->roots, scope->len, sizeof(scope->roots[0]), cmp_string_ptr);
    size_t out = 1;
    for (size_t i = 1; i < scope->len; i++) {
        if (strcmp(scope->roots[out - 1], scope->roots[i]) == 0) {
            free(scope->roots[i]);
            continue;
        }
        scope->roots[out++] = scope->roots[i];
    }
    scope->len = out;
}

int isoboxfs_scope_from_manifest_string(struct isoboxfs_scope_set *scope, const char *input) {
    isoboxfs_scope_free(scope);
    if (input == NULL) {
        return 0;
    }

    char *copy = strdup(input);
    if (copy == NULL) {
        return -1;
    }

    char *line = copy;
    while (line != NULL) {
        char *next = strchr(line, '\n');
        if (next != NULL) {
            *next++ = '\0';
        }
        if (scope_add_line(scope, line) != 0) {
            int saved = errno;
            free(copy);
            isoboxfs_scope_free(scope);
            errno = saved;
            return -1;
        }
        line = next;
    }
    free(copy);
    scope_sort_dedup(scope);
    return 0;
}

int isoboxfs_scope_from_manifest_file(struct isoboxfs_scope_set *scope, const char *path) {
    isoboxfs_scope_free(scope);
    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }

    char *line = NULL;
    size_t cap = 0;
    ssize_t nread;
    int rc = 0;
    while ((nread = getline(&line, &cap, f)) >= 0) {
        (void)nread;
        if (scope_add_line(scope, line) != 0) {
            rc = -1;
            break;
        }
    }
    int saved = errno;
    free(line);
    if (ferror(f) && rc == 0) {
        rc = -1;
        saved = errno;
    }
    fclose(f);
    if (rc != 0) {
        isoboxfs_scope_free(scope);
        errno = saved;
        return -1;
    }
    scope_sort_dedup(scope);
    return 0;
}

int isoboxfs_scope_is_empty(const struct isoboxfs_scope_set *scope) {
    return scope == NULL || scope->len == 0;
}

int isoboxfs_contains_component(const char *root, const char *path) {
    if (root == NULL || path == NULL) {
        return 0;
    }
    if (strcmp(root, "/") == 0) {
        return path[0] == '/';
    }
    size_t root_len = strlen(root);
    if (strncmp(root, path, root_len) != 0) {
        return 0;
    }
    return path[root_len] == '\0' || path[root_len] == '/';
}

int isoboxfs_scope_allows(const struct isoboxfs_scope_set *scope, const char *path) {
    if (scope == NULL || path == NULL) {
        return 0;
    }
    char *normalized = isoboxfs_normalize_lexical(path);
    if (normalized == NULL) {
        return 0;
    }
    int allowed = 0;
    for (size_t i = 0; i < scope->len; i++) {
        if (isoboxfs_contains_component(scope->roots[i], normalized)) {
            allowed = 1;
            break;
        }
    }
    free(normalized);
    return allowed;
}
