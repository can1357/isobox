#ifndef ISOBOXFS_SCOPE_H
#define ISOBOXFS_SCOPE_H

#include <stddef.h>

struct isoboxfs_scope_set {
    char **roots;
    size_t len;
    size_t cap;
};

void isoboxfs_scope_init(struct isoboxfs_scope_set *scope);
void isoboxfs_scope_free(struct isoboxfs_scope_set *scope);
int isoboxfs_scope_from_manifest_string(struct isoboxfs_scope_set *scope, const char *input);
int isoboxfs_scope_from_manifest_file(struct isoboxfs_scope_set *scope, const char *path);
int isoboxfs_scope_is_empty(const struct isoboxfs_scope_set *scope);
int isoboxfs_scope_allows(const struct isoboxfs_scope_set *scope, const char *path);
int isoboxfs_contains_component(const char *root, const char *path);
char *isoboxfs_normalize_lexical(const char *path);

#endif
