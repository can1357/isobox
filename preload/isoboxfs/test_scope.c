#include "scope.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond)                                                                  \
    do {                                                                             \
        if (!(cond)) {                                                               \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #cond); \
            exit(1);                                                                 \
        }                                                                            \
    } while (0)

static void manifest_ignores_blank_lines_and_comments(void) {
    struct isoboxfs_scope_set scopes;
    isoboxfs_scope_init(&scopes);
    CHECK(isoboxfs_scope_from_manifest_string(&scopes, "\n# comment\n/var/tmp\n\n/usr/bin\n") == 0);
    CHECK(scopes.len == 2);
    CHECK(strcmp(scopes.roots[0], "/usr/bin") == 0);
    CHECK(strcmp(scopes.roots[1], "/var/tmp") == 0);
    isoboxfs_scope_free(&scopes);
}

static void manifest_rejects_relative_paths(void) {
    struct isoboxfs_scope_set scopes;
    isoboxfs_scope_init(&scopes);
    errno = 0;
    CHECK(isoboxfs_scope_from_manifest_string(&scopes, "/ok\nrelative\n") == -1);
    CHECK(errno == EINVAL);
    CHECK(scopes.len == 0);
    isoboxfs_scope_free(&scopes);
}

static void matching_respects_component_boundaries(void) {
    struct isoboxfs_scope_set scopes;
    isoboxfs_scope_init(&scopes);
    CHECK(isoboxfs_scope_from_manifest_string(&scopes, "/tmp/isobox\n") == 0);
    CHECK(isoboxfs_scope_allows(&scopes, "/tmp/isobox"));
    CHECK(isoboxfs_scope_allows(&scopes, "/tmp/isobox/file"));
    CHECK(isoboxfs_scope_allows(&scopes, "/tmp/isobox/nested/file"));
    CHECK(!isoboxfs_scope_allows(&scopes, "/tmp/isobox-other"));
    CHECK(!isoboxfs_scope_allows(&scopes, "/tmp/isobox2/file"));
    isoboxfs_scope_free(&scopes);
}

static void root_scope_matches_absolute_paths_only(void) {
    CHECK(isoboxfs_contains_component("/", "/etc/passwd"));
    CHECK(isoboxfs_contains_component("/", "/"));
    CHECK(!isoboxfs_contains_component("/", "relative"));
}

static void lexical_normalization_handles_dot_and_parent_components(void) {
    char *normalized = isoboxfs_normalize_lexical("/a/./b/../c");
    CHECK(normalized != NULL);
    CHECK(strcmp(normalized, "/a/c") == 0);
    free(normalized);

    struct isoboxfs_scope_set scopes;
    isoboxfs_scope_init(&scopes);
    CHECK(isoboxfs_scope_from_manifest_string(&scopes, "/a/c\n") == 0);
    CHECK(isoboxfs_scope_allows(&scopes, "/a/b/../c/file"));
    isoboxfs_scope_free(&scopes);
}

static void lexical_normalization_does_not_escape_absolute_root(void) {
    char *normalized = isoboxfs_normalize_lexical("/..");
    CHECK(normalized != NULL);
    CHECK(strcmp(normalized, "/") == 0);
    free(normalized);

    normalized = isoboxfs_normalize_lexical("/a/../..");
    CHECK(normalized != NULL);
    CHECK(strcmp(normalized, "/") == 0);
    free(normalized);

    normalized = isoboxfs_normalize_lexical("/a/../../b");
    CHECK(normalized != NULL);
    CHECK(strcmp(normalized, "/b") == 0);
    free(normalized);
}

static void duplicate_manifest_roots_are_deduplicated_after_normalization(void) {
    struct isoboxfs_scope_set scopes;
    isoboxfs_scope_init(&scopes);
    CHECK(isoboxfs_scope_from_manifest_string(&scopes, "/a/b\n/a/./b\n/a/c/..//b\n") == 0);
    CHECK(scopes.len == 1);
    CHECK(strcmp(scopes.roots[0], "/a/b") == 0);
    isoboxfs_scope_free(&scopes);
}

int main(void) {
    manifest_ignores_blank_lines_and_comments();
    manifest_rejects_relative_paths();
    matching_respects_component_boundaries();
    root_scope_matches_absolute_paths_only();
    lexical_normalization_handles_dot_and_parent_components();
    lexical_normalization_does_not_escape_absolute_root();
    duplicate_manifest_roots_are_deduplicated_after_normalization();
    return 0;
}
