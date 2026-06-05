#define _GNU_SOURCE
#ifndef __linux__
#error "isoboxfs preload is Linux-only"
#endif

#include "scope.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#ifndef ISOBOXFS_VERSION_TEXT
#define ISOBOXFS_VERSION_TEXT "0.1.0"
#endif

static const char env_mode[] = "ISOBOXFS_MODE";
static const char env_readable[] = "ISOBOXFS_READABLE";
static const char env_read_deny[] = "ISOBOXFS_READ_DENY";
static const char env_writable[] = "ISOBOXFS_WRITABLE";
static const char env_upper[] = "ISOBOXFS_UPPER";
static const char env_detect[] = "ISOBOXFS_DETECT";
static const char env_active[] = "ISOBOXFS";
static const char env_version[] = "ISOBOXFS_VERSION";
static const char env_ld_preload[] = "LD_PRELOAD";
static const char whiteout_dir[] = ".isoboxfs-whiteouts";

static const char *const preserved_env[] = {
    env_mode,  env_readable, env_read_deny,  env_writable,
    env_upper, env_detect,   env_ld_preload, env_version,
};

static __thread int recursion_guard;

static int guarded(void) {
    return recursion_guard != 0;
}

static int enter_guard(void) {
    if (recursion_guard != 0) {
        return 0;
    }
    recursion_guard = 1;
    return 1;
}

static void leave_guard(int entered) {
    if (entered) {
        recursion_guard = 0;
    }
}

struct isoboxfs_config {
    int enforce;
    int readable_set;
    struct isoboxfs_scope_set readable;
    struct isoboxfs_scope_set read_deny;
    int writable_set;
    struct isoboxfs_scope_set writable;
    char *upper;
};

static struct isoboxfs_config config;
static pthread_once_t config_once = PTHREAD_ONCE_INIT;

static void *real_symbol(const char *name) {
    return dlsym(RTLD_NEXT, name);
}

#define DEFINE_REAL(getter, type, symbol)   \
    static type getter(void) {              \
        static type fn;                     \
        if (fn == NULL) {                   \
            fn = (type)real_symbol(symbol); \
        }                                   \
        return fn;                          \
    }

typedef int (*open_fn)(const char *, int, ...);
typedef int (*open2_fn)(const char *, int);
typedef int (*openat_fn)(int, const char *, int, ...);
typedef int (*openat2_fn)(int, const char *, int);
typedef int (*creat_fn)(const char *, mode_t);
typedef int (*unlink_fn)(const char *);
typedef int (*unlinkat_fn)(int, const char *, int);
typedef int (*renameat_fn)(int, const char *, int, const char *);
typedef int (*renameat2_fn)(int, const char *, int, const char *, unsigned int);
typedef int (*mkdir_fn)(const char *, mode_t);
typedef int (*mkdirat_fn)(int, const char *, mode_t);
typedef int (*rmdir_fn)(const char *);
typedef int (*truncate_fn)(const char *, off_t);
typedef int (*truncate64_fn)(const char *, off64_t);
typedef int (*ftruncate_fn)(int, off_t);
typedef int (*ftruncate64_fn)(int, off64_t);
typedef int (*chmod_fn)(const char *, mode_t);
typedef int (*fchmod_fn)(int, mode_t);
typedef int (*fchmodat_fn)(int, const char *, mode_t, int);
typedef int (*chown_fn)(const char *, uid_t, gid_t);
typedef int (*fchown_fn)(int, uid_t, gid_t);
typedef int (*fchownat_fn)(int, const char *, uid_t, gid_t, int);
typedef int (*access_fn)(const char *, int);
typedef int (*faccessat_fn)(int, const char *, int, int);
typedef int (*stat_fn)(const char *, struct stat *);
typedef int (*stat64_fn)(const char *, struct stat64 *);
typedef int (*fstatat_fn)(int, const char *, struct stat *, int);
typedef int (*xstat_fn)(int, const char *, struct stat *);
typedef int (*xstat64_fn)(int, const char *, struct stat64 *);
typedef int (*fxstatat_fn)(int, int, const char *, struct stat *, int);
typedef int (*fxstatat64_fn)(int, int, const char *, struct stat64 *, int);
typedef ssize_t (*readlink_fn)(const char *, char *, size_t);
typedef ssize_t (*readlinkat_fn)(int, const char *, char *, size_t);
typedef int (*link_fn)(const char *, const char *);
typedef int (*linkat_fn)(int, const char *, int, const char *, int);
typedef int (*symlink_fn)(const char *, const char *);
typedef int (*symlinkat_fn)(const char *, int, const char *);
typedef int (*utime_fn)(const char *, const struct utimbuf *);
typedef int (*utimes_fn)(const char *, const struct timeval[2]);
typedef int (*utimensat_fn)(int, const char *, const struct timespec[2], int);
typedef ssize_t (*xattr_get_fn)(const char *, const char *, void *, size_t);
typedef ssize_t (*xattr_list_fn)(const char *, char *, size_t);
typedef int (*xattr_set_fn)(const char *, const char *, const void *, size_t, int);
typedef int (*xattr_remove_fn)(const char *, const char *);
typedef int (*execve_fn)(const char *, char *const[], char *const[]);
typedef int (*clearenv_fn)(void);
typedef int (*close_fn)(int);
typedef ssize_t (*write_fn)(int, const void *, size_t);
typedef ssize_t (*pwrite_fn)(int, const void *, size_t, off_t);
typedef ssize_t (*pwrite64_fn)(int, const void *, size_t, off64_t);
typedef ssize_t (*writev_fn)(int, const struct iovec *, int);
typedef ssize_t (*pwritev_fn)(int, const struct iovec *, int, off_t);
typedef ssize_t (*pwritev64_fn)(int, const struct iovec *, int, off64_t);
typedef void *(*mmap_fn)(void *, size_t, int, int, int, off_t);
typedef void *(*mmap64_fn)(void *, size_t, int, int, int, off64_t);
typedef void *(*dlopen_fn)(const char *, int);
typedef FILE *(*fopen_fn)(const char *, const char *);
typedef FILE *(*freopen_fn)(const char *, const char *, FILE *);

DEFINE_REAL(real_open, open_fn, "open")
DEFINE_REAL(real_open64, open_fn, "open64")
DEFINE_REAL(real_open_2, open2_fn, "__open_2")
DEFINE_REAL(real_open64_2, open2_fn, "__open64_2")
DEFINE_REAL(real_openat, openat_fn, "openat")
DEFINE_REAL(real_openat64, openat_fn, "openat64")
DEFINE_REAL(real_openat_2, openat2_fn, "__openat_2")
DEFINE_REAL(real_openat64_2, openat2_fn, "__openat64_2")
DEFINE_REAL(real_creat, creat_fn, "creat")
DEFINE_REAL(real_creat64, creat_fn, "creat64")
DEFINE_REAL(real_unlink, unlink_fn, "unlink")
DEFINE_REAL(real_unlinkat, unlinkat_fn, "unlinkat")
DEFINE_REAL(real_renameat, renameat_fn, "renameat")
DEFINE_REAL(real_renameat2, renameat2_fn, "renameat2")
DEFINE_REAL(real_mkdir, mkdir_fn, "mkdir")
DEFINE_REAL(real_mkdirat, mkdirat_fn, "mkdirat")
DEFINE_REAL(real_rmdir, rmdir_fn, "rmdir")
DEFINE_REAL(real_truncate, truncate_fn, "truncate")
DEFINE_REAL(real_truncate64, truncate64_fn, "truncate64")
DEFINE_REAL(real_ftruncate, ftruncate_fn, "ftruncate")
DEFINE_REAL(real_ftruncate64, ftruncate64_fn, "ftruncate64")
DEFINE_REAL(real_chmod, chmod_fn, "chmod")
DEFINE_REAL(real_fchmod, fchmod_fn, "fchmod")
DEFINE_REAL(real_fchmodat, fchmodat_fn, "fchmodat")
DEFINE_REAL(real_chown, chown_fn, "chown")
DEFINE_REAL(real_lchown, chown_fn, "lchown")
DEFINE_REAL(real_fchown, fchown_fn, "fchown")
DEFINE_REAL(real_fchownat, fchownat_fn, "fchownat")
DEFINE_REAL(real_access, access_fn, "access")
DEFINE_REAL(real_faccessat, faccessat_fn, "faccessat")
DEFINE_REAL(real_stat, stat_fn, "stat")
DEFINE_REAL(real_stat64, stat64_fn, "stat64")
DEFINE_REAL(real_lstat, stat_fn, "lstat")
DEFINE_REAL(real_lstat64, stat64_fn, "lstat64")
DEFINE_REAL(real_fstatat, fstatat_fn, "fstatat")
DEFINE_REAL(real_xstat, xstat_fn, "__xstat")
DEFINE_REAL(real_xstat64, xstat64_fn, "__xstat64")
DEFINE_REAL(real_lxstat, xstat_fn, "__lxstat")
DEFINE_REAL(real_lxstat64, xstat64_fn, "__lxstat64")
DEFINE_REAL(real_fxstatat, fxstatat_fn, "__fxstatat")
DEFINE_REAL(real_fxstatat64, fxstatat64_fn, "__fxstatat64")
DEFINE_REAL(real_readlink, readlink_fn, "readlink")
DEFINE_REAL(real_readlinkat, readlinkat_fn, "readlinkat")
DEFINE_REAL(real_link, link_fn, "link")
DEFINE_REAL(real_linkat, linkat_fn, "linkat")
DEFINE_REAL(real_symlink, symlink_fn, "symlink")
DEFINE_REAL(real_symlinkat, symlinkat_fn, "symlinkat")
DEFINE_REAL(real_utime, utime_fn, "utime")
DEFINE_REAL(real_utimes, utimes_fn, "utimes")
DEFINE_REAL(real_lutimes, utimes_fn, "lutimes")
DEFINE_REAL(real_utimensat, utimensat_fn, "utimensat")
DEFINE_REAL(real_getxattr, xattr_get_fn, "getxattr")
DEFINE_REAL(real_lgetxattr, xattr_get_fn, "lgetxattr")
DEFINE_REAL(real_listxattr, xattr_list_fn, "listxattr")
DEFINE_REAL(real_llistxattr, xattr_list_fn, "llistxattr")
DEFINE_REAL(real_setxattr, xattr_set_fn, "setxattr")
DEFINE_REAL(real_lsetxattr, xattr_set_fn, "lsetxattr")
DEFINE_REAL(real_removexattr, xattr_remove_fn, "removexattr")
DEFINE_REAL(real_lremovexattr, xattr_remove_fn, "lremovexattr")
DEFINE_REAL(real_execve, execve_fn, "execve")
DEFINE_REAL(real_clearenv, clearenv_fn, "clearenv")
DEFINE_REAL(real_close, close_fn, "close")
DEFINE_REAL(real_write, write_fn, "write")
DEFINE_REAL(real_pwrite, pwrite_fn, "pwrite")
DEFINE_REAL(real_pwrite64, pwrite64_fn, "pwrite64")
DEFINE_REAL(real_writev, writev_fn, "writev")
DEFINE_REAL(real_pwritev, pwritev_fn, "pwritev")
DEFINE_REAL(real_pwritev64, pwritev64_fn, "pwritev64")
DEFINE_REAL(real_mmap, mmap_fn, "mmap")
DEFINE_REAL(real_mmap64, mmap64_fn, "mmap64")
DEFINE_REAL(real_dlopen, dlopen_fn, "dlopen")
DEFINE_REAL(real_fopen, fopen_fn, "fopen")
DEFINE_REAL(real_fopen64, fopen_fn, "fopen64")
DEFINE_REAL(real_freopen, freopen_fn, "freopen")
DEFINE_REAL(real_freopen64, freopen_fn, "freopen64")

static int fail_int(int error) {
    errno = error;
    return -1;
}

static ssize_t fail_ssize(int error) {
    errno = error;
    return -1;
}

static void *fail_ptr(int error) {
    errno = error;
    return NULL;
}

static void *fail_mmap(int error) {
    errno = error;
    return MAP_FAILED;
}

static int io_errno(void) {
    return errno == 0 ? EIO : errno;
}

static char *xstrdup(const char *s) {
    char *out = strdup(s == NULL ? "" : s);
    return out;
}

static char *xstrndup(const char *s, size_t n) {
    char *out = malloc(n + 1);
    if (out == NULL) {
        return NULL;
    }
    memcpy(out, s, n);
    out[n] = '\0';
    return out;
}

static char *join_paths(const char *base, const char *rel) {
    if (base == NULL || rel == NULL) {
        errno = EINVAL;
        return NULL;
    }
    if (rel[0] == '\0') {
        return xstrdup(base);
    }
    size_t base_len = strlen(base);
    size_t rel_len = strlen(rel);
    int slash = base_len > 0 && base[base_len - 1] != '/';
    char *out = malloc(base_len + (size_t)slash + rel_len + 1);
    if (out == NULL) {
        return NULL;
    }
    memcpy(out, base, base_len);
    char *cursor = out + base_len;
    if (slash) {
        *cursor++ = '/';
    }
    memcpy(cursor, rel, rel_len);
    cursor[rel_len] = '\0';
    return out;
}

static char *parent_path(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return xstrdup(".");
    }
    const char *slash = strrchr(path, '/');
    if (slash == NULL) {
        return xstrdup(".");
    }
    if (slash == path) {
        return xstrdup("/");
    }
    return xstrndup(path, (size_t)(slash - path));
}

static const char *base_name(const char *path) {
    const char *slash = path == NULL ? NULL : strrchr(path, '/');
    if (slash == NULL) {
        return path == NULL || path[0] == '\0' ? "isoboxfs" : path;
    }
    return slash[1] == '\0' ? "isoboxfs" : slash + 1;
}

static int mkdir_existing_dir_ok(const char *path, mode_t mode) {
    if (mkdir(path, mode) == 0) {
        return 0;
    }
    if (errno != EEXIST) {
        return -1;
    }
    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    return 0;
}

static int mkdir_p(const char *path, mode_t mode) {
    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    char *tmp = xstrdup(path);
    if (tmp == NULL) {
        return -1;
    }
    size_t len = strlen(tmp);
    while (len > 1 && tmp[len - 1] == '/') {
        tmp[--len] = '\0';
    }
    for (char *p = tmp + 1; *p != '\0'; p++) {
        if (*p != '/') {
            continue;
        }
        *p = '\0';
        if (tmp[0] != '\0' && mkdir_existing_dir_ok(tmp, mode) != 0) {
            int saved = errno;
            free(tmp);
            errno = saved;
            return -1;
        }
        *p = '/';
    }
    int rc = mkdir_existing_dir_ok(tmp, mode);
    int saved = errno;
    free(tmp);
    errno = saved;
    return rc;
}

static int ensure_parent(const char *path) {
    char *parent = parent_path(path);
    if (parent == NULL) {
        return -1;
    }
    int rc = mkdir_p(parent, 0777);
    int saved = errno;
    free(parent);
    errno = saved;
    return rc;
}

static char *readlink_alloc(const char *path) {
    size_t cap = 128;
    for (;;) {
        char *buf = malloc(cap + 1);
        if (buf == NULL) {
            return NULL;
        }
        ssize_t n = readlink(path, buf, cap);
        if (n < 0) {
            int saved = errno;
            free(buf);
            errno = saved;
            return NULL;
        }
        if ((size_t)n < cap) {
            buf[n] = '\0';
            return buf;
        }
        free(buf);
        if (cap > (SIZE_MAX / 2)) {
            errno = ENAMETOOLONG;
            return NULL;
        }
        cap *= 2;
    }
}

static char *absolute_path(const char *path) {
    if (path == NULL) {
        errno = EINVAL;
        return NULL;
    }
    if (path[0] == '/') {
        return isoboxfs_normalize_lexical(path);
    }
    char *cwd = getcwd(NULL, 0);
    if (cwd == NULL) {
        return NULL;
    }
    char *joined = join_paths(cwd, path);
    free(cwd);
    if (joined == NULL) {
        return NULL;
    }
    char *normalized = isoboxfs_normalize_lexical(joined);
    free(joined);
    return normalized;
}

static char *absolute_path_at(int dirfd, const char *path) {
    if (path == NULL) {
        errno = EINVAL;
        return NULL;
    }
    if (path[0] == '/') {
        return isoboxfs_normalize_lexical(path);
    }
    if (dirfd == AT_FDCWD) {
        return absolute_path(path);
    }
    char proc[64];
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", dirfd);
    char *base = readlink_alloc(proc);
    if (base == NULL) {
        return NULL;
    }
    if (base[0] != '/') {
        free(base);
        errno = EACCES;
        return NULL;
    }
    char *joined = join_paths(base, path);
    free(base);
    if (joined == NULL) {
        return NULL;
    }
    char *normalized = isoboxfs_normalize_lexical(joined);
    free(joined);
    return normalized;
}

static char *canonical_existing(const char *path, int follow_final) {
    if (follow_final) {
        char *resolved = realpath(path, NULL);
        if (resolved == NULL) {
            return NULL;
        }
        char *normalized = isoboxfs_normalize_lexical(resolved);
        free(resolved);
        return normalized;
    }

    char *parent = parent_path(path);
    if (parent == NULL) {
        return NULL;
    }
    char *resolved_parent = realpath(parent, NULL);
    free(parent);
    if (resolved_parent == NULL) {
        return NULL;
    }
    char *joined = join_paths(resolved_parent, base_name(path));
    free(resolved_parent);
    if (joined == NULL) {
        return NULL;
    }
    char *normalized = isoboxfs_normalize_lexical(joined);
    free(joined);
    return normalized;
}

static int load_scope_env(const char *name, struct isoboxfs_scope_set *scope) {
    isoboxfs_scope_init(scope);
    const char *path = getenv(name);
    if (path == NULL) {
        return 0;
    }
    if (isoboxfs_scope_from_manifest_file(scope, path) != 0) {
        isoboxfs_scope_free(scope);
        return 0;
    }
    return 1;
}

static void load_config_once(void) {
    int entered = enter_guard();
    const char *mode = getenv(env_mode);
    config.enforce = mode != NULL && strcmp(mode, "enforce") == 0;

    config.readable_set = load_scope_env(env_readable, &config.readable);
    if (config.readable_set && isoboxfs_scope_is_empty(&config.readable)) {
        isoboxfs_scope_free(&config.readable);
        config.readable_set = 0;
    }

    if (!load_scope_env(env_read_deny, &config.read_deny)) {
        isoboxfs_scope_init(&config.read_deny);
    }

    config.writable_set = load_scope_env(env_writable, &config.writable);

    const char *upper = getenv(env_upper);
    if (upper != NULL) {
        config.upper = isoboxfs_normalize_lexical(upper);
    }
    leave_guard(entered);
}

static const struct isoboxfs_config *get_config(void) {
    pthread_once(&config_once, load_config_once);
    return &config;
}

static int scope_contains_path(const struct isoboxfs_scope_set *scope, const char *path) {
    for (size_t i = 0; i < scope->len; i++) {
        if (isoboxfs_contains_component(scope->roots[i], path)) {
            return 1;
        }
    }
    return 0;
}

static int scope_allows_checked(const struct isoboxfs_scope_set *scope, const char *path,
                                int follow_final) {
    if (!scope_contains_path(scope, path)) {
        return 0;
    }
    char *canon = canonical_existing(path, follow_final);
    if (canon == NULL) {
        return 1;
    }
    int allowed = scope_contains_path(scope, canon);
    free(canon);
    return allowed;
}

static int scope_denies_checked(const struct isoboxfs_scope_set *scope, const char *path,
                                int follow_final) {
    if (scope_contains_path(scope, path)) {
        return 1;
    }
    char *canon = canonical_existing(path, follow_final);
    if (canon == NULL) {
        return 0;
    }
    int denied = scope_contains_path(scope, canon);
    free(canon);
    return denied;
}

static int can_read_abs(const char *path, int follow_final) {
    const struct isoboxfs_config *cfg = get_config();
    if (!cfg->enforce) {
        return 1;
    }
    if (scope_denies_checked(&cfg->read_deny, path, follow_final)) {
        return 0;
    }
    if (cfg->readable_set) {
        return scope_allows_checked(&cfg->readable, path, follow_final);
    }
    return 1;
}

static int can_persist_write_abs(const char *path, int follow_final) {
    const struct isoboxfs_config *cfg = get_config();
    if (!cfg->enforce) {
        return 1;
    }
    if (cfg->writable_set) {
        return scope_allows_checked(&cfg->writable, path, follow_final);
    }
    return 1;
}

static int open_writes(int flags) {
    int accmode = flags & O_ACCMODE;
    return accmode == O_WRONLY || accmode == O_RDWR || (flags & O_CREAT) != 0 ||
           (flags & O_TRUNC) != 0;
}

static int open_needs_mode(int flags) {
    if ((flags & O_CREAT) != 0) {
        return 1;
    }
#ifdef O_TMPFILE
    if ((flags & O_TMPFILE) == O_TMPFILE) {
        return 1;
    }
#endif
    return 0;
}

static int fopen_writes(const char *mode) {
    if (mode == NULL) {
        return 0;
    }
    for (const unsigned char *p = (const unsigned char *)mode; *p != '\0'; p++) {
        if (*p == 'w' || *p == 'a' || *p == '+') {
            return 1;
        }
    }
    return 0;
}

static char *upper_path(const char *abs) {
    const struct isoboxfs_config *cfg = get_config();
    if (cfg->upper == NULL) {
        errno = EACCES;
        return NULL;
    }
    const char *rel = abs[0] == '/' ? abs + 1 : abs;
    return join_paths(cfg->upper, rel);
}

static char *hex_path(const char *path) {
    static const char hex[] = "0123456789abcdef";
    size_t len = strlen(path);
    if (len > (SIZE_MAX - 1) / 2) {
        errno = ENOMEM;
        return NULL;
    }
    char *out = malloc(len * 2 + 1);
    if (out == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char b = (unsigned char)path[i];
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0x0f];
    }
    out[len * 2] = '\0';
    return out;
}

static char *whiteout_path(const char *abs) {
    const struct isoboxfs_config *cfg = get_config();
    if (cfg->upper == NULL) {
        errno = EACCES;
        return NULL;
    }
    char *dir = join_paths(cfg->upper, whiteout_dir);
    if (dir == NULL) {
        return NULL;
    }
    char *hex = hex_path(abs);
    if (hex == NULL) {
        free(dir);
        return NULL;
    }
    char *out = join_paths(dir, hex);
    free(dir);
    free(hex);
    return out;
}

static int is_whiteouted(const char *abs) {
    char *path = whiteout_path(abs);
    if (path == NULL) {
        return 0;
    }
    struct stat st;
    int exists = lstat(path, &st) == 0;
    free(path);
    return exists;
}

static void remove_whiteout(const char *abs) {
    char *path = whiteout_path(abs);
    if (path == NULL) {
        return;
    }
    unlink(path);
    free(path);
}

static int create_whiteout(const char *abs) {
    char *path = whiteout_path(abs);
    if (path == NULL) {
        return 0;
    }
    if (ensure_parent(path) != 0) {
        int saved = errno;
        free(path);
        errno = saved;
        return -1;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        int saved = errno;
        free(path);
        errno = saved;
        return -1;
    }
    int rc = close(fd);
    int saved = errno;
    free(path);
    errno = saved;
    return rc;
}

static int copy_metadata(const struct stat *src, const char *dst) {
    chmod(dst, src->st_mode & 07777);
    chown(dst, src->st_uid, src->st_gid);
    struct timespec times[2];
    times[0].tv_sec = src->st_atim.tv_sec;
    times[0].tv_nsec = src->st_atim.tv_nsec;
    times[1].tv_sec = src->st_mtim.tv_sec;
    times[1].tv_nsec = src->st_mtim.tv_nsec;
    utimensat(AT_FDCWD, dst, times, 0);
    return 0;
}

static int write_all(int fd, const char *buf, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

static int copy_file(const char *lower, const char *upper, const struct stat *meta) {
    int in = open(lower, O_RDONLY);
    if (in < 0) {
        return -1;
    }
    int out = open(upper, O_WRONLY | O_CREAT | O_TRUNC, meta->st_mode & 07777);
    if (out < 0) {
        int saved = errno;
        close(in);
        errno = saved;
        return -1;
    }
    char buf[65536];
    for (;;) {
        ssize_t n = read(in, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            int saved = errno;
            close(in);
            close(out);
            errno = saved;
            return -1;
        }
        if (n == 0) {
            break;
        }
        if (write_all(out, buf, (size_t)n) != 0) {
            int saved = errno;
            close(in);
            close(out);
            errno = saved;
            return -1;
        }
    }
    if (close(in) != 0) {
        int saved = errno;
        close(out);
        errno = saved;
        return -1;
    }
    if (close(out) != 0) {
        return -1;
    }
    copy_metadata(meta, upper);
    return 0;
}

static int ensure_private_path(const char *path, int follow_final);

static int copy_up(const char *lower, const char *upper, int follow_final) {
    if (ensure_parent(upper) != 0) {
        return -1;
    }
    struct stat existing;
    if (lstat(upper, &existing) == 0) {
        return ensure_private_path(upper, follow_final);
    }

    struct stat meta;
    if ((follow_final ? stat(lower, &meta) : lstat(lower, &meta)) != 0) {
        return -1;
    }
    if (S_ISLNK(meta.st_mode) && !follow_final) {
        char *target = readlink_alloc(lower);
        if (target == NULL) {
            return -1;
        }
        int rc = symlink(target, upper);
        int saved = errno;
        free(target);
        errno = saved;
        return rc;
    }
    if (S_ISDIR(meta.st_mode)) {
        if (mkdir_p(upper, 0777) != 0) {
            return -1;
        }
        copy_metadata(&meta, upper);
        return 0;
    }
    if (S_ISREG(meta.st_mode)) {
        return copy_file(lower, upper, &meta);
    }
    int fd = open(upper, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return -1;
    }
    return close(fd);
}

static int ensure_private_path(const char *path, int follow_final) {
    struct stat meta;
    if ((follow_final ? stat(path, &meta) : lstat(path, &meta)) != 0) {
        return errno == ENOENT ? 0 : -1;
    }
    if (meta.st_nlink <= 1 || !(S_ISREG(meta.st_mode) || S_ISLNK(meta.st_mode))) {
        return 0;
    }

    char *parent = parent_path(path);
    if (parent == NULL) {
        return -1;
    }
    const char *name = base_name(path);
    size_t needed = strlen(parent) + strlen(name) + 64;
    char *tmp = malloc(needed);
    if (tmp == NULL) {
        free(parent);
        return -1;
    }
    snprintf(tmp, needed, "%s/.%s.isoboxfs-copy-%ld", parent, name, (long)getpid());
    free(parent);
    unlink(tmp);
    if (copy_up(path, tmp, follow_final) != 0) {
        int saved = errno;
        free(tmp);
        errno = saved;
        return -1;
    }
    int rc = rename(tmp, path);
    int saved = errno;
    free(tmp);
    errno = saved;
    return rc;
}

static char *mutation_path(const char *path, int follow_final) {
    if (follow_final) {
        char *canon = canonical_existing(path, 1);
        if (canon != NULL) {
            return canon;
        }
    }
    return xstrdup(path);
}

static int route_read_abs(const char *path, int follow_final, char **out) {
    if (is_whiteouted(path)) {
        return ENOENT;
    }
    char *upper = upper_path(path);
    if (upper != NULL) {
        struct stat st;
        if (lstat(upper, &st) == 0) {
            *out = upper;
            return 0;
        }
        free(upper);
    }
    if (!can_read_abs(path, follow_final)) {
        return EACCES;
    }
    *out = xstrdup(path);
    return *out == NULL ? ENOMEM : 0;
}

static int route_read_at(int dirfd, const char *path, int follow_final, char **out) {
    char *abs = absolute_path_at(dirfd, path);
    if (abs == NULL) {
        return EACCES;
    }
    int rc = route_read_abs(abs, follow_final, out);
    free(abs);
    return rc;
}

static int route_write_abs(const char *path, int copy_existing, int follow_final, char **out) {
    char *target = mutation_path(path, follow_final);
    if (target == NULL) {
        return ENOMEM;
    }
    if (can_persist_write_abs(target, follow_final)) {
        if (copy_existing && ensure_private_path(target, follow_final) != 0) {
            int saved = io_errno();
            free(target);
            return saved;
        }
        free(target);
        *out = xstrdup(path);
        return *out == NULL ? ENOMEM : 0;
    }
    free(target);

    char *upper = upper_path(path);
    if (upper == NULL) {
        return EACCES;
    }
    struct stat st;
    if (copy_existing && !is_whiteouted(path) && lstat(path, &st) == 0) {
        if (copy_up(path, upper, follow_final) != 0) {
            int saved = io_errno();
            free(upper);
            return saved;
        }
    } else {
        if (ensure_parent(upper) != 0) {
            int saved = io_errno();
            free(upper);
            return saved;
        }
        if (copy_existing && lstat(upper, &st) == 0 &&
            ensure_private_path(upper, follow_final) != 0) {
            int saved = io_errno();
            free(upper);
            return saved;
        }
    }
    remove_whiteout(path);
    *out = upper;
    return 0;
}

static int route_write_at(int dirfd, const char *path, int copy_existing, int follow_final,
                          char **out) {
    char *abs = absolute_path_at(dirfd, path);
    if (abs == NULL) {
        return EACCES;
    }
    int rc = route_write_abs(abs, copy_existing, follow_final, out);
    free(abs);
    return rc;
}

static int route_access_at(int dirfd, const char *path, int mode, char **out) {
    if ((mode & W_OK) != 0) {
        return route_write_at(dirfd, path, 0, 1, out);
    }
    return route_read_at(dirfd, path, 1, out);
}

static char *fd_path(int fd) {
    char proc[64];
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    char *path = readlink_alloc(proc);
    if (path == NULL) {
        return NULL;
    }
    if (path[0] != '/') {
        free(path);
        errno = EACCES;
        return NULL;
    }
    char *normalized = isoboxfs_normalize_lexical(path);
    free(path);
    return normalized;
}

static int fd_write_allowed(int fd) {
    const struct isoboxfs_config *cfg = get_config();
    if (!cfg->enforce) {
        return 1;
    }
    char proc[64];
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    struct stat st;
    if (stat(proc, &st) != 0 || !S_ISREG(st.st_mode)) {
        return 1;
    }
    char *path = fd_path(fd);
    if (path == NULL) {
        return 1;
    }
    if (cfg->upper != NULL && isoboxfs_contains_component(cfg->upper, path)) {
        free(path);
        return 1;
    }
    int allowed = can_persist_write_abs(path, 1);
    free(path);
    return allowed;
}

static int preserve_fd_write(int fd) {
    return fd_write_allowed(fd) ? 0 : EACCES;
}

static char *env_entry(const char *key, const char *value) {
    size_t key_len = strlen(key);
    size_t value_len = strlen(value);
    char *entry = malloc(key_len + 1 + value_len + 1);
    if (entry == NULL) {
        return NULL;
    }
    memcpy(entry, key, key_len);
    entry[key_len] = '=';
    memcpy(entry + key_len + 1, value, value_len);
    entry[key_len + 1 + value_len] = '\0';
    return entry;
}

static int env_has_key(char **entries, size_t len, const char *key) {
    size_t key_len = strlen(key);
    for (size_t i = 0; i < len; i++) {
        if (strncmp(entries[i], key, key_len) == 0 && entries[i][key_len] == '=') {
            return 1;
        }
    }
    return 0;
}

static void free_env_entries(char **entries) {
    if (entries == NULL) {
        return;
    }
    for (size_t i = 0; entries[i] != NULL; i++) {
        free(entries[i]);
    }
    free(entries);
}

static int env_append(char ***entries, size_t *len, size_t *cap, char *entry) {
    if (*len + 1 >= *cap) {
        size_t next = *cap == 0 ? 16 : *cap * 2;
        char **grown = realloc(*entries, next * sizeof((*entries)[0]));
        if (grown == NULL) {
            return -1;
        }
        *entries = grown;
        *cap = next;
    }
    (*entries)[(*len)++] = entry;
    (*entries)[*len] = NULL;
    return 0;
}

static char **envp_with_preserved(char *const envp[]) {
    char **entries = NULL;
    size_t len = 0;
    size_t cap = 0;
    if (env_append(&entries, &len, &cap, NULL) != 0) {
        return NULL;
    }
    len = 0;
    if (envp != NULL) {
        for (size_t i = 0; envp[i] != NULL; i++) {
            char *copy = xstrdup(envp[i]);
            if (copy == NULL || env_append(&entries, &len, &cap, copy) != 0) {
                free(copy);
                free_env_entries(entries);
                return NULL;
            }
        }
    }
    for (size_t i = 0; i < sizeof(preserved_env) / sizeof(preserved_env[0]); i++) {
        const char *key = preserved_env[i];
        if (env_has_key(entries, len, key)) {
            continue;
        }
        const char *value = getenv(key);
        if (value == NULL) {
            continue;
        }
        char *entry = env_entry(key, value);
        if (entry == NULL || env_append(&entries, &len, &cap, entry) != 0) {
            free(entry);
            free_env_entries(entries);
            return NULL;
        }
    }
    return entries;
}

struct saved_env_entry {
    const char *key;
    char *value;
};

static void
save_preserved_env(struct saved_env_entry saved[sizeof(preserved_env) / sizeof(preserved_env[0])]) {
    for (size_t i = 0; i < sizeof(preserved_env) / sizeof(preserved_env[0]); i++) {
        saved[i].key = preserved_env[i];
        const char *value = getenv(preserved_env[i]);
        saved[i].value = value == NULL ? NULL : xstrdup(value);
    }
}

static void
free_saved_env(struct saved_env_entry saved[sizeof(preserved_env) / sizeof(preserved_env[0])]) {
    for (size_t i = 0; i < sizeof(preserved_env) / sizeof(preserved_env[0]); i++) {
        free(saved[i].value);
    }
}

static int path_component_count(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return 0;
    }
    int count = path[0] == '/' ? 1 : 0;
    const char *p = path;
    while (*p != '\0') {
        while (*p == '/') {
            p++;
        }
        if (*p == '\0') {
            break;
        }
        count++;
        while (*p != '\0' && *p != '/') {
            p++;
        }
    }
    return count;
}

static int wrap_open_common(open_fn real, const char *path, int flags, mode_t mode, int has_mode) {
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return has_mode ? real(path, flags, mode) : real(path, flags);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = open_writes(flags) ? route_write_at(AT_FDCWD, path, 1, 1, &routed)
                                   : route_read_at(AT_FDCWD, path, 1, &routed);
    int rc =
        error == 0 ? (has_mode ? real(routed, flags, mode) : real(routed, flags)) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

static int wrap_open2_common(open2_fn real, const char *path, int flags) {
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(path, flags);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = open_writes(flags) ? route_write_at(AT_FDCWD, path, 1, 1, &routed)
                                   : route_read_at(AT_FDCWD, path, 1, &routed);
    int rc = error == 0 ? real(routed, flags) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

static int wrap_openat_common(openat_fn real, int dirfd, const char *path, int flags, mode_t mode,
                              int has_mode) {
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return has_mode ? real(dirfd, path, flags, mode) : real(dirfd, path, flags);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = open_writes(flags) ? route_write_at(dirfd, path, 1, 1, &routed)
                                   : route_read_at(dirfd, path, 1, &routed);
    int rc = error == 0
                 ? (has_mode ? real(AT_FDCWD, routed, flags, mode) : real(AT_FDCWD, routed, flags))
                 : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

static int wrap_openat2_common(openat2_fn real, int dirfd, const char *path, int flags) {
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(dirfd, path, flags);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = open_writes(flags) ? route_write_at(dirfd, path, 1, 1, &routed)
                                   : route_read_at(dirfd, path, 1, &routed);
    int rc = error == 0 ? real(AT_FDCWD, routed, flags) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int open(const char *path, int flags, ...) {
    mode_t mode = 0;
    int has_mode = open_needs_mode(flags);
    if (has_mode) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    return wrap_open_common(real_open(), path, flags, mode, has_mode);
}

int open64(const char *path, int flags, ...) {
    mode_t mode = 0;
    int has_mode = open_needs_mode(flags);
    if (has_mode) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    return wrap_open_common(real_open64(), path, flags, mode, has_mode);
}

int __open_2(const char *path, int flags) {
    return wrap_open2_common(real_open_2(), path, flags);
}

int __open64_2(const char *path, int flags) {
    return wrap_open2_common(real_open64_2(), path, flags);
}

int openat(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    int has_mode = open_needs_mode(flags);
    if (has_mode) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    return wrap_openat_common(real_openat(), dirfd, path, flags, mode, has_mode);
}

int openat64(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    int has_mode = open_needs_mode(flags);
    if (has_mode) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    return wrap_openat_common(real_openat64(), dirfd, path, flags, mode, has_mode);
}

int __openat_2(int dirfd, const char *path, int flags) {
    return wrap_openat2_common(real_openat_2(), dirfd, path, flags);
}

int __openat64_2(int dirfd, const char *path, int flags) {
    return wrap_openat2_common(real_openat64_2(), dirfd, path, flags);
}

static int wrap_creat_common(creat_fn real, const char *path, mode_t mode) {
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(path, mode);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_write_at(AT_FDCWD, path, 1, 1, &routed);
    int rc = error == 0 ? real(routed, mode) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int creat(const char *path, mode_t mode) {
    return wrap_creat_common(real_creat(), path, mode);
}

int creat64(const char *path, mode_t mode) {
    return wrap_creat_common(real_creat64(), path, mode);
}

static FILE *wrap_fopen_common(fopen_fn real, const char *path, const char *mode) {
    if (real == NULL) {
        return fail_ptr(ENOSYS);
    }
    if (guarded()) {
        return real(path, mode);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = fopen_writes(mode) ? route_write_at(AT_FDCWD, path, 1, 1, &routed)
                                   : route_read_at(AT_FDCWD, path, 1, &routed);
    FILE *rc = error == 0 ? real(routed, mode) : fail_ptr(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

FILE *fopen(const char *path, const char *mode) {
    return wrap_fopen_common(real_fopen(), path, mode);
}

FILE *fopen64(const char *path, const char *mode) {
    return wrap_fopen_common(real_fopen64(), path, mode);
}

static FILE *wrap_freopen_common(freopen_fn real, const char *path, const char *mode,
                                 FILE *stream) {
    if (real == NULL) {
        return fail_ptr(ENOSYS);
    }
    if (guarded() || path == NULL) {
        return real(path, mode, stream);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = fopen_writes(mode) ? route_write_at(AT_FDCWD, path, 1, 1, &routed)
                                   : route_read_at(AT_FDCWD, path, 1, &routed);
    FILE *rc = error == 0 ? real(routed, mode, stream) : fail_ptr(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

FILE *freopen(const char *path, const char *mode, FILE *stream) {
    return wrap_freopen_common(real_freopen(), path, mode, stream);
}

FILE *freopen64(const char *path, const char *mode, FILE *stream) {
    return wrap_freopen_common(real_freopen64(), path, mode, stream);
}

int access(const char *path, int mode) {
    access_fn real = real_access();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(path, mode);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_access_at(AT_FDCWD, path, mode, &routed);
    int rc = error == 0 ? real(routed, mode) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int faccessat(int dirfd, const char *path, int mode, int flags) {
    faccessat_fn real = real_faccessat();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(dirfd, path, mode, flags);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_access_at(dirfd, path, mode, &routed);
    int rc = error == 0 ? real(AT_FDCWD, routed, mode, flags) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

static int wrap_stat_common(stat_fn real, const char *path, struct stat *buf, int follow) {
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(path, buf);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_read_at(AT_FDCWD, path, follow, &routed);
    int rc = error == 0 ? real(routed, buf) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

static int wrap_stat64_common(stat64_fn real, const char *path, struct stat64 *buf, int follow) {
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(path, buf);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_read_at(AT_FDCWD, path, follow, &routed);
    int rc = error == 0 ? real(routed, buf) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int stat(const char *path, struct stat *buf) {
    return wrap_stat_common(real_stat(), path, buf, 1);
}

int stat64(const char *path, struct stat64 *buf) {
    return wrap_stat64_common(real_stat64(), path, buf, 1);
}

int lstat(const char *path, struct stat *buf) {
    return wrap_stat_common(real_lstat(), path, buf, 0);
}

int lstat64(const char *path, struct stat64 *buf) {
    return wrap_stat64_common(real_lstat64(), path, buf, 0);
}

static int wrap_xstat_common(xstat_fn real, int ver, const char *path, struct stat *buf,
                             int follow) {
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(ver, path, buf);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_read_at(AT_FDCWD, path, follow, &routed);
    int rc = error == 0 ? real(ver, routed, buf) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

static int wrap_xstat64_common(xstat64_fn real, int ver, const char *path, struct stat64 *buf,
                               int follow) {
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(ver, path, buf);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_read_at(AT_FDCWD, path, follow, &routed);
    int rc = error == 0 ? real(ver, routed, buf) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int __xstat(int ver, const char *path, struct stat *buf) {
    return wrap_xstat_common(real_xstat(), ver, path, buf, 1);
}

int __xstat64(int ver, const char *path, struct stat64 *buf) {
    return wrap_xstat64_common(real_xstat64(), ver, path, buf, 1);
}

int __lxstat(int ver, const char *path, struct stat *buf) {
    return wrap_xstat_common(real_lxstat(), ver, path, buf, 0);
}

int __lxstat64(int ver, const char *path, struct stat64 *buf) {
    return wrap_xstat64_common(real_lxstat64(), ver, path, buf, 0);
}

static int wrap_fstatat_common(fstatat_fn real, int dirfd, const char *path, struct stat *buf,
                               int flags) {
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(dirfd, path, buf, flags);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    int error = route_read_at(dirfd, path, follow, &routed);
    int rc = error == 0 ? real(AT_FDCWD, routed, buf, flags) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int fstatat(int dirfd, const char *path, struct stat *buf, int flags) {
    return wrap_fstatat_common(real_fstatat(), dirfd, path, buf, flags);
}

int newfstatat(int dirfd, const char *path, struct stat *buf, int flags) {
    return wrap_fstatat_common(real_fstatat(), dirfd, path, buf, flags);
}

static int wrap_fxstatat_common(fxstatat_fn real, int ver, int dirfd, const char *path,
                                struct stat *buf, int flags) {
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(ver, dirfd, path, buf, flags);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    int error = route_read_at(dirfd, path, follow, &routed);
    int rc = error == 0 ? real(ver, AT_FDCWD, routed, buf, flags) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

static int wrap_fxstatat64_common(fxstatat64_fn real, int ver, int dirfd, const char *path,
                                  struct stat64 *buf, int flags) {
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(ver, dirfd, path, buf, flags);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    int error = route_read_at(dirfd, path, follow, &routed);
    int rc = error == 0 ? real(ver, AT_FDCWD, routed, buf, flags) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int __fxstatat(int ver, int dirfd, const char *path, struct stat *buf, int flags) {
    return wrap_fxstatat_common(real_fxstatat(), ver, dirfd, path, buf, flags);
}

int __fxstatat64(int ver, int dirfd, const char *path, struct stat64 *buf, int flags) {
    return wrap_fxstatat64_common(real_fxstatat64(), ver, dirfd, path, buf, flags);
}

int unlink(const char *path) {
    unlink_fn real = real_unlink();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(path);
    }
    int entered = enter_guard();
    char *abs = absolute_path(path);
    if (abs == NULL) {
        leave_guard(entered);
        return fail_int(EACCES);
    }
    if (can_persist_write_abs(abs, 0)) {
        int rc = real(path);
        free(abs);
        leave_guard(entered);
        return rc;
    }
    char *upper = upper_path(abs);
    if (upper == NULL) {
        free(abs);
        leave_guard(entered);
        return fail_int(EACCES);
    }
    unlink(upper);
    struct stat st;
    int rc = 0;
    if (lstat(abs, &st) == 0 && create_whiteout(abs) != 0) {
        rc = fail_int(io_errno());
    }
    free(upper);
    free(abs);
    leave_guard(entered);
    return rc;
}

int unlinkat(int dirfd, const char *path, int flags) {
    unlinkat_fn real = real_unlinkat();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(dirfd, path, flags);
    }
    int entered = enter_guard();
    char *abs = absolute_path_at(dirfd, path);
    if (abs == NULL) {
        leave_guard(entered);
        return fail_int(EACCES);
    }
    if (can_persist_write_abs(abs, 0)) {
        int rc = real(AT_FDCWD, abs, flags);
        free(abs);
        leave_guard(entered);
        return rc;
    }
    char *upper = upper_path(abs);
    if (upper == NULL) {
        free(abs);
        leave_guard(entered);
        return fail_int(EACCES);
    }
    if ((flags & AT_REMOVEDIR) != 0) {
        rmdir(upper);
    } else {
        unlink(upper);
    }
    struct stat st;
    int rc = 0;
    if (lstat(abs, &st) == 0 && create_whiteout(abs) != 0) {
        rc = fail_int(io_errno());
    }
    free(upper);
    free(abs);
    leave_guard(entered);
    return rc;
}

static int renameat_impl(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    renameat_fn real = real_renameat();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(olddirfd, oldpath, newdirfd, newpath);
    }
    int entered = enter_guard();
    char *old_abs = absolute_path_at(olddirfd, oldpath);
    char *new_abs = absolute_path_at(newdirfd, newpath);
    if (old_abs == NULL || new_abs == NULL) {
        free(old_abs);
        free(new_abs);
        leave_guard(entered);
        return fail_int(EACCES);
    }
    if (can_persist_write_abs(old_abs, 0) && can_persist_write_abs(new_abs, 0)) {
        int rc = real(AT_FDCWD, old_abs, AT_FDCWD, new_abs);
        free(old_abs);
        free(new_abs);
        leave_guard(entered);
        return rc;
    }
    char *old_upper = upper_path(old_abs);
    char *new_upper = upper_path(new_abs);
    if (old_upper == NULL || new_upper == NULL) {
        free(old_abs);
        free(new_abs);
        free(old_upper);
        free(new_upper);
        leave_guard(entered);
        return fail_int(EACCES);
    }
    struct stat st;
    if (lstat(old_upper, &st) != 0 && lstat(old_abs, &st) == 0 && !is_whiteouted(old_abs)) {
        if (copy_up(old_abs, old_upper, 0) != 0) {
            int saved = io_errno();
            free(old_abs);
            free(new_abs);
            free(old_upper);
            free(new_upper);
            leave_guard(entered);
            return fail_int(saved);
        }
    }
    if (ensure_parent(new_upper) != 0) {
        int saved = io_errno();
        free(old_abs);
        free(new_abs);
        free(old_upper);
        free(new_upper);
        leave_guard(entered);
        return fail_int(saved);
    }
    int rc;
    if (rename(old_upper, new_upper) == 0) {
        create_whiteout(old_abs);
        remove_whiteout(new_abs);
        rc = 0;
    } else {
        rc = fail_int(io_errno());
    }
    free(old_abs);
    free(new_abs);
    free(old_upper);
    free(new_upper);
    leave_guard(entered);
    return rc;
}

int rename(const char *oldpath, const char *newpath) {
    return renameat_impl(AT_FDCWD, oldpath, AT_FDCWD, newpath);
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    return renameat_impl(olddirfd, oldpath, newdirfd, newpath);
}

int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath,
              unsigned int flags) {
    if (flags != 0) {
        renameat2_fn real = real_renameat2();
        if (guarded() && real != NULL) {
            return real(olddirfd, oldpath, newdirfd, newpath, flags);
        }
        return fail_int(EACCES);
    }
    return renameat_impl(olddirfd, oldpath, newdirfd, newpath);
}

int mkdir(const char *path, mode_t mode) {
    mkdir_fn real = real_mkdir();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(path, mode);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_write_at(AT_FDCWD, path, 0, 0, &routed);
    int rc = error == 0 ? real(routed, mode) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int mkdirat(int dirfd, const char *path, mode_t mode) {
    mkdirat_fn real = real_mkdirat();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(dirfd, path, mode);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_write_at(dirfd, path, 0, 0, &routed);
    int rc = error == 0 ? real(AT_FDCWD, routed, mode) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int rmdir(const char *path) {
    rmdir_fn real = real_rmdir();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(path);
    }
    int entered = enter_guard();
    char *abs = absolute_path(path);
    if (abs == NULL) {
        leave_guard(entered);
        return fail_int(EACCES);
    }
    if (can_persist_write_abs(abs, 0)) {
        int rc = real(path);
        free(abs);
        leave_guard(entered);
        return rc;
    }
    char *upper = upper_path(abs);
    if (upper == NULL) {
        free(abs);
        leave_guard(entered);
        return fail_int(EACCES);
    }
    rmdir(upper);
    struct stat st;
    int rc = 0;
    if (lstat(abs, &st) == 0 && create_whiteout(abs) != 0) {
        rc = fail_int(io_errno());
    }
    free(upper);
    free(abs);
    leave_guard(entered);
    return rc;
}

static int wrap_truncate_common(truncate_fn real, const char *path, off_t length) {
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(path, length);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_write_at(AT_FDCWD, path, 1, 1, &routed);
    int rc = error == 0 ? real(routed, length) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

static int wrap_truncate64_common(truncate64_fn real, const char *path, off64_t length) {
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(path, length);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_write_at(AT_FDCWD, path, 1, 1, &routed);
    int rc = error == 0 ? real(routed, length) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int truncate(const char *path, off_t length) {
    return wrap_truncate_common(real_truncate(), path, length);
}

int truncate64(const char *path, off64_t length) {
    return wrap_truncate64_common(real_truncate64(), path, length);
}

static int wrap_ftruncate_common(ftruncate_fn real, int fd, off_t length) {
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(fd, length);
    }
    int entered = enter_guard();
    int error = preserve_fd_write(fd);
    int rc = error == 0 ? real(fd, length) : fail_int(error);
    leave_guard(entered);
    return rc;
}

static int wrap_ftruncate64_common(ftruncate64_fn real, int fd, off64_t length) {
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(fd, length);
    }
    int entered = enter_guard();
    int error = preserve_fd_write(fd);
    int rc = error == 0 ? real(fd, length) : fail_int(error);
    leave_guard(entered);
    return rc;
}

int ftruncate(int fd, off_t length) {
    return wrap_ftruncate_common(real_ftruncate(), fd, length);
}

int ftruncate64(int fd, off64_t length) {
    return wrap_ftruncate64_common(real_ftruncate64(), fd, length);
}

static int wrap_chmod_path(chmod_fn real, const char *path, mode_t mode, int follow) {
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(path, mode);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_write_at(AT_FDCWD, path, 1, follow, &routed);
    int rc = error == 0 ? real(routed, mode) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int chmod(const char *path, mode_t mode) {
    return wrap_chmod_path(real_chmod(), path, mode, 1);
}

int fchmod(int fd, mode_t mode) {
    fchmod_fn real = real_fchmod();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(fd, mode);
    }
    int entered = enter_guard();
    int error = preserve_fd_write(fd);
    int rc = error == 0 ? real(fd, mode) : fail_int(error);
    leave_guard(entered);
    return rc;
}

int fchmodat(int dirfd, const char *path, mode_t mode, int flags) {
    fchmodat_fn real = real_fchmodat();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(dirfd, path, mode, flags);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    int error = route_write_at(dirfd, path, 1, follow, &routed);
    int rc = error == 0 ? real(AT_FDCWD, routed, mode, flags) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

static int wrap_chown_path(chown_fn real, const char *path, uid_t owner, gid_t group, int follow) {
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(path, owner, group);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_write_at(AT_FDCWD, path, 1, follow, &routed);
    int rc = error == 0 ? real(routed, owner, group) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int chown(const char *path, uid_t owner, gid_t group) {
    return wrap_chown_path(real_chown(), path, owner, group, 1);
}

int lchown(const char *path, uid_t owner, gid_t group) {
    return wrap_chown_path(real_lchown(), path, owner, group, 0);
}

int fchown(int fd, uid_t owner, gid_t group) {
    fchown_fn real = real_fchown();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(fd, owner, group);
    }
    int entered = enter_guard();
    int error = preserve_fd_write(fd);
    int rc = error == 0 ? real(fd, owner, group) : fail_int(error);
    leave_guard(entered);
    return rc;
}

int fchownat(int dirfd, const char *path, uid_t owner, gid_t group, int flags) {
    fchownat_fn real = real_fchownat();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(dirfd, path, owner, group, flags);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    int error = route_write_at(dirfd, path, 1, follow, &routed);
    int rc = error == 0 ? real(AT_FDCWD, routed, owner, group, flags) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int link(const char *oldpath, const char *newpath) {
    link_fn real = real_link();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(oldpath, newpath);
    }
    int entered = enter_guard();
    char *old_routed = NULL;
    char *new_routed = NULL;
    int error = route_read_at(AT_FDCWD, oldpath, 1, &old_routed);
    if (error == 0) {
        error = route_write_at(AT_FDCWD, newpath, 0, 0, &new_routed);
    }
    int rc = error == 0 ? real(old_routed, new_routed) : fail_int(error);
    free(old_routed);
    free(new_routed);
    leave_guard(entered);
    return rc;
}

int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {
    linkat_fn real = real_linkat();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(olddirfd, oldpath, newdirfd, newpath, flags);
    }
    int entered = enter_guard();
    char *old_routed = NULL;
    char *new_routed = NULL;
    int follow = (flags & AT_SYMLINK_FOLLOW) != 0;
    int error = route_read_at(olddirfd, oldpath, follow, &old_routed);
    if (error == 0) {
        error = route_write_at(newdirfd, newpath, 0, 0, &new_routed);
    }
    int rc = error == 0 ? real(AT_FDCWD, old_routed, AT_FDCWD, new_routed, flags) : fail_int(error);
    free(old_routed);
    free(new_routed);
    leave_guard(entered);
    return rc;
}

int symlink(const char *target, const char *linkpath) {
    symlink_fn real = real_symlink();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(target, linkpath);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_write_at(AT_FDCWD, linkpath, 0, 0, &routed);
    int rc = error == 0 ? real(target, routed) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int symlinkat(const char *target, int dirfd, const char *linkpath) {
    symlinkat_fn real = real_symlinkat();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(target, dirfd, linkpath);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_write_at(dirfd, linkpath, 0, 0, &routed);
    int rc = error == 0 ? real(target, AT_FDCWD, routed) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int utime(const char *path, const struct utimbuf *times) {
    utime_fn real = real_utime();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(path, times);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_write_at(AT_FDCWD, path, 1, 1, &routed);
    int rc = error == 0 ? real(routed, times) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int utimes(const char *path, const struct timeval times[2]) {
    utimes_fn real = real_utimes();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(path, times);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_write_at(AT_FDCWD, path, 1, 1, &routed);
    int rc = error == 0 ? real(routed, times) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int lutimes(const char *path, const struct timeval times[2]) {
    utimes_fn real = real_lutimes();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(path, times);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_write_at(AT_FDCWD, path, 1, 0, &routed);
    int rc = error == 0 ? real(routed, times) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int utimensat(int dirfd, const char *path, const struct timespec times[2], int flags) {
    utimensat_fn real = real_utimensat();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(dirfd, path, times, flags);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    int error = route_write_at(dirfd, path, 1, follow, &routed);
    int rc = error == 0 ? real(AT_FDCWD, routed, times, flags) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

ssize_t readlink(const char *path, char *buf, size_t size) {
    readlink_fn real = real_readlink();
    if (real == NULL) {
        return fail_ssize(ENOSYS);
    }
    if (guarded()) {
        return real(path, buf, size);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_read_at(AT_FDCWD, path, 0, &routed);
    ssize_t rc = error == 0 ? real(routed, buf, size) : fail_ssize(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

ssize_t readlinkat(int dirfd, const char *path, char *buf, size_t size) {
    readlinkat_fn real = real_readlinkat();
    if (real == NULL) {
        return fail_ssize(ENOSYS);
    }
    if (guarded()) {
        return real(dirfd, path, buf, size);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_read_at(dirfd, path, 0, &routed);
    ssize_t rc = error == 0 ? real(AT_FDCWD, routed, buf, size) : fail_ssize(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

static ssize_t wrap_xattr_get(xattr_get_fn real, const char *path, const char *name, void *value,
                              size_t size, int follow) {
    if (real == NULL) {
        return fail_ssize(ENOSYS);
    }
    if (guarded()) {
        return real(path, name, value, size);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_read_at(AT_FDCWD, path, follow, &routed);
    ssize_t rc = error == 0 ? real(routed, name, value, size) : fail_ssize(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

ssize_t getxattr(const char *path, const char *name, void *value, size_t size) {
    return wrap_xattr_get(real_getxattr(), path, name, value, size, 1);
}

ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size) {
    return wrap_xattr_get(real_lgetxattr(), path, name, value, size, 0);
}

static ssize_t wrap_xattr_list(xattr_list_fn real, const char *path, char *list, size_t size,
                               int follow) {
    if (real == NULL) {
        return fail_ssize(ENOSYS);
    }
    if (guarded()) {
        return real(path, list, size);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_read_at(AT_FDCWD, path, follow, &routed);
    ssize_t rc = error == 0 ? real(routed, list, size) : fail_ssize(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

ssize_t listxattr(const char *path, char *list, size_t size) {
    return wrap_xattr_list(real_listxattr(), path, list, size, 1);
}

ssize_t llistxattr(const char *path, char *list, size_t size) {
    return wrap_xattr_list(real_llistxattr(), path, list, size, 0);
}

static int wrap_xattr_set(xattr_set_fn real, const char *path, const char *name, const void *value,
                          size_t size, int flags, int follow) {
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(path, name, value, size, flags);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_write_at(AT_FDCWD, path, 1, follow, &routed);
    int rc = error == 0 ? real(routed, name, value, size, flags) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int setxattr(const char *path, const char *name, const void *value, size_t size, int flags) {
    return wrap_xattr_set(real_setxattr(), path, name, value, size, flags, 1);
}

int lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags) {
    return wrap_xattr_set(real_lsetxattr(), path, name, value, size, flags, 0);
}

static int wrap_xattr_remove(xattr_remove_fn real, const char *path, const char *name, int follow) {
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(path, name);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_write_at(AT_FDCWD, path, 1, follow, &routed);
    int rc = error == 0 ? real(routed, name) : fail_int(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int removexattr(const char *path, const char *name) {
    return wrap_xattr_remove(real_removexattr(), path, name, 1);
}

int lremovexattr(const char *path, const char *name) {
    return wrap_xattr_remove(real_lremovexattr(), path, name, 0);
}

ssize_t write(int fd, const void *buf, size_t count) {
    write_fn real = real_write();
    if (real == NULL) {
        return fail_ssize(ENOSYS);
    }
    if (guarded()) {
        return real(fd, buf, count);
    }
    int entered = enter_guard();
    int error = preserve_fd_write(fd);
    ssize_t rc = error == 0 ? real(fd, buf, count) : fail_ssize(error);
    leave_guard(entered);
    return rc;
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
    pwrite_fn real = real_pwrite();
    if (real == NULL) {
        return fail_ssize(ENOSYS);
    }
    if (guarded()) {
        return real(fd, buf, count, offset);
    }
    int entered = enter_guard();
    int error = preserve_fd_write(fd);
    ssize_t rc = error == 0 ? real(fd, buf, count, offset) : fail_ssize(error);
    leave_guard(entered);
    return rc;
}

ssize_t pwrite64(int fd, const void *buf, size_t count, off64_t offset) {
    pwrite64_fn real = real_pwrite64();
    if (real == NULL) {
        return fail_ssize(ENOSYS);
    }
    if (guarded()) {
        return real(fd, buf, count, offset);
    }
    int entered = enter_guard();
    int error = preserve_fd_write(fd);
    ssize_t rc = error == 0 ? real(fd, buf, count, offset) : fail_ssize(error);
    leave_guard(entered);
    return rc;
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    writev_fn real = real_writev();
    if (real == NULL) {
        return fail_ssize(ENOSYS);
    }
    if (guarded()) {
        return real(fd, iov, iovcnt);
    }
    int entered = enter_guard();
    int error = preserve_fd_write(fd);
    ssize_t rc = error == 0 ? real(fd, iov, iovcnt) : fail_ssize(error);
    leave_guard(entered);
    return rc;
}

ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset) {
    pwritev_fn real = real_pwritev();
    if (real == NULL) {
        return fail_ssize(ENOSYS);
    }
    if (guarded()) {
        return real(fd, iov, iovcnt, offset);
    }
    int entered = enter_guard();
    int error = preserve_fd_write(fd);
    ssize_t rc = error == 0 ? real(fd, iov, iovcnt, offset) : fail_ssize(error);
    leave_guard(entered);
    return rc;
}

ssize_t pwritev64(int fd, const struct iovec *iov, int iovcnt, off64_t offset) {
    pwritev64_fn real = real_pwritev64();
    if (real == NULL) {
        return fail_ssize(ENOSYS);
    }
    if (guarded()) {
        return real(fd, iov, iovcnt, offset);
    }
    int entered = enter_guard();
    int error = preserve_fd_write(fd);
    ssize_t rc = error == 0 ? real(fd, iov, iovcnt, offset) : fail_ssize(error);
    leave_guard(entered);
    return rc;
}

static void *wrap_mmap_common(mmap_fn real, void *addr, size_t length, int prot, int flags, int fd,
                              off_t offset) {
    if (real == NULL) {
        return fail_mmap(ENOSYS);
    }
    if (guarded()) {
        return real(addr, length, prot, flags, fd, offset);
    }
    int entered = enter_guard();
    if (fd >= 0 && (prot & PROT_WRITE) != 0 && (flags & MAP_SHARED) != 0) {
        int error = preserve_fd_write(fd);
        if (error != 0) {
            leave_guard(entered);
            return fail_mmap(error);
        }
    }
    void *rc = real(addr, length, prot, flags, fd, offset);
    leave_guard(entered);
    return rc;
}

static void *wrap_mmap64_common(mmap64_fn real, void *addr, size_t length, int prot, int flags,
                                int fd, off64_t offset) {
    if (real == NULL) {
        return fail_mmap(ENOSYS);
    }
    if (guarded()) {
        return real(addr, length, prot, flags, fd, offset);
    }
    int entered = enter_guard();
    if (fd >= 0 && (prot & PROT_WRITE) != 0 && (flags & MAP_SHARED) != 0) {
        int error = preserve_fd_write(fd);
        if (error != 0) {
            leave_guard(entered);
            return fail_mmap(error);
        }
    }
    void *rc = real(addr, length, prot, flags, fd, offset);
    leave_guard(entered);
    return rc;
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    return wrap_mmap_common(real_mmap(), addr, length, prot, flags, fd, offset);
}

void *mmap64(void *addr, size_t length, int prot, int flags, int fd, off64_t offset) {
    return wrap_mmap64_common(real_mmap64(), addr, length, prot, flags, fd, offset);
}

void *dlopen(const char *filename, int flags) {
    dlopen_fn real = real_dlopen();
    if (real == NULL) {
        return fail_ptr(ENOSYS);
    }
    if (guarded() || filename == NULL) {
        return real(filename, flags);
    }
    int entered = enter_guard();
    if (path_component_count(filename) <= 1) {
        void *rc = real(filename, flags);
        leave_guard(entered);
        return rc;
    }
    char *routed = NULL;
    int error = route_read_at(AT_FDCWD, filename, 1, &routed);
    void *rc = error == 0 ? real(routed, flags) : fail_ptr(error);
    free(routed);
    leave_guard(entered);
    return rc;
}

int execve(const char *path, char *const argv[], char *const envp[]) {
    execve_fn real = real_execve();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real(path, argv, envp);
    }
    int entered = enter_guard();
    char *routed = NULL;
    int error = route_read_at(AT_FDCWD, path, 1, &routed);
    if (error != 0) {
        leave_guard(entered);
        return fail_int(error);
    }
    char **env = envp_with_preserved(envp);
    int rc = env == NULL ? real(routed, argv, envp) : real(routed, argv, env);
    int saved = errno;
    free(routed);
    free_env_entries(env);
    leave_guard(entered);
    errno = saved;
    return rc;
}

int clearenv(void) {
    clearenv_fn real = real_clearenv();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    if (guarded()) {
        return real();
    }
    int entered = enter_guard();
    struct saved_env_entry saved[sizeof(preserved_env) / sizeof(preserved_env[0])];
    save_preserved_env(saved);
    int rc = real();
    if (rc == 0) {
        for (size_t i = 0; i < sizeof(saved) / sizeof(saved[0]); i++) {
            if (saved[i].value != NULL) {
                setenv(saved[i].key, saved[i].value, 1);
            }
        }
    }
    int saved_errno = errno;
    free_saved_env(saved);
    leave_guard(entered);
    errno = saved_errno;
    return rc;
}

int close(int fd) {
    close_fn real = real_close();
    if (real == NULL) {
        return fail_int(ENOSYS);
    }
    return real(fd);
}

static void isoboxfs_init(void) __attribute__((constructor));
static void isoboxfs_init(void) {
    const char *detect = getenv(env_detect);
    if (detect != NULL) {
        int code = 90;
        char *end = NULL;
        long parsed = strtol(detect, &end, 10);
        if (end != detect) {
            code = (int)parsed;
        }
        static const char prefix[] = "isoboxfs ";
        static const char suffix[] = "\n";
        syscall(SYS_write, STDERR_FILENO, prefix, sizeof(prefix) - 1);
        syscall(SYS_write, STDERR_FILENO, ISOBOXFS_VERSION_TEXT, strlen(ISOBOXFS_VERSION_TEXT));
        syscall(SYS_write, STDERR_FILENO, suffix, sizeof(suffix) - 1);
        _exit(code);
    }

    int entered = enter_guard();
    setenv(env_active, "true", 1);
    setenv(env_version, ISOBOXFS_VERSION_TEXT, 1);
    get_config();
    leave_guard(entered);
}
