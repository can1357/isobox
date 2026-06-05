#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern int clearenv(void);

static void die(const char *message) {
    perror(message);
    exit(1);
}

static char *xstrdup(const char *s) {
    char *out = strdup(s);
    if (out == NULL) {
        die("strdup");
    }
    return out;
}

static char *join_path(const char *base, const char *rel) {
    size_t base_len = strlen(base);
    size_t rel_len = strlen(rel);
    int slash = base_len > 0 && base[base_len - 1] != '/';
    char *out = malloc(base_len + (size_t)slash + rel_len + 1);
    if (out == NULL) {
        die("malloc");
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

static void mkdir_checked(const char *path) {
    if (mkdir(path, 0700) != 0 && errno != EEXIST) {
        die(path);
    }
}

static void write_file(const char *path, const char *contents) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        die(path);
    }
    size_t len = strlen(contents);
    const char *cursor = contents;
    while (len > 0) {
        ssize_t n = write(fd, cursor, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            die("write");
        }
        cursor += n;
        len -= (size_t)n;
    }
    if (close(fd) != 0) {
        die("close");
    }
}

static char *read_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        die(path);
    }
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n < 0) {
        die("read");
    }
    if (close(fd) != 0) {
        die("close");
    }
    buf[n] = '\0';
    return xstrdup(buf);
}

static int rm_rf(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        return errno == ENOENT ? 0 : -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        return unlink(path);
    }
    DIR *dir = opendir(path);
    if (dir == NULL) {
        return -1;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        char *child = join_path(path, entry->d_name);
        if (rm_rf(child) != 0) {
            int saved = errno;
            free(child);
            closedir(dir);
            errno = saved;
            return -1;
        }
        free(child);
    }
    if (closedir(dir) != 0) {
        return -1;
    }
    return rmdir(path);
}

static int wait_status(pid_t pid) {
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        die("waitpid");
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return 128;
}

static int run_detect(const char *lib) {
    pid_t pid = fork();
    if (pid < 0) {
        die("fork");
    }
    if (pid == 0) {
        setenv("LD_PRELOAD", lib, 1);
        setenv("ISOBOXFS_DETECT", "42", 1);
        execl("/bin/sh", "sh", "-c", "exit 0", (char *)NULL);
        _exit(127);
    }
    return wait_status(pid);
}

static int run_child(const char *self, const char *lib, const char *readable_manifest,
                     const char *read_deny_manifest, const char *writable_manifest,
                     const char *upper, const char *allowed, const char *denied,
                     const char *created) {
    pid_t pid = fork();
    if (pid < 0) {
        die("fork");
    }
    if (pid == 0) {
        setenv("LD_PRELOAD", lib, 1);
        setenv("ISOBOXFS_MODE", "enforce", 1);
        setenv("ISOBOXFS_READABLE", readable_manifest, 1);
        setenv("ISOBOXFS_READ_DENY", read_deny_manifest, 1);
        setenv("ISOBOXFS_WRITABLE", writable_manifest, 1);
        setenv("ISOBOXFS_UPPER", upper, 1);
        execl(self, self, "--child", allowed, denied, created, (char *)NULL);
        _exit(127);
    }
    return wait_status(pid);
}

static int child_main(const char *allowed, const char *denied, const char *created) {
    int fd = open(allowed, O_RDONLY);
    if (fd < 0) {
        return 10;
    }
    char byte;
    if (read(fd, &byte, 1) != 1) {
        return 11;
    }
    close(fd);

    fd = open(denied, O_RDONLY);
    if (fd >= 0) {
        close(fd);
        return 12;
    }
    if (errno != EACCES) {
        return 13;
    }

    fd = open(created, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return 14;
    }
    if (write(fd, "upper", 5) != 5) {
        return 15;
    }
    if (close(fd) != 0) {
        return 16;
    }

    if (clearenv() != 0) {
        return 17;
    }
    if (getenv("ISOBOXFS_MODE") == NULL || getenv("LD_PRELOAD") == NULL) {
        return 18;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 5 && strcmp(argv[1], "--child") == 0) {
        return child_main(argv[2], argv[3], argv[4]);
    }
    if (argc != 2) {
        fprintf(stderr, "usage: %s ./libisoboxfs.so\n", argv[0]);
        return 2;
    }

    char *self = realpath(argv[0], NULL);
    char *lib = realpath(argv[1], NULL);
    if (self == NULL || lib == NULL) {
        die("realpath");
    }

    int detect = run_detect(lib);
    if (detect != 42) {
        fprintf(stderr, "detect exited %d, want 42\n", detect);
        return 3;
    }

    char template[] = "/tmp/isoboxfs-runtime-XXXXXX";
    char *root = mkdtemp(template);
    if (root == NULL) {
        die("mkdtemp");
    }

    char *lower = join_path(root, "lower");
    char *secret_dir = join_path(root, "secret");
    char *upper = join_path(root, "upper");
    mkdir_checked(lower);
    mkdir_checked(secret_dir);
    mkdir_checked(upper);

    char *allowed = join_path(lower, "allowed.txt");
    char *denied = join_path(secret_dir, "secret.txt");
    char *created = join_path(lower, "created.txt");
    write_file(allowed, "allowed");
    write_file(denied, "secret");

    char *readable_manifest = join_path(root, "readable.manifest");
    char *read_deny_manifest = join_path(root, "read-deny.manifest");
    char *writable_manifest = join_path(root, "writable.manifest");
    write_file(readable_manifest, "");
    char *deny_line = malloc(strlen(denied) + 2);
    if (deny_line == NULL) {
        die("malloc");
    }
    sprintf(deny_line, "%s\n", denied);
    write_file(read_deny_manifest, deny_line);
    write_file(writable_manifest, "");

    int child = run_child(self, lib, readable_manifest, read_deny_manifest, writable_manifest,
                          upper, allowed, denied, created);
    if (child != 0) {
        fprintf(stderr, "preloaded child exited %d\n", child);
        return 4;
    }

    if (access(created, F_OK) == 0 || errno != ENOENT) {
        fprintf(stderr, "created file unexpectedly reached lower layer\n");
        return 5;
    }
    char *created_rel = created[0] == '/' ? created + 1 : created;
    char *upper_created = join_path(upper, created_rel);
    char *contents = read_file(upper_created);
    if (strcmp(contents, "upper") != 0) {
        fprintf(stderr, "upper contents %s, want upper\n", contents);
        return 6;
    }

    free(contents);
    free(upper_created);
    free(deny_line);
    free(readable_manifest);
    free(read_deny_manifest);
    free(writable_manifest);
    free(allowed);
    free(denied);
    free(created);
    free(lower);
    free(secret_dir);
    free(upper);
    free(self);
    free(lib);
    if (rm_rf(root) != 0) {
        die("rm_rf");
    }
    return 0;
}
