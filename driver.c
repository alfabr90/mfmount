#include "driver.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fuse.h>

#include "sffs.h"
#include "util.h"
#include "log.h"

static pthread_mutex_t lock;

static int sf_access(const char *path, int mask)
{
    int ret;
    mode_t st_mode;
    uid_t uid, st_uid;
    gid_t gid, st_gid;
    struct sf_file *file;
    struct sf_node *node;

    ret = 0;

    sf_log_debug("sf_access(path=%s, mask=%d)\n", path, mask);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    sf_util_mutex_lock(&lock);
    file = sf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = sf_node_get(file->ino);

    st_mode = node->st->st_mode;
    st_uid = node->st->st_uid;
    st_gid = node->st->st_gid;
    sf_util_mutex_unlock(&lock);

    if (node != NULL) {
        uid = getuid();
        gid = getgid();

        if (uid != 0 && mask & R_OK) {
            if (!((st_uid == uid && st_mode & S_IRUSR) || (st_gid == gid && st_mode & S_IRGRP) || (st_uid != uid && st_gid != gid && st_mode & S_IROTH))) {
                ret = -EACCES;
                goto err_unlock;
            }
        }

        if (uid != 0 && mask & W_OK) {
            if (!((st_uid == uid && st_mode & S_IWUSR) || (st_gid == gid && st_mode & S_IWGRP) || (st_uid != uid && st_gid != gid && st_mode & S_IWOTH))) {
                ret = -EACCES;
                goto err_unlock;
            }
        }

        if (mask & X_OK) {
            if (!((st_uid == uid && st_mode & S_IXUSR) || (st_gid == gid && st_mode & S_IXGRP) || (st_uid != uid && st_gid != gid && st_mode & S_IXOTH))) {
                ret = -EACCES;
                goto err_unlock;
            }
        }
    }

    return ret;

err_unlock:
    sf_util_mutex_unlock(&lock);
err:
    sf_log_error("sf_access(path=%s, mask=%d): %s\n", path, mask, strerror(-ret));
    return ret;
}

static int sf_getattr(const char *path, struct stat *statbuf)
{
    int ret;
    struct sf_file *file;
    struct sf_node *node;

    ret = 0;

    sf_log_debug("sf_getattr(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    sf_util_mutex_lock(&lock);
    file = sf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = sf_node_get(file->ino);

    memcpy(statbuf, node->st, sizeof(struct stat));
    sf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    sf_util_mutex_unlock(&lock);
err:
    sf_log_error("sf_getattr(path=%s): %s\n", path, strerror(-ret));
    return ret;
}

static int sf_chmod(const char *path, mode_t mode)
{
    int ret;
    struct sf_file *file;
    struct sf_node *node;

    ret = 0;

    sf_log_debug("sf_chmod(path=%s, mode=%u)\n", path, mode);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    sf_util_mutex_lock(&lock);
    file = sf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = sf_node_get(file->ino);

    node->st->st_mode = mode;
    node->st->st_ctime = time(NULL);
    sf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    sf_util_mutex_unlock(&lock);
err:
    sf_log_error("sf_chmod(path=%s, mode=%u): %s\n", path, mode, strerror(-ret));
    return ret;
}

static int sf_chown(const char *path, uid_t uid, gid_t gid)
{
    int ret;
    struct sf_file *file;
    struct sf_node *node;

    ret = 0;

    sf_log_debug("sf_chown(path=%s, uid=%u, gid=%u)\n", path, uid, gid);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    sf_util_mutex_lock(&lock);
    file = sf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = sf_node_get(file->ino);

    node->st->st_uid = uid;
    node->st->st_gid = gid;
    node->st->st_ctime = time(NULL);
    sf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    sf_util_mutex_unlock(&lock);
err:
    sf_log_error("sf_chown(path=%s, uid=%u, gid=%u): %s\n", path, uid, gid, strerror(-ret));
    return ret;
}

static int sf_utimens(const char *path, const struct timespec ts[2])
{
    int ret;
    struct sf_file *file;
    struct sf_node *node;

    ret = 0;

    sf_log_debug("sf_utimens(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    sf_util_mutex_lock(&lock);
    file = sf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = sf_node_get(file->ino);

    node->st->st_atime = ts[0].tv_sec;
    node->st->st_mtime = ts[1].tv_sec;
    node->st->st_ctime = time(NULL);
    sf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    sf_util_mutex_unlock(&lock);
err:
    sf_log_error("sf_utimens(path=%s): %s\n", path, strerror(-ret));
    return ret;
}

static int sf_mkdir(const char *path, mode_t mode)
{
    int ret;
    char *name;
    const char *delim;
    struct sf_file *file;

    ret = 0;

    sf_log_debug("sf_mkdir(path=%s, mode=%u)\n", path, mode);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    sf_util_mutex_lock(&lock);
    if (sf_file_find(path) != NULL) {
        ret = -EEXIST;
        goto err_unlock;
    }

    file = sf_file_find_parent(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    delim = DIR_DELIMITER;

    name = sf_util_filename_from_path(path, delim);

    ret = sf_file_add(file, name);

    free(name);

    if (ret < 0)
        goto err_unlock;

    file = sf_file_find(path);

    ret = sf_node_put(file->ino, S_IFDIR | mode);

    if (ret < 0) {
        sf_file_remove(file);
        goto err_unlock;
    }
    sf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    sf_util_mutex_unlock(&lock);
err:
    sf_log_error("sf_mkdir(path=%s, mode=%u): %s\n", path, mode, strerror(-ret));
    return ret;
}

static int sf_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    int ret;
    struct stat st;
    struct sf_file *file;
    struct sf_filelist_item *item;
    struct sf_node *node;

    ret = 0;

    sf_log_debug("sf_readdir(path=%s, offset=%lu)\n", path, offset);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    sf_util_mutex_lock(&lock);
    file = sf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = sf_node_get(file->ino);

    node->st->st_atime = time(NULL);

    item = file->filelist;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    while (item != NULL) {
        file = item->file;

        node = sf_node_get(file->ino);

        memcpy(&st, node->st, sizeof(struct stat));

        if (filler(buf, file->name, &st, 0) != 0) {
            ret = -ENOMEM;
            goto err_unlock;
        }

        item = item->next;
    }
    sf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    sf_util_mutex_unlock(&lock);
err:
    sf_log_error("sf_readdir(path=%s, offset=%lu): %s\n", path, offset, strerror(-ret));
    return ret;
}

static int sf_opendir(const char *path, struct fuse_file_info *fi)
{
    int ret;
    struct sf_file *file;
    struct sf_node *node;

    ret = 0;

    sf_log_debug("sf_opendir(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    sf_util_mutex_lock(&lock);
    file = sf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = sf_node_get(file->ino);

    sf_util_mutex_lock(&(node->lock));
    node->open++;
    sf_util_mutex_unlock(&(node->lock));

    // TODO: consider absence of FUSE's `default_permission` option in order to check permissions
    node->st->st_atime = time(NULL);
    sf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    sf_util_mutex_unlock(&lock);
err:
    sf_log_error("sf_opendir(path=%s): %s\n", path, strerror(-ret));
    return ret;
}

static int sf_rmdir(const char *path)
{
    int ret;
    struct sf_file *file;
    struct sf_node *node;

    ret = 0;

    sf_log_debug("sf_rmdir(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    sf_util_mutex_lock(&lock);
    file = sf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = sf_node_get(file->ino);

    sf_file_remove(file);

    sf_util_mutex_lock(&(node->lock));
    node->remove = 1;

    if (node->open == 0)
        sf_node_remove(node);
    else
        sf_util_mutex_unlock(&(node->lock));
    sf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    sf_util_mutex_unlock(&lock);
err:
    sf_log_error("sf_rmdir(path=%s): %s\n", path, strerror(-ret));
    return ret;
}

static int sf_releasedir(const char *path, struct fuse_file_info *fi)
{
    int ret;
    struct sf_file *file;
    struct sf_node *node;

    ret = 0;

    sf_log_debug("sf_releasedir(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    sf_util_mutex_lock(&lock);
    file = sf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = sf_node_get(file->ino);

    sf_util_mutex_lock(&(node->lock));
    node->open--;

    if (node->remove == 1 && node->open == 0)
        sf_node_remove(node);
    else
        sf_util_mutex_unlock(&(node->lock));
    sf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    sf_util_mutex_unlock(&lock);
err:
    sf_log_error("sf_releasedir(path=%s): %s\n", path, strerror(-ret));
    return ret;
}

static int sf_mknod(const char *path, mode_t mode, dev_t dev)
{
    int ret;
    char *name;
    const char *delim;
    struct sf_file *file;

    ret = 0;

    sf_log_debug("sf_mknod(path=%s, mode=%u, dev=%u)\n", path, mode, dev);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    sf_util_mutex_lock(&lock);
    if (sf_file_find(path) != NULL) {
        ret = -EEXIST;
        goto err_unlock;
    }

    file = sf_file_find_parent(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    delim = DIR_DELIMITER;

    name = sf_util_filename_from_path(path, delim);

    ret = sf_file_add(file, name);

    free(name);

    if (ret < 0)
        goto err_unlock;

    file = sf_file_find(path);

    ret = sf_node_put(file->ino, S_IFREG | mode);

    if (ret < 0) {
        sf_file_remove(file);
        goto err_unlock;
    }
    sf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    sf_util_mutex_unlock(&lock);
err:
    sf_log_error("sf_mknod(path=%s, mode=%u, dev=%u): %s\n", path, mode, dev, strerror(-ret));
    return ret;
}

static int sf_open(const char *path, struct fuse_file_info *fi)
{
    int ret;
    struct sf_file *file;
    struct sf_node *node;

    ret = 0;

    sf_log_debug("sf_open(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    sf_util_mutex_lock(&lock);
    file = sf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = sf_node_get(file->ino);

    sf_util_mutex_lock(&(node->lock));
    node->open++;
    sf_util_mutex_unlock(&(node->lock));

    // TODO: consider absence of FUSE's `default_permission` option in order to check permissions
    node->st->st_atime = time(NULL);
    sf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    sf_util_mutex_unlock(&lock);
err:
    sf_log_error("sf_open(path=%s): %s\n", path, strerror(-ret));
    return ret;
}

static int sf_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    int ret;
    struct sf_file *file;
    struct sf_node *node;

    ret = 0;

    sf_log_debug("sf_read(path=%s, size=%lu, offset=%lu)\n", path, size, offset);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    sf_util_mutex_lock(&lock);
    file = sf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = sf_node_get(file->ino);
    sf_util_mutex_unlock(&lock);

    sf_node_lock(NODE_LOCKMODE_R, node);
    ret = (int) sf_node_read(buf, size, offset, node);

    node->st->st_atime = time(NULL);
    sf_node_unlock(NODE_LOCKMODE_R, node);

    if (ret < 0)
        goto err;

    return ret;

err_unlock:
    sf_util_mutex_unlock(&lock);
err:
    sf_log_error("sf_read(path=%s, size=%lu, offset=%lu): %s\n", path, size, offset, strerror(-ret));
    return ret;
}

static int sf_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    int ret;
    struct sf_file *file;
    struct sf_node *node;

    ret = 0;

    sf_log_debug("sf_write(path=%s, size=%lu, offset=%lu)\n", path, size, offset);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    if (!sf_has_availspace(size)) {
        ret = -ENOSPC;
        goto err;
    }

    sf_util_mutex_lock(&lock);
    file = sf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = sf_node_get(file->ino);
    sf_util_mutex_unlock(&lock);

    sf_node_lock(NODE_LOCKMODE_W, node);
    ret = (int) sf_node_write(buf, size, offset, node);

    node->st->st_mtime = time(NULL);
    sf_node_unlock(NODE_LOCKMODE_W, node);

    if (ret < 0)
        goto err;

    return ret;

err_unlock:
    sf_util_mutex_unlock(&lock);
err:
    sf_log_error("sf_write(path=%s, size=%lu, offset=%lu): %s\n", path, size, offset, strerror(-ret));
    return ret;
}

static int sf_truncate(const char *path, off_t size)
{
    int ret;
    time_t t;
    struct sf_file *file;
    struct sf_node *node;

    ret = 0;

    sf_log_debug("sf_truncate(path=%s, size=%lu)\n", path, size);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    sf_util_mutex_lock(&lock);
    file = sf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = sf_node_get(file->ino);

    if (S_ISDIR(node->st->st_mode)) {
        ret = -EISDIR;
        goto err_unlock;
    }
    sf_util_mutex_unlock(&lock);

    sf_node_lock(NODE_LOCKMODE_W, node);
    ret = (int) sf_node_resize(node, size);

    t = time(NULL);

    node->st->st_mtime = t;
    node->st->st_ctime = t;
    sf_node_unlock(NODE_LOCKMODE_W, node);

    if (ret < 0)
        goto err;

    return ret;

err_unlock:
    sf_util_mutex_unlock(&lock);
err:
    sf_log_error("sf_truncate(path=%s, size=%lu): %s\n", path, size, strerror(-ret));
    return ret;
}

static int sf_rename(const char *path, const char *newpath)
{
    int ret;
    time_t t;
    char *name;
    const char *delim;
    struct sf_file *oldfile, *newfile, *newfileparent;
    struct sf_node *oldnode, *newnode, *oldnodeparent, *newnodeparent;
    struct sf_blocklist_item *item;

    ret = 0;

    sf_log_debug("sf_rename(path=%s, newpath=%s)\n", path, newpath);

    if (strlen(path) > PATH_MAX || strlen(newpath) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    if (strcmp(path, newpath) == 0)
        return ret;

    sf_util_mutex_lock(&lock);
    oldfile = sf_file_find(path);

    if (oldfile == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    newfile = sf_file_find(newpath);

    if (newfile == NULL) {
        newfileparent = sf_file_find_parent(newpath);

        if (newfileparent == NULL) {
            ret = -ENOENT;
            goto err_unlock;
        }
    } else {
        newfileparent = newfile->parent;
    }

    oldnode = sf_node_get(oldfile->ino);

    oldnodeparent = sf_node_get(oldfile->parent->ino);
    newnodeparent = sf_node_get(newfileparent->ino);

    if (newfile != NULL)
        newnode = sf_node_get(newfile->ino);

    t = time(NULL);

    delim = DIR_DELIMITER;

    // TODO: consider links, pipes etc
    if (S_ISDIR(oldnode->st->st_mode) || S_ISREG(oldnode->st->st_mode)) {
        if (newfile == NULL) {
            name = sf_util_filename_from_path(newpath, delim);

            ret = sf_file_add(newfileparent, name);

            free(name);

            if (ret < 0)
                goto err_unlock;

            newfile = sf_file_find(newpath);

            ret = sf_node_put(newfile->ino, oldnode->st->st_mode);

            if (ret < 0) {
                sf_file_remove(newfile);
                goto err_unlock;
            }

            newnode = sf_node_get(newfile->ino);
        }

        if (S_ISDIR(oldnode->st->st_mode)) {
            if (S_ISDIR(newnode->st->st_mode)) {
                if (newfile->filelist != NULL) {
                    ret = -ENOTEMPTY;
                    goto err_unlock;
                }
            } else {
                ret = -ENOTDIR;
                goto err_unlock;
            }

            newnode->st->st_mtime = t;
            newnode->st->st_ctime = t;
        } else if (S_ISREG(oldnode->st->st_mode)) {
            if (!S_ISREG(newnode->st->st_mode)) {
                ret = -EISDIR;
                goto err_unlock;
            }

            // TODO: check whether there is need for concurrency control with read and write operations
            item = newnode->blocklist;
            newnode->blocklist = oldnode->blocklist;
            oldnode->blocklist = item;

            newnode->st->st_size = oldnode->st->st_size;
            newnode->st->st_blocks = oldnode->st->st_blocks;

            newnode->st->st_ctime = t;
        }
    } else {
        ret = -ENOTSUP;
        goto err_unlock;
    }

    sf_file_remove(oldfile);
    sf_node_remove(oldnode);

    oldnodeparent->st->st_mtime = t;
    oldnodeparent->st->st_ctime = t;

    newnodeparent->st->st_mtime = t;
    newnodeparent->st->st_ctime = t;
    sf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    sf_util_mutex_unlock(&lock);
err:
    sf_log_error("sf_rename(path=%s, newpath=%s): %s\n", path, newpath, strerror(-ret));
    return ret;
}

static int sf_unlink(const char *path)
{
    int ret;
    struct sf_file *file;
    struct sf_node *node;

    ret = 0;

    sf_log_debug("sf_unlink(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    sf_util_mutex_lock(&lock);
    file = sf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = sf_node_get(file->ino);

    sf_file_remove(file);

    sf_util_mutex_lock(&(node->lock));
    node->remove = 1;

    if (node->open == 0)
        sf_node_remove(node);
    else
        sf_util_mutex_unlock(&(node->lock));
    sf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    sf_util_mutex_unlock(&lock);
err:
    sf_log_error("sf_unlink(path=%s): %s\n", path, strerror(-ret));
    return ret;
}

static int sf_release(const char *path, struct fuse_file_info *fi)
{
    int ret;
    struct sf_file *file;
    struct sf_node *node;

    ret = 0;

    sf_log_debug("sf_release(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    sf_util_mutex_lock(&lock);
    file = sf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = sf_node_get(file->ino);

    sf_util_mutex_lock(&(node->lock));
    node->open--;

    if (node->remove == 1 && node->open == 0)
        sf_node_remove(node);
    else
        sf_util_mutex_unlock(&(node->lock));
    sf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    sf_util_mutex_unlock(&lock);
err:
    sf_log_error("sf_release(path=%s): %s\n", path, strerror(-ret));
    return ret;
}

static int sf_statfs(const char *path, struct statvfs *stbuf)
{
    int ret;
    struct sf_file *file;
    struct statvfs *st;

    ret = 0;

    sf_log_debug("sf_statfs(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    sf_util_mutex_lock(&lock);
    file = sf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }
    sf_util_mutex_unlock(&lock);

    st = sf_get_statfs();
    memcpy(stbuf, st, sizeof(struct statvfs));

    free(st);

    return ret;

err_unlock:
    sf_util_mutex_unlock(&lock);
err:
    sf_log_error("sf_release(path=%s): %s\n", path, strerror(-ret));
    return ret;
}

int main(int argc, char** argv)
{
    int ret;
    const char *filename;
    struct fuse_operations sf_operations = {
        .access = sf_access,
        .getattr = sf_getattr,
        .chmod = sf_chmod,
        .chown = sf_chown,
        .utimens = sf_utimens,
        .mkdir = sf_mkdir,
        .readdir = sf_readdir,
        .opendir = sf_opendir,
        .rmdir = sf_rmdir,
        .releasedir = sf_releasedir,
        .mknod = sf_mknod,
        .open = sf_open,
        .read = sf_read,
        .write = sf_write,
        .truncate = sf_truncate,
        .rename = sf_rename,
        .unlink = sf_unlink,
        .release = sf_release,
        .statfs = sf_statfs,
    };

    // TODO: check for suid to avoid privilege escalations

    // TODO: validate program arguments

    filename = argv[1];

    argv[1] = argv[2];
    argv[2] = NULL;
    argc--;

    sf_log_init(LOG_ERROR, "./log.txt", "w+");

    ret = pthread_mutex_init(&lock, NULL);

    if (ret != 0)
        goto fatal;

    ret = sf_init(filename);

    if (ret != 0)
        goto fatal;

    ret = fuse_main(argc, argv, &sf_operations, NULL);

    sf_destroy();

    pthread_mutex_destroy(&lock);

    sf_log_destroy();

    return ret;

fatal:
    sf_log_fatal("main(argc=%d, argv=%p): %s\n", argc, argv, strerror(ret));
    exit(EXIT_FAILURE);
}
