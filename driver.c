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

#include "mffs.h"
#include "util.h"
#include "log.h"

static pthread_mutex_t lock;

static int mf_access(const char *path, int mask)
{
    int ret;
    mode_t st_mode;
    uid_t uid, st_uid;
    gid_t gid, st_gid;
    struct stat *st;
    struct mf_file *file;
    struct mf_node *node;

    ret = 0;

    mf_log_debug("mf_access(path=%s, mask=%d)\n", path, mask);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    mf_util_mutex_lock(&lock);
    file = mf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = mf_node_get(file->ino);

    st = node->st;

    st_mode = st->st_mode;
    st_uid = st->st_uid;
    st_gid = st->st_gid;
    mf_util_mutex_unlock(&lock);

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
    mf_util_mutex_unlock(&lock);
err:
    mf_log_error("mf_access(path=%s, mask=%d): %s\n", path, mask, strerror(-ret));
    return ret;
}

static int mf_getattr(const char *path, struct stat *statbuf)
{
    int ret;
    struct mf_file *file;
    struct mf_node *node;

    ret = 0;

    mf_log_debug("mf_getattr(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    mf_util_mutex_lock(&lock);
    file = mf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = mf_node_get(file->ino);

    memcpy(statbuf, node->st, sizeof(struct stat));
    mf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    mf_util_mutex_unlock(&lock);
err:
    mf_log_error("mf_getattr(path=%s): %s\n", path, strerror(-ret));
    return ret;
}

static int mf_chmod(const char *path, mode_t mode)
{
    int ret;
    struct stat *st;
    struct mf_file *file;
    struct mf_node *node;

    ret = 0;

    mf_log_debug("mf_chmod(path=%s, mode=%u)\n", path, mode);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    mf_util_mutex_lock(&lock);
    file = mf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = mf_node_get(file->ino);

    st = node->st;

    st->st_mode = mode;
    st->st_ctime = time(NULL);
    mf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    mf_util_mutex_unlock(&lock);
err:
    mf_log_error("mf_chmod(path=%s, mode=%u): %s\n", path, mode, strerror(-ret));
    return ret;
}

static int mf_chown(const char *path, uid_t uid, gid_t gid)
{
    int ret;
    struct stat *st;
    struct mf_file *file;
    struct mf_node *node;

    ret = 0;

    mf_log_debug("mf_chown(path=%s, uid=%u, gid=%u)\n", path, uid, gid);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    mf_util_mutex_lock(&lock);
    file = mf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = mf_node_get(file->ino);

    st = node->st;

    st->st_uid = uid;
    st->st_gid = gid;
    st->st_ctime = time(NULL);
    mf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    mf_util_mutex_unlock(&lock);
err:
    mf_log_error("mf_chown(path=%s, uid=%u, gid=%u): %s\n", path, uid, gid, strerror(-ret));
    return ret;
}

static int mf_utimens(const char *path, const struct timespec ts[2])
{
    int ret;
    struct stat *st;
    struct mf_file *file;
    struct mf_node *node;

    ret = 0;

    mf_log_debug("mf_utimens(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    mf_util_mutex_lock(&lock);
    file = mf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = mf_node_get(file->ino);

    st = node->st;

    st->st_atime = ts[0].tv_sec;
    st->st_mtime = ts[1].tv_sec;
    st->st_ctime = time(NULL);
    mf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    mf_util_mutex_unlock(&lock);
err:
    mf_log_error("mf_utimens(path=%s): %s\n", path, strerror(-ret));
    return ret;
}

static int mf_mkdir(const char *path, mode_t mode)
{
    int ret;
    char *name;
    const char *delim;
    struct mf_file *file;

    ret = 0;

    mf_log_debug("mf_mkdir(path=%s, mode=%u)\n", path, mode);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    mf_util_mutex_lock(&lock);
    if (mf_file_find(path) != NULL) {
        ret = -EEXIST;
        goto err_unlock;
    }

    file = mf_file_find_parent(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    delim = DIR_DELIMITER;

    name = mf_util_filename_from_path(path, delim);

    ret = mf_file_add(file, name);

    free(name);

    if (ret < 0)
        goto err_unlock;

    file = mf_file_find(path);

    ret = mf_node_put(file->ino, S_IFDIR | mode);

    if (ret < 0) {
        mf_file_remove(file);
        goto err_unlock;
    }
    mf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    mf_util_mutex_unlock(&lock);
err:
    mf_log_error("mf_mkdir(path=%s, mode=%u): %s\n", path, mode, strerror(-ret));
    return ret;
}

static int mf_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    int ret;
    struct stat st;
    struct mf_file *file;
    struct mf_filelist_item *item;
    struct mf_node *node;

    ret = 0;

    mf_log_debug("mf_readdir(path=%s, offset=%lu)\n", path, offset);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    mf_util_mutex_lock(&lock);
    file = mf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = mf_node_get(file->ino);

    node->st->st_atime = time(NULL);

    item = file->filelist;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    while (item != NULL) {
        file = item->file;

        node = mf_node_get(file->ino);

        memcpy(&st, node->st, sizeof(struct stat));

        if (filler(buf, file->name, &st, 0) != 0) {
            ret = -ENOMEM;
            goto err_unlock;
        }

        item = item->next;
    }
    mf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    mf_util_mutex_unlock(&lock);
err:
    mf_log_error("mf_readdir(path=%s, offset=%lu): %s\n", path, offset, strerror(-ret));
    return ret;
}

static int mf_opendir(const char *path, struct fuse_file_info *fi)
{
    int ret;
    struct mf_file *file;
    struct mf_node *node;
    pthread_mutex_t *nodelock;

    ret = 0;

    mf_log_debug("mf_opendir(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    mf_util_mutex_lock(&lock);
    file = mf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = mf_node_get(file->ino);
    nodelock = &(node->lock);

    // TODO: consider absence of FUSE's `default_permission` option in order to check permissions
    mf_util_mutex_unlock(&lock);

    mf_util_mutex_lock(nodelock);
    node->open++;
    node->st->st_atime = time(NULL);
    mf_util_mutex_unlock(nodelock);

    return ret;

err_unlock:
    mf_util_mutex_unlock(&lock);
err:
    mf_log_error("mf_opendir(path=%s): %s\n", path, strerror(-ret));
    return ret;
}

static int mf_rmdir(const char *path)
{
    int ret;
    struct mf_file *file;
    struct mf_node *node;
    pthread_mutex_t *nodelock;

    ret = 0;

    mf_log_debug("mf_rmdir(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    mf_util_mutex_lock(&lock);
    file = mf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = mf_node_get(file->ino);
    nodelock = &(node->lock);

    mf_file_remove(file);
    mf_util_mutex_unlock(&lock);

    mf_util_mutex_lock(nodelock);
    node->remove = 1;

    if (node->open == 0)
        mf_node_remove(node);
    else
        mf_util_mutex_unlock(nodelock);

    return ret;

err_unlock:
    mf_util_mutex_unlock(&lock);
err:
    mf_log_error("mf_rmdir(path=%s): %s\n", path, strerror(-ret));
    return ret;
}

static int mf_releasedir(const char *path, struct fuse_file_info *fi)
{
    int ret;
    struct mf_file *file;
    struct mf_node *node;
    pthread_mutex_t *nodelock;

    ret = 0;

    mf_log_debug("mf_releasedir(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    mf_util_mutex_lock(&lock);
    file = mf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = mf_node_get(file->ino);
    nodelock = &(node->lock);
    mf_util_mutex_unlock(&lock);

    mf_util_mutex_lock(nodelock);
    node->open--;

    if (node->remove == 1 && node->open == 0)
        mf_node_remove(node);
    else
        mf_util_mutex_unlock(nodelock);

    return ret;

err_unlock:
    mf_util_mutex_unlock(&lock);
err:
    mf_log_error("mf_releasedir(path=%s): %s\n", path, strerror(-ret));
    return ret;
}

static int mf_mknod(const char *path, mode_t mode, dev_t dev)
{
    int ret;
    char *name;
    const char *delim;
    struct mf_file *file;

    ret = 0;

    mf_log_debug("mf_mknod(path=%s, mode=%u, dev=%u)\n", path, mode, dev);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    mf_util_mutex_lock(&lock);
    if (mf_file_find(path) != NULL) {
        ret = -EEXIST;
        goto err_unlock;
    }

    file = mf_file_find_parent(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    delim = DIR_DELIMITER;

    name = mf_util_filename_from_path(path, delim);

    ret = mf_file_add(file, name);

    free(name);

    if (ret < 0)
        goto err_unlock;

    file = mf_file_find(path);

    ret = mf_node_put(file->ino, S_IFREG | mode);

    if (ret < 0) {
        mf_file_remove(file);
        goto err_unlock;
    }
    mf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    mf_util_mutex_unlock(&lock);
err:
    mf_log_error("mf_mknod(path=%s, mode=%u, dev=%u): %s\n", path, mode, dev, strerror(-ret));
    return ret;
}

static int mf_open(const char *path, struct fuse_file_info *fi)
{
    int ret;
    struct mf_file *file;
    struct mf_node *node;
    pthread_mutex_t *nodelock;

    ret = 0;

    mf_log_debug("mf_open(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    mf_util_mutex_lock(&lock);
    file = mf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = mf_node_get(file->ino);
    nodelock = &(node->lock);
    // TODO: consider absence of FUSE's `default_permission` option in order to check permissions
    mf_util_mutex_unlock(&lock);

    mf_util_mutex_lock(nodelock);
    node->open++;
    node->st->st_atime = time(NULL);
    mf_util_mutex_unlock(nodelock);

    return ret;

err_unlock:
    mf_util_mutex_unlock(&lock);
err:
    mf_log_error("mf_open(path=%s): %s\n", path, strerror(-ret));
    return ret;
}

static int mf_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    int ret;
    struct mf_file *file;
    struct mf_node *node;

    ret = 0;

    mf_log_debug("mf_read(path=%s, size=%lu, offset=%lu)\n", path, size, offset);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    mf_util_mutex_lock(&lock);
    file = mf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = mf_node_get(file->ino);
    mf_util_mutex_unlock(&lock);

    mf_node_lock(NODE_LOCKMODE_R, node);
    ret = (int) mf_node_read(buf, size, offset, node);

    node->st->st_atime = time(NULL);
    mf_node_unlock(NODE_LOCKMODE_R, node);

    if (ret < 0)
        goto err;

    return ret;

err_unlock:
    mf_util_mutex_unlock(&lock);
err:
    mf_log_error("mf_read(path=%s, size=%lu, offset=%lu): %s\n", path, size, offset, strerror(-ret));
    return ret;
}

static int mf_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    int ret;
    struct mf_file *file;
    struct mf_node *node;

    ret = 0;

    mf_log_debug("mf_write(path=%s, size=%lu, offset=%lu)\n", path, size, offset);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    if (!mf_has_availspace(size)) {
        ret = -ENOSPC;
        goto err;
    }

    mf_util_mutex_lock(&lock);
    file = mf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = mf_node_get(file->ino);
    mf_util_mutex_unlock(&lock);

    mf_node_lock(NODE_LOCKMODE_W, node);
    ret = (int) mf_node_write(buf, size, offset, node);

    node->st->st_mtime = time(NULL);
    mf_node_unlock(NODE_LOCKMODE_W, node);

    if (ret < 0)
        goto err;

    return ret;

err_unlock:
    mf_util_mutex_unlock(&lock);
err:
    mf_log_error("mf_write(path=%s, size=%lu, offset=%lu): %s\n", path, size, offset, strerror(-ret));
    return ret;
}

static int mf_truncate(const char *path, off_t size)
{
    int ret;
    time_t t;
    struct stat *st;
    struct mf_file *file;
    struct mf_node *node;

    ret = 0;

    mf_log_debug("mf_truncate(path=%s, size=%lu)\n", path, size);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    mf_util_mutex_lock(&lock);
    file = mf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = mf_node_get(file->ino);

    st = node->st;

    if (S_ISDIR(st->st_mode)) {
        ret = -EISDIR;
        goto err_unlock;
    }
    mf_util_mutex_unlock(&lock);

    mf_node_lock(NODE_LOCKMODE_W, node);
    ret = (int) mf_node_resize(node, size);

    t = time(NULL);

    st->st_mtime = t;
    st->st_ctime = t;
    mf_node_unlock(NODE_LOCKMODE_W, node);

    if (ret < 0)
        goto err;

    return ret;

err_unlock:
    mf_util_mutex_unlock(&lock);
err:
    mf_log_error("mf_truncate(path=%s, size=%lu): %s\n", path, size, strerror(-ret));
    return ret;
}

static int mf_rename(const char *path, const char *newpath)
{
    int ret;
    time_t t;
    char *name;
    const char *delim;
    struct stat *oldst, *newst;
    struct mf_file *oldfile, *newfile, *newfileparent;
    struct mf_node *oldnode, *newnode, *oldnodeparent, *newnodeparent;
    struct mf_blocklist_item *item;

    ret = 0;

    mf_log_debug("mf_rename(path=%s, newpath=%s)\n", path, newpath);

    if (strlen(path) > PATH_MAX || strlen(newpath) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    if (strcmp(path, newpath) == 0)
        return ret;

    mf_util_mutex_lock(&lock);
    oldfile = mf_file_find(path);

    if (oldfile == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    newfile = mf_file_find(newpath);

    if (newfile == NULL) {
        newfileparent = mf_file_find_parent(newpath);

        if (newfileparent == NULL) {
            ret = -ENOENT;
            goto err_unlock;
        }
    } else {
        newfileparent = newfile->parent;
    }

    oldnode = mf_node_get(oldfile->ino);

    oldst = oldnode->st;

    oldnodeparent = mf_node_get(oldfile->parent->ino);
    newnodeparent = mf_node_get(newfileparent->ino);

    if (newfile != NULL)
        newnode = mf_node_get(newfile->ino);

    t = time(NULL);

    delim = DIR_DELIMITER;

    // TODO: consider links, pipes etc
    if (S_ISDIR(oldst->st_mode) || S_ISREG(oldst->st_mode)) {
        if (newfile == NULL) {
            name = mf_util_filename_from_path(newpath, delim);

            ret = mf_file_add(newfileparent, name);

            free(name);

            if (ret < 0)
                goto err_unlock;

            newfile = mf_file_find(newpath);

            ret = mf_node_put(newfile->ino, oldst->st_mode);

            if (ret < 0) {
                mf_file_remove(newfile);
                goto err_unlock;
            }

            newnode = mf_node_get(newfile->ino);
        }

        newst = newnode->st;

        if (S_ISDIR(oldst->st_mode)) {
            if (S_ISDIR(newst->st_mode)) {
                if (newfile->filelist != NULL) {
                    ret = -ENOTEMPTY;
                    goto err_unlock;
                }
            } else {
                ret = -ENOTDIR;
                goto err_unlock;
            }

            newst->st_mtime = t;
            newst->st_ctime = t;
        } else if (S_ISREG(oldst->st_mode)) {
            if (!S_ISREG(newst->st_mode)) {
                ret = -EISDIR;
                goto err_unlock;
            }

            mf_node_lock(NODE_LOCKMODE_W, newnode);
            mf_node_lock(NODE_LOCKMODE_W, oldnode);
            item = newnode->blocklist;
            newnode->blocklist = oldnode->blocklist;
            oldnode->blocklist = item;

            newst->st_size = oldst->st_size;
            newst->st_blocks = oldst->st_blocks;

            newst->st_ctime = t;
            mf_node_unlock(NODE_LOCKMODE_W, oldnode);
            mf_node_unlock(NODE_LOCKMODE_W, newnode);
        }
    } else {
        ret = -ENOTSUP;
        goto err_unlock;
    }

    mf_file_remove(oldfile);
    mf_node_remove(oldnode);

    oldst = oldnodeparent->st;

    oldst->st_mtime = t;
    oldst->st_ctime = t;

    newst = newnodeparent->st;

    newst->st_mtime = t;
    newst->st_ctime = t;
    mf_util_mutex_unlock(&lock);

    return ret;

err_unlock:
    mf_util_mutex_unlock(&lock);
err:
    mf_log_error("mf_rename(path=%s, newpath=%s): %s\n", path, newpath, strerror(-ret));
    return ret;
}

static int mf_unlink(const char *path)
{
    int ret;
    struct mf_file *file;
    struct mf_node *node;
    pthread_mutex_t *nodelock;

    ret = 0;

    mf_log_debug("mf_unlink(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    mf_util_mutex_lock(&lock);
    file = mf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = mf_node_get(file->ino);
    nodelock = &(node->lock);

    mf_file_remove(file);
    mf_util_mutex_unlock(&lock);

    mf_util_mutex_lock(nodelock);
    node->remove = 1;

    if (node->open == 0)
        mf_node_remove(node);
    else
        mf_util_mutex_unlock(nodelock);

    return ret;

err_unlock:
    mf_util_mutex_unlock(&lock);
err:
    mf_log_error("mf_unlink(path=%s): %s\n", path, strerror(-ret));
    return ret;
}

static int mf_release(const char *path, struct fuse_file_info *fi)
{
    int ret;
    struct mf_file *file;
    struct mf_node *node;
    pthread_mutex_t *nodelock;

    ret = 0;

    mf_log_debug("mf_release(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    mf_util_mutex_lock(&lock);
    file = mf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }

    node = mf_node_get(file->ino);
    nodelock = &(node->lock);
    mf_util_mutex_unlock(&lock);

    mf_util_mutex_lock(nodelock);
    node->open--;

    if (node->remove == 1 && node->open == 0)
        mf_node_remove(node);
    else
        mf_util_mutex_unlock(nodelock);

    return ret;

err_unlock:
    mf_util_mutex_unlock(&lock);
err:
    mf_log_error("mf_release(path=%s): %s\n", path, strerror(-ret));
    return ret;
}

static int mf_statfs(const char *path, struct statvfs *stbuf)
{
    int ret;
    struct mf_file *file;
    struct statvfs *st;

    ret = 0;

    mf_log_debug("mf_statfs(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        ret = -ENAMETOOLONG;
        goto err;
    }

    mf_util_mutex_lock(&lock);
    file = mf_file_find(path);

    if (file == NULL) {
        ret = -ENOENT;
        goto err_unlock;
    }
    mf_util_mutex_unlock(&lock);

    st = mf_get_statfs();
    memcpy(stbuf, st, sizeof(struct statvfs));

    free(st);

    return ret;

err_unlock:
    mf_util_mutex_unlock(&lock);
err:
    mf_log_error("mf_release(path=%s): %s\n", path, strerror(-ret));
    return ret;
}

static void mf_show_usage(const char *error)
{
    int status;
    FILE *fh;

    if (error == NULL) {
        status = EXIT_SUCCESS;
        fh = stdout;
    } else {
        status = EXIT_FAILURE;
        fh = stderr;
        fprintf(fh, "mfmount: %s\n\n", error);
    }

    fprintf(fh, "FUSE driver for mounting a multi-file file system.\n");
    fprintf(fh, "\nUsage:\n");
    fprintf(fh, "  mfmount [options] [fuseoptions] -- <file>... <mount>\n");
    fprintf(fh, "\nOptions:\n");
    fprintf(fh, "  -l                    Enable log.\n");
    fprintf(fh, "  -h --help             Show this screen.\n");
    fprintf(fh, "  --version             Show version.\n");
    fprintf(fh, "  --loglevel=<level>    Define the log level [DEBUG|WARN|INFO|ERROR|FATAL] [default: ERROR].\n");
    fprintf(fh, "  --logfile=<file>      Define the file where log messages will be written into [default: ./mfmount.log].\n");

    exit(status);
}

static void mf_show_version()
{
    printf("%s\n", VERSION);

    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
    int i, ret, lflag, fsep, loglevel, numfuseopts, numfilenames;
    char **fuseopts;
    const char *logfile, **filenames;
    struct fuse_operations mf_operations = {
        .access = mf_access,
        .getattr = mf_getattr,
        .chmod = mf_chmod,
        .chown = mf_chown,
        .utimens = mf_utimens,
        .mkdir = mf_mkdir,
        .readdir = mf_readdir,
        .opendir = mf_opendir,
        .rmdir = mf_rmdir,
        .releasedir = mf_releasedir,
        .mknod = mf_mknod,
        .open = mf_open,
        .read = mf_read,
        .write = mf_write,
        .truncate = mf_truncate,
        .rename = mf_rename,
        .unlink = mf_unlink,
        .release = mf_release,
        .statfs = mf_statfs,
    };

    lflag = 0;
    fsep = 0;
    loglevel = LOG_ERROR;
    logfile = "./mfmount.log";
    numfuseopts = 0;
    numfilenames = 0;

    // TODO: check for suid to avoid privilege escalations
    // TODO: consider FUSE command-line options and configurations

    fuseopts = calloc(argc - 1, sizeof(const char *));

    if (fuseopts == NULL) {
        perror("Could not allocate fuse options array");
        exit(EXIT_FAILURE);
    }

    filenames = calloc(argc - 1, sizeof(const char *));

    if (filenames == NULL) {
        perror("Could not allocate file names array");
        exit(EXIT_FAILURE);
    }

    i = 0;
    // argv[0] is passed in to `fuse_main`
    fuseopts[numfuseopts++] = argv[i++];

    while (i < argc) {
        if (!fsep) {
            if (strcmp(argv[i], "--") == 0) {
                fsep = 1;
            } else if (strcmp(argv[i], "-l") == 0) {
                lflag = 1;
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                mf_show_usage(NULL);
            } else if (strcmp(argv[i], "--version") == 0) {
                mf_show_version();
            } else if (strncmp(argv[i], "--loglevel=", 11) == 0) {
                loglevel = mf_log_parse_level(argv[i] + 11);

                if (loglevel == -1)
                    mf_show_usage("Invalid log level");
            } else if (strncmp(argv[i], "--logfile=", 10) == 0) {
                logfile = argv[i] + 10;

                if (strlen(logfile) == 0)
                    mf_show_usage("Invalid log file name");
            } else {
                fuseopts[numfuseopts++] = argv[i];
            }
        } else {
            if (i == argc - 1 && numfilenames < 1) {
                mf_show_usage("Missing file names");
            } else if (i == argc - 1)
                fuseopts[numfuseopts++] = argv[i];
            else
                filenames[numfilenames++] = argv[i];
        }

        i++;
    }

    if (numfuseopts < 2 || numfilenames < 1)
        mf_show_usage("Wrong number of arguments");

    ret = pthread_mutex_init(&lock, NULL);

    if (ret != 0) {
        fprintf(stderr, "Could not initialize mutex: %s\n", strerror(ret));
        exit(EXIT_FAILURE);
    }

    if (lflag) {
        ret = mf_log_init(loglevel, logfile, "w+");

        if (ret < 0) {
            fprintf(stderr, "Could not initialize log: %s\n", strerror(-ret));
            exit(EXIT_FAILURE);
        }
    }

    ret = mf_init(numfilenames, filenames);

    if (ret != 0) {
        fprintf(stderr, "Could not initialize file system: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    ret = fuse_main(numfuseopts, fuseopts, &mf_operations, NULL);

    mf_destroy();

    pthread_mutex_destroy(&lock);

    mf_log_destroy();

    return ret;
}
