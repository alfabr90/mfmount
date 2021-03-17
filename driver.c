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

#include "log.h"
#include "sffs.h"

static pthread_mutex_t lock_node;

static int sf_access(const char *path, int mask)
{
    struct sf_node *node;

    sf_log_debug("sf_access(path=%s, mask=%d)\n", path, mask);

    if (strlen(path) > PATH_MAX) {
        sf_log_error("sf_access(path=%s, mask=%d): %s\n", path, mask, strerror(ENAMETOOLONG));
        return -ENAMETOOLONG;
    }

    pthread_mutex_lock(&lock_node);
    node = sf_node_find(path);

    if (node == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_access(path=%s, mask=%d): %s\n", path, mask, strerror(ENOENT));
        return -ENOENT;
    }

    // TODO: check permissions
    pthread_mutex_unlock(&lock_node);

    return 0;
}

static int sf_getattr(const char *path, struct stat *statbuf)
{
    struct sf_node *node;

    sf_log_debug("sf_getattr(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        sf_log_error("sf_getattr(path=%s): %s\n", path, strerror(ENAMETOOLONG));
        return -ENAMETOOLONG;
    }

    pthread_mutex_lock(&lock_node);
    node = sf_node_find(path);

    if (node == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_getattr(path=%s): %s\n", path, strerror(ENOENT));
        return -ENOENT;
    }

    memcpy(statbuf, node->st, sizeof(struct stat));
    pthread_mutex_unlock(&lock_node);

    return 0;
}

static int sf_chmod(const char *path, mode_t mode)
{
    struct sf_node *node;

    sf_log_debug("sf_chmod(path=%s, mode=%u)\n", path, mode);

    if (strlen(path) > PATH_MAX) {
        sf_log_error("sf_chmod(path=%s, mode=%u): %s\n", path, mode, strerror(ENAMETOOLONG));
        return -ENAMETOOLONG;
    }

    pthread_mutex_lock(&lock_node);
    node = sf_node_find(path);

    if (node == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_chmod(path=%s, mode=%u): %s\n", path, mode, strerror(ENOENT));
        return -ENOENT;
    }

    node->st->st_mode = mode;
    node->st->st_ctime = time(NULL);
    pthread_mutex_unlock(&lock_node);

    return 0;
}

static int sf_chown(const char *path, uid_t uid, gid_t gid)
{
    struct sf_node *node;

    sf_log_debug("sf_chown(path=%s, uid=%u, gid=%u)\n", path, uid, gid);

    if (strlen(path) > PATH_MAX) {
        sf_log_error("sf_chown(path=%s, uid=%u, gid=%u): %s\n", path, uid, gid, strerror(ENAMETOOLONG));
        return -ENAMETOOLONG;
    }

    pthread_mutex_lock(&lock_node);
    node = sf_node_find(path);

    if (node == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_chown(path=%s, uid=%u, gid=%u): %s\n", path, uid, gid, strerror(ENOENT));
        return -ENOENT;
    }

    node->st->st_uid = uid;
    node->st->st_gid = gid;
    node->st->st_ctime = time(NULL);
    pthread_mutex_unlock(&lock_node);

    return 0;
}

static int sf_utimens(const char *path, const struct timespec ts[2])
{
    struct sf_node *node;

    sf_log_debug("sf_utimens(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        sf_log_error("sf_utimens(path=%s): %s\n", path, strerror(ENAMETOOLONG));
        return -ENAMETOOLONG;
    }

    pthread_mutex_lock(&lock_node);
    node = sf_node_find(path);

    if (node == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_utimens(path=%s): %s\n", path, strerror(ENOENT));
        return -ENOENT;
    }

    node->st->st_atime = ts[0].tv_sec;
    node->st->st_mtime = ts[1].tv_sec;
    node->st->st_ctime = time(NULL);
    pthread_mutex_unlock(&lock_node);

    return 0;
}

static int sf_mkdir(const char *path, mode_t mode)
{
    int ret;
    char *name;
    struct sf_node *parent, *node;

    sf_log_debug("sf_mkdir(path=%s, mode=%u)\n", path, mode);

    if (strlen(path) > PATH_MAX) {
        sf_log_error("sf_mkdir(path=%s, mode=%u): %s\n", path, mode, strerror(ENAMETOOLONG));
        return -ENAMETOOLONG;
    }

    pthread_mutex_lock(&lock_node);
    if (sf_node_find(path) != NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_mkdir(path=%s, mode=%u): %s\n", path, mode, strerror(EEXIST));
        return -EEXIST;
    }

    parent = sf_node_find_parent(path);

    if (parent == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_mkdir(path=%s, mode=%u): %s\n", path, mode, strerror(ENOENT));
        return -ENOENT;
    }

    name = sf_get_filename(path);

    node = sf_node_create(name, S_IFDIR | mode, parent);

    free(name);

    if (node == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_mkdir(path=%s, mode=%u): %s\n", path, mode, strerror(errno));
        return -errno;
    }

    ret = sf_node_add(parent, node);
    pthread_mutex_unlock(&lock_node);

    if (ret < 0) {
        sf_node_destroy(node);

        sf_log_error("sf_mkdir(path=%s, mode=%u): %s\n", path, mode, strerror(-ret));
        return ret;
    }

    return 0;
}

static int sf_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    int ret;
    struct stat st;
    struct sf_node *node;
    struct sf_nodelist_item *item;

    sf_log_debug("sf_readdir(path=%s, offset=%lu)\n", path, offset);

    pthread_mutex_lock(&lock_node);
    node = sf_node_find(path);

    if (node == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_readdir(path=%s, offset=%lu): %s\n", path, offset, strerror(ENOENT));
        return -ENOENT;
    }

    ret = 0;

    item = node->nodelist;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    while (item != NULL) {
        memcpy(&st, item->node->st, sizeof(struct stat));

        if (filler(buf, item->node->name, &st, 0) != 0) {
            pthread_mutex_unlock(&lock_node);

            sf_log_error("sf_readdir(path=%s, offset=%lu): %s\n", path, offset, strerror(ENOMEM));
            ret = -ENOMEM;
            break;
        }

        item = item->next;
    }

    node->st->st_atime = time(NULL);
    pthread_mutex_unlock(&lock_node);

    return ret;
}

static int sf_opendir(const char *path, struct fuse_file_info *fi)
{
    struct sf_node *node;

    sf_log_debug("sf_opendir(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        sf_log_error("sf_opendir(path=%s): %s\n", path, strerror(ENAMETOOLONG));
        return -ENAMETOOLONG;
    }

    pthread_mutex_lock(&lock_node);
    node = sf_node_find(path);

    if (node == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_opendir(path=%s): %s\n", path, strerror(ENOENT));
        return -ENOENT;
    }

    // TODO: check permissions (open flags in `fi`)
    node->st->st_atime = time(NULL);
    pthread_mutex_unlock(&lock_node);

    return 0;
}

static int sf_releasedir(const char *path, struct fuse_file_info *fi)
{
    struct sf_node *node;

    sf_log_debug("sf_releasedir(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        sf_log_error("sf_releasedir(path=%s): %s\n", path, strerror(ENAMETOOLONG));
        return -ENAMETOOLONG;
    }

    pthread_mutex_lock(&lock_node);
    node = sf_node_find(path);

    if (node == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_releasedir(path=%s): %s\n", path, strerror(ENOENT));
        return -ENOENT;
    }
    pthread_mutex_unlock(&lock_node);

    return 0;
}

static int sf_rmdir(const char *path)
{
    struct sf_node *node;

    sf_log_debug("sf_rmdir(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        sf_log_error("sf_rmdir(path=%s): %s\n", path, strerror(ENAMETOOLONG));
        return -ENAMETOOLONG;
    }

    pthread_mutex_lock(&lock_node);
    node = sf_node_find(path);

    if (node == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_rmdir(path=%s): %s\n", path, strerror(ENOENT));
        return -ENOENT;
    }

    sf_node_remove(node);
    sf_node_destroy(node);
    pthread_mutex_unlock(&lock_node);

    return 0;
}

static int sf_mknod(const char *path, mode_t mode, dev_t dev)
{
    int ret;
    char *name;
    struct sf_node *parent, *node;

    sf_log_debug("sf_mknod(path=%s, mode=%u, dev=%u)\n", path, mode, dev);

    if (strlen(path) > PATH_MAX) {
        sf_log_error("sf_mknod(path=%s, mode=%u, dev=%u): %s\n", path, mode, dev, strerror(ENAMETOOLONG));
        return -ENAMETOOLONG;
    }

    pthread_mutex_lock(&lock_node);
    if (sf_node_find(path) != NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_mknod(path=%s, mode=%u, dev=%u): %s\n", path, mode, dev, strerror(EEXIST));
        return -EEXIST;
    }

    parent = sf_node_find_parent(path);

    if (parent == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_mknod(path=%s, mode=%u, dev=%u): %s\n", path, mode, dev, strerror(ENOENT));
        return -ENOENT;
    }

    name = sf_get_filename(path);

    node = sf_node_create(name, S_IFREG | mode, parent);

    free(name);

    if (node == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_mknod(path=%s, mode=%u, dev=%u): %s\n", path, mode, dev, strerror(errno));
        return -errno;
    }

    ret = sf_node_add(parent, node);
    pthread_mutex_unlock(&lock_node);

    if (ret < 0) {
        sf_node_destroy(node);

        sf_log_error("sf_mknod(path=%s, mode=%u, dev=%u): %s\n", path, mode, dev, strerror(-ret));
        return ret;
    }

    return 0;
}

static int sf_open(const char *path, struct fuse_file_info *fi)
{
    struct sf_node *node;

    sf_log_debug("sf_open(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        sf_log_error("sf_open(path=%s): %s\n", path, strerror(ENAMETOOLONG));
        return -ENAMETOOLONG;
    }

    pthread_mutex_lock(&lock_node);
    node = sf_node_find(path);

    if (node == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_open(path=%s): %s\n", path, strerror(ENOENT));
        return -ENOENT;
    }

    // TODO: check permissions
    node->st->st_atime = time(NULL);
    pthread_mutex_unlock(&lock_node);

    return 0;
}

static int sf_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    int ret;
    struct sf_node *node;

    sf_log_debug("sf_read(path=%s, size=%lu, offset=%lu)\n", path, size, offset);

    pthread_mutex_lock(&lock_node);
    node = sf_node_find(path);

    if (node == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_read(path=%s, size=%lu, offset=%lu): %s\n", path, size, offset, strerror(ENOENT));
        return -ENOENT;
    }

    ret = (int) sf_node_read(buf, size, offset, node);

    node->st->st_atime = time(NULL);
    pthread_mutex_unlock(&lock_node);

    if (ret < 0) {
        sf_log_error("sf_read(path=%s, size=%lu, offset=%lu): %s\n", path, size, offset, strerror(-ret));
        return ret;
    }

    return ret;
}

static int sf_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    int ret;
    struct sf_node *node;

    sf_log_debug("sf_write(path=%s, size=%lu, offset=%lu)\n", path, size, offset);

    if (!sf_has_availspace(size)) {
        sf_log_error("sf_write(path=%s, size=%lu, offset=%lu): %s\n", path, size, offset, strerror(ENOSPC));
        return -ENOSPC;
    }

    pthread_mutex_lock(&lock_node);
    node = sf_node_find(path);

    if (node == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_write(path=%s, size=%lu, offset=%lu): %s\n", path, size, offset, strerror(ENOENT));
        return -ENOENT;
    }

    ret = (int) sf_node_write(buf, size, offset, node);

    node->st->st_mtime = time(NULL);
    pthread_mutex_unlock(&lock_node);

    if (ret < 0) {
        sf_log_error("sf_write(path=%s, size=%lu, offset=%lu): %s\n", path, size, offset, strerror(-ret));
        return ret;
    }

    return ret;
}

static int sf_truncate(const char *path, off_t size)
{
    int ret;
    time_t t;
    struct sf_node *node;

    sf_log_debug("sf_truncate(path=%s, size=%lu)\n", path, size);

    if (strlen(path) > PATH_MAX) {
        sf_log_error("sf_truncate(path=%s, size=%lu): %s\n", path, size, strerror(ENAMETOOLONG));
        return -ENAMETOOLONG;
    }

    if (size < 0) {
        sf_log_error("sf_truncate(path=%s, size=%lu): %s\n", path, size, strerror(EINVAL));
        return -EINVAL;
    }

    pthread_mutex_lock(&lock_node);
    node = sf_node_find(path);

    if (node == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_truncate(path=%s, size=%lu): %s\n", path, size, strerror(ENOENT));
        return -ENOENT;
    }

    if (S_ISDIR(node->st->st_mode)) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_truncate(path=%s, size=%lu): %s\n", path, size, strerror(EISDIR));
        return -EISDIR;
    }

    ret = (int) sf_node_resize(node, size);

    t = time(NULL);

    node->st->st_mtime = t;
    node->st->st_ctime = t;
    pthread_mutex_unlock(&lock_node);

    if (ret < 0) {
        sf_log_error("sf_truncate(path=%s, size=%lu): %s\n", path, size, strerror(-ret));
        return ret;
    }

    return ret;
}

static int sf_rename(const char *path, const char *newpath)
{
    int ret;
    time_t t;
    char *name;
    struct sf_node *oldnode, *newnode, *oldparent, *newparent;
    struct sf_blocklist_item *item;

    sf_log_error("sf_rename(path=%s, newpath=%s)\n", path, newpath);

    if (strlen(path) > PATH_MAX || strlen(newpath) > PATH_MAX) {
        sf_log_error("sf_rename(path=%s, newpath=%s): %s\n", path, newpath, strerror(ENAMETOOLONG));
        return -ENAMETOOLONG;
    }

    if (strcmp(path, newpath) == 0)
        return 0;

    pthread_mutex_lock(&lock_node);
    oldnode = sf_node_find(path);

    if (oldnode == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_rename(path=%s, newpath=%s): %s\n", path, newpath, strerror(ENOENT));
        return -ENOENT;
    }

    oldparent = oldnode->parent;

    newnode = sf_node_find(newpath);

    if (newnode == NULL) {
        newparent = sf_node_find_parent(newpath);

        if (newparent == NULL) {
            pthread_mutex_unlock(&lock_node);

            sf_log_error("sf_rename(path=%s, newpath=%s): %s\n", path, newpath, strerror(ENOENT));
            return -ENOENT;
        }
    } else {
        newparent = newnode->parent;
    }

    t = time(NULL);

    if (S_ISDIR(oldnode->st->st_mode) || S_ISREG(oldnode->st->st_mode)) {
        if (newnode == NULL) {
            name = sf_get_filename(newpath);

            newnode = sf_node_create(name, oldnode->st->st_mode, newparent);

            free(name);

            if (newnode == NULL) {
                pthread_mutex_unlock(&lock_node);

                sf_node_destroy(newnode);

                sf_log_error("sf_rename(path=%s, newpath=%s): %s\n", path, newpath, strerror(errno));
                return -errno;
            }
        }

        if (S_ISDIR(oldnode->st->st_mode)) {
            if (S_ISDIR(newnode->st->st_mode)) {
                if (newnode->nodelist != NULL) {
                    pthread_mutex_unlock(&lock_node);

                    sf_log_error("sf_rename(path=%s, newpath=%s): %s\n", path, newpath, strerror(ENOTEMPTY));
                    return -ENOTEMPTY;
                }
            } else {
                pthread_mutex_unlock(&lock_node);

                // TODO: consider links, pipes etc

                sf_log_error("sf_rename(path=%s, newpath=%s): %s\n", path, newpath, strerror(ENOTDIR));
                return -ENOTDIR;
            }

            newnode->st->st_mtime = t;
            newnode->st->st_ctime = t;
        } else if (S_ISREG(oldnode->st->st_mode)) {
            if (!S_ISREG(newnode->st->st_mode)) {
                pthread_mutex_unlock(&lock_node);

                // TODO: consider links, pipes etc

                sf_log_error("sf_rename(path=%s, newpath=%s): %s\n", path, newpath, strerror(EISDIR));
                return -EISDIR;
            }

            item = newnode->blocklist;
            newnode->blocklist = oldnode->blocklist;
            oldnode->blocklist = item;

            newnode->st->st_size = oldnode->st->st_size;
            newnode->st->st_blocks = oldnode->st->st_blocks;

            newnode->st->st_ctime = t;
        }
    } else {
        pthread_mutex_unlock(&lock_node);

        // TODO: use correct errno

        sf_log_error("Invalid file type\n");
        return -1;
    }

    ret = sf_node_add(newparent, newnode);

    if (ret < 0) {
        pthread_mutex_unlock(&lock_node);

        //sf_node_destroy(newnode);

        sf_log_error("sf_rename(path=%s, newpath=%s): %s\n", path, newpath, strerror(-ret));
        return ret;
    }

    sf_node_remove(oldnode);
    sf_node_destroy(oldnode);

    oldparent->st->st_mtime = t;
    oldparent->st->st_ctime = t;

    newparent->st->st_mtime = t;
    newparent->st->st_ctime = t;
    pthread_mutex_unlock(&lock_node);

    return 0;
}

static int sf_release(const char *path, struct fuse_file_info *fi)
{
    struct sf_node *node;

    sf_log_debug("sf_release(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        sf_log_error("sf_release(path=%s): %s\n", path, strerror(ENAMETOOLONG));
        return -ENAMETOOLONG;
    }

    pthread_mutex_lock(&lock_node);
    node = sf_node_find(path);

    if (node == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_release(path=%s): %s\n", path, strerror(ENOENT));
        return -ENOENT;
    }
    pthread_mutex_unlock(&lock_node);

    return 0;
}

static int sf_unlink(const char *path)
{
    struct sf_node *node;

    sf_log_debug("sf_unlink(path=%s)\n", path);

    if (strlen(path) > PATH_MAX) {
        sf_log_error("sf_unlink(path=%s): %s\n", path, strerror(ENAMETOOLONG));
        return -ENAMETOOLONG;
    }

    pthread_mutex_lock(&lock_node);
    node = sf_node_find(path);

    if (node == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_unlink(path=%s): %s\n", path, strerror(ENOENT));
        return -ENOENT;
    }

    sf_node_remove(node);
    sf_node_destroy(node);
    pthread_mutex_unlock(&lock_node);

    return 0;
}

static int sf_statfs(const char *path, struct statvfs *stbuf)
{
    struct sf_node *node;
    struct statvfs *st;

    sf_log_debug("sf_statfs(path=%s)\n", path);

    pthread_mutex_lock(&lock_node);
    node = sf_node_find(path);

    if (node == NULL) {
        pthread_mutex_unlock(&lock_node);

        sf_log_error("sf_statfs(path=%s): %s\n", path, strerror(ENOENT));
        return -ENOENT;
    }

    st = sf_get_statfs();
    memcpy(stbuf, st, sizeof(struct statvfs));
    pthread_mutex_unlock(&lock_node);

    free(st);

    return 0;
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
        .releasedir = sf_releasedir,
        .rmdir = sf_rmdir,
        .mknod = sf_mknod,
        .open = sf_open,
        .read = sf_read,
        .write = sf_write,
        .truncate = sf_truncate,
        .rename = sf_rename,
        .release = sf_release,
        .unlink = sf_unlink,
        .statfs = sf_statfs,
    };

    // TODO: check for suid to avoid privilege escalations

    // TODO: validate program arguments

    filename = argv[1];

    argv[1] = argv[2];
    argv[2] = NULL;
    argc--;

#ifdef SF_LOG
    sf_log_init(LOG_DEBUG, "./log.txt", "w+");
#endif

    ret = pthread_mutex_init(&lock_node, NULL);

    if (ret < 0) {
        sf_log_fatal("%s\n", strerror(-ret));
        exit(EXIT_FAILURE);
    }

    ret = sf_init(filename);

    if (ret < 0) {
        sf_log_fatal("%s\n", strerror(-ret));
        exit(EXIT_FAILURE);
    }

    ret = fuse_main(argc, argv, &sf_operations, sf_get_state());

    sf_destroy();

    pthread_mutex_destroy(&lock_node);

#ifdef SF_LOG
    sf_log_destroy();
#endif

    return ret;
}
