#include "mffs.h"

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

#include "util.h"
#include "log.h"

static pthread_mutex_t lock_ino;
static pthread_mutex_t lock_addr;
static pthread_mutex_t lock_stat;

static size_t curfile;

static struct mf_state *mf_data;

static ino_t mf_ino_get_free()
{
    int i, j;
    ino_t ino, len;
    unsigned char *map;

    mf_log_debug("mf_ino_get_free()\n");

    ino = -1;
    len = INO_MAX / CHAR_BIT;
    map = mf_data->inomap;

    mf_util_mutex_lock(&lock_ino);
    for (i = 0; i < len; i++) {
        if (map[i] != 0xFF) {
            for (j = 0; j < CHAR_BIT; j++) {
                if ((unsigned char) (map[i] << j) < 0x80) {
                    ino = i * CHAR_BIT + j;
                    map[i] = map[i] | (0x1 << (CHAR_BIT - j - 1));
                    break;
                }
            }
        }

        if (ino != -1)
            break;
    }
    mf_util_mutex_unlock(&lock_ino);

    if (ino == -1)
        return -EDQUOT;

    mf_util_mutex_lock(&lock_stat);
    mf_data->st->f_ffree--;
    mf_data->st->f_favail = mf_data->st->f_ffree;
    mf_util_mutex_unlock(&lock_stat);

    return ino;
}

static void mf_ino_free(ino_t ino)
{
    ino_t i, j;

    mf_log_debug("mf_ino_free(ino=%lu)\n", ino);

    i = ino / CHAR_BIT;
    j = ino % CHAR_BIT;

    mf_util_mutex_lock(&lock_ino);
    mf_data->inomap[i] = mf_data->inomap[i] & ~(0x1 << (CHAR_BIT - j - 1));
    mf_util_mutex_unlock(&lock_ino);

    mf_util_mutex_lock(&lock_stat);
    mf_data->st->f_ffree++;
    mf_data->st->f_favail = mf_data->st->f_ffree;
    mf_util_mutex_unlock(&lock_stat);
}

static struct mf_address *mf_addr_get_free()
{
    int i, j;
    size_t fileno, addr, len;
    fsblkcnt_t blksize;
    unsigned char *map;
    struct mf_address *ret;

    mf_log_debug("mf_addr_get_free()\n");

    addr = -1;
    len = mf_data->st->f_blocks / CHAR_BIT;
    blksize = mf_data->st->f_bsize;

    mf_util_mutex_lock(&lock_addr);
    // TODO: improve free address policy
    curfile = (curfile + 1) % mf_data->numstorages;
    fileno = curfile;

    map = mf_data->storage[fileno]->addrmap;

    for (i = 0; i < len; i++) {
        if (map[i] != 0xFF) {
            for (j = 0; j < CHAR_BIT; j++) {
                if ((unsigned char) (map[i] << j) < 0x80) {
                    addr = (i * CHAR_BIT + j) * blksize;
                    map[i] = map[i] | (0x1 << (CHAR_BIT - j - 1));
                    break;
                }
            }
        }

        if (addr != -1)
            break;
    }
    mf_util_mutex_unlock(&lock_addr);

    if (addr == -1) {
        errno = ENOSPC;
        return NULL;
    }

    mf_util_mutex_lock(&lock_stat);
    mf_data->st->f_bfree--;
    mf_data->st->f_bavail = mf_data->st->f_bfree;
    mf_util_mutex_unlock(&lock_stat);

    ret = malloc(sizeof(struct mf_address));

    if (ret == NULL) {
        mf_log_fatal("Could not allocate address structure: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    ret->fileno = fileno;
    ret->addrno = addr;

    return ret;
}

static void mf_addr_free(struct mf_address *addr)
{
    size_t i, j;

    mf_log_debug("mf_addr_free(addr=%p)\n", addr);

    i = addr->addrno / mf_data->st->f_bsize / CHAR_BIT;
    j = addr->addrno / mf_data->st->f_bsize % CHAR_BIT;

    mf_util_mutex_lock(&lock_addr);
    mf_data->storage[addr->fileno]->addrmap[i] = mf_data->storage[addr->fileno]->addrmap[i] & ~(0x1 << (CHAR_BIT - j - 1));
    mf_util_mutex_unlock(&lock_addr);

    mf_util_mutex_lock(&lock_stat);
    mf_data->st->f_bfree++;
    mf_data->st->f_bavail = mf_data->st->f_bfree;
    mf_util_mutex_unlock(&lock_stat);
}

static struct mf_blocklist_item *mf_blocklist_item_create(struct mf_address *addr)
{
    struct mf_blocklist_item *item;

    mf_log_debug("mf_blocklist_item_create(addr=%p)\n", addr);

    item = malloc(sizeof(struct mf_blocklist_item));

    if (item == NULL) {
        mf_log_fatal("Could not allocate blocklist item for address \"%lu\": %s\n", addr, strerror(errno));
        exit(EXIT_FAILURE);
    }

    item->addr = addr;
    item->prev = NULL;
    item->next = NULL;

    return item;
}

static void mf_blocklist_item_add(struct mf_node *node, struct mf_blocklist_item *item)
{
    struct mf_blocklist_item *tmp;

    mf_log_debug("mf_blocklist_item_add(node=%p, item=%p)\n", node, item);

    tmp = node->blocklist;

    while (tmp != NULL) {
        if (tmp->next == NULL) {
            item->prev = tmp;
            tmp->next = item;
            return;
        }

        tmp = tmp->next;
    }

    node->blocklist = item;
}

static struct stat *mf_stat_create(ino_t ino, mode_t mode)
{
    time_t t;
    struct stat *st;

    mf_log_debug("mf_stat_create(mode=%u)\n", mode);

    st = malloc(sizeof(struct stat));

    if (st == NULL) {
        mf_log_fatal("Could not allocate stat: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    t = time(NULL);

    st->st_ino = ino;
    st->st_mode = mode;
    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_atime = t;
    st->st_mtime = t;
    st->st_ctime = t;
    st->st_size = 0;
    st->st_blksize = mf_data->st->f_bsize;
    st->st_blocks = 0;
    st->st_dev = 0;
    st->st_rdev = 0;
    st->st_nlink = 0;

    return st;
}

static void mf_node_destroy(struct mf_node *node)
{
    struct mf_blocklist_item *curblock, *nextblock;

    curblock = node->blocklist;

    while (curblock != NULL) {
        nextblock = curblock->next;
        mf_addr_free(curblock->addr);
        free(curblock);
        curblock = nextblock;
    }

    mf_ino_free(node->st->st_ino);

    free(node->st);

    pthread_mutex_destroy(&(node->lock));
    pthread_cond_destroy(&(node->cond));

    free(node);
}

static struct mf_node *mf_node_create(ino_t ino, mode_t mode)
{
    struct stat *st;
    struct mf_node *node;

    mf_log_debug("mf_node_create(ino=%lu, mode=%u)\n", ino, mode);

    node = malloc(sizeof(struct mf_node));

    if (node == NULL) {
        mf_log_fatal("Could not allocate node with number \"%lu\": %s\n", ino, strerror(errno));
        exit(EXIT_FAILURE);
    }

    st = mf_stat_create(ino, mode);

    if (st == NULL)
        return NULL;

    node->st = st;

    node->open = 0;
    node->reading = 0;
    node->writing = 0;
    node->remove = 0;

    errno = pthread_mutex_init(&(node->lock), NULL);

    if (errno != 0) {
        mf_node_destroy(node);
        return NULL;
    }

    errno = pthread_cond_init(&(node->cond), NULL);

    if (errno != 0) {
        mf_node_destroy(node);
        return NULL;
    }

    node->blocklist = NULL;

    return node;
}

static struct mf_nodelist_item *mf_nodelist_item_create(struct mf_node *node)
{
    struct mf_nodelist_item *item;

    mf_log_debug("mf_nodelist_item_create(node=%p)\n", node);

    item = malloc(sizeof(struct mf_nodelist_item));

    if (item == NULL) {
        mf_log_fatal("Could not allocate nodelist item for node with number \"%lu\": %s\n", node->st->st_ino, strerror(errno));
        exit(EXIT_FAILURE);
    }

    item->node = node;
    item->prev = NULL;
    item->next = NULL;

    return item;
}

static struct mf_file *mf_file_create(const char *name, struct mf_file *parent)
{
    ino_t ino;
    struct mf_file *file;

    mf_log_debug("mf_file_create(name=%s, parent=%p)\n", name, parent);

    file = malloc(sizeof(struct mf_file));

    if (file == NULL) {
        mf_log_fatal("Could not allocate file with name \"%s\": %s\n", name, strerror(errno));
        exit(EXIT_FAILURE);
    }

    ino = mf_ino_get_free();

    if (ino < 0) {
        errno = -ino;
        return NULL;
    }

    file->name = strdup(name);
    file->ino = ino;
    file->parent = parent;
    file->filelist = NULL;

    return file;
}

static struct mf_filelist_item *mf_filelist_item_find(struct mf_file *current, const char *name)
{
    struct mf_filelist_item *item;

    mf_log_debug("mf_filelist_item_find(current=%p, name=%s)\n", current, name);

    item = current->filelist;

    while (item != NULL && strcmp(item->file->name, name) != 0)
        item = item->next;

    return item;
}

static struct mf_filelist_item *mf_filelist_item_create(struct mf_file *file)
{
    struct mf_filelist_item *item;

    mf_log_debug("mf_filelist_item_create(file=%p)\n", file);

    item = malloc(sizeof(struct mf_filelist_item));

    if (item == NULL) {
        mf_log_fatal("Could not allocate filelist item for file with name \"%s\": %s\n", file->name, strerror(errno));
        exit(EXIT_FAILURE);
    }

    item->file = file;
    item->prev = NULL;
    item->next = NULL;

    return item;
}

static void mf_file_destroy(struct mf_file *file)
{
    free(file->name);
    free(file);
}

struct mf_file *mf_file_find(const char *path)
{
    char *dup, *saveptr, *name;
    const char *delim;
    struct mf_file *file;
    struct mf_filelist_item *item;

    mf_log_debug("mf_file_find(path=%s)\n", path);

    file = mf_data->filelist->file;

    delim = DIR_DELIMITER;

    // TODO: improve search of file (e.g., using a hashtree, as ext4 does?)
    dup = strdup(path);
    name = strtok_r(dup, delim, &saveptr);

    while (name != NULL) {
        item = mf_filelist_item_find(file, name);

        if (item == NULL) {
            file = NULL;
            break;
        }

        file = item->file;
        name = strtok_r(NULL, delim, &saveptr);
    }

    free(dup);

    return file;
}

struct mf_file *mf_file_find_parent(const char *path)
{
    char *dup, *saveptr, *name;
    const char *delim;
    struct mf_file *parent;
    struct mf_filelist_item *item;

    mf_log_debug("mf_file_find_parent(path=%s)\n", path);

    parent = mf_data->filelist->file;

    delim = DIR_DELIMITER;

    dup = strdup(path);
    name = strtok_r(dup, delim, &saveptr);

    while (name != NULL) {
        item = mf_filelist_item_find(parent, name);

        if (item == NULL)
            break;

        parent = item->file;
        name = strtok_r(NULL, delim, &saveptr);
    }

    if (name == NULL && parent->parent != NULL) {
        parent = parent->parent;
    }

    free(dup);

    return parent;
}

int mf_file_add(struct mf_file *parent, const char *name)
{
    int ret;
    struct mf_file *file;
    struct mf_filelist_item *item, *tmp;

    ret = 0;

    mf_log_debug("mf_file_add(parent=%p, name=%s)\n", parent, name);

    file = mf_file_create(name, parent);

    if (file == NULL)
        return -errno;

    item = mf_filelist_item_create(file);

    if (item == NULL) {
        mf_file_destroy(file);
        return -errno;
    }

    tmp = parent->filelist;
    parent->filelist = item;
    item->next = tmp;

    if (tmp != NULL)
        tmp->prev = item;

    return ret;
}

void mf_file_remove(struct mf_file *file)
{
    struct mf_filelist_item *item;

    mf_log_debug("mf_file_remove(file=%p)\n", file);

    item = file->parent->filelist;

    if (item->file == file)
        file->parent->filelist = item->next;

    while (item->file != file)
        item = item->next;

    if (item->prev != NULL)
        item->prev->next = item->next;

    if (item->next != NULL)
        item->next->prev = item->prev;

    mf_file_destroy(file);
    free(item);
}

struct mf_node *mf_node_get(ino_t ino)
{
    struct mf_nodelist_item *item;

    mf_log_debug("mf_node_get(ino=%lu)\n", ino);

    item = mf_data->nodetbl[ino % INO_TBL_SIZE];

    while (item != NULL && item->node->st->st_ino != ino)
        item = item->next;

    if (item == NULL)
        return NULL;

    return item->node;
}

int mf_node_put(ino_t ino, mode_t mode)
{
    ino_t pos;
    struct mf_node *node;
    struct mf_nodelist_item *item, *tmp;

    mf_log_debug("mf_node_put(ino=%lu, mode=%u)\n", ino, mode);

    node = mf_node_create(ino, mode);

    if (node == NULL) {
        mf_ino_free(ino);
        return -errno;
    }

    item = mf_nodelist_item_create(node);

    if (item == NULL)
        return -errno;

    pos = node->st->st_ino % INO_TBL_SIZE;

    tmp = mf_data->nodetbl[pos];
    mf_data->nodetbl[pos] = item;
    item->next = tmp;

    if (tmp != NULL)
        tmp->prev = item;

    return 0;
}

ssize_t mf_node_read(char *buf, size_t size, off_t offset, struct mf_node *node)
{
    int i;
    size_t off;
    ssize_t b_read;
    fsblkcnt_t blksize;
    struct mf_blocklist_item *item;
    struct mf_storage *storage;
    struct mf_address *addr;
    FILE* fh;

    mf_log_debug("mf_node_read(size=%lu, offset=%lu, node=%p)\n", size, offset, node);

    blksize = mf_data->st->f_bsize;
    item = node->blocklist;

    for (i = 0; i < offset / (off_t) blksize; item = item->next, i++)
        ;

    off = offset % blksize;

    b_read = 0;

    while (item != NULL && b_read < size) {
        addr = item->addr;
        storage = mf_data->storage[addr->fileno];
        fh = storage->fh;

        mf_util_mutex_lock(&(storage->lock));
        // TODO: improve seeking of file's position
        fseek(fh, addr->addrno + off, SEEK_SET);

        off = fread(buf, sizeof(char), mf_util_min(size - (size_t) b_read, blksize - off), fh);

        if (ferror(fh)) {
            mf_util_mutex_unlock(&(storage->lock));

            b_read = -EIO;
            break;
        }
        mf_util_mutex_unlock(&(storage->lock));

        buf += off;
        b_read += off;

        off = 0;
        item = item->next;
    }

    return b_read;
}

ssize_t mf_node_write(const char *buf, size_t size, off_t offset, struct mf_node *node)
{
    int i;
    size_t off;
    ssize_t b_written;
    fsblkcnt_t blksize;
    struct mf_blocklist_item *item;
    struct mf_storage *storage;
    struct mf_address *addr;
    FILE* fh;

    fh = NULL;

    mf_log_debug("mf_node_write(size=%lu, offset=%lu, node=%p)\n", size, offset, node);

    blksize = mf_data->st->f_bsize;
    item = node->blocklist;

    for (i = 0; i < offset / (off_t) blksize; item = item->next, i++)
        ;

    off = offset % blksize;

    b_written = 0;

    while (b_written < size) {
        if (item == NULL) {
            addr = mf_addr_get_free();

            if (addr == NULL)
                return -errno;

            item = mf_blocklist_item_create(addr);

            if (item == NULL) {
                mf_addr_free(addr);
                b_written = -EIO;
                break;
            }

            mf_blocklist_item_add(node, item);

            node->st->st_blocks += blksize / 512;
        } else {
            addr = item->addr;
        }

        storage = mf_data->storage[addr->fileno];
        fh = storage->fh;

        mf_util_mutex_lock(&(storage->lock));
        // TODO: improve seeking of file's position
        fseek(fh, addr->addrno + off, SEEK_SET);

        off = fwrite(buf, sizeof(char), mf_util_min(size - (size_t) b_written, blksize - off), fh);

        node->st->st_size += off;

        if (ferror(fh)) {
            mf_util_mutex_unlock(&(storage->lock));

            b_written = -EIO;
            break;
        }
        mf_util_mutex_unlock(&(storage->lock));

        buf += off;
        b_written += off;

        off = 0;
        item = item->next;
    }

    if (fh != NULL)
        fflush(fh);

    return b_written;
}

ssize_t mf_node_resize(struct mf_node *node, size_t size)
{
    int i;
    size_t diff;
    ssize_t ret;
    fsblkcnt_t blksize;
    char *buf;
    struct mf_blocklist_item *curblock, *nextblock;

    mf_log_debug("mf_node_resize(node=%p, size=%lu)\n", node, size);

    ret = 0;

    blksize = mf_data->st->f_bsize;

    if (node->st->st_size != size) {
        if (node->st->st_size < size) {
            diff = size - node->st->st_size;

            if (!mf_has_availspace(diff))
                return -ENOSPC;

            buf = calloc(diff, sizeof(char));

            if (buf == NULL) {
                mf_log_fatal("Could not allocate buffer to truncate file: %s\n", strerror(errno));
                exit(EXIT_FAILURE);
            }

            ret = mf_node_write(buf, diff, node->st->st_size, node);
        } else {
            diff = 0;
            buf = NULL;

            ret = size / blksize;

            if (size % blksize) {
                ret++;

                diff = blksize - (size % blksize);

                buf = calloc(diff, sizeof(char));

                if (buf == NULL) {
                    mf_log_fatal("Could not allocate buffer to truncate file: %s\n", strerror(errno));
                    exit(EXIT_FAILURE);
                }
            }

            curblock = node->blocklist;

            for (i = 0; i < ret; i++)
                curblock = curblock->next;

            while (curblock != NULL) {
                nextblock = curblock->next;
                mf_addr_free(curblock->addr);
                free(curblock);
                curblock = nextblock;
            }

            if (diff > 0)
                ret = mf_node_write(buf, diff, ret * blksize - diff, node);
        }

        if (ret < 0)
            return ret;

        node->st->st_size = size;
    }

    return ret;
}

int mf_node_lock(int mode, struct mf_node *node)
{
    int ret;

    ret = 0;

    mf_log_debug("mf_node_lock(mode=%d, node=%p)\n", mode, node);

    if (node == NULL) {
        ret = EINVAL;
        goto err;
    }

    if (!(mode & NODE_LOCKMODE_R) && !(mode & NODE_LOCKMODE_W)) {
        ret = ENOTSUP;
        goto err;
    }

    mf_util_mutex_lock(&(node->lock));
    while (node->writing || (mode & NODE_LOCKMODE_W && node->reading))
        mf_util_cond_wait(&(node->cond), &(node->lock));

    if (mode & NODE_LOCKMODE_R)
        node->reading++;
    else if (mode & NODE_LOCKMODE_W)
        node->writing = 1;
    mf_util_mutex_unlock(&(node->lock));

    return ret;

err:
    mf_log_error("mf_node_lock(mode=%d, node=%p): %s\n", mode, node, strerror(ret));
    return -ret;
}

int mf_node_unlock(int mode, struct mf_node *node)
{
    int ret;

    ret = 0;

    mf_log_debug("mf_node_unlock(mode=%d, node=%p)\n", mode, node);

    if (node == NULL) {
        ret = EINVAL;
        goto err;
    }

    if (!(mode & NODE_LOCKMODE_R) && !(mode & NODE_LOCKMODE_W)) {
        ret = ENOTSUP;
        goto err;
    }

    mf_util_mutex_lock(&(node->lock));
    if (mode & NODE_LOCKMODE_R)
        node->reading--;
    else if (mode & NODE_LOCKMODE_W)
        node->writing = 0;
    mf_util_cond_signal(&(node->cond));
    mf_util_mutex_unlock(&(node->lock));

    return ret;

err:
    mf_log_error("mf_node_unlock(mode=%d, node=%p): %s\n", mode, node, strerror(ret));
    return -ret;
}

void mf_node_remove(struct mf_node *node)
{
    ino_t pos;
    struct mf_nodelist_item *item;

    mf_log_debug("mf_node_remove(node=%p)\n", node);

    pos = node->st->st_ino % INO_TBL_SIZE;

    item = mf_data->nodetbl[pos];

    if (item->node == node)
        mf_data->nodetbl[pos] = item->next;

    while (item->node != node)
        item = item->next;

    if (item->prev != NULL)
        item->prev->next = item->next;

    if (item->next != NULL)
        item->next->prev = item->prev;

    mf_node_destroy(node);
    free(item);
}

struct statvfs *mf_get_statfs()
{
    struct statvfs *st;

    mf_log_debug("mf_get_statfs()\n");

    st = malloc(sizeof(struct statvfs));

    if (st == NULL) {
        mf_log_fatal("Could not allocate file system stats: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    mf_util_mutex_lock(&lock_stat);
    memcpy(st, mf_data->st, sizeof(struct statvfs));
    mf_util_mutex_unlock(&lock_stat);

    return st;
}

int mf_has_availspace(size_t size)
{
    int ret;
    fsblkcnt_t blocks, blksize;

    ret = 0;

    mf_log_debug("mf_has_availspace(size=%lu)\n", size);

    blksize = mf_data->st->f_bsize;

    blocks = size / blksize;

    if (size % blksize)
        blocks++;

    mf_util_mutex_lock(&lock_stat);
    ret = mf_data->st->f_bfree >= blocks;
    mf_util_mutex_unlock(&lock_stat);

    return ret;
}

int mf_init(size_t numfiles, const char **filenames)
{
    int ret;
    size_t i;
    fsblkcnt_t size, totsize;
    const char *rootname;
    struct mf_file *rootfile;

    ret = 0;
    totsize = 0;
    rootname = "";

    curfile = 0;

    mf_log_debug("mf_init(numfiles=%ld, filenames=%p)\n", numfiles, filenames);

    if (mf_data != NULL)
        return ret;

    mf_data = malloc(sizeof(struct mf_state));

    if (mf_data == NULL) {
        mf_log_fatal("Could not allocate file system metadata: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    mf_data->numstorages = numfiles;

    mf_data->storage = malloc(mf_data->numstorages * sizeof(struct mf_storage *));

    if (mf_data->storage == NULL) {
        mf_log_fatal("Could not allocate storage array: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < numfiles; i++) {
        mf_data->storage[i] = malloc(sizeof(struct mf_storage));

        if (mf_data->storage[i] == NULL) {
            mf_log_fatal("Could not allocate storage for file \"%s\": %s\n", filenames[i], strerror(errno));
            exit(EXIT_FAILURE);
        }

        mf_data->storage[i]->fh = fopen(filenames[i], "rb+");

        if (mf_data->storage[i]->fh == NULL) {
            ret = -errno;
            goto err;
        }

        fseek(mf_data->storage[i]->fh, 0, SEEK_END);
        size = ftell(mf_data->storage[i]->fh);
        fseek(mf_data->storage[i]->fh, 0, SEEK_SET);

        totsize += size;

        mf_data->storage[i]->addrmap = calloc(size / ((fsblkcnt_t) BLOCK_SIZE / CHAR_BIT), sizeof(char));

        if (mf_data->storage[i]->addrmap == NULL) {
            mf_log_fatal("Could not allocate file system block addresses bitmap for file \"%s\": %s\n", filenames[i], strerror(errno));
            exit(EXIT_FAILURE);
        }

        ret = pthread_mutex_init(&(mf_data->storage[i]->lock), NULL);

        if (ret != 0)
            goto err;
    }

    mf_data->inomap = calloc(INO_MAX / ((size_t) CHAR_BIT) - 1, sizeof(char));

    if (mf_data->inomap == NULL) {
        mf_log_fatal("Could not allocate file system inode bitmap: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    mf_data->nodetbl = calloc(INO_TBL_SIZE, sizeof(struct mf_nodelist_item **));

    if (mf_data->nodetbl == NULL) {
        mf_log_fatal("Could not allocate file system nodes table: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    mf_data->st = malloc(sizeof(struct statvfs));

    if (mf_data->st == NULL) {
        mf_log_fatal("Could not allocate file system stats structure: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    mf_data->st->f_bsize = BLOCK_SIZE;
    mf_data->st->f_frsize = mf_data->st->f_bsize;
    mf_data->st->f_blocks = totsize / (fsblkcnt_t) BLOCK_SIZE;
    mf_data->st->f_bfree = mf_data->st->f_blocks;
    mf_data->st->f_bavail = mf_data->st->f_blocks;
    mf_data->st->f_files = INO_MAX;
    mf_data->st->f_ffree = mf_data->st->f_files;
    mf_data->st->f_favail = mf_data->st->f_files;
    mf_data->st->f_fsid = 1;
    mf_data->st->f_flag = 0;
    mf_data->st->f_namemax = NAME_MAX;

    rootfile = mf_file_create(rootname, NULL);

    if (rootfile == NULL) {
        ret = -errno;
        goto err;
    }

    mf_data->filelist = mf_filelist_item_create(rootfile);

    if (mf_data->filelist == NULL) {
        ret = -errno;
        goto err;
    }

    ret = mf_node_put(rootfile->ino, S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO);

    if (ret < 0)
        goto err;

    ret = pthread_mutex_init(&lock_ino, NULL);

    if (ret != 0)
        goto err;

    ret = pthread_mutex_init(&lock_addr, NULL);

    if (ret != 0)
        goto err;

    ret = pthread_mutex_init(&lock_stat, NULL);

    if (ret != 0)
        goto err;

    return ret;

err:
    mf_destroy();
    return ret;
}

void mf_destroy()
{
    size_t i;
    struct mf_nodelist_item *curitem, *nextitem;

    mf_log_debug("mf_destroy()\n");

    for (i = 0; i < INO_TBL_SIZE; i++) {
        curitem = mf_data->nodetbl[i];

        while (curitem != NULL) {
            nextitem = curitem->next;
            mf_node_remove(curitem->node);
            curitem = nextitem;
        }
    }

    for (i = 0; i < mf_data->numstorages; i++) {
        if (mf_data->storage[i]->fh != NULL)
            fclose(mf_data->storage[i]->fh);

        free(mf_data->storage[i]->addrmap);

        pthread_mutex_destroy(&(mf_data->storage[i]->lock));

        free(mf_data->storage[i]);
    }

    free(mf_data->storage);

    if (mf_data->filelist != NULL)
        mf_file_remove(mf_data->filelist->file);

    free(mf_data->inomap);
    //free(mf_data->filelist);
    free(mf_data->nodetbl);
    free(mf_data->st);

    pthread_mutex_destroy(&lock_ino);
    pthread_mutex_destroy(&lock_addr);
    pthread_mutex_destroy(&lock_stat);

    free(mf_data);
}