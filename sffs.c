#include "sffs.h"

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

static struct sf_state *sf_data;

static ino_t sf_ino_get_free()
{
    int i, j;
    ino_t ino, len;
    unsigned char *map;

    sf_log_debug("sf_ino_get_free()\n");

    ino = -1;
    len = INO_MAX / CHAR_BIT;
    map = sf_data->inomap;

    sf_util_mutex_lock(&lock_ino);
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
    sf_util_mutex_unlock(&lock_ino);

    if (ino == -1)
        return -EDQUOT;

    sf_util_mutex_lock(&lock_stat);
    sf_data->st->f_ffree--;
    sf_data->st->f_favail = sf_data->st->f_ffree;
    sf_util_mutex_unlock(&lock_stat);

    return ino;
}

static void sf_ino_free(ino_t ino)
{
    ino_t i, j;

    sf_log_debug("sf_ino_free(ino=%lu)\n", ino);

    i = ino / CHAR_BIT;
    j = ino % CHAR_BIT;

    sf_util_mutex_lock(&lock_ino);
    sf_data->inomap[i] = sf_data->inomap[i] & ~(0x1 << (CHAR_BIT - j - 1));
    sf_util_mutex_unlock(&lock_ino);

    sf_util_mutex_lock(&lock_stat);
    sf_data->st->f_ffree++;
    sf_data->st->f_favail = sf_data->st->f_ffree;
    sf_util_mutex_unlock(&lock_stat);
}

static struct sf_address *sf_addr_get_free()
{
    int i, j;
    size_t fileno, addr, len;
    fsblkcnt_t blksize;
    unsigned char *map;
    struct sf_address *ret;

    sf_log_debug("sf_addr_get_free()\n");

    addr = -1;
    len = sf_data->st->f_blocks / CHAR_BIT;
    blksize = sf_data->st->f_bsize;

    sf_util_mutex_lock(&lock_addr);
    // TODO: improve free address policy
    curfile = (curfile + 1) % sf_data->numstorages;
    fileno = curfile;

    map = sf_data->storage[fileno]->addrmap;

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
    sf_util_mutex_unlock(&lock_addr);

    if (addr == -1) {
        errno = ENOSPC;
        return NULL;
    }

    sf_util_mutex_lock(&lock_stat);
    sf_data->st->f_bfree--;
    sf_data->st->f_bavail = sf_data->st->f_bfree;
    sf_util_mutex_unlock(&lock_stat);

    ret = malloc(sizeof(struct sf_address));

    if (ret == NULL) {
        sf_log_fatal("Could not allocate address structure: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    ret->fileno = fileno;
    ret->addrno = addr;

    return ret;
}

static void sf_addr_free(struct sf_address *addr)
{
    size_t i, j;

    sf_log_debug("sf_addr_free(addr=%p)\n", addr);

    i = addr->addrno / sf_data->st->f_bsize / CHAR_BIT;
    j = addr->addrno / sf_data->st->f_bsize % CHAR_BIT;

    sf_util_mutex_lock(&lock_addr);
    sf_data->storage[addr->fileno]->addrmap[i] = sf_data->storage[addr->fileno]->addrmap[i] & ~(0x1 << (CHAR_BIT - j - 1));
    sf_util_mutex_unlock(&lock_addr);

    sf_util_mutex_lock(&lock_stat);
    sf_data->st->f_bfree++;
    sf_data->st->f_bavail = sf_data->st->f_bfree;
    sf_util_mutex_unlock(&lock_stat);
}

static struct sf_blocklist_item *sf_blocklist_item_create(struct sf_address *addr)
{
    struct sf_blocklist_item *item;

    sf_log_debug("sf_blocklist_item_create(addr=%p)\n", addr);

    item = malloc(sizeof(struct sf_blocklist_item));

    if (item == NULL) {
        sf_log_fatal("Could not allocate blocklist item for address \"%lu\": %s\n", addr, strerror(errno));
        exit(EXIT_FAILURE);
    }

    item->addr = addr;
    item->prev = NULL;
    item->next = NULL;

    return item;
}

static void sf_blocklist_item_add(struct sf_node *node, struct sf_blocklist_item *item)
{
    struct sf_blocklist_item *tmp;

    sf_log_debug("sf_blocklist_item_add(node=%p, item=%p)\n", node, item);

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

static struct stat *sf_stat_create(ino_t ino, mode_t mode)
{
    time_t t;
    struct stat *st;

    sf_log_debug("sf_stat_create(mode=%u)\n", mode);

    st = malloc(sizeof(struct stat));

    if (st == NULL) {
        sf_log_fatal("Could not allocate stat: %s\n", strerror(errno));
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
    st->st_blksize = sf_data->st->f_bsize;
    st->st_blocks = 0;
    st->st_dev = 0;
    st->st_rdev = 0;
    st->st_nlink = 0;

    return st;
}

static void sf_node_destroy(struct sf_node *node)
{
    struct sf_blocklist_item *curblock, *nextblock;

    curblock = node->blocklist;

    while (curblock != NULL) {
        nextblock = curblock->next;
        sf_addr_free(curblock->addr);
        free(curblock);
        curblock = nextblock;
    }

    sf_ino_free(node->st->st_ino);

    free(node->st);

    pthread_mutex_destroy(&(node->lock));
    pthread_cond_destroy(&(node->cond));

    free(node);
}

static struct sf_node *sf_node_create(ino_t ino, mode_t mode)
{
    struct stat *st;
    struct sf_node *node;

    sf_log_debug("sf_node_create(ino=%lu, mode=%u)\n", ino, mode);

    node = malloc(sizeof(struct sf_node));

    if (node == NULL) {
        sf_log_fatal("Could not allocate node with number \"%lu\": %s\n", ino, strerror(errno));
        exit(EXIT_FAILURE);
    }

    st = sf_stat_create(ino, mode);

    if (st == NULL)
        return NULL;

    node->st = st;

    node->open = 0;
    node->reading = 0;
    node->writing = 0;
    node->remove = 0;

    errno = pthread_mutex_init(&(node->lock), NULL);

    if (errno != 0) {
        sf_node_destroy(node);
        return NULL;
    }

    errno = pthread_cond_init(&(node->cond), NULL);

    if (errno != 0) {
        sf_node_destroy(node);
        return NULL;
    }

    node->blocklist = NULL;

    return node;
}

static struct sf_nodelist_item *sf_nodelist_item_create(struct sf_node *node)
{
    struct sf_nodelist_item *item;

    sf_log_debug("sf_nodelist_item_create(node=%p)\n", node);

    item = malloc(sizeof(struct sf_nodelist_item));

    if (item == NULL) {
        sf_log_fatal("Could not allocate nodelist item for node with number \"%lu\": %s\n", node->st->st_ino, strerror(errno));
        exit(EXIT_FAILURE);
    }

    item->node = node;
    item->prev = NULL;
    item->next = NULL;

    return item;
}

static struct sf_file *sf_file_create(const char *name, struct sf_file *parent)
{
    ino_t ino;
    struct sf_file *file;

    sf_log_debug("sf_file_create(name=%s, parent=%p)\n", name, parent);

    file = malloc(sizeof(struct sf_file));

    if (file == NULL) {
        sf_log_fatal("Could not allocate file with name \"%s\": %s\n", name, strerror(errno));
        exit(EXIT_FAILURE);
    }

    ino = sf_ino_get_free();

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

static struct sf_filelist_item *sf_filelist_item_find(struct sf_file *current, const char *name)
{
    struct sf_filelist_item *item;

    sf_log_debug("sf_filelist_item_find(current=%p, name=%s)\n", current, name);

    item = current->filelist;

    while (item != NULL && strcmp(item->file->name, name) != 0)
        item = item->next;

    return item;
}

static struct sf_filelist_item *sf_filelist_item_create(struct sf_file *file)
{
    struct sf_filelist_item *item;

    sf_log_debug("sf_filelist_item_create(file=%p)\n", file);

    item = malloc(sizeof(struct sf_filelist_item));

    if (item == NULL) {
        sf_log_fatal("Could not allocate filelist item for file with name \"%s\": %s\n", file->name, strerror(errno));
        exit(EXIT_FAILURE);
    }

    item->file = file;
    item->prev = NULL;
    item->next = NULL;

    return item;
}

static void sf_file_destroy(struct sf_file *file)
{
    free(file->name);
    free(file);
}

struct sf_file *sf_file_find(const char *path)
{
    char *dup, *saveptr, *name;
    const char *delim;
    struct sf_file *file;
    struct sf_filelist_item *item;

    sf_log_debug("sf_file_find(path=%s)\n", path);

    file = sf_data->filelist->file;

    delim = DIR_DELIMITER;

    // TODO: improve search of file (e.g., using a hashtree, as ext4 does?)
    dup = strdup(path);
    name = strtok_r(dup, delim, &saveptr);

    while (name != NULL) {
        item = sf_filelist_item_find(file, name);

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

struct sf_file *sf_file_find_parent(const char *path)
{
    char *dup, *saveptr, *name;
    const char *delim;
    struct sf_file *parent;
    struct sf_filelist_item *item;

    sf_log_debug("sf_file_find_parent(path=%s)\n", path);

    parent = sf_data->filelist->file;

    delim = DIR_DELIMITER;

    dup = strdup(path);
    name = strtok_r(dup, delim, &saveptr);

    while (name != NULL) {
        item = sf_filelist_item_find(parent, name);

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

int sf_file_add(struct sf_file *parent, const char *name)
{
    int ret;
    struct sf_file *file;
    struct sf_filelist_item *item, *tmp;

    ret = 0;

    sf_log_debug("sf_file_add(parent=%p, name=%s)\n", parent, name);

    file = sf_file_create(name, parent);

    if (file == NULL)
        return -errno;

    item = sf_filelist_item_create(file);

    if (item == NULL) {
        sf_file_destroy(file);
        return -errno;
    }

    tmp = parent->filelist;
    parent->filelist = item;
    item->next = tmp;

    if (tmp != NULL)
        tmp->prev = item;

    return ret;
}

void sf_file_remove(struct sf_file *file)
{
    struct sf_filelist_item *item;

    sf_log_debug("sf_file_remove(file=%p)\n", file);

    item = file->parent->filelist;

    if (item->file == file)
        file->parent->filelist = item->next;

    while (item->file != file)
        item = item->next;

    if (item->prev != NULL)
        item->prev->next = item->next;

    if (item->next != NULL)
        item->next->prev = item->prev;

    sf_file_destroy(file);
    free(item);
}

struct sf_node *sf_node_get(ino_t ino)
{
    struct sf_nodelist_item *item;

    sf_log_debug("sf_node_get(ino=%lu)\n", ino);

    item = sf_data->nodetbl[ino % INO_TBL_SIZE];

    while (item != NULL && item->node->st->st_ino != ino)
        item = item->next;

    if (item == NULL)
        return NULL;

    return item->node;
}

int sf_node_put(ino_t ino, mode_t mode)
{
    ino_t pos;
    struct sf_node *node;
    struct sf_nodelist_item *item, *tmp;

    sf_log_debug("sf_node_put(ino=%lu, mode=%u)\n", ino, mode);

    node = sf_node_create(ino, mode);

    if (node == NULL) {
        sf_ino_free(ino);
        return -errno;
    }

    item = sf_nodelist_item_create(node);

    if (item == NULL)
        return -errno;

    pos = node->st->st_ino % INO_TBL_SIZE;

    tmp = sf_data->nodetbl[pos];
    sf_data->nodetbl[pos] = item;
    item->next = tmp;

    if (tmp != NULL)
        tmp->prev = item;

    return 0;
}

ssize_t sf_node_read(char *buf, size_t size, off_t offset, struct sf_node *node)
{
    int i;
    size_t off;
    ssize_t b_read;
    fsblkcnt_t blksize;
    struct sf_blocklist_item *item;
    struct sf_storage *storage;
    struct sf_address *addr;
    FILE* fh;

    sf_log_debug("sf_node_read(size=%lu, offset=%lu, node=%p)\n", size, offset, node);

    blksize = sf_data->st->f_bsize;
    item = node->blocklist;

    for (i = 0; i < offset / (off_t) blksize; item = item->next, i++)
        ;

    off = offset % blksize;

    b_read = 0;

    while (item != NULL && b_read < size) {
        addr = item->addr;
        storage = sf_data->storage[addr->fileno];
        fh = storage->fh;

        sf_util_mutex_lock(&(storage->lock));
        // TODO: improve seeking of file's position
        fseek(fh, addr->addrno + off, SEEK_SET);

        off = fread(buf, sizeof(char), sf_util_min(size - (size_t) b_read, blksize - off), fh);

        if (ferror(fh)) {
            sf_util_mutex_unlock(&(storage->lock));

            b_read = -EIO;
            break;
        }
        sf_util_mutex_unlock(&(storage->lock));

        buf += off;
        b_read += off;

        off = 0;
        item = item->next;
    }

    return b_read;
}

ssize_t sf_node_write(const char *buf, size_t size, off_t offset, struct sf_node *node)
{
    int i;
    size_t off;
    ssize_t b_written;
    fsblkcnt_t blksize;
    struct sf_blocklist_item *item;
    struct sf_storage *storage;
    struct sf_address *addr;
    FILE* fh;

    fh = NULL;

    sf_log_debug("sf_node_write(size=%lu, offset=%lu, node=%p)\n", size, offset, node);

    blksize = sf_data->st->f_bsize;
    item = node->blocklist;

    for (i = 0; i < offset / (off_t) blksize; item = item->next, i++)
        ;

    off = offset % blksize;

    b_written = 0;

    while (b_written < size) {
        if (item == NULL) {
            addr = sf_addr_get_free();

            if (addr == NULL)
                return -errno;

            item = sf_blocklist_item_create(addr);

            if (item == NULL) {
                sf_addr_free(addr);
                b_written = -EIO;
                break;
            }

            sf_blocklist_item_add(node, item);

            node->st->st_blocks += blksize / 512;
        } else {
            addr = item->addr;
        }

        storage = sf_data->storage[addr->fileno];
        fh = storage->fh;

        sf_util_mutex_lock(&(storage->lock));
        // TODO: improve seeking of file's position
        fseek(fh, addr->addrno + off, SEEK_SET);

        off = fwrite(buf, sizeof(char), sf_util_min(size - (size_t) b_written, blksize - off), fh);

        node->st->st_size += off;

        if (ferror(fh)) {
            sf_util_mutex_unlock(&(storage->lock));

            b_written = -EIO;
            break;
        }
        sf_util_mutex_unlock(&(storage->lock));

        buf += off;
        b_written += off;

        off = 0;
        item = item->next;
    }

    if (fh != NULL)
        fflush(fh);

    return b_written;
}

ssize_t sf_node_resize(struct sf_node *node, size_t size)
{
    int i;
    size_t diff;
    ssize_t ret;
    fsblkcnt_t blksize;
    char *buf;
    struct sf_blocklist_item *curblock, *nextblock;

    sf_log_debug("sf_node_resize(node=%p, size=%lu)\n", node, size);

    ret = 0;

    blksize = sf_data->st->f_bsize;

    if (node->st->st_size != size) {
        if (node->st->st_size < size) {
            diff = size - node->st->st_size;

            if (!sf_has_availspace(diff))
                return -ENOSPC;

            buf = calloc(diff, sizeof(char));

            if (buf == NULL) {
                sf_log_fatal("Could not allocate buffer to truncate file: %s\n", strerror(errno));
                exit(EXIT_FAILURE);
            }

            ret = sf_node_write(buf, diff, node->st->st_size, node);
        } else {
            diff = 0;
            buf = NULL;

            ret = size / blksize;

            if (size % blksize) {
                ret++;

                diff = blksize - (size % blksize);

                buf = calloc(diff, sizeof(char));

                if (buf == NULL) {
                    sf_log_fatal("Could not allocate buffer to truncate file: %s\n", strerror(errno));
                    exit(EXIT_FAILURE);
                }
            }

            curblock = node->blocklist;

            for (i = 0; i < ret; i++)
                curblock = curblock->next;

            while (curblock != NULL) {
                nextblock = curblock->next;
                sf_addr_free(curblock->addr);
                free(curblock);
                curblock = nextblock;
            }

            if (diff > 0)
                ret = sf_node_write(buf, diff, ret * blksize - diff, node);
        }

        if (ret < 0)
            return ret;

        node->st->st_size = size;
    }

    return ret;
}

int sf_node_lock(int mode, struct sf_node *node)
{
    int ret;

    ret = 0;

    sf_log_debug("sf_node_lock(mode=%d, node=%p)\n", mode, node);

    if (node == NULL) {
        ret = EINVAL;
        goto err;
    }

    if (!(mode & NODE_LOCKMODE_R) && !(mode & NODE_LOCKMODE_W)) {
        ret = ENOTSUP;
        goto err;
    }

    sf_util_mutex_lock(&(node->lock));
    while (node->writing || (mode & NODE_LOCKMODE_W && node->reading))
        sf_util_cond_wait(&(node->cond), &(node->lock));

    if (mode & NODE_LOCKMODE_R)
        node->reading++;
    else if (mode & NODE_LOCKMODE_W)
        node->writing = 1;
    sf_util_mutex_unlock(&(node->lock));

    return ret;

err:
    sf_log_error("sf_node_lock(mode=%d, node=%p): %s\n", mode, node, strerror(ret));
    return -ret;
}

int sf_node_unlock(int mode, struct sf_node *node)
{
    int ret;

    ret = 0;

    sf_log_debug("sf_node_unlock(mode=%d, node=%p)\n", mode, node);

    if (node == NULL) {
        ret = EINVAL;
        goto err;
    }

    if (!(mode & NODE_LOCKMODE_R) && !(mode & NODE_LOCKMODE_W)) {
        ret = ENOTSUP;
        goto err;
    }

    sf_util_mutex_lock(&(node->lock));
    if (mode & NODE_LOCKMODE_R)
        node->reading--;
    else if (mode & NODE_LOCKMODE_W)
        node->writing = 0;
    sf_util_cond_signal(&(node->cond));
    sf_util_mutex_unlock(&(node->lock));

    return ret;

err:
    sf_log_error("sf_node_unlock(mode=%d, node=%p): %s\n", mode, node, strerror(ret));
    return -ret;
}

void sf_node_remove(struct sf_node *node)
{
    ino_t pos;
    struct sf_nodelist_item *item;

    sf_log_debug("sf_node_remove(node=%p)\n", node);

    pos = node->st->st_ino % INO_TBL_SIZE;

    item = sf_data->nodetbl[pos];

    if (item->node == node)
        sf_data->nodetbl[pos] = item->next;

    while (item->node != node)
        item = item->next;

    if (item->prev != NULL)
        item->prev->next = item->next;

    if (item->next != NULL)
        item->next->prev = item->prev;

    sf_node_destroy(node);
    free(item);
}

struct statvfs *sf_get_statfs()
{
    struct statvfs *st;

    sf_log_debug("sf_get_statfs()\n");

    st = malloc(sizeof(struct statvfs));

    if (st == NULL) {
        sf_log_fatal("Could not allocate file system stats: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    sf_util_mutex_lock(&lock_stat);
    memcpy(st, sf_data->st, sizeof(struct statvfs));
    sf_util_mutex_unlock(&lock_stat);

    return st;
}

int sf_has_availspace(size_t size)
{
    int ret;
    fsblkcnt_t blocks, blksize;

    ret = 0;

    sf_log_debug("sf_has_availspace(size=%lu)\n", size);

    blksize = sf_data->st->f_bsize;

    blocks = size / blksize;

    if (size % blksize)
        blocks++;

    sf_util_mutex_lock(&lock_stat);
    ret = sf_data->st->f_bfree >= blocks;
    sf_util_mutex_unlock(&lock_stat);

    return ret;
}

int sf_init(size_t numfiles, const char **filenames)
{
    int ret;
    size_t i;
    fsblkcnt_t size, totsize;
    const char *rootname;
    struct sf_file *rootfile;

    ret = 0;
    totsize = 0;
    rootname = "";

    curfile = 0;

    sf_log_debug("sf_init(numfiles=%ld, filenames=%p)\n", numfiles, filenames);

    if (sf_data != NULL)
        return ret;

    sf_data = malloc(sizeof(struct sf_state));

    if (sf_data == NULL) {
        sf_log_fatal("Could not allocate file system metadata: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    sf_data->numstorages = numfiles;

    sf_data->storage = malloc(sf_data->numstorages * sizeof(struct sf_storage *));

    if (sf_data->storage == NULL) {
        sf_log_fatal("Could not allocate storage array: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < numfiles; i++) {
        sf_data->storage[i] = malloc(sizeof(struct sf_storage));

        if (sf_data->storage[i] == NULL) {
            sf_log_fatal("Could not allocate storage for file \"%s\": %s\n", filenames[i], strerror(errno));
            exit(EXIT_FAILURE);
        }

        sf_data->storage[i]->fh = fopen(filenames[i], "rb+");

        if (sf_data->storage[i]->fh == NULL) {
            ret = -errno;
            goto err;
        }

        fseek(sf_data->storage[i]->fh, 0, SEEK_END);
        size = ftell(sf_data->storage[i]->fh);
        fseek(sf_data->storage[i]->fh, 0, SEEK_SET);

        totsize += size;

        sf_data->storage[i]->addrmap = calloc(size / ((fsblkcnt_t) BLOCK_SIZE / CHAR_BIT), sizeof(char));

        if (sf_data->storage[i]->addrmap == NULL) {
            sf_log_fatal("Could not allocate file system block addresses bitmap for file \"%s\": %s\n", filenames[i], strerror(errno));
            exit(EXIT_FAILURE);
        }

        ret = pthread_mutex_init(&(sf_data->storage[i]->lock), NULL);

        if (ret != 0)
            goto err;
    }

    sf_data->inomap = calloc(INO_MAX / ((size_t) CHAR_BIT) - 1, sizeof(char));

    if (sf_data->inomap == NULL) {
        sf_log_fatal("Could not allocate file system inode bitmap: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    sf_data->nodetbl = calloc(INO_TBL_SIZE, sizeof(struct sf_nodelist_item **));

    if (sf_data->nodetbl == NULL) {
        sf_log_fatal("Could not allocate file system nodes table: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    sf_data->st = malloc(sizeof(struct statvfs));

    if (sf_data->st == NULL) {
        sf_log_fatal("Could not allocate file system stats structure: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    sf_data->st->f_bsize = BLOCK_SIZE;
    sf_data->st->f_frsize = sf_data->st->f_bsize;
    sf_data->st->f_blocks = totsize / (fsblkcnt_t) BLOCK_SIZE;
    sf_data->st->f_bfree = sf_data->st->f_blocks;
    sf_data->st->f_bavail = sf_data->st->f_blocks;
    sf_data->st->f_files = INO_MAX;
    sf_data->st->f_ffree = sf_data->st->f_files;
    sf_data->st->f_favail = sf_data->st->f_files;
    sf_data->st->f_fsid = 1;
    sf_data->st->f_flag = 0;
    sf_data->st->f_namemax = NAME_MAX;

    rootfile = sf_file_create(rootname, NULL);

    if (rootfile == NULL) {
        ret = -errno;
        goto err;
    }

    sf_data->filelist = sf_filelist_item_create(rootfile);

    if (sf_data->filelist == NULL) {
        ret = -errno;
        goto err;
    }

    ret = sf_node_put(rootfile->ino, S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO);

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
    sf_destroy();
    return ret;
}

void sf_destroy()
{
    size_t i;
    struct sf_nodelist_item *curitem, *nextitem;

    sf_log_debug("sf_destroy()\n");

    for (i = 0; i < INO_TBL_SIZE; i++) {
        curitem = sf_data->nodetbl[i];

        while (curitem != NULL) {
            nextitem = curitem->next;
            sf_node_remove(curitem->node);
            curitem = nextitem;
        }
    }

    for (i = 0; i < sf_data->numstorages; i++) {
        if (sf_data->storage[i]->fh != NULL)
            fclose(sf_data->storage[i]->fh);

        free(sf_data->storage[i]->addrmap);

        pthread_mutex_destroy(&(sf_data->storage[i]->lock));

        free(sf_data->storage[i]);
    }

    free(sf_data->storage);

    if (sf_data->filelist != NULL)
        sf_file_remove(sf_data->filelist->file);

    free(sf_data->inomap);
    //free(sf_data->filelist);
    free(sf_data->nodetbl);
    free(sf_data->st);

    pthread_mutex_destroy(&lock_ino);
    pthread_mutex_destroy(&lock_addr);
    pthread_mutex_destroy(&lock_stat);

    free(sf_data);
}
