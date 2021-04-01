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

#include "sffs.h"
#include "log.h"

static const char *DIR_DELIMITER = "/";

static pthread_mutex_t lock_ino;
static pthread_mutex_t lock_addr;
static pthread_mutex_t lock_stat;

static struct sf_state *sf_data;

static size_t sf_util_min(size_t a, size_t b)
{
    return a < b ? a : b;
}

static ino_t sf_ino_get_free()
{
    int i, j;
    ino_t ino, len;
    unsigned char *map;

    sf_log_debug("sf_ino_get_free()\n");

    ino = -1;
    len = INO_MAX / CHAR_BIT;
    map = sf_data->inomap;

    pthread_mutex_lock(&lock_ino);
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
    pthread_mutex_unlock(&lock_ino);

    if (ino == -1)
        return -EDQUOT;

    pthread_mutex_lock(&lock_stat);
    sf_data->st->f_ffree--;
    sf_data->st->f_favail = sf_data->st->f_ffree;
    pthread_mutex_unlock(&lock_stat);

    return ino;
}

static void sf_ino_free(ino_t ino)
{
    ino_t i, j;

    sf_log_debug("sf_ino_free(ino=%lu)\n", ino);

    i = ino / CHAR_BIT;
    j = ino % CHAR_BIT;

    pthread_mutex_lock(&lock_ino);
    sf_data->inomap[i] = sf_data->inomap[i] & ~(0x1 << (CHAR_BIT - j - 1));
    pthread_mutex_unlock(&lock_ino);

    pthread_mutex_lock(&lock_stat);
    sf_data->st->f_ffree++;
    sf_data->st->f_favail = sf_data->st->f_ffree;
    pthread_mutex_unlock(&lock_stat);
}

static size_t sf_addr_get_free()
{
    int i, j;
    size_t addr, len;
    fsblkcnt_t blksize;
    unsigned char *map;

    sf_log_debug("sf_addr_get_free()\n");

    addr = -1;
    len = sf_data->st->f_blocks / CHAR_BIT;
    blksize = sf_data->st->f_bsize;
    map = sf_data->addrmap;

    pthread_mutex_lock(&lock_addr);
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
    pthread_mutex_unlock(&lock_addr);

    if (addr == -1)
        return -ENOSPC;

    pthread_mutex_lock(&lock_stat);
    sf_data->st->f_bfree--;
    sf_data->st->f_bavail = sf_data->st->f_bfree;
    pthread_mutex_unlock(&lock_stat);

    return addr;
}

static void sf_addr_free(size_t addr)
{
    size_t i, j;

    sf_log_debug("sf_addr_free(addr=%lu)\n", addr);

    i = addr / sf_data->st->f_bsize / CHAR_BIT;
    j = addr / sf_data->st->f_bsize % CHAR_BIT;

    pthread_mutex_lock(&lock_addr);
    sf_data->addrmap[i] = sf_data->addrmap[i] & ~(0x1 << (CHAR_BIT - j - 1));
    pthread_mutex_unlock(&lock_addr);

    pthread_mutex_lock(&lock_stat);
    sf_data->st->f_bfree++;
    sf_data->st->f_bavail = sf_data->st->f_bfree;
    pthread_mutex_unlock(&lock_stat);
}

static struct sf_blocklist_item *sf_blocklist_item_create(size_t addr)
{
    struct sf_blocklist_item *item;

    sf_log_debug("sf_blocklist_item_create(addr=%lu)\n", addr);

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

static int sf_blocklist_item_add(struct sf_node *node, struct sf_blocklist_item *item)
{
    struct sf_blocklist_item *tmp;

    sf_log_debug("sf_blocklist_item_add(node=%p, item=%p)\n", node, item);

    tmp = node->blocklist;

    while (tmp != NULL) {
        if (tmp->next == NULL) {
            item->prev = tmp;
            tmp->next = item;
            return 0;
        }

        tmp = tmp->next;
    }

    node->blocklist = item;

    return 0;
}

static struct sf_nodelist_item *sf_nodelist_item_find(struct sf_nodelist_item *item, const char *name)
{
    struct sf_nodelist_item *tmp;

    sf_log_debug("sf_nodelist_item_find(item=%p, name=%s)\n", item, name);

    for (tmp = item; tmp != NULL && strcmp(tmp->name, name) != 0; tmp = tmp->next)
        ;

    return tmp;
}

static struct sf_nodelist_item *sf_nodelist_item_create(const char *name, ino_t ino, struct sf_nodelist_item *parent)
{
    struct sf_nodelist_item *item;

    sf_log_debug("sf_nodelist_item_create(name=%s, ino=%lu, parent=%p)\n", name, ino, parent);

    item = malloc(sizeof(struct sf_nodelist_item));

    if (item == NULL) {
        sf_log_fatal("Could not allocate nodelist item with name \"%s\": %s\n", name, strerror(errno));
        exit(EXIT_FAILURE);
    }

    item->name = strdup(name);
    item->ino = ino;
    item->parent = parent;
    item->nodelist = NULL;
    item->prev = NULL;
    item->next = NULL;

    return item;
}

static struct sf_tablelist_item *sf_tablelist_item_create(struct sf_node *node)
{
    struct sf_tablelist_item *item;

    sf_log_debug("sf_tablelist_item_create(node=%p)\n", node);

    item = malloc(sizeof(struct sf_tablelist_item));

    if (item == NULL) {
        sf_log_fatal("Could not allocate tablelist item for node with name \"%s\": %s\n", node->name, strerror(errno));
        exit(EXIT_FAILURE);
    }

    item->node = node;
    item->prev = NULL;
    item->next = NULL;

    return item;
}

static struct stat *sf_stat_create(mode_t mode)
{
    ino_t ino;
    time_t t;
    struct stat *st;

    sf_log_debug("sf_stat_create(mode=%u)\n", mode);

    st = malloc(sizeof(struct stat));

    if (st == NULL) {
        sf_log_fatal("Could not allocate stat: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    t = time(NULL);

    ino = sf_ino_get_free();

    if (ino < 0) {
        errno = ino;
        return NULL;
    }

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

char *sf_get_filename(const char *path)
{
    char *dup, *saveptr, *name, *tmp;

    sf_log_debug("sf_get_filename(path=%s)\n", path);

    dup = strdup(path);
    tmp = strtok_r(dup, DIR_DELIMITER, &saveptr);

    do {
        name = tmp;
    } while ((tmp = strtok_r(NULL, DIR_DELIMITER, &saveptr)) != NULL);

    name = strdup(name);

    free(dup);

    return name;
}

struct sf_nodelist_item *sf_node_find(const char *path)
{
    char *dup, *saveptr, *name;
    struct sf_nodelist_item *item;

    sf_log_debug("sf_node_find(path=%s)\n", path);

    item = sf_data->nodelist;

    dup = strdup(path);
    name = strtok_r(dup, DIR_DELIMITER, &saveptr);

    while (name != NULL) {
        item = sf_nodelist_item_find(item->nodelist, name);

        if (item == NULL)
            break;

        name = strtok_r(NULL, DIR_DELIMITER, &saveptr);
    }

    free(dup);

    return item;
}

struct sf_nodelist_item *sf_node_find_parent(const char *path)
{
    char *dup, *saveptr, *name;
    struct sf_nodelist_item *item, *parent;

    sf_log_debug("sf_node_find_parent(path=%s)\n", path);

    parent = sf_data->nodelist;

    dup = strdup(path);
    name = strtok_r(dup, DIR_DELIMITER, &saveptr);

    if (name == NULL)
        return parent->parent;

    do {
        item = sf_nodelist_item_find(parent->nodelist, name);

        name = strtok_r(NULL, DIR_DELIMITER, &saveptr);

        if (name != NULL) {
            if (item == NULL) {
                parent = NULL;
                break;
            } else {
                parent = item;
            }
        }
    } while (name != NULL);

    free(dup);

    return parent;
}

struct sf_node *sf_node_create(const char *name, mode_t mode)
{
    struct stat *st;
    struct sf_node *node;

    sf_log_debug("sf_node_create(name=%s, mode=%u)\n", name, mode);

    node = malloc(sizeof(struct sf_node));

    if (node == NULL) {
        sf_log_fatal("Could not allocate node: %s\n", name, strerror(errno));
        exit(EXIT_FAILURE);
    }

    st = sf_stat_create(mode);

    if (st == NULL)
        return NULL;

    node->name = strdup(name);
    node->st = st;
    node->blocklist = NULL;

    return node;
}

int sf_node_add(struct sf_nodelist_item *parent, struct sf_node *node)
{
    int ret;
    struct sf_nodelist_item *item, *tmp;

    ret = 0;

    sf_log_debug("sf_node_add(parent=%p, node=%p)\n", parent, node);

    item = sf_nodelist_item_create(node->name, node->st->st_ino, parent);

    if (item == NULL)
        return -errno;

    tmp = parent->nodelist;
    parent->nodelist = item;
    item->next = tmp;

    if (tmp != NULL)
        tmp->prev = item;

    return ret;
}

ssize_t sf_node_read(char *buf, size_t size, off_t offset, struct sf_node *node)
{
    int i;
    size_t off;
    ssize_t b_read;
    fsblkcnt_t blksize;
    struct sf_blocklist_item *item;
    FILE* fh;

    sf_log_debug("sf_node_read(size=%lu, offset=%lu, node=%p)\n", size, offset, node);

    fh = sf_data->fh;
    blksize = sf_data->st->f_bsize;
    item = node->blocklist;

    for (i = 0; i < offset / (off_t) blksize; item = item->next, i++)
        ;

    off = offset % blksize;

    b_read = 0;

    while (item != NULL && b_read < size) {
        // TODO: improve seeking of file's starting writing position
        fseek(fh, item->addr + off, SEEK_SET);

        off = fread(buf, sizeof(char), sf_util_min(size - (size_t) b_read, blksize - off), fh);

        if (ferror(fh)) {
            b_read = -EIO;
            break;
        }

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
    size_t addr, off;
    ssize_t b_written;
    fsblkcnt_t blksize;
    struct sf_blocklist_item *item;
    FILE* fh;

    sf_log_debug("sf_node_write(size=%lu, offset=%lu, node=%p)\n", size, offset, node);

    fh = sf_data->fh;
    blksize = sf_data->st->f_bsize;
    item = node->blocklist;

    for (i = 0; i < offset / (off_t) blksize; item = item->next, i++)
        ;

    off = offset % blksize;

    b_written = 0;

    while (b_written < size) {
        if (item == NULL) {
            addr = sf_addr_get_free();

            if (addr < 0)
                return addr;

            item = sf_blocklist_item_create(addr);
            sf_blocklist_item_add(node, item);

            node->st->st_blocks += BLOCK_SIZE / 512;
        }

        // TODO: improve seeking of file's starting writing position
        fseek(fh, item->addr + off, SEEK_SET);

        off = fwrite(buf, sizeof(char), sf_util_min(size - (size_t) b_written, blksize - off), fh);

        node->st->st_size += off;

        if (ferror(fh)) {
            b_written = -EIO;
            break;
        }

        buf += off;
        b_written += off;

        off = 0;
        item = item->next;
    }

    fflush(fh);

    return b_written;
}

ssize_t sf_node_resize(struct sf_node *node, size_t size)
{
    int i;
    size_t diff;
    ssize_t ret;
    char *buf;
    struct sf_blocklist_item *curblock, *nextblock;

    sf_log_debug("sf_node_resize(node=%p, size=%lu)\n", node, size);

    ret = 0;

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

            ret = size / BLOCK_SIZE;

            if (size % BLOCK_SIZE) {
                ret++;

                diff = BLOCK_SIZE - (size % BLOCK_SIZE);

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
                ret = sf_node_write(buf, diff, ret * BLOCK_SIZE - diff, node);
        }

        if (ret < 0)
            return ret;

        node->st->st_size = size;
    }

    return ret;
}

void sf_node_remove(struct sf_node *node)
{
    struct sf_nodelist_item *tmp;

    sf_log_debug("sf_node_remove(item=%p)\n", item);

    tmp = item->parent->nodelist;

    if (tmp->ino == item->ino)
        item->parent->nodelist = item->next;

    while (tmp->ino != item->ino)
        tmp = tmp->next;

    if (tmp->prev != NULL)
        tmp->prev->next = tmp->next;

    if (tmp->next != NULL)
        tmp->next->prev = tmp->prev;

    free(item);
}

void sf_node_destroy(struct sf_node *node)
{
    struct sf_blocklist_item *curblock, *nextblock;

    sf_log_debug("sf_node_destroy(node=%p)\n", node);

    curblock = node->blocklist;

    while (curblock != NULL) {
        nextblock = curblock->next;
        sf_addr_free(curblock->addr);
        free(curblock);
        curblock = nextblock;
    }

    sf_ino_free(node->st->st_ino);

    free(node->name);
    free(node->st);
    free(node);
}

struct sf_tablelist_item *sf_table_get(ino_t ino)
{
    struct sf_tablelist_item *item;

    sf_log_debug("sf_table_get(ino=%lu)\n", ino);

    item = sf_data->nodetbl[ino % INO_TBL_SIZE];

    while (item != NULL && item->node->st->st_ino != ino)
        item = item->next;

    return item;
}

int sf_table_put(struct sf_node *node)
{
    ino_t pos;
    struct sf_tablelist_item *item, *tmp;

    sf_log_debug("sf_table_put(node=%p)\n", node);

    item = sf_tablelist_item_create(node);

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

int sf_table_remove(struct sf_node *node)
{
    ino_t pos;
    struct sf_tablelist_item *item;

    sf_log_debug("sf_table_remove(node=%p)\n", node);

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

    //free(item);

    return 0;
}

struct sf_state *sf_get_state()
{
    sf_log_debug("sf_get_state()\n");

    return sf_data;
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

    pthread_mutex_lock(&lock_stat);
    memcpy(st, sf_data->st, sizeof(struct statvfs));
    pthread_mutex_unlock(&lock_stat);

    return st;
}

int sf_has_availspace(size_t size)
{
    int ret;
    fsblkcnt_t blocks;

    ret = 0;

    sf_log_debug("sf_has_availspace(size=%lu)\n", size);

    blocks = size / BLOCK_SIZE;

    if (size % BLOCK_SIZE)
        blocks++;

    pthread_mutex_lock(&lock_stat);
    ret = sf_data->st->f_bfree >= blocks;
    pthread_mutex_unlock(&lock_stat);

    return ret;
}

int sf_init(const char *filename)
{
    int ret;
    fsblkcnt_t size;
    const char *rootname = "";
    struct sf_node *rootnode;

    ret = 0;

    sf_log_debug("sf_init(filename=%s)\n", filename);

    if (sf_get_state() != NULL)
        return ret;

    sf_data = malloc(sizeof(struct sf_state));

    if (sf_data == NULL) {
        sf_log_fatal("Could not allocate file system metadata: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    sf_data->fh = fopen(filename, "rb+");

    if (sf_data->fh == NULL) {
        ret = -errno;
        goto err;
    }

    fseek(sf_data->fh, 0, SEEK_END);
    size = ftell(sf_data->fh);
    fseek(sf_data->fh, 0, SEEK_SET);

    sf_data->inomap = calloc(INO_MAX / ((size_t) CHAR_BIT) - 1, sizeof(char));

    if (sf_data->inomap == NULL) {
        sf_log_fatal("Could not allocate file system inode bitmap: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    sf_data->addrmap = calloc(size / ((fsblkcnt_t) BLOCK_SIZE / CHAR_BIT), sizeof(char));

    if (sf_data->addrmap == NULL) {
        sf_log_fatal("Could not allocate file system block addresses bitmap: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    sf_data->nodetbl = malloc(INO_TBL_SIZE * sizeof(struct sf_nodelist_item **));

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
    sf_data->st->f_blocks = size / (fsblkcnt_t) BLOCK_SIZE;
    sf_data->st->f_bfree = sf_data->st->f_blocks;
    sf_data->st->f_bavail = sf_data->st->f_blocks;
    sf_data->st->f_files = INO_MAX;
    sf_data->st->f_ffree = sf_data->st->f_files;
    sf_data->st->f_favail = sf_data->st->f_files;
    sf_data->st->f_fsid = 1;
    sf_data->st->f_flag = 0;
    sf_data->st->f_namemax = NAME_MAX;

    rootnode = sf_node_create(rootname, S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO);

    if (rootnode == NULL) {
        sf_destroy();
        return -errno;
    }

    sf_data->nodelist = sf_nodelist_item_create(rootnode->name, rootnode->st->st_ino, NULL);

    if (sf_data->rootnode == NULL) {
        ret = -errno;
        goto err;
    }

    ret = pthread_mutex_init(&lock_ino, NULL);

    if (ret < 0)
        goto err;

    ret = pthread_mutex_init(&lock_addr, NULL);

    if (ret < 0)
        goto err;

    ret = pthread_mutex_init(&lock_stat, NULL);

    if (ret < 0)
        goto err;

    return ret;

err:
    sf_destroy();
    return ret;
}

void sf_destroy()
{
    int i;
    struct sf_tablelist_item *curitem, *nextitem;

    sf_log_debug("sf_destroy()\n");

    for (i = 0; i < INO_TBL_SIZE; i++) {
        curitem = sf_data->nodetbl[i];

        while (curitem != NULL) {
            nextitem = curitem->next;
            free(curitem);
            curitem = nextitem;
        }
    }

    // TODO: destroy remaining nodes

    if (sf_data->fh != NULL)
        fclose(sf_data->fh);

    free(sf_data->inomap);
    free(sf_data->addrmap);
    free(sf_data->nodetbl);
    free(sf_data->st);

    pthread_mutex_destroy(&lock_ino);
    pthread_mutex_destroy(&lock_addr);
    pthread_mutex_destroy(&lock_stat);

    free(sf_data);
}
