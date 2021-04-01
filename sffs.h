#ifndef SFFS_H
#define SFFS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

#define BLOCK_SIZE 4096
#define INO_MAX 4194304
#define INO_TBL_SIZE 65599 // Prime number near 65536
#define PATH_MAX 4096

struct sf_blocklist_item {
    size_t addr;
    struct sf_blocklist_item *prev;
    struct sf_blocklist_item *next;
};

struct sf_node {
    char *name;
    struct stat *st;
    struct sf_blocklist_item *blocklist;
};

struct sf_nodelist_item {
    char *name;
    ino_t ino;
    struct sf_nodelist_item *parent;
    struct sf_nodelist_item *nodelist;
    struct sf_nodelist_item *prev;
    struct sf_nodelist_item *next;
};

struct sf_tablelist_item {
    struct sf_node *node;
    struct sf_tablelist_item *prev;
    struct sf_tablelist_item *next;
};

struct sf_state {
    struct statvfs *st;
    unsigned char *inomap;
    unsigned char *addrmap;
    struct sf_nodelist_item *nodelist;
    struct sf_tablelist_item **nodetbl;
    FILE *fh;
};

char *sf_get_filename(const char *path);

struct sf_nodelist_item *sf_node_find(const char *path);

struct sf_nodelist_item *sf_node_find_parent(const char *path);

struct sf_node *sf_node_create(const char *name, mode_t mode);

int sf_node_add(struct sf_nodelist_item *parent, struct sf_node *node);

ssize_t sf_node_read(char *buf, size_t size, off_t offset, struct sf_node *node);

ssize_t sf_node_write(const char *buf, size_t size, off_t offset, struct sf_node *node);

ssize_t sf_node_resize(struct sf_node *node, size_t size);

void sf_node_remove(struct sf_node *node);

void sf_node_destroy(struct sf_node *node);

struct sf_tablelist_item *sf_table_get(ino_t ino);

int sf_table_put(struct sf_node *node);

int sf_table_remove(struct sf_node *node);

struct sf_state *sf_get_state();

struct statvfs *sf_get_statfs();

int sf_has_availspace(size_t size);

int sf_init(const char *imgname);

void sf_destroy();

#endif // SFFS_H
