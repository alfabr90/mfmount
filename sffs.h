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
#define INO_TBL_SIZE 65599 // Prime number nearest 65536
#define PATH_MAX 4096

struct sf_blocklist_item {
    size_t addr;
    struct sf_blocklist_item *prev;
    struct sf_blocklist_item *next;
};

struct sf_node {
    struct stat *st;
    struct sf_blocklist_item *blocklist;
};

struct sf_nodelist_item {
    struct sf_node *node;
    struct sf_nodelist_item *prev;
    struct sf_nodelist_item *next;
};

struct sf_file {
    char *name;
    ino_t ino;
    struct sf_file *parent;
    struct sf_filelist_item *filelist;
};

struct sf_filelist_item {
    struct sf_file *file;
    struct sf_filelist_item *prev;
    struct sf_filelist_item *next;
};

struct sf_state {
    struct statvfs *st;
    unsigned char *inomap;
    unsigned char *addrmap;
    struct sf_filelist_item *filelist;
    struct sf_nodelist_item **nodetbl;
    FILE *fh;
};

// Helper functions

char *sf_get_filename(const char *path);

// File operations

struct sf_file *sf_file_find(const char *path);

struct sf_file *sf_file_find_parent(const char *path);

int sf_file_add(struct sf_file *parent, const char *name);

void sf_file_remove(struct sf_file *file);

// Node operations

struct sf_node *sf_node_get(ino_t ino);

int sf_node_put(ino_t ino, mode_t mode);

ssize_t sf_node_read(char *buf, size_t size, off_t offset, struct sf_node *node);

ssize_t sf_node_write(const char *buf, size_t size, off_t offset, struct sf_node *node);

ssize_t sf_node_resize(struct sf_node *node, size_t size);

void sf_node_remove(struct sf_node *node);

// File system operations

struct statvfs *sf_get_statfs();

int sf_has_availspace(size_t size);

int sf_init(const char *imgname);

void sf_destroy();

#endif // SFFS_H
