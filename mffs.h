#ifndef MFFS_H
#define MFFS_H

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
#define DIR_DELIMITER "/"

#define NODE_LOCKMODE_R 1
#define NODE_LOCKMODE_W 2

struct mf_address {
    size_t fileno;
    size_t addrno;
};

struct mf_blocklist_item {
    struct mf_address *addr;
    struct mf_blocklist_item *prev;
    struct mf_blocklist_item *next;
};

struct mf_node {
    struct stat *st;
    int open;
    int reading;
    int writing;
    int remove;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    struct mf_blocklist_item *blocklist;
};

struct mf_nodelist_item {
    struct mf_node *node;
    struct mf_nodelist_item *prev;
    struct mf_nodelist_item *next;
};

struct mf_file {
    char *name;
    ino_t ino;
    struct mf_file *parent;
    struct mf_filelist_item *filelist;
};

struct mf_filelist_item {
    struct mf_file *file;
    struct mf_filelist_item *prev;
    struct mf_filelist_item *next;
};

struct mf_storage {
    unsigned char *addrmap;
    pthread_mutex_t lock;
    FILE *fh;
};

struct mf_state {
    uid_t uid;
    gid_t gid;
    size_t numstorages;
    struct statvfs *st;
    unsigned char *inomap;
    struct mf_filelist_item *filelist;
    struct mf_nodelist_item **nodetbl;
    struct mf_storage **storage;
};

// File operations

struct mf_file *mf_file_find(const char *path);

struct mf_file *mf_file_find_parent(const char *path);

int mf_file_add(struct mf_file *parent, const char *name);

void mf_file_remove(struct mf_file *file);

// Node operations

struct mf_node *mf_node_get(ino_t ino);

int mf_node_put(ino_t ino, mode_t mode);

ssize_t mf_node_read(char *buf, size_t size, off_t offset, struct mf_node *node);

ssize_t mf_node_write(const char *buf, size_t size, off_t offset, struct mf_node *node);

ssize_t mf_node_resize(struct mf_node *node, size_t size);

int mf_node_lock(int mode, struct mf_node *node);

int mf_node_unlock(int mode, struct mf_node *node);

void mf_node_remove(struct mf_node *node);

// File system operations

struct statvfs *mf_get_statfs();

int mf_has_availspace(size_t size);

int mf_init(size_t numfiles, const char **filenames);

void mf_destroy();

#endif // MFFS_H
