#ifndef IMFS_H
#define IMFS_H

#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>

/*
 * The fixed size of a data block allocated to a file.
 * By tweaking this parameter, you can adjust the tradeoff
 * between the ratio of useful bytes (payload) to total bytes
 * (payload + metadata) and the amount of wasted space.
 * Larger blocks increase the useful-to-total byte ratio but 
 * may lead to more wasted space for small files, while smaller 
 * blocks reduce waste but decrease the efficiency in terms of
 * useful-to-total byte ratio. 256 Bytes per block seems a
 * good value because it leads to a minimum of 97% efficiency
 * considering that any datablock has one pointer of overhead.
 * NOTE: This is a minimum value that is rounded to a multiple
 * of the direlem struct size
 */
#define SS_MIN_DATA_BLOCK_SIZE_POW2 8

/*
 * The max length for a file or a directory name
 */
#define SS_MAX_NAME_LEN 32

struct ss_desc;

struct ss_conf {
    size_t mem_size;
    size_t max_num_fnodes;
    unsigned int max_opened_files;
};

/*
 * File flags
 */

/* Open the file in read-only mode */
#define SS_RDONLY   0
/* Open the file in read-write mode */
#define SS_RDWR     1
/* Create the file if it does not exists */
#define SS_CREAT    2
/* Start writing at the end of the file */
#define SS_APPEND   4

/*
 * Initialize a SS at [base] with [conf] as configuration.
 * If [format] is false and a SS is already initialized at [base]
 * this function just returns the descriptor of the previous SS
 * (This acts as a "mount" operation).
 * If [format] is true then a new SS is created with no regards
 * of previous (if any) SS with [conf] as configuration.
 */
struct ss_desc *imfs_init(char *base, struct ss_conf *conf, bool format);

int imfs_mkdir(struct ss_desc *ssd, const char *pathname);
int imfs_open(struct ss_desc *ssd, const char *pathname, int flags);
int imfs_close(struct ss_desc *ssd, int fd);
ssize_t imfs_read(struct ss_desc *ssd, int fd, void *buf, size_t count);
ssize_t imfs_write(struct ss_desc *ssd, int fd, const void *buf, size_t count);

#endif
