/*
 * Copyright 2024 Raffaele del Gaudio
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the “Software”), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
 * LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef IMFS_H
#define IMFS_H

#include <stdbool.h>
#include <stddef.h>

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
#define IMFS_MIN_DATA_BLOCK_SIZE_POW2 8

/*
 * The max length for a file or a directory name
 */
#define IMFS_MAX_NAME_LEN 32

struct imfs;

struct imfs_conf {
    size_t max_num_fnodes;
    unsigned int max_opened_files;
};

/*
 * File flags
 */

/* Open the file in read-only mode */
#define IMFS_RDONLY   0
/* Open the file in read-write mode */
#define IMFS_RDWR     1
/* Create the file if it does not exists */
#define IMFS_CREAT    2
/* Truncate the file */
#define IMFS_TRUNC    4

/*
 * Initialize a IMFS at [base] of size [size] with [conf] as configuration.
 * If [format] is false and a IMFS is already initialized at [base]
 * this function just returns the descriptor of the previous IMFS
 * (This acts as a "mount" operation).
 * If [format] is true then a new IMFS is created with no regards
 * of previous (if any) IMFS with [conf] as configuration.
 */
struct imfs *
imfs_init(char *base, size_t size, struct imfs_conf *conf, bool format);

int imfs_link(struct imfs *fs, const char *oldpath, const char *newpath);
int imfs_unlink(struct imfs *fs, const char *pathname);

int imfs_mkdir(struct imfs *fs, const char *pathname);
int imfs_rmdir(struct imfs *fs, const char *pathname);

int imfs_open(struct imfs *fs, const char *pathname, int flags);
int imfs_close(struct imfs *fs, int fd);
long imfs_read(struct imfs *fs, int fd, void *buf, size_t count);
long imfs_write(struct imfs *fs, int fd, const void *buf, size_t count);

#endif
