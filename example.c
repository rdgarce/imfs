#include <stdio.h>
#include <string.h>
#include "imfs.h"

#define MSIZE 128*1024
#define BSIZE 1024

char base_mem[MSIZE];
char wbuf[BSIZE];
char rbuf[BSIZE];

int main(void)
{
    struct imfs_conf c = {
        .mem_size = MSIZE,
        .max_num_fnodes = 5,
        .max_opened_files = 5
    };

    struct imfs *fs = imfs_init(base_mem, &c, true);

    if (imfs_mkdir(fs, "/folder1"))
    {
        perror("Error in mkdir!\n");
        return -1;
    }

    if (!fgets(wbuf, BSIZE, stdin))
    {
        perror("Error in fgets!\n");
        return -1;
    }

    int fd1 = imfs_open(fs, "/folder1/../folder1/./file1", IMFS_CREAT | IMFS_RDWR);

    size_t len = strlen(wbuf) + 1;
    if (imfs_write(fs, fd1, wbuf, len) != (ssize_t)len)
    {
        perror("Error in write!\n");
        return -1;
    }
    
    ssize_t rlen = imfs_read(fs, fd1, rbuf, BSIZE);
    if (rlen < 0)
    {
        perror("Error in read!\n");
        return -1;
    }

    puts(rbuf);

    return 0;
}