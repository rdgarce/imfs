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

    if (!fs)
    {
        fputs("Error in IMFS init!\n", stdout);
        return -1;
    }
    
    fputs("# IMFS: Filesystem started\n", stdout);

    if (imfs_mkdir(fs, "/folder1"))
    {
        fputs("Error in mkdir!\n", stdout);
        return -1;
    }

    int fd1 = imfs_open(fs, "/folder1/../folder1/./file1", IMFS_CREAT | IMFS_RDWR);

    fputs("# IMFS: File created\n", stdout);

    fputs("Write something in the file: ", stdout);

    if (!fgets(wbuf, BSIZE, stdin))
    {
        fputs("Error in fgets!\n", stdout);
        return -1;
    }

    size_t len = strlen(wbuf) + 1;
    if (imfs_write(fs, fd1, wbuf, len) != (ssize_t)len)
    {
        fputs("Error in write!\n", stdout);
        return -1;
    }
    
    ssize_t rlen = imfs_read(fs, fd1, rbuf, BSIZE);
    if (rlen < 0)
    {
        fputs("Error in read!\n", stdout);
        return -1;
    }

    printf("The content read from the file is: %s", rbuf);

    if (imfs_close(fs, fd1))
    {
        fputs("Error in close!\n", stdout);
        return -1;
    }

    fputs("# IMFS: File closed\n", stdout);

    return 0;
}