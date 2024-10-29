#include "imfs.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

typedef struct {
    char *buffer;
    size_t capacity;
    size_t size;
    size_t read_pos;
    size_t write_pos;
} ByteQueue;

void queue_init(ByteQueue *queue, char *buffer, size_t capacity) {
    queue->buffer = buffer;
    queue->capacity = capacity;
    queue->size = 0;
    queue->read_pos = 0;
    queue->write_pos = 0;
}

long queue_write(ByteQueue *queue, const char *data, size_t len) {
    if (len > queue->capacity - queue->size) {
        return -1;
    }
    
    size_t write_end = queue->capacity - queue->write_pos;
    if (len > write_end) {
        memcpy(queue->buffer + queue->write_pos, data, write_end);
        memcpy(queue->buffer, data + write_end, len - write_end);
    } else {
        memcpy(queue->buffer + queue->write_pos, data, len);
    }
    queue->write_pos = (queue->write_pos + len) % queue->capacity;
    queue->size += len;
    return len;
}

long queue_read(ByteQueue *queue, char *buffer, size_t len) {
    if (queue->size == 0) {
        return 0;
    }

    if (len > queue->size) {
        len = queue->size;
    }

    size_t read_end = queue->capacity - queue->read_pos;
    if (len > read_end) {
        memcpy(buffer, queue->buffer + queue->read_pos, read_end);
        memcpy(buffer + read_end, queue->buffer, len - read_end);
    } else {
        memcpy(buffer, queue->buffer + queue->read_pos, len);
    }
    queue->read_pos = (queue->read_pos + len) % queue->capacity;
    queue->size -= len;
    return len;
}

#define MAX_DIR_NAME_LENGTH IMFS_MAX_NAME_LEN
#define MAX_DEPTH 50
#define MAX_PATH_LENGTH \
        ((MAX_DIR_NAME_LENGTH + 1) * MAX_DEPTH + 1)

static char *random_name(char *buffer, size_t min_len, size_t max_len) {
    static const char charset[] =
        ".abcdefghijklmnopqrstu"
        "vwxyzABCDEFGHIJKLMNOPQ"
        "RSTUVWXYZ0123456789";
    
    if (min_len > max_len)
        min_len = max_len;
    if (max_len > MAX_DIR_NAME_LENGTH)
        max_len = MAX_DIR_NAME_LENGTH;

    size_t len = min_len + rand() % (max_len - min_len + 1);
    
    for (size_t i = 0; i < len; i++)
        *buffer++ = charset[rand() % (sizeof(charset) - 1)];
    
    *buffer = '\0';

    return buffer;
}

static char *random_path(size_t max_depth) {
    static char buf[MAX_PATH_LENGTH];
    *buf = '/';
    size_t depth = rand() % max_depth % MAX_DEPTH + 1;
    char *p = buf + 1;
    for (size_t i = 0; i < depth-1; i++) {
        p = random_name(p, MAX_DIR_NAME_LENGTH/4, MAX_DIR_NAME_LENGTH);
        *p++ = '/';
    }
    p = random_name(p, MAX_DIR_NAME_LENGTH/4, MAX_DIR_NAME_LENGTH);
    *p = '\0';

    return buf;
}

#define MSIZE 256*1024*1024
char base_mem[MSIZE];
char queue_mem[MSIZE];
char read_bufs[2][MSIZE];

static bool test_init(void)
{
    memset(base_mem, 0, MSIZE);
    struct imfs_conf c = {
        .max_num_fnodes = rand() % 100,
        .max_opened_files = rand() % 100
    };

    struct imfs *ssd = imfs_init(base_mem, MSIZE, &c, true);
    if (!ssd) return false;

    struct imfs *ssd1 = imfs_init(base_mem, MSIZE, &c, false);
    if (ssd != ssd1) return false;

    if(imfs_init(base_mem, MSIZE, NULL, false) != ssd) return false;
    if(imfs_init(base_mem, MSIZE, NULL, true)) return false;
    
    return true;
}

static bool test_big_read_write(void)
{
    memset(base_mem, 0, MSIZE);
    struct imfs_conf c = {
        .max_num_fnodes = 1,
        .max_opened_files = 1
    };

    struct imfs *ssd = imfs_init(base_mem, MSIZE, &c, true);
    if (!ssd) return false;

    int fd = imfs_open(ssd, "/file", IMFS_CREAT | IMFS_RDWR);
    if (fd < 0) return false;

    ByteQueue bq;
    queue_init(&bq, queue_mem, MSIZE);

    char *random_str = random_path(MAX_DEPTH);
    size_t len = strlen(random_str);

    long ss_res = imfs_read(ssd, fd, read_bufs[0], MSIZE);
    long bq_res = queue_read(&bq, read_bufs[1], MSIZE);
    if (ss_res != bq_res) return false;

    ss_res = imfs_write(ssd, fd, random_str, len);
    bq_res = queue_write(&bq, random_str, len);
    if (ss_res != bq_res) return false;

    ss_res = imfs_read(ssd, fd, read_bufs[0], MSIZE);
    bq_res = queue_read(&bq, read_bufs[1], MSIZE);
    if ((ss_res != bq_res) ||
        (ss_res >= 0 &&
        memcmp(read_bufs[0], read_bufs[1], ss_res)))
        return false;
    
    return true;
}

static bool test_one_M_random_read_write(void)
{
    memset(base_mem, 0, MSIZE);
    struct imfs_conf c = {
        .max_num_fnodes = 1,
        .max_opened_files = 1
    };

    struct imfs *ssd = imfs_init(base_mem, MSIZE, &c, true);
    if (!ssd) return false;

    int fd = imfs_open(ssd, "/file", IMFS_CREAT | IMFS_RDWR);
    if (fd < 0) return false;

    ByteQueue bq;
    queue_init(&bq, queue_mem, MSIZE);

    for (size_t i = 0; i < 1000000; i++)
    {
        if (rand() % 2)
        {
            // Read
            size_t r_size = rand() % MSIZE;
            long ss_res = imfs_read(ssd, fd, read_bufs[0], r_size);
            long bq_res = queue_read(&bq, read_bufs[1], r_size);
            if ((ss_res != bq_res) ||
                (ss_res >= 0 &&
                memcmp(read_bufs[0], read_bufs[1], ss_res)))
                {
                    printf("++ Read failed with ret val %ld instead of %ld\n", ss_res, bq_res);
                    return false;
                }
        }
        else
        {
            // Write
            char *random = random_path(MAX_DEPTH);
            size_t len = strlen(random) % 1024;
            long ss_res = imfs_write(ssd, fd, random, len);
            long bq_res = queue_write(&bq, random, len);
            if (ss_res != bq_res)
            {
                printf("++ Write failed with ret val %ld instead of %ld. Write len was %ld\n", ss_res, bq_res, len);
                return false;
            }
        }
    }
    
    return true;
}

static bool test_file_openings(void)
{
    #define NUMOPFLS 100
    memset(base_mem, 0, MSIZE);
    struct imfs_conf c = {
        .max_num_fnodes = 1,
        .max_opened_files = NUMOPFLS
    };

    struct imfs *ssd = imfs_init(base_mem, MSIZE, &c, true);
    if (!ssd) return false;

    int fds[NUMOPFLS];

    for (size_t i = 0; i < NUMOPFLS; i++)
        fds[i] = imfs_open(ssd, "/file", IMFS_CREAT);
    
    if (fds[NUMOPFLS-1] != NUMOPFLS)
    {
        printf("++ last expected is %u but is %u\n", fds[NUMOPFLS-1], fds[NUMOPFLS-1]);
        return false;
    }
    
    if (imfs_open(ssd, "/file", IMFS_CREAT) != -1)
    {
        printf("++ Expected no memory for file opening but file was opened\n");
        return false;
    }
    
    for (long i = NUMOPFLS-1; i >= 0; i--)
        if (imfs_close(ssd, fds[i]) != 0)
        {
            printf("++ Unexpected error while closing file descriptors\n");
            return false;
        }
    
    int last;
    if ((last = imfs_open(ssd, "/file", IMFS_CREAT)) != fds[0])
    {
        printf("++ Unexpected file descriptor. Expected was %d but was %d\n", fds[0], last);
        return false;
    }

    return true;
}

static bool test_random_good_paths(void)
{
    #define NUMDIR 1000
    memset(base_mem, 0, MSIZE);
    struct imfs_conf c = {
        .max_num_fnodes = NUMDIR,
        .max_opened_files = NUMDIR
    };

    struct imfs *ssd = imfs_init(base_mem, MSIZE, &c, true);
    if (!ssd)
    {
        printf("++ Failed in first init\n");
        return false;
    }

    for (size_t i = 0; i < NUMDIR; i++)
        if (imfs_mkdir(ssd, random_path(1)) != 0)
        {
            printf("++ Error in mkdir\n");
            return false;
        }
    
    ssd = imfs_init(base_mem, MSIZE, &c, true);
    if (!ssd)
    {
        printf("++ Failed in second init\n");
        return false;
    }

    for (size_t i = 0; i < NUMDIR; i++)
        if (imfs_open(ssd, random_path(1), IMFS_CREAT) <= 0)
        {
            printf("++ Error in file creation\n");
            return false;
        }

    return true;
}

static bool test_common_usage(void)
{
    #define NUMDIR 1000
    
    #define RBLEN 1000
    #define FNAME_MAX_LEN 5
    memset(base_mem, 0, MSIZE);
    struct imfs_conf c = {
        .max_num_fnodes = 2*NUMDIR,
        .max_opened_files = NUMDIR
    };

    // Generate NUMDIR random file names, paths
    // and sizes of writes/reads
    static char comp_path[MAX_PATH_LENGTH+1+FNAME_MAX_LEN+1];
    static char paths[NUMDIR][MAX_PATH_LENGTH];
    static char fnames[NUMDIR][FNAME_MAX_LEN+1];
    static long w_r_sizes[NUMDIR];
    static char random_bytes[RBLEN];
    static char read_buffer[RBLEN];
    strncpy(random_bytes, random_path(MAX_DEPTH), RBLEN);
    for (size_t i = 0; i < NUMDIR; i++)
    {
        random_name(fnames[i], FNAME_MAX_LEN, FNAME_MAX_LEN);
        strcpy(paths[i], random_path(1));
        w_r_sizes[i] = rand() % RBLEN;
    }


    struct imfs *ssd = imfs_init(base_mem, MSIZE, &c, true);
    if (!ssd)
    {
        printf("++ Failed in first init\n");
        return false;
    }
    
    for (size_t i = 0; i < NUMDIR; i++)
        if (imfs_mkdir(ssd, paths[i]) != 0)
        {
            printf("++ Failed in first mkdir\n");
            return false;
        }
    
    for (size_t i = 0; i < NUMDIR; i++)
    {
        char *p = strcpy(comp_path, paths[i]);
        p += strlen(paths[i]);
        *p++ = '/';        
        strcpy(p, fnames[i]);
        p += strlen(fnames[i]);
        *p = '\0';
        
        int fd = imfs_open(ssd, comp_path, IMFS_CREAT | IMFS_RDWR);
        if (fd <= 0)
        {
            printf("++ Failed in first file opening. fd = %d\n", fd);
            return false;
        }
        
        long res;
        if ((res = imfs_write(ssd, fd, random_bytes, w_r_sizes[i])) != 
            w_r_sizes[i])
        {
            printf("++ First Write failed with ret val %ld instead of %ld.\n", res, w_r_sizes[i]);
            return false;
        }
        if ((res = imfs_read(ssd, fd, read_buffer, RBLEN)) != w_r_sizes[i])
        {
            printf("++ First Read failed with ret val %ld instead of %ld.\n", res, w_r_sizes[i]);
            return false;
        }

        if (imfs_close(ssd, fd) != 0)
        {
            printf("++ Failed in first file closing. fd = %d\n", fd);
            return false;
        }
    }

    // Second round
    struct imfs *ssd2 = imfs_init(base_mem, MSIZE, &c, false);
    if (!ssd2)
    {
        printf("++ Failed in second init\n");
        return false;
    }

    for (size_t i = 0; i < NUMDIR; i++)
    {
        char *p = strcpy(comp_path, paths[i]);
        p += strlen(paths[i]);
        *p++ = '/';
        strcpy(p, fnames[i]);
        p += strlen(fnames[i]);
        *p = '\0';

        int fd = imfs_open(ssd2, comp_path, IMFS_CREAT | IMFS_RDWR);
        if (fd <= 0)
        {
            printf("++ Failed in second file opening. fd = %d\n", fd);
            return false;
        }
        
        long res;
        if ((res = imfs_read(ssd2, fd, read_buffer, RBLEN)) != w_r_sizes[i] ||
            memcmp(read_buffer, random_bytes, res))
        {
            printf("++ Second Read failed with ret val %ld instead of %ld.\n", res, w_r_sizes[i]);
            return false;
        }

        if (imfs_close(ssd2, fd) != 0)
        {
            printf("++ Failed in second file closing. fd = %d\n", fd);
            return false;
        }

        // Reopen with IMFS_TRUNC, so read should return no bytes
        fd = imfs_open(ssd2, comp_path, IMFS_CREAT | IMFS_RDWR | IMFS_TRUNC);
        if (fd <= 0)
        {
            printf("++ Failed in third file opening. fd = %d\n", fd);
            return false;
        }

        if (imfs_read(ssd2, fd, read_buffer, RBLEN) != 0)
        {
            printf("++ Third Read failed with ret val %ld instead of 0.\n", res);
            return false;
        }

        if (imfs_close(ssd2, fd) != 0)
        {
            printf("++ Failed in third file closing. fd = %d\n", fd);
            return false;
        }
    }
    
    return true;
}

int main(void)
{
    printf("==== IMFS Tests start ====\n");
    
    printf("test_init: %s\n",
        test_init() ? "Success" : "Failed");
    
    printf("test_file_openings: %s\n",
        test_file_openings() ? "Success" : "Failed");
    
    printf("test_common_usage: %s\n",
        test_common_usage() ? "Success" : "Failed");

    printf("test_random_good_paths: %s\n",
        test_random_good_paths() ? "Success" : "Failed");
    
    printf("test_big_read_write: %s\n",
        test_big_read_write() ? "Success" : "Failed");
    
    printf("test_one_M_random_read_write: %s\n",
        test_one_M_random_read_write() ? "Success" : "Failed");
    
    printf("==== IMFS Tests end ====\n");

    return 0;
}