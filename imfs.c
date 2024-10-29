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

#include "imfs.h"
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <limits.h>

_Static_assert(IMFS_MIN_DATA_BLOCK_SIZE_POW2 > 5,
    "Minimum file data block size is 64 bytes.");

#define ALIGN_ADDR_POW2(addr, pow2)                     \
    ({                                                  \
        uintptr_t addr_ = (uintptr_t)(addr);            \
        uintptr_t pow2_ = (uintptr_t)(pow2);            \
        addr_ += - addr_ & (pow2_ - 1UL);               \
    })

#define IMFS_PRE_ADJ_DATA_BLOCK_SIZE                    \
    (1UL << IMFS_MIN_DATA_BLOCK_SIZE_POW2)

struct direlem {
    size_t fnodeID;
    unsigned char name_len;
    char name[IMFS_MAX_NAME_LEN];
};
/* Statically defined fnodeid for the '/' directory */
#define ROOT_DIR_FNODEID 0

/* 
 * Number of struct direlem elements per file data
 * block approximated by the excess
 */
#define DIRELEM_PER_FDB                                 \
    ((IMFS_PRE_ADJ_DATA_BLOCK_SIZE +                    \
    sizeof(struct direlem) - 1)/                        \
    sizeof(struct direlem))

/* 
 * The file data block size is calculated as the smallest
 * integer bigger that IMFS_PRE_ADJ_DATA_BLOCK_SIZE such that
 * it's a multiple of the size of struct direlem.
 */
#define IMFS_DATA_BLOCK_SIZE                            \
    (sizeof(struct direlem) *                           \
    DIRELEM_PER_FDB)


struct fdatablock {
    union fdbhead{
        /* next is used while in freelist for easy management */
        struct fdatablock *next;
        /* xor is used while allocated to a fnode as next ^ prev */
        uintptr_t xor;
    } h;
    /*
     * data is aligned as struct direlem so that it can be casted to
     * an array of such structs
     */
    char _Alignas(struct direlem) data[IMFS_DATA_BLOCK_SIZE];
};
// We want to use the LSB of [h.next] to store allocation
// status so we need to impose a minimum alignment of 2
_Static_assert(_Alignof(struct fdatablock) > 1);

struct fnode {
    union {
        /*
         * Points to the head of the circular xor list
         * of filedatablock allocated to this fnode
         */
        struct fdatablock *data_blocks_head;
        /* next ptr is used while fnode is in the circular freelist */
        struct fnode *next;
    };
    /* 
     * Points to the tail of the circular xor list
     * of filedatablock allocated to this fnode.
     * Needed to start the traversal of the list
     */
    struct fdatablock *data_blocks_tail;
    /* The number of used bytes of the last fdatablock */
    size_t last_block_used;
    /* the number of direlem referencing this fnode */
    unsigned short link_count;
    /* the number of opened files referencing this fnode */
    unsigned short open_count;
    enum {
        IMFS_FILE,
        IMFS_DIR
    } type;
};

struct file {
    size_t fnodeID;
    union {
        struct fileptr {
            struct fdatablock *curr;
            struct fdatablock *prev;
            size_t b_index;
        } read_ptr;
        /* Used while in the freelist */
        struct file *next;
    };
    bool readonly;
};

/* IMFS */
#define IMFS_MAGIC 0x494D4653

struct imfs {
    uint32_t magic;
    /* size of the whole available memory */
    size_t mem_size;
    
    /* file memory area */
    struct file *files;
    /* Number of files in the table */
    size_t files_len;
    /* file circular freelist tail */
    struct file *files_cfl_tail;

    /* fnode memory area */
    struct fnode *fn;
    /* Number of fnodes in the table */
    size_t fn_len;
    /* fnode circular freelist tail */
    struct fnode *fn_cfl_tail;
    
    /* fdatablock memory area */
    struct fdatablock *fb;
    /* Number of fdatablocks in the table */
    size_t fb_len;
    /* fdatablock freelist head */
    struct fdatablock *fb_fl_head;
};

/* ------------------------------------------------------------------------- */

#define FDATABLOCK_IS_VALID(fs, fdb)                    \
    ({                                                  \
        struct imfs *fs_ = fs;                          \
        uintptr_t fdb_ = (uintptr_t)fdb;                \
        uintptr_t start_ =                              \
            (uintptr_t)&fs_->fb[0];                     \
        uintptr_t end_ =                                \
            (uintptr_t)&fs_->fb[fs_->fb_len-1];         \
        fdb_ >= start_ && fdb_ <= end_ &&               \
        (fdb_ - start_) %                               \
        sizeof(struct fdatablock) == 0;                 \
    })
#define FDATABLOCK_IS_FREE(fdb)                         \
    ({                                                  \
        struct fdatablock *fdb_ = fdb;                  \
        (uintptr_t)fdb_->h.next & 1;                    \
    })

static struct fdatablock *alloc_fdatablock(struct imfs *fs)
{
    // At this level we ASSUME a valid imfs
    assert(fs);
    
    struct fdatablock *new = fs->fb_fl_head;
    
    if (fs->fb_fl_head)
    {
        fs->fb_fl_head = (struct fdatablock *)
            ((uintptr_t)(fs->fb_fl_head->h.next)
            & ~(uintptr_t)1);
        new->h.next = NULL;
    }
    
    return new;
}

static void free_fdatablock(struct imfs *fs, struct fdatablock *fdb)
{
    assert(fs && FDATABLOCK_IS_VALID(fs, fdb));
    // Catch double frees
    if (FDATABLOCK_IS_FREE(fdb)) return;
    
    fdb->h.next = (struct fdatablock *)
        ((uintptr_t)fs->fb_fl_head | (uintptr_t)1);
    fs->fb_fl_head = fdb;
}

/* ------------------------------------------------------------------------- */

#define FNODE_IS_VALID(fs, f)                           \
    ({                                                  \
        struct imfs *fs_ = fs;                          \
        uintptr_t f_ = (uintptr_t)f;                    \
        uintptr_t start_ =                              \
            (uintptr_t)&fs_->fn[0];                     \
        uintptr_t end_ =                                \
            (uintptr_t)&fs_->fn[fs_->fn_len-1];         \
        f_ >= start_ && f_ <= end_ &&                   \
        (f_ - start_) % sizeof(struct fnode) == 0;      \
    })
#define FNODE_IS_FREE(fs, f)                            \
    FNODE_IS_VALID(fs, ((struct fnode *)f)->next)

static struct fnode *alloc_fnode(struct imfs *fs)
{
    // At this level we ASSUME a valid imfs
    assert(fs);
    struct fnode *new = fs->fn_cfl_tail;
    
    if (fs->fn_cfl_tail)
    {
        if(fs->fn_cfl_tail == 
            fs->fn_cfl_tail->next)
            // We're removing the last element of the list
            fs->fn_cfl_tail = NULL;
        else
        {
            // List has more than one element so we have to
            // remove the one following the tail
            new = fs->fn_cfl_tail->next;
            fs->fn_cfl_tail->next = new->next;
        }
        // We init next to NULL because this is the 
        // way we can tell apart allocated nodes from free ones
        new->next = NULL;

        // We also init the fnode to be sure it respects the right
        // semantic.
        new->data_blocks_head = new->data_blocks_tail = NULL;
        new->last_block_used = 0;
        new->link_count = 0;
        new->open_count = 0;
    }
    
    return new;
}

static void free_fnode(struct imfs *fs, struct fnode *f)
{
    // Valid [fs] and [f] is assumed here
    assert(fs && FNODE_IS_VALID(fs, f));
    // Double freeing the node? I don't think so!
    // Considering we have an array of fnode - [fnodes] -
    // and a circular linked list of free fnode starting
    // from [cfl_tail], we can check that [f] is in the
    // freelist without searching the whole list.
    // If [f] is in the freelist than [f]->next MUST
    // point to a fnode. Since any fnode resides in the
    // [fnodes] array we can just check that [f]->next
    // points to an fnode contained in the [fnodes] array.
    if (FNODE_IS_FREE(fs, f)) return;
    
    // Ok, so we need to actually free the node [f]
    if(fs->fn_cfl_tail)
    {
        // Inserting in the circular queue after the tail
        f->next = fs->fn_cfl_tail->next;
        fs->fn_cfl_tail->next = f;
    }
    else
    {
        // Freelist was empty and this is the only element
        fs->fn_cfl_tail = f;
        f->next = f;
    }
}

/* ------------------------------------------------------------------------- */

static void append_fdatablock_to_fnode(struct imfs *fs, struct fnode *dst,
                struct fdatablock *src)
{
    assert(fs && FNODE_IS_VALID(fs, dst) && !FNODE_IS_FREE(fs, dst) &&
        FDATABLOCK_IS_VALID(fs, src) && !FDATABLOCK_IS_FREE(src));
    
    assert((dst->data_blocks_head && dst->data_blocks_tail) ||
        (!dst->data_blocks_head && !dst->data_blocks_tail));

    uintptr_t head_next, tail_prev;

    src->h.xor =
        (uintptr_t)dst->data_blocks_tail ^
        (uintptr_t)dst->data_blocks_head;
    dst->last_block_used = 0;

    if(dst->data_blocks_tail)
    {
        if (dst->data_blocks_head != dst->data_blocks_tail)
        {
            // At least two blocks are present before appending
            head_next = dst->data_blocks_head->h.xor ^
                (uintptr_t)dst->data_blocks_tail;
            tail_prev = dst->data_blocks_tail->h.xor ^
                (uintptr_t)dst->data_blocks_head;
            
            dst->data_blocks_tail->h.xor = tail_prev ^ (uintptr_t)src;
            
            dst->data_blocks_head->h.xor = (uintptr_t)src ^ head_next;
        }
        dst->data_blocks_tail = src;
    }
    else
    {
        dst->data_blocks_head = src;
        dst->data_blocks_tail = src;
    }
}

static struct fdatablock *pop_fdatablock_from_fnode(struct imfs *fs,
                            struct fnode *src)
{
    assert(fs &&
        FNODE_IS_VALID(fs, src) && !FNODE_IS_FREE(fs, src));

    struct fdatablock *block = src->data_blocks_tail;

    assert((src->data_blocks_head && src->data_blocks_tail) ||
        (!src->data_blocks_head && !src->data_blocks_tail));

    struct fdatablock *tail_prev;
    uintptr_t tail_prev_prev;

    if (src->data_blocks_tail)
    {
        uintptr_t head_next = src->data_blocks_head->h.xor ^
            (uintptr_t)src->data_blocks_tail;
        
        if (src->data_blocks_tail == src->data_blocks_head)
            src->data_blocks_tail = src->data_blocks_head = NULL;
        else if (head_next == (uintptr_t)src->data_blocks_tail)
            src->data_blocks_tail = src->data_blocks_head;
        else
        {
            tail_prev = (struct fdatablock *)
                (src->data_blocks_tail->h.xor ^
                (uintptr_t)src->data_blocks_head);
        
            tail_prev_prev = tail_prev->h.xor ^
                (uintptr_t)src->data_blocks_tail;

            tail_prev->h.xor = tail_prev_prev ^
                (uintptr_t)src->data_blocks_head;
            
            src->data_blocks_head->h.xor = 
                (uintptr_t)tail_prev ^ head_next;

            src->data_blocks_tail = tail_prev;
        }
        src->last_block_used = IMFS_DATA_BLOCK_SIZE;
    }
    
    return block;
}

static long append_bytes_to_fnode(struct imfs *fs, struct fnode *f,
                const void *buf, size_t len, size_t alignment)
{
    assert(fs && buf && len <= LONG_MAX &&
            alignment < IMFS_DATA_BLOCK_SIZE &&
            (alignment & (alignment - 1UL)) == 0 &&
            FNODE_IS_VALID(fs, f) && !FNODE_IS_FREE(fs, f));
    
    if (0 == len) return 0;
    if (!f->data_blocks_tail)
    {
        struct fdatablock *first = alloc_fdatablock(fs);
        if (!first) return -1;
        append_fdatablock_to_fnode(fs, f, first);
    }
    assert(f->data_blocks_tail && f->data_blocks_head);
    
    // The first write is preceded by the alignment
    size_t pad = -(uintptr_t)
        (&f->data_blocks_tail->data[f->last_block_used]) &
        (alignment - 1UL);
    if (f->last_block_used + pad < IMFS_DATA_BLOCK_SIZE)
        f->last_block_used += pad;
    else
    {
        struct fdatablock *new = alloc_fdatablock(fs);
        if (!new) return -1;
        append_fdatablock_to_fnode(fs, f, new);
        pad = -(uintptr_t)
            (&f->data_blocks_tail->data[f->last_block_used]) &
            (alignment - 1UL);
        assert(pad < IMFS_DATA_BLOCK_SIZE);
        f->last_block_used += pad;
    }
    
    char *cbuf = (char *)buf;
    size_t tot_written = 0;
    
    size_t avlbl = IMFS_DATA_BLOCK_SIZE - f->last_block_used;
    size_t to_write = len - tot_written;
    size_t w_len = avlbl < to_write ? avlbl : to_write;
    memcpy(&f->data_blocks_tail->data[f->last_block_used],
            &cbuf[tot_written], w_len);
    tot_written += w_len;
    f->last_block_used += w_len;

    while (tot_written < len)
    {
        struct fdatablock *new = alloc_fdatablock(fs);
        if (!new) return -1;
        append_fdatablock_to_fnode(fs, f, new);
        avlbl = IMFS_DATA_BLOCK_SIZE - f->last_block_used;
        to_write = len - tot_written;
        w_len = avlbl < to_write ? avlbl : to_write;
        memcpy(&f->data_blocks_tail->data[f->last_block_used],
                &cbuf[tot_written], w_len);
        tot_written += w_len;
        f->last_block_used += w_len;
    }

    return (long)tot_written;
}

/* ------------------------------------------------------------------------- */

#define FILE_IS_VALID(fs, s)                            \
    ({                                                  \
        struct imfs *fs_ = fs;                          \
        uintptr_t s_ = (uintptr_t)s;                    \
        uintptr_t start_ =                              \
            (uintptr_t)&fs_->files[0];                  \
        uintptr_t end_ =                                \
            (uintptr_t)&fs_->files[fs_->files_len-1];   \
        s_ >= start_ && s_ <= end_ &&                   \
        (s_ - start_) % sizeof(struct file) == 0;       \
    })
#define FILE_IS_FREE(fs, s)                             \
        FILE_IS_VALID(fs,                               \
            ((struct file *)s)->next)

static struct file *alloc_file(struct imfs *fs)
{
    assert(fs);

    struct file *new = fs->files_cfl_tail;
    
    if (fs->files_cfl_tail)
    {
        if (fs->files_cfl_tail == 
            fs->files_cfl_tail->next)
        {
            fs->files_cfl_tail = NULL;
        }
        else
        {
            new = fs->files_cfl_tail->next;
            fs->files_cfl_tail->next = new->next;
        }
        new->next = NULL;
    }
    
    return new;
}

static void free_file(struct imfs *fs, struct file *files)
{
    assert(fs && FILE_IS_VALID(fs, files));
    
    if (FILE_IS_FREE(fs, files)) return;
    
    if (fs->files_cfl_tail)
    {
        files->next = fs->files_cfl_tail->next;
        fs->files_cfl_tail->next = files;
    }
    else
    {
        fs->files_cfl_tail = files;
        files->next = files;
    }
}

static unsigned int get_fileID(struct imfs *fs, struct file *files)
{
    assert(fs && FILE_IS_VALID(fs, files));
    return (unsigned int)(files - fs->files);
}

/* ------------------------------------------------------------------------- */

static size_t get_fnodeID(struct imfs *fs, struct fnode *f)
{
    assert(fs && FNODE_IS_VALID(fs, f));
    return (size_t)(f - fs->fn);
}

static int init_fnode_as_dir(struct imfs *fs, struct fnode *f,
                size_t parentID)
{
    assert(fs && FNODE_IS_VALID(fs, f) &&
        !FNODE_IS_FREE(fs, f) && parentID < fs->fn_len &&
        !FNODE_IS_FREE(fs, &fs->fn[parentID]));
    
    f->type = IMFS_DIR;

    struct direlem init_dirs[] = {
        {
        .fnodeID = ROOT_DIR_FNODEID,
        .name_len = 1,
        .name = {'.'}
        },
        {
        .fnodeID = ROOT_DIR_FNODEID,
        .name_len = 2,
        .name = {'.', '.'}
        }
    };

    init_dirs[0].fnodeID = get_fnodeID(fs, f);
    init_dirs[1].fnodeID = parentID;

    if (append_bytes_to_fnode(fs, f, init_dirs,
        sizeof(init_dirs), _Alignof(init_dirs))
        != (long)sizeof(init_dirs)) return -1;

    return 0;
}

static struct direlem *
search_son_in_dir(struct imfs *fs, struct fnode *dir,
    const char *son_name, size_t name_len)
{
    assert(fs && FNODE_IS_VALID(fs, dir) &&
        !FNODE_IS_FREE(fs, dir)
        && dir->type == IMFS_DIR &&
        son_name && name_len <= IMFS_MAX_NAME_LEN);

    const size_t lbu = dir->last_block_used;
    struct fdatablock *prev = dir->data_blocks_tail;
    struct fdatablock *curr = dir->data_blocks_head;
    struct fdatablock *next = NULL;

    assert((!curr && !prev) ||
        (FDATABLOCK_IS_VALID(fs, curr) &&
        FDATABLOCK_IS_VALID(fs, prev) &&
        !FDATABLOCK_IS_FREE(curr) &&
        !FDATABLOCK_IS_FREE(prev)));

    bool l;
    struct direlem *dirs;
    size_t numdirelem;
    size_t i;
    
    while (next != dir->data_blocks_head)
    {
        next = (struct fdatablock *)
            (curr->h.xor ^ (uintptr_t)prev);
        l = next == dir->data_blocks_head;
        numdirelem =
            l * (lbu / sizeof(struct direlem)) +
            (1 - l) * DIRELEM_PER_FDB;
        dirs = (struct direlem *)
            ALIGN_ADDR_POW2(&curr->data,
            _Alignof(struct direlem));
        
        i = 0;

        while (i < numdirelem &&
            (dirs[i].name_len != name_len ||
            memcmp(dirs[i].name, son_name,
                dirs[i].name_len)))
            i++;
        
        if (i < numdirelem) return &dirs[i];
        else
        {
            prev = curr;
            curr = next;
        }
    }

    return NULL;
}


/*
 * Given a [pathname] returns a pointer to a remaining slice of
 * the path - that is a string corresponding to a file or a
 * directory name - or NULL if some error occurred.
 * If [parent] is true the path traversal is stopped to the penultimate
 * element and the returned pointer points to the first character of the
 * last element of the path. Correctness of the last element is still verified.
 * If [parent] is false the path traversal is executed completely.
 * Additionally, if completed with no errors:
 *  - *fnodeID will contain the ID of the fnode corresponding to the last
 *      analyzed element of the path
 *  - *last_len will contain the length of the remaining not analyzed
 *      string slice ('\0' NOT counted)
 * 
 * COMMENTS:
 * Given that a VALID pathname is used for:
 *  - creating a file, in the form "/folder1/folder2/new-file-name"
 *  - opening a file, in the form "/folder1/folder2/file-name"
 *  - deleting a file, in the form "/folder1/folder2/file-name"
 *  - creating a directory in a parent directory, in the form
 *      "/folder1/folder2/new-folder-name"
 *  - deleting a directory in a parent directory, in the form
 *      "/folder1/folder2/folder-name"
 * 
 * we have different needs in use cases.
 * While creating a new file or a new directory we want this function
 * to return the fnodeID of the parent directory, when opening a file,
 * deleting a file or deleting a directory we want the fnodeID of
 * the file/directory itself (it already exists).
 * Let's use a flag "parent" that will stop the traversal to the parent
 */
static char *pathname_lookup(struct imfs *fs, const char *pathname,
                bool parent, size_t *fnodeID, size_t *last_len)
{
    assert(fs && pathname && fnodeID && last_len &&
        !FNODE_IS_FREE(fs, &fs->fn[ROOT_DIR_FNODEID]) &&
        fs->fn[ROOT_DIR_FNODEID].type == IMFS_DIR);

    if (*pathname != '/') return NULL;

    char *last_head = (char *)pathname + 1;
    char *p = last_head;
    size_t fnID = ROOT_DIR_FNODEID;
    
    do
    {
        while ('\0' != *p && '/' != *p &&
            p - last_head <= IMFS_MAX_NAME_LEN)
            p++;

        if (p - last_head > IMFS_MAX_NAME_LEN)
        {
            last_head = NULL;
            break;
        }
        else if ('\0' == *p)
        {
            // End of pathname reached.
            // If [parent] is true, we have to just check
            // that the last element name is correct,
            // otherwise we need to search for the element
            // name in the fnID fnode and retreive it's fnodeID.
            if (parent && p - last_head > 0) break;
            else if (parent && p - last_head <= 0)
            {
                last_head = NULL;
                break;
            }
            else
            {
                assert(fnID < fs->fn_len &&
                !FNODE_IS_FREE(fs, &fs->fn[fnID]) &&
                fs->fn[fnID].type == IMFS_DIR);

                struct direlem *d =
                    search_son_in_dir(fs, &fs->fn[fnID],
                        last_head, p - last_head);
                if (!d)
                {
                    last_head = NULL;
                    break;
                }
                else
                {
                    fnID = d->fnodeID;
                    assert(fnID < fs->fn_len &&
                        !FNODE_IS_FREE(fs, &fs->fn[fnID]));
                    last_head = p = p + 1;
                    break;
                }
            }
        }
        else // '/' == *p
        {
            // End of element reached correctly.
            // We need to search for the element name in
            // the fnID fnode and retreive it's fnodeID.
            assert(fnID < fs->fn_len &&
                !FNODE_IS_FREE(fs, &fs->fn[fnID]) &&
                fs->fn[fnID].type == IMFS_DIR);
            // Let's search
            struct direlem *d =
                    search_son_in_dir(fs, &fs->fn[fnID],
                        last_head, p - last_head);
            // This search can fail both because there is
            // no element with such name or because it's a
            // file and not a dir
            if (!d)
            {
                last_head = NULL;
                break;
            }
            else
            {
                fnID = d->fnodeID;
                assert(fnID < fs->fn_len &&
                !FNODE_IS_FREE(fs, &fs->fn[fnID]));

                if (fs->fn[d->fnodeID].type != IMFS_DIR)
                {
                    last_head = NULL;
                    break;
                }
                last_head = p = p + 1;
            }
        }
    } while (true);

    *fnodeID = fnID;
    *last_len = p - last_head;
    return last_head;
}

/*
 * Check if fnode has to be freed due to link_count
 * and open_count reached zero. This is a macro
 * because it is used in places where the assertion
 * of the validity of its parameters is already done.
 */
#define MAYBE_FREE_FNODE(fs, fID) do                    \
{                                                       \
    if (fs->fn[fID].link_count == 0 &&                  \
        fs->fn[fID].open_count == 0)                    \
    {                                                   \
        struct fdatablock *p;                           \
        while ((p = pop_fdatablock_from_fnode(fs,       \
                        &fs->fn[fID])))                 \
            free_fdatablock(fs, p);                     \
        free_fnode(fs, &fs->fn[fID]);                   \
    }                                                   \
} while (0)

int imfs_mkdir(struct imfs *fs, const char *pathname)
{
    if (!fs || !pathname) return -1;
    
    size_t parentID;
    size_t last_len;
    char *last = pathname_lookup(fs, pathname,
                    true, &parentID, &last_len);
    if (!last) return -1;
    
    assert(last_len <= IMFS_MAX_NAME_LEN
            && parentID < fs->fn_len &&
            !FNODE_IS_FREE(fs, &fs->fn[parentID]) &&
            fs->fn[parentID].type == IMFS_DIR);
    
    // Before actually create newdir we need to check
    // if it is already present a file or another dir
    // with the same name
    size_t newdirID;
    if (search_son_in_dir(fs, &fs->fn[parentID],
        last, last_len)) return -1;
    
    struct fnode *newdir = alloc_fnode(fs);
    if (!newdir) return -1;
    newdirID = get_fnodeID(fs, newdir);
    init_fnode_as_dir(fs, newdir, parentID);

    struct direlem de = {
        .fnodeID = newdirID,
        .name_len = last_len
    };
    strncpy(de.name, last, IMFS_MAX_NAME_LEN);

    if (append_bytes_to_fnode(fs, &fs->fn[parentID],
        &de, sizeof(de), _Alignof(de))
        != (long)sizeof(de)) return -1;
    
    return 0;
}

int imfs_rmdir(struct imfs *fs, const char *pathname)
{
    if (!fs || !pathname) return -1;

    size_t pID;
    size_t last_len;
    char *last = pathname_lookup(fs, pathname,
                    true, &pID, &last_len);
    if (!last) return -1;

    assert(last_len <= IMFS_MAX_NAME_LEN
            && pID < fs->fn_len &&
            !FNODE_IS_FREE(fs, &fs->fn[pID]) &&
            fs->fn[pID].type == IMFS_DIR);

    struct direlem *d =
        search_son_in_dir(fs, &fs->fn[pID],
            last, last_len);
    if (!d) return -1;
    
    size_t fID = d->fnodeID;

    assert(fID < fs->fn_len &&
            !FNODE_IS_FREE(fs, &fs->fn[fID]));
    
    // Special direlems "." and ".." (curr and prev
    // directories) can't be removed by this
    // function. Since both names starts with '.'
    // it's simple as checking the first char value.
    if (fs->fn[fID].type != IMFS_DIR ||
        '.' == d->name[0])
        return -1;

    assert(fs->fn[fID].data_blocks_head &&
        fs->fn[fID].data_blocks_tail &&
        fs->fn[fID].last_block_used >=
        2 * sizeof(struct direlem));

    #define dirs ((struct direlem *)    \
        fs->fn[fID].data_blocks_head->data)
    // First two direlem are always expected
    // to be "." and ".."
    assert(dirs[0].name_len == 1 &&
        dirs[0].name[0] == '.' &&
        dirs[1].name_len == 2 &&
        dirs[1].name[0] == '.' &&
        dirs[1].name[1] == '.');
    #undef dirs
    
    // The dir can be removed only if it's empty.
    // This means having no more that one allocated
    // fdatablock and that only "." and ".."
    // direlems are present.
    if (fs->fn[fID].data_blocks_head !=
        fs->fn[fID].data_blocks_tail ||
        fs->fn[fID].last_block_used >
        2 * sizeof(struct direlem))
        return -1;
    
    // Free the fID fnode and its fdatablocks 
    struct fdatablock *p;
    while ((p = pop_fdatablock_from_fnode(fs,
                    &fs->fn[fID])))
        free_fdatablock(fs, p);
    free_fnode(fs, &fs->fn[fID]);

    // Delete the direlem d from fs->fn[pID]
    // by cutting the last direlem from fs->fn[pID]
    // and pasting in the place of d.
    const size_t sd = sizeof(struct direlem);
    size_t lbu = fs->fn[pID].last_block_used;
    assert(lbu >= sd);
    size_t idx = lbu - sd;
    struct direlem *s = (struct direlem *)
        &fs->fn[pID].data_blocks_tail->data[idx];
    
    if (d != s) memcpy(d, s, sd);
    fs->fn[pID].last_block_used -= sd;
    
    if (fs->fn[pID].last_block_used == 0)
    {
        struct fdatablock *p = 
            pop_fdatablock_from_fnode(fs,
                &fs->fn[pID]);
        assert(p);
        free_fdatablock(fs, p);
    }
    
    return 0;
}

int imfs_open(struct imfs *fs, const char *pathname, int flags)
{
    if (!fs || !pathname) return -1;

    size_t fID;
    size_t len;
    bool create = flags & IMFS_CREAT;
    bool rdwr = flags & IMFS_RDWR;
    char *last = pathname_lookup(fs ,pathname, create,
                    &fID, &len);
    if (!last) return -1;

    assert(len <= IMFS_MAX_NAME_LEN && fID < fs->fn_len &&
            !FNODE_IS_FREE(fs, &fs->fn[fID]));

    struct direlem *d = search_son_in_dir(fs, &fs->fn[fID],
        last, len);
    if (d) fID = d->fnodeID;

    if (create && !d)
    {
        // If create is true we have the fnodeID of
        // the parent directory
        assert(fs->fn[fID].type == IMFS_DIR);
        
        struct fnode *newfilenode = alloc_fnode(fs);
        if (!newfilenode) return -1;
        newfilenode->type = IMFS_FILE;

        struct direlem newfile = {
            .fnodeID = get_fnodeID(fs, newfilenode),
            .name_len = len
        };
        strncpy(newfile.name, last, IMFS_MAX_NAME_LEN);

        if(append_bytes_to_fnode(fs, &fs->fn[fID], &newfile,
            sizeof(newfile), _Alignof(newfile))
            != (long)sizeof(newfile)) return -1;
        
        fID = newfile.fnodeID;
        // Increment the link count
        fs->fn[fID].link_count++;
    }

    // fID contains the ID of the file
    assert(fID < fs->fn_len &&
        !FNODE_IS_FREE(fs, &fs->fn[fID]) &&
        fs->fn[fID].type == IMFS_FILE);

    if (fs->fn[fID].open_count == USHRT_MAX)
        return -1;

    struct file *file = alloc_file(fs);
    if (!file) return -1;
    
    if (flags & IMFS_TRUNC && rdwr)
    {
        // File truncation
        // NOTE: Consider optimizing with one function that
        // frees all the block of the file apart from the first
        struct fdatablock *p;
        while ((p = pop_fdatablock_from_fnode(fs, &fs->fn[fID])))
            free_fdatablock(fs, p);
    }
    
    file->fnodeID = fID;
    file->read_ptr.curr = NULL;
    file->read_ptr.prev = NULL;
    file->read_ptr.b_index = 0;
    file->readonly = !rdwr;

    // Increment the open files count
    fs->fn[fID].open_count++;

    return get_fileID(fs, file) + 1;
}

int imfs_close(struct imfs *fs, int fd)
{
    fd -= 1U;
    if(!fs || fd < 0 ||
        (size_t)fd >= fs->files_len ||
        FILE_IS_FREE(fs, &fs->files[fd]))
        return -1;

    size_t fID = fs->files[fd].fnodeID;

    assert(fID < fs->fn_len &&
        !FNODE_IS_FREE(fs, &fs->fn[fID]));

    fs->fn[fID].open_count--;

    MAYBE_FREE_FNODE(fs, fID);

    free_file(fs, &fs->files[fd]);

    return 0;
}

long imfs_read(struct imfs *fs, int fd, void *buf, size_t count)
{
    fd -= 1U;
    if(!fs || !buf || fd < 0 ||
        (size_t)fd >= fs->files_len ||
        FILE_IS_FREE(fs, &fs->files[fd]))
        return -1;
    
    size_t fID = fs->files[fd].fnodeID;

    assert(fID < fs->fn_len);

    // Maybe someone deleted the file after we opened it
    if (FNODE_IS_FREE(fs, &fs->fn[fID]))
        return -1;
    
    assert(fs->fn[fID].type == IMFS_FILE);

    size_t tot_read = 0;
    char *cbuf = (char *)buf;

    // Always try to set the read pointer if it is still NULL
    // This is the case in the following scenario:
    // 1) Open a new empty file or Open one with IMFS_TRUNC
    // 2) Write some bytes to it
    // 3) Read some bytes from it
    if (!fs->files[fd].read_ptr.curr)
    {
        fs->files[fd].read_ptr.curr = fs->fn[fID].data_blocks_head;
        fs->files[fd].read_ptr.prev = fs->fn[fID].data_blocks_tail;
    }
    // Update the prev pointer to the new tail when curr still points
    // to the head but previous writes had created a new tail.
    if (fs->files[fd].read_ptr.curr == fs->fn[fID].data_blocks_head &&
        fs->files[fd].read_ptr.prev != fs->fn[fID].data_blocks_tail)
    {
        fs->files[fd].read_ptr.prev = fs->fn[fID].data_blocks_tail;
    }
    
    
    struct fdatablock *r_curr = fs->files[fd].read_ptr.curr;
    struct fdatablock *r_prev = fs->files[fd].read_ptr.prev;
    struct fdatablock *r_next = NULL;
    size_t r_b_index = fs->files[fd].read_ptr.b_index;

    assert((!r_curr && !r_prev) ||
        (FDATABLOCK_IS_VALID(fs, r_curr) &&
        FDATABLOCK_IS_VALID(fs, r_prev) &&
        !FDATABLOCK_IS_FREE(r_curr) &&
        !FDATABLOCK_IS_FREE(r_prev)));

    char last;
    size_t block_size;
    size_t bytes_avlbl;
    size_t to_read;
    size_t r_len;

    while (r_next != fs->fn[fID].data_blocks_head)
    {
        r_next = (struct fdatablock *)
            (r_curr->h.xor ^ (uintptr_t)r_prev);
        assert(FDATABLOCK_IS_VALID(fs, r_next) &&
            !FDATABLOCK_IS_FREE(r_next));
        
        last = r_next == fs->fn[fID].data_blocks_head;
        block_size = last * fs->fn[fID].last_block_used +
            (1 - last) * IMFS_DATA_BLOCK_SIZE;
        
        assert(r_b_index <= block_size);

        bytes_avlbl = block_size - r_b_index;
        to_read = count - tot_read;
        r_len = to_read < bytes_avlbl ? to_read : bytes_avlbl;
        memcpy(&cbuf[tot_read], &r_curr->data[r_b_index], r_len);
        tot_read += r_len;
        r_b_index += r_len;
        
        // Update pointer
        if (r_b_index == IMFS_DATA_BLOCK_SIZE && !last)
        {
            r_b_index = 0;
            r_prev = r_curr;
            r_curr = r_next;
        }
        else break;
    }
    
    // Update the read pointer
    fs->files[fd].read_ptr.curr = r_curr;
    fs->files[fd].read_ptr.prev = r_prev;
    fs->files[fd].read_ptr.b_index = r_b_index;

    return tot_read;
}

long imfs_write(struct imfs *fs, int fd, const void *buf, size_t count)
{
    fd -= 1U;
    if(!fs || !buf || fd < 0 ||
        (size_t)fd >= fs->files_len ||
        FILE_IS_FREE(fs, &fs->files[fd]) ||
        fs->files[fd].readonly)
        return -1;
    
    size_t fID = fs->files[fd].fnodeID;

    assert(fID < fs->fn_len);

    // Maybe someone deleted the file after we opened it
    if (FNODE_IS_FREE(fs, &fs->fn[fID]))
        return -1;
    
    assert(fs->fn[fID].type == IMFS_FILE);

    return append_bytes_to_fnode(fs, &fs->fn[fID], buf, count, 1);
}

struct imfs *
imfs_init(char *base, size_t size, struct imfs_conf *conf, bool format)
{
    struct imfs *fs = (struct imfs *)
        ALIGN_ADDR_POW2(base, _Alignof(struct imfs));

    if (format || fs->magic != IMFS_MAGIC)
    {
        if(!conf || conf->max_opened_files >= INT_MAX) return NULL;

        struct file *files = (struct file *)
            ALIGN_ADDR_POW2(fs + 1, _Alignof(struct file));

        struct fnode *fnodes = (struct fnode *)
            ALIGN_ADDR_POW2(files + conf->max_opened_files,
                _Alignof(struct fnode));

        struct fdatablock *fdatablocks = (struct fdatablock *)
            ALIGN_ADDR_POW2(fnodes + conf->max_num_fnodes + 1,
                _Alignof(struct fdatablock));

        // Invalid fs descriptor is returned if
        // we have no space for at least one fdatablock
        if (((uintptr_t)base + size) <=
            (uintptr_t)(fdatablocks+1)) return NULL;
        
        fs->magic = IMFS_MAGIC;
        fs->mem_size = size;
        fs->files = files;
        fs->files_len = conf->max_opened_files;
        fs->fn = fnodes;
        fs->fn_len = conf->max_num_fnodes + 1;
        fs->fb = fdatablocks;
        fs->fb_len = ((uintptr_t)base + size -
                        (uintptr_t)fdatablocks) /
                        sizeof(struct fdatablock);

        // Initialize the fnode circular freelist
        for (size_t i = 0; i < fs->fn_len-1; i++)
            fs->fn[i].next = &fs->fn[i+1];
        
        fs->fn[fs->fn_len-1].next = &fs->fn[0];
        fs->fn_cfl_tail = &fs->fn[fs->fn_len-1];

        // Initialize the fdatablocks freelist
        for (size_t i = 0; i < fs->fb_len-1; i++)
            fs->fb[i].h.next = (struct fdatablock *)
                    ((uintptr_t)&fs->fb[i+1] | (uintptr_t)1);
        
        fs->fb[fs->fb_len-1].h.next = (struct fdatablock *)
                    ((uintptr_t)NULL | (uintptr_t)1);
        fs->fb_fl_head = &fs->fb[0];

        assert(_Alignof(fs->files) == _Alignof(struct file));
        assert(_Alignof(fs->files_cfl_tail) == _Alignof(struct file));
        assert(_Alignof(fs->fn) == _Alignof(struct fnode));
        assert(_Alignof(fs->fn_cfl_tail) == _Alignof(struct fnode));
        assert(_Alignof(fs->fb) == _Alignof(struct fdatablock));
        assert(_Alignof(fs->fb_fl_head) == _Alignof(struct fdatablock));

        // Init the root directory
        struct fnode *root = alloc_fnode(fs);
        if (!root) return NULL;
        assert (get_fnodeID(fs, root) == ROOT_DIR_FNODEID);
        init_fnode_as_dir(fs, root, ROOT_DIR_FNODEID);
    }
    
    // Initialize the file circular freelist.
    // This is done even in the case of a mount.
    for (size_t i = 0; i < fs->files_len-1; i++)
        fs->files[i].next = &fs->files[i+1];
    
    fs->files[fs->files_len-1].next = &fs->files[0];
    fs->files_cfl_tail = &fs->files[fs->files_len-1];

    return fs;
}

int imfs_link(struct imfs *fs, const char *oldpath, const char *newpath)
{
    if (!fs || !oldpath || !newpath) return -1;

    size_t oldfID;
    size_t newlen;
    if (!pathname_lookup(fs, oldpath, false, &oldfID, &newlen))
        return -1;

    assert(oldfID < fs->fn_len && !FNODE_IS_FREE(fs, &fs->fn[oldfID]));

    if (fs->fn[oldfID].type != IMFS_FILE ||
        fs->fn[oldfID].link_count == USHRT_MAX) return -1;

    size_t newfID;
    char *last = pathname_lookup(fs, newpath, true, &newfID, &newlen);
    if (!last) return -1;
    
    assert(newlen <= IMFS_MAX_NAME_LEN && newfID < fs->fn_len &&
        !FNODE_IS_FREE(fs, &fs->fn[newfID]) &&
        fs->fn[newfID].type == IMFS_DIR);

    if (search_son_in_dir(fs, &fs->fn[newfID], last, newlen))
        return -1;
    
    struct direlem newfile = {
            .fnodeID = oldfID,
            .name_len = newlen
    };
    strncpy(newfile.name, last, IMFS_MAX_NAME_LEN);

    if(append_bytes_to_fnode(fs, &fs->fn[newfID], &newfile,
        sizeof(newfile), _Alignof(newfile))
        != (long)sizeof(newfile)) return -1;

    // Increment the link count
    fs->fn[oldfID].link_count++;

    return 0;
}

int imfs_unlink(struct imfs *fs, const char *pathname)
{
    if (!fs || !pathname) return -1;
    
    size_t pID, len;
    char *last = pathname_lookup(fs, pathname, true,
                    &pID, &len);
    if (!last) return -1;
    
    assert(len <= IMFS_MAX_NAME_LEN &&
        pID < fs->fn_len &&
        !FNODE_IS_FREE(fs, &fs->fn[pID]) &&
        fs->fn[pID].type == IMFS_DIR);
    
    struct direlem *d = 
        search_son_in_dir(fs, &fs->fn[pID], last,
            len);
    if (!d) return -1;
    
    size_t fID = d->fnodeID;

    assert(fID < fs->fn_len &&
        !FNODE_IS_FREE(fs, &fs->fn[fID]));
    
    if (fs->fn[fID].type != IMFS_FILE)
        return -1;

    // Delete the direlem d from fs->fn[pID]
    // by cutting the last direlem from fs->fn[pID]
    // and pasting in the place of d.
    const size_t sd = sizeof(struct direlem);
    size_t lbu = fs->fn[pID].last_block_used;
    assert(lbu >= sd);
    size_t idx = lbu - sd;
    struct direlem *s = (struct direlem *)
        &fs->fn[pID].data_blocks_tail->data[idx];
    
    if (d != s) memcpy(d, s, sd);
    fs->fn[pID].last_block_used -= sd;
    
    if (fs->fn[pID].last_block_used == 0)
    {
        struct fdatablock *p = 
            pop_fdatablock_from_fnode(fs,
                &fs->fn[pID]);
        assert(p);
        free_fdatablock(fs, p);
    }
    
    fs->fn[fID].link_count--;

    MAYBE_FREE_FNODE(fs, fID);
    
    return 0;
}
