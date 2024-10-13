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

#define ALIGN_ADDR_POW2(addr, pow2)                 \
    ({                                              \
        uintptr_t addr_ = (uintptr_t)(addr);        \
        uintptr_t pow2_ = (uintptr_t)(pow2);        \
        addr_ += - addr_ & (pow2_ - 1UL);           \
    })

#define IMFS_PRE_ADJ_DATA_BLOCK_SIZE                \
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
#define DIRELEM_PER_FDB                             \
    ((IMFS_PRE_ADJ_DATA_BLOCK_SIZE +                \
    sizeof(struct direlem) - 1)/                    \
    sizeof(struct direlem))

/* 
 * The file data block size is calculated as the smallest
 * integer bigger that SS_PRE_ADJ_DATA_BLOCK_SIZE such that
 * it's a multiple of the size of struct direlem.
 */
#define IMFS_DATA_BLOCK_SIZE                        \
    (sizeof(struct direlem) *                       \
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
    enum {
        SS_FILE,
        SS_DIR
    } type;
};

struct ssfile {
    size_t fnodeID;
    union {
        struct ssfileptr {
            struct fdatablock *curr;
            struct fdatablock *prev;
            size_t b_index;
        } read_ptr;
        /* Used while in the freelist */
        struct ssfile *next;
    };
    bool readonly;
};

static const char imfs_magic[] = {24, 10, 98, 06, 05, 99, 1, 1};
#define IMFS_SS_MAGIC_SIZE (sizeof(imfs_magic)/sizeof(imfs_magic[0]))

struct imfs {
    /* size of the whole available memory */
    size_t mem_size;
    
    /* ssfile memory area */
    struct ssfile *ssf;
    /* Number of ssfiles in the table */
    size_t ssf_len;
    /* ssfile circular freelist tail */
    struct ssfile *ssf_cfl_tail;

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

#define FDATABLOCK_IS_VALID(fs, fdb)               \
    ({                                              \
        struct imfs *fs_ = fs;                    \
        uintptr_t fdb_ = (uintptr_t)fdb;            \
        uintptr_t start_ =                          \
            (uintptr_t)&fs_->fb[0];                \
        uintptr_t end_ =                            \
            (uintptr_t)&fs_->fb[fs_->fb_len-1];   \
        fdb_ >= start_ && fdb_ <= end_ &&           \
        (fdb_ - start_) %                           \
        sizeof(struct fdatablock) == 0;             \
    })
#define FDATABLOCK_IS_FREE(fdb)                     \
    ({                                              \
        struct fdatablock *fdb_ = fdb;              \
        (uintptr_t)fdb_->h.next & 1;                \
    })

static struct fdatablock *alloc_fdatablock(struct imfs *fs)
{
    // At this level we ASSUME a valid ss_desc
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

#define FNODE_IS_VALID(fs, f)                      \
    ({                                              \
        struct imfs *fs_ = fs;                    \
        uintptr_t f_ = (uintptr_t)f;                \
        uintptr_t start_ =                          \
            (uintptr_t)&fs_->fn[0];                \
        uintptr_t end_ =                            \
            (uintptr_t)&fs_->fn[fs_->fn_len-1];   \
        f_ >= start_ && f_ <= end_ &&               \
        (f_ - start_) % sizeof(struct fnode) == 0;  \
    })
#define FNODE_IS_FREE(fs, f)                       \
    FNODE_IS_VALID(fs, ((struct fnode *)f)->next)

static struct fnode *alloc_fnode(struct imfs *fs)
{
    // At this level we ASSUME a valid ss_desc
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

static ssize_t append_bytes_to_fnode(struct imfs *fs, struct fnode *f,
                const void *buf, size_t len, size_t alignment)
{
    assert(fs && buf && len <= SSIZE_MAX &&
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

    return (ssize_t)tot_written;
}

/* ------------------------------------------------------------------------- */

#define SSFILE_IS_VALID(fs, s)                     \
    ({                                              \
        struct imfs *fs_ = fs;                    \
        uintptr_t s_ = (uintptr_t)s;                \
        uintptr_t start_ =                          \
            (uintptr_t)&fs_->ssf[0];               \
        uintptr_t end_ =                            \
            (uintptr_t)&fs_->ssf[fs_->ssf_len-1]; \
        s_ >= start_ && s_ <= end_ &&               \
        (s_ - start_) % sizeof(struct ssfile) == 0; \
    })
#define SSFILE_IS_FREE(fs, s)                      \
        SSFILE_IS_VALID(fs,                        \
            ((struct ssfile *)s)->next)

static struct ssfile *alloc_ssfile(struct imfs *fs)
{
    assert(fs);

    struct ssfile *new = fs->ssf_cfl_tail;
    
    if (fs->ssf_cfl_tail)
    {
        if (fs->ssf_cfl_tail == 
            fs->ssf_cfl_tail->next)
        {
            fs->ssf_cfl_tail = NULL;
        }
        else
        {
            new = fs->ssf_cfl_tail->next;
            fs->ssf_cfl_tail->next = new->next;
        }
        new->next = NULL;
    }
    
    return new;
}

static void free_ssfile(struct imfs *fs, struct ssfile *ssf)
{
    assert(fs && SSFILE_IS_VALID(fs, ssf));
    
    if (SSFILE_IS_FREE(fs, ssf)) return;
    
    if (fs->ssf_cfl_tail)
    {
        ssf->next = fs->ssf_cfl_tail->next;
        fs->ssf_cfl_tail->next = ssf;
    }
    else
    {
        fs->ssf_cfl_tail = ssf;
        ssf->next = ssf;
    }
}

static unsigned int get_ssfileID(struct imfs *fs, struct ssfile *ssf)
{
    assert(fs && SSFILE_IS_VALID(fs, ssf));
    return (unsigned int)(ssf - fs->ssf);
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
    
    f->type = SS_DIR;

    static struct direlem init_dirs[] = {
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
        != (ssize_t)sizeof(init_dirs)) return -1;

    return 0;
}

static bool search_son_in_dir(struct imfs *fs, struct fnode *dir,
                const char *son_name, size_t name_len, size_t *sonID)
{
    assert(fs && FNODE_IS_VALID(fs, dir) &&
        !FNODE_IS_FREE(fs, dir) && dir->type == SS_DIR &&
        son_name && name_len <= IMFS_MAX_NAME_LEN);
    
    size_t ID;
    bool found = false;

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
    
    while (next != dir->data_blocks_head && !found)
    {
        next = (struct fdatablock *)
            (curr->h.xor ^ (uintptr_t)prev);
        l = next == dir->data_blocks_head;
        numdirelem = l * (lbu / sizeof(struct direlem)) +
            (1 - l) * DIRELEM_PER_FDB;
        dirs = (struct direlem *)
            ALIGN_ADDR_POW2(&curr->data,
            _Alignof(struct direlem));
        
        i = 0;

        while (i < numdirelem &&
            (dirs[i].name_len != name_len ||
            memcmp(dirs[i].name, son_name, dirs[i].name_len)))
            i++;
        
        if (i < numdirelem)
        {
            found = true;
            ID = dirs[i].fnodeID;
        }
        else
        {
            prev = curr;
            curr = next;
        }
    }

    if (found && sonID) *sonID = ID;
    return found;
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
 * the file/directory itself (it already exist).
 * Let's use a flag "parent" that will stop the traversal to the parent
 */
static char *pathname_lookup(struct imfs *fs, const char *pathname,
                bool parent, size_t *fnodeID, size_t *last_len)
{
    assert(fs && pathname && fnodeID && last_len &&
        !FNODE_IS_FREE(fs, &fs->fn[ROOT_DIR_FNODEID]) &&
        fs->fn[ROOT_DIR_FNODEID].type == SS_DIR);

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
                fs->fn[fnID].type == SS_DIR);

                if (!search_son_in_dir(fs, &fs->fn[fnID],
                last_head, p - last_head, &fnID))
                {
                    last_head = NULL;
                    break;
                }
                else
                {
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
                fs->fn[fnID].type == SS_DIR);
            // Let's search
            bool f = search_son_in_dir(fs, &fs->fn[fnID],
                last_head, p - last_head, &fnID);
            assert(fnID < fs->fn_len &&
                !FNODE_IS_FREE(fs, &fs->fn[fnID]));
            // This search can fail both because there is
            // no element with such name or because it's a
            // file and not a dir
            if (!f || fs->fn[fnID].type != SS_DIR)
            {
                last_head = NULL;
                break;
            }
            else last_head = p = p + 1;
        }
    } while (true);

    *fnodeID = fnID;
    *last_len = p - last_head;
    return last_head;
}

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
            fs->fn[parentID].type == SS_DIR);
    
    // Before actually create newdir we need to check
    // if it is already present a file or another dir
    // with the same name
    size_t newdirID;
    if (search_son_in_dir(fs, &fs->fn[parentID],
        last, last_len, &newdirID)) return -1;
    
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
        != (ssize_t)sizeof(de)) return -1;
    
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
    
    if (create && !search_son_in_dir(fs, &fs->fn[fID],
        last, len, &fID))
    {
        // If create is true we have the fnodeID of
        // the parent directory
        assert(fs->fn[fID].type == SS_DIR);
        
        struct fnode *newfilenode = alloc_fnode(fs);
        if (!newfilenode) return -1;
        newfilenode->type = SS_FILE;

        struct direlem newfile = {
            .fnodeID = get_fnodeID(fs, newfilenode),
            .name_len = len
        };
        strncpy(newfile.name, last, IMFS_MAX_NAME_LEN);

        if(append_bytes_to_fnode(fs, &fs->fn[fID], &newfile,
            sizeof(newfile), _Alignof(newfile))
            != (ssize_t)sizeof(newfile)) return -1;
        
        fID = newfile.fnodeID;
    }

    // fID contains the ID of the file
    assert(fs->fn[fID].type == SS_FILE);

    struct ssfile *ssf = alloc_ssfile(fs);
    if (!ssf) return -1;
    
    if (flags & IMFS_TRUNC && rdwr)
    {
        // File truncation
        // NOTE: Consider optimizing with one function that
        // frees all the block of the file apart from the first
        struct fdatablock *p;
        while ((p = pop_fdatablock_from_fnode(fs, &fs->fn[fID])))
            free_fdatablock(fs, p);
    }
    
    ssf->fnodeID = fID;
    ssf->read_ptr.curr = NULL;
    ssf->read_ptr.prev = NULL;
    ssf->read_ptr.b_index = 0;
    ssf->readonly = !rdwr;

    return get_ssfileID(fs, ssf) + 1;
}

int imfs_close(struct imfs *fs, int fd)
{
    fd -= 1U;
    if(!fs || fd < 0 ||
        (size_t)fd >= fs->ssf_len ||
        SSFILE_IS_FREE(fs, &fs->ssf[fd]))
        return -1;

    free_ssfile(fs, &fs->ssf[fd]);

    return 0;
}

ssize_t imfs_read(struct imfs *fs, int fd, void *buf, size_t count)
{
    fd -= 1U;
    if(!fs || fd < 0 ||
        (size_t)fd >= fs->ssf_len ||
        SSFILE_IS_FREE(fs, &fs->ssf[fd]))
        return -1;
    
    size_t fID = fs->ssf[fd].fnodeID;

    assert(fID < fs->fn_len);

    // Maybe someone deleted the file after we opened it
    if (FNODE_IS_FREE(fs, &fs->fn[fID]))
        return -1;
    
    assert(fs->fn[fID].type == SS_FILE);

    size_t tot_read = 0;
    char *cbuf = (char *)buf;

    // Always try to set the read pointer if it is still NULL
    // This is the case in the following scenario:
    // 1) Open a new empty file or Open one without SS_APPEND
    // 2) Write some bytes to it
    // 3) Read some bytes from it
    if (!fs->ssf[fd].read_ptr.curr)
    {
        fs->ssf[fd].read_ptr.curr = fs->fn[fID].data_blocks_head;
        fs->ssf[fd].read_ptr.prev = fs->fn[fID].data_blocks_tail;
    }
    // Update the prev pointer to the new tail when curr still points
    // to the head but previous writes had created a new tail.
    if (fs->ssf[fd].read_ptr.curr == fs->fn[fID].data_blocks_head &&
        fs->ssf[fd].read_ptr.prev != fs->fn[fID].data_blocks_tail)
    {
        fs->ssf[fd].read_ptr.prev = fs->fn[fID].data_blocks_tail;
    }
    
    
    struct fdatablock *r_curr = fs->ssf[fd].read_ptr.curr;
    struct fdatablock *r_prev = fs->ssf[fd].read_ptr.prev;
    struct fdatablock *r_next = NULL;
    size_t r_b_index = fs->ssf[fd].read_ptr.b_index;

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
    fs->ssf[fd].read_ptr.curr = r_curr;
    fs->ssf[fd].read_ptr.prev = r_prev;
    fs->ssf[fd].read_ptr.b_index = r_b_index;

    return tot_read;
}

ssize_t imfs_write(struct imfs *fs, int fd, const void *buf, size_t count)
{
    fd -= 1U;
    if(!fs || !buf || fd < 0 || (size_t)fd >= fs->ssf_len ||
        SSFILE_IS_FREE(fs, &fs->ssf[fd]) ||
        fs->ssf[fd].readonly)
        return -1;
    
    size_t fID = fs->ssf[fd].fnodeID;

    assert(fID < fs->fn_len);

    // Maybe someone deleted the file after we opened it
    if (FNODE_IS_FREE(fs, &fs->fn[fID]))
        return -1;
    
    assert(fs->fn[fID].type == SS_FILE);

    return append_bytes_to_fnode(fs, &fs->fn[fID], buf, count, 1);
}

struct imfs *
imfs_init(char *base, size_t size, struct imfs_conf *conf, bool format)
{
    struct imfs *fs = (struct imfs *)
        ALIGN_ADDR_POW2(base + IMFS_SS_MAGIC_SIZE,
            _Alignof(struct imfs));

    if (!format && !memcmp(base, imfs_magic, IMFS_SS_MAGIC_SIZE))
        return fs;
    
    if(!conf || conf->max_opened_files >= INT_MAX) return NULL;

    struct ssfile *ssfiles = (struct ssfile *)
        ALIGN_ADDR_POW2(fs + 1, _Alignof(struct ssfile));

    struct fnode *fnodes = (struct fnode *)
        ALIGN_ADDR_POW2(ssfiles + conf->max_opened_files,
            _Alignof(struct fnode));

    struct fdatablock *fdatablocks = (struct fdatablock *)
        ALIGN_ADDR_POW2(fnodes + conf->max_num_fnodes + 1,
            _Alignof(struct fdatablock));

    // Invalid fs descriptor is returned if
    // we have no space for at least one fdatablock
    if (((uintptr_t)base + size) <=
        (uintptr_t)(fdatablocks+1)) return NULL;
    
    memcpy(base, imfs_magic, IMFS_SS_MAGIC_SIZE);
    fs->mem_size = size;
    fs->ssf = ssfiles;
    fs->ssf_len = conf->max_opened_files;
    fs->fn = fnodes;
    fs->fn_len = conf->max_num_fnodes + 1;
    fs->fb = fdatablocks;
    fs->fb_len = ((uintptr_t)base + size -
                    (uintptr_t)fdatablocks) /
                    sizeof(struct fdatablock);

    // Initialize the ssfile circular freelist
    for (size_t i = 0; i < fs->ssf_len-1; i++)
        fs->ssf[i].next = &fs->ssf[i+1];
    
    fs->ssf[fs->ssf_len-1].next = &fs->ssf[0];
    fs->ssf_cfl_tail = &fs->ssf[fs->ssf_len-1];

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

    assert(_Alignof(fs->ssf) == _Alignof(struct ssfile));
    assert(_Alignof(fs->ssf_cfl_tail) == _Alignof(struct ssfile));
    assert(_Alignof(fs->fn) == _Alignof(struct fnode));
    assert(_Alignof(fs->fn_cfl_tail) == _Alignof(struct fnode));
    assert(_Alignof(fs->fb) == _Alignof(struct fdatablock));
    assert(_Alignof(fs->fb_fl_head) == _Alignof(struct fdatablock));

    // Init the root directory
    struct fnode *root = alloc_fnode(fs);
    if (!root) return NULL;
    assert (get_fnodeID(fs, root) == ROOT_DIR_FNODEID);
    init_fnode_as_dir(fs, root, ROOT_DIR_FNODEID);

    return fs;
}