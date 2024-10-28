# In Memory File System
A simple in-memory file system written in C.

This project marks my first venture into the world of file systems and was inspired by the structure of the [Linux VFS](https://docs.kernel.org/filesystems/vfs.html).

The goal was to provide a way to store data permanently on addressable non-volatile memories (such as flash), while remaining light enough to be used in resource-constrained embedded environments.

## Specs
- Supports hard links,
- Lacks complex file operations like renaming or moving the file r/w pointer,
- No support for multi-threaded usage. User code must handle serialization when accessing the file system,
- Not atomic with respect to failures during operations.

## Usage
Simply add `imfs.c` to your project and include `imfs.h`. That's all you need! :)

## Example
Using IMFS is simple as:
```c
struct imfs *fs = imfs_init(base_mem, mem_size, &c, true);
int fd = imfs_open(fs, "/file1", IMFS_CREAT | IMFS_RDWR);
imfs_write(fs, fd, wbuf, len);
imfs_read(fs, fd, rbuf, BSIZE);
imfs_close(fs, fd);
```
Use `make example && ./example` to compile and run an example program.

## Tests & Coverage
A combination of random tests and common usage patterns was used for testing.\
Run `make tests` to compile and execute the tests; run `make cov` to execute the tests with code coverage.