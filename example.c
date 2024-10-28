#include <stdio.h>
#include <string.h>
#include "imfs.h"

#define MSIZE 128*1024
#define BSIZE 1024

char base_mem[MSIZE];
char buf[BSIZE];

int main(void)
{
    struct imfs_conf c = {
        .max_num_fnodes = 50,
        .max_opened_files = 50
    };

    struct imfs *fs = imfs_init(base_mem, MSIZE, &c, true);

    if (!fs)
    {
        fputs("IMFS: Error in IMFS init!\n", stdout);
        return -1;
    }
    
    fputs("IMFS: Filesystem started\n", stdout);

    bool cont = true;
    int fd;
    size_t size;
    ssize_t result;
    do
    {
        fputs("\nSelect an option:\n"
            "1: Create a directory\n"
            "2: Remove a directory\n"
            "3: Open/Create a file\n"
            "4: Close a file\n"
            "5: Read from a file\n"
            "6: Write to a file\n"
            "7: Create an hard link\n"
            "8: Delete an hard link\n"
            "Other: Exit\n"
            "# ", stdout);
        
        fgets(buf, sizeof(buf), stdin);

        switch (buf[0])
        {
        case '1':
            fputs("Path of the directory:\n"
                "# ", stdout);
            fgets(buf, sizeof(buf), stdin);
            buf[strcspn(buf, "\n")] = '\0';

            printf("STATUS: %s\n", imfs_mkdir(fs, buf) ? "ERROR" : "OK");
            break;
        
        case '2':
            fputs("Path of the directory:\n"
                "# ", stdout);
            fgets(buf, sizeof(buf), stdin);
            buf[strcspn(buf, "\n")] = '\0';

            printf("STATUS: %s\n", imfs_rmdir(fs, buf) ? "ERROR" : "OK");
            break;

        case '3':
            fputs("Path of the file:\n"
                "# ", stdout);
            fgets(buf, sizeof(buf), stdin);
            buf[strcspn(buf, "\n")] = '\0';

            printf("FD (< 0 IS ERROR): %d\n",
                imfs_open(fs, buf, IMFS_CREAT | IMFS_RDWR));
            break;

        case '4':
            fputs("File descriptor:\n"
                "# ", stdout);
            fgets(buf, sizeof(buf), stdin);
            sscanf(buf, "%d", &fd);

            printf("STATUS: %s\n", imfs_close(fs, fd) ? "ERROR" : "OK");
            break;

        case '5':
            fputs("File descriptor:\n"
                "# ", stdout);
            fgets(buf, sizeof(buf), stdin);
            sscanf(buf, "%d", &fd);
            
            fputs("Num. bytes to read:\n"
                "# ", stdout);
            fgets(buf, sizeof(buf), stdin);
            sscanf(buf, "%zu", &size);
            size = size < sizeof(buf) ? size : sizeof(buf);
            
            result = imfs_read(fs, fd, buf, size);
            printf("NUM. BYTES READ (< 0 IS ERROR): %zi\n", result);
            if (result > 0)
            {
                buf[result] = '\0';
                printf("BYTES: %s\n", buf);
            }
            break;

        case '6':
            fputs("File descriptor:\n"
                "# ", stdout);
            fgets(buf, sizeof(buf), stdin);
            sscanf(buf, "%d", &fd);
            
            fputs("Bytes to write:\n"
                "# ", stdout);
            fgets(buf, sizeof(buf), stdin);
            buf[strcspn(buf, "\n")] = '\0';

            printf("BYTES WRITTEN (< 0 IS ERROR): %zi\n",
                imfs_write(fs, fd, buf, strlen(buf)));
            break;

        case '7':
            fputs("Path of the old file:\n"
                "# ", stdout);
            fgets(buf, sizeof(buf), stdin);
            buf[strcspn(buf, "\n")] = '\0';
            size = strlen(buf) + 1;

            fputs("Path of the new file:\n"
                "# ", stdout);
            fgets(&buf[size], sizeof(buf) - size, stdin);
            buf[size + strcspn(&buf[size], "\n")] = '\0';

            printf("STATUS: %s\n",
                imfs_link(fs, buf, &buf[size]) ? "ERROR" : "OK");
            break;

        case '8':
            fputs("Path of the file:\n"
                "# ", stdout);
            fgets(buf, sizeof(buf), stdin);
            buf[strcspn(buf, "\n")] = '\0';

            printf("STATUS: %s\n",
                imfs_unlink(fs, buf) ? "ERROR" : "OK");
            break;
        
        default:
            cont = false;
            break;
        }

    } while (cont);
    
    fputs("IMFS: Filesystem shutdowned\n", stdout);

    return 0;
}