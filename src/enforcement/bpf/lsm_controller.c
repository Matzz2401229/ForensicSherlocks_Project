
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <limits.h>

/* Validate the supplied target file and extract its identity. */
int inspect_target(const char *path)
{
    struct stat st;
    char *resolved_path;

    uint32_t dev_major;
    uint32_t dev_minor;
    uint64_t inode_number;

    /* Resolve the supplied path. */
    resolved_path = realpath(path, NULL);

    if (resolved_path == NULL) {
        perror("Failed to resolve target path");
        return -1;
    }

    /* Obtain file metadata. */
    if (stat(resolved_path, &st) != 0) {
        perror("Failed to inspect target file");
        free(resolved_path);
        return -1;
    }

    /* Only allow regular files for this experiment. */
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "Error: target must be a regular file.\n");
        free(resolved_path);
        return -1;
    }

    /*
     * Extract the filesystem device identity.
     * major() and minor() decode the user-space st_dev value.
     */
    dev_major = major(st.st_dev);
    dev_minor = minor(st.st_dev);

    /* Extract the file's inode number. */
    inode_number = st.st_ino;

    printf("\nTarget file information\n");
    printf("-----------------------\n");
    printf("Path       : %s\n", resolved_path);
    printf("Major      : %u\n", dev_major);
    printf("Minor      : %u\n", dev_minor);
    printf("Inode      : %llu\n",
           (unsigned long long)inode_number);

    free(resolved_path);

    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr,
                "Usage: %s <target-file-path>\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    if (inspect_target(argv[1]) != 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
