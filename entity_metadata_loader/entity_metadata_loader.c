#include "entity_metadata_loader.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

struct lib_func_node *load_entity_metadata(char *dir_name) {
    DIR *FD;
    struct dirent *in_file;
    FILE *common_file;
    FILE *entry_file;
    char buffer[BUFSIZ];

    FD = opendir(dir_name);
    if (NULL == FD) {
        fprintf(stderr, "Error : Failed to open input directory - %s\n",
                strerror(errno));
        return NULL;
    }

    struct lib_func_node *root = NULL;

    in_file = readdir(FD);
    while (in_file) {
        if (!strcmp(in_file->d_name, "."))
            continue;
        if (!strcmp(in_file->d_name, ".."))
            continue;

        entry_file = fopen(in_file->d_name, "r");
        if (entry_file == NULL) {
            fprintf(stderr, "Error : Failed to open entry file - %s\n",
                    strerror(errno));

            return NULL;
        }

        while (fgets(buffer, BUFSIZ, entry_file) != NULL) {
            /* Use fprintf or fwrite to write some stuff into common_file*/
        }

        fclose(entry_file);

        in_file = readdir(FD);
    }

    closedir(FD);

    return 0;
}
