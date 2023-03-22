#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "entity_metadata_loader.h"

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
    struct lib_func_node *curr = NULL;

    in_file = readdir(FD);
    while (in_file) {
        if (!strcmp(in_file->d_name, ".") || !strcmp(in_file->d_name, "..")) {
            in_file = readdir(FD);
            continue;
        }

        char *filename_ext;
        char full_filename[4096];
        char filename[4096];
        memset(filename, 0, sizeof(filename));
        strcpy(filename, in_file->d_name);
        sprintf(full_filename, "%s/%s", dir_name, in_file->d_name);

        entry_file = fopen(full_filename, "r");
        if (entry_file == NULL) {
            fprintf(stderr, "Error : Failed to open entry file - %s\n",
                    strerror(errno));

            return NULL;
        }

        size_t filesize;
        fseek(entry_file, 0, SEEK_END);
        filesize = ftell(entry_file);
        fseek(entry_file, 0L, SEEK_SET);

        filename_ext = strtok(filename, ".");
        filename_ext = strtok(NULL, ".");

        printf("filename is %s. ext is %s\n", filename, filename_ext);

        curr = lib_func_get(root, filename);
        if (curr == NULL) {
            // very inefficient?
            root = lib_func_insert(root, filename);
            curr = lib_func_get(root, filename);

            size_t filename_len = strlen(filename);
            curr->info.func_name = malloc(filename_len * sizeof(char));
            strcpy(curr->info.func_name, filename);
        }

        if (strcmp(filename_ext, "entity_metadata")) {
            size_t num_items = filesize / sizeof(uint64_t);
            size_t num_items_read;

            curr->info.entity_metadata = malloc(filesize);
            printf("entity_filesize is %lu\n", filesize);
            uint64_t *entity_metadata_curr = curr->info.entity_metadata;
            num_items_read = fread(entity_metadata_curr, sizeof(uint64_t),
                                   num_items_read, entry_file);
            while (num_items_read) {
                entity_metadata_curr += num_items_read;
                num_items_read = fread(entity_metadata_curr, sizeof(uint64_t),
                                       num_items_read, entry_file);
            }
            curr->info.entity_metadata_size = filesize;
        } else if (strcmp(filename_ext, "arg_entity_index")) {
            size_t num_items = filesize / sizeof(int);
            size_t num_items_read;

            curr->info.arg_entity_index = malloc(filesize);
            int *arg_entity_index_curr = curr->info.arg_entity_index;
            num_items_read = fread(arg_entity_index_curr, sizeof(int),
                                   num_items_read, entry_file);
            while (num_items_read) {
                arg_entity_index_curr += num_items_read;
                num_items_read = fread(arg_entity_index_curr, sizeof(int),
                                       num_items_read, entry_file);
            }
            curr->info.arg_entity_index_size = num_items;
        } else if (strcmp(filename_ext, "ret_entity_index")) {
            size_t num_items = filesize / sizeof(int);
            size_t num_items_read;

            curr->info.ret_entity_index = malloc(filesize);
            int *ret_entity_index_curr = curr->info.ret_entity_index;
            num_items_read = fread(ret_entity_index_curr, sizeof(int),
                                   num_items_read, entry_file);
            while (num_items_read) {
                ret_entity_index_curr += num_items_read;
                num_items_read = fread(ret_entity_index_curr, sizeof(int),
                                       num_items_read, entry_file);
            }
            curr->info.arg_entity_index_size = num_items;
        }
        fclose(entry_file);

        in_file = readdir(FD);
        break;
    }

    closedir(FD);

    return root;
}

// destroy_entity_metadata() {
