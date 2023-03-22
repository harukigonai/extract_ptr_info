#ifndef _LIB_FUNC_BST_H_
#define _LIB_FUNC_BST_H_

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct lib_func_info {
    char *func_name;

    uint64_t *entity_metadata;
    size_t entity_metadata_size;

    int *arg_entity_index;
    size_t arg_entity_index_size;

    int *ret_entity_index;
    size_t ret_entity_index_size;
};

struct lib_func_node {
    char *k;
    struct lib_func_node *l;
    struct lib_func_node *r;
    struct lib_func_info info;
};

static struct lib_func_node *new_lib_func_node(char *k);

struct lib_func_node *lib_func_insert(struct lib_func_node *root, char *k);

struct lib_func_node *lib_func_get(struct lib_func_node *root, char *k);

void lib_func_inorder(struct lib_func_node *root);

#endif
