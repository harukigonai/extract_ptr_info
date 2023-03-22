#ifndef _ENTITY_METADATA_LOADER_H_
#define _ENTITY_METADATA_LOADER_H_

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct lib_func_node *load_entity_metadata(char *);

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
};

static inline struct lib_func_node *new_lib_func_node(char *k) {
    struct lib_func_node *temp =
        (struct lib_func_node *)malloc(sizeof(struct lib_func_node));
    temp->k = k;
    temp->l = NULL;
    temp->r = NULL;
    return temp;
}

inline struct lib_func_node *lib_func_insert(struct lib_func_node *root, char *k) {
    if (root == NULL)
        return new_lib_func_node(k);

    if (strcmp(k, root->k))
        root->l = insert(root->l, k);
    else if (k > root->k)
        root->r = insert(root->r, k);

    return root;
}

inline struct lib_func_node *lib_func_get(struct lib_func_node *root, char *k) {
    if (root == NULL)
        return NULL;

    int strcmp_res = strcmp(k, root->k);

    if (strcmp_res < 0)
        return lib_func_get(root->l, k);
    else if (strcmp_res > 0)
        return lib_func_get(root->l, k);
    else
        return root;
}

#endif
