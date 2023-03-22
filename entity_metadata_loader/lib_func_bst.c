#include <stdio.h>
#include <stdlib.h>
#include "lib_func_bst.h"

static struct lib_func_node *new_lib_func_node(char *k) {
    struct lib_func_node *temp =
        (struct lib_func_node *)malloc(sizeof(struct lib_func_node));
    temp->k = k;
    temp->l = NULL;
    temp->r = NULL;
    return temp;
}

struct lib_func_node *lib_func_insert(struct lib_func_node *root, char *k) {
    if (root == NULL)
        return new_lib_func_node(k);

    int strcmp_res = strcmp(k, root->k);

    if (strcmp_res > 0)
        root->l = lib_func_insert(root->l, k);
    else if (strcmp_res < 0)
        root->r = lib_func_insert(root->r, k);

    return root;
}

struct lib_func_node *lib_func_get(struct lib_func_node *root, char *k) {
    if (root == NULL)
        return NULL;

    int strcmp_res = strcmp(k, root->k);

    if (strcmp_res > 0)
        return lib_func_get(root->l, k);
    else if (strcmp_res < 0)
        return lib_func_get(root->l, k);
    return root;
}

void lib_func_inorder(struct lib_func_node *root)
{
    if (root != NULL) {
        lib_func_inorder(root->l);
        struct lib_func_info *info = &root->info;
        printf("func_name: %s\n", info->func_name);

        printf("entity_metadata (size: %lu):\n", info->entity_metadata_size);
        for (size_t i = 0; i < info->entity_metadata_size; i++) {
            printf("%lu ", info->entity_metadata[i]);
        }
        printf("\n");

        printf("arg_entity_index (size: %lu):\n", info->arg_entity_index_size);
        for (size_t i = 0; i < info->arg_entity_index_size; i++) {
            printf("%d ", info->arg_entity_index[i]);
        }
        printf("\n");

        printf("ret_entity_index: (size: %lu)\n", info->ret_entity_index_size);
        for (size_t i = 0; i < info->ret_entity_index_size; i++) {
            printf("%d ", info->ret_entity_index[i]);
        }
        printf("\n\n");

        lib_func_inorder(root->r);
    }
}
