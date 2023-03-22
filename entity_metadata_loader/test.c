#include <stdio.h>
#include "entity_metadata_loader.h"
#include "lib_func_bst.h"



/* In practice, this would be the shim program or */
int main()
{
    struct lib_func_node *root = load_entity_metadata("../entity_metadata_constructor/bin");
    printf("%p\n", root);
    lib_func_inorder(root);
}
