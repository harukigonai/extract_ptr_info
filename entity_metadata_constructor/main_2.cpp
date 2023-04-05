#include <cstdint>
#include <iostream>
#include <fstream>

#include <set>
#include <stdexcept>
#include <string>
#include <vector>
#include <unordered_map>

#include "struct_info.h"
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include <llvm/ADT/Triple.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/DebugInfoMetadata.h>
// #include <clang/AST/Type.h>

using std::cout;
using std::endl;
using std::set;
using std::unique_ptr;
using std::unordered_map;
using std::vector;
using std::string;
using std::fstream;
using std::ios;

using llvm::ArrayRef;
using llvm::ArrayType;
using llvm::CallGraph;
using llvm::DataLayout;
using llvm::EngineBuilder;
using llvm::ExecutionEngine;
using llvm::Function;
using llvm::FunctionType;
using llvm::GenericValue;
using llvm::IntegerType;
using llvm::LibFunc;
using llvm::LLVMContext;
using llvm::Module;
using llvm::parseIRFile;
using llvm::PointerType;
using llvm::SMDiagnostic;
using llvm::StringRef;
using llvm::StructLayout;
using llvm::StructType;
using llvm::TargetLibraryInfo;
using llvm::TargetLibraryInfoImpl;
using llvm::Triple;
using llvm::Type;
using llvm::DISubprogram;
using llvm::Metadata;
using llvm::DISubroutineType;
using llvm::DITypeRefArray;
using llvm::DIType;
using llvm::DIDerivedType;
using llvm::SmallVector;
using llvm::MDNode;
using llvm::DICompositeType;
using llvm::dyn_cast;
using llvm::dyn_cast_or_null;
using llvm::DINodeArray;
using llvm::DINode;

bool void_ptr_used = false;

void print_types_helper(set<struct type_info *> &entity_processed,
                        struct type_info *type_info) {
  const bool is_in = entity_processed.find(type_info) != entity_processed.end();
  if (is_in)
    return;
  entity_processed.insert(type_info);

  cout << "Type address is " << type_info << "\n";
  if (type_info->name != NULL)
    cout << "Type Name is " << type_info->name << "\n";
  cout << "Size is " << type_info->size << "\n";
  for (int j = 0; j < type_info->child_types->size(); j++) {
    struct child_type *child_type = (*type_info->child_types)[j];
    cout << "Child offset is " << child_type->offset << ". ";
    cout << "Child Address is " << child_type->type_info << ". ";
    cout << "Child Name is " << child_type->name << "\n";
  }
  cout << "\n";

  for (int j = 0; j < type_info->child_types->size(); j++) {
    struct child_type *child_type = (*type_info->child_types)[j];
    print_types_helper(entity_processed, child_type->type_info);
  }
}

void print_types(unordered_map<Type *, struct type_info *> &types) {
  cout << "Size of types is " << types.size() << "\n\n";

  set<struct type_info *> entity_processed;
  for (auto &t : types) {
    struct type_info *type_info = t.second;
    print_types_helper(entity_processed, type_info);
  }
}

/*
 * Add a child_type_info to its parents child_type vector
 */
void saveChildType(vector<struct child_type *> *child_types,
                   struct type_info *child_type_info, size_t offset) {
  struct child_type *child_type = new struct child_type;
  child_type->offset = offset;
  child_type->type_info = child_type_info;
  child_types->insert(child_types->end(), child_type);
}

/*
 * Generates graph of types in @types
 */
struct type_info *
extract_types(DataLayout &dataLayout,
              unordered_map<Type *, struct type_info *> &types, Type *type) {
  // Is the type already in types? If so we don't need to do anything
  unordered_map<Type *, struct type_info *>::const_iterator got =
      types.find(type);
  if (got != types.end())
    return got->second;

  // Create new type_info
  struct type_info *type_info = new struct type_info;

  // Populate some metadata in type_info
  type_info->type = type->getTypeID();
  memset(type_info->name, 0, 4096);
  if (type->isSized())
    type_info->size = dataLayout.getTypeAllocSize(type);
  else
    type_info->size = 0;

  type_info->child_types = new vector<struct child_type *>();
  vector<struct child_type *> *child_types = type_info->child_types;

  type_info->type_ptr = type;

  // Add type to types
  types[type] = type_info;

  if (type->isPointerTy()) {
    strcpy(type_info->name, "pointer");

    // child_type is whatever the pointer points to
    Type *child_type = type->getContainedType(0);
    struct type_info *child_type_info =
        extract_types(dataLayout, types, child_type);

    saveChildType(child_types, child_type_info, 0);
  } else if (type->isStructTy()) {
    StructType *structType = (StructType *)type;

    const StructLayout *structLayout = dataLayout.getStructLayout(structType);
    if (structType->hasName()) {
      strcpy(type_info->name, (char *)structType->getName().data());
      if (structType->getName().data() != NULL) {
        string str = structType->getName().data();
        string::difference_type n = count(str.begin(), str.end(), '.');
        if (n == 2) {
          bool found_first_dot = false;
          for (int i = 0; i < str.length(); i++) {
            if (str[i] == '.') {
              if (!found_first_dot) {
                found_first_dot = true;
              } else {
                str[i] = '\0';
              }
            }
          }
          strcpy(type_info->name, str.data());
        }
      }
    } else {
      // Do we handle this case?
      strcpy(type_info->name, "struct.unnamed");
    }

    // structType->dump();
    // printf("is canonical: %d\n", q->getLocallyUnqualifiedSingleStepDesugaredType());
    // printf("struct %s has size %lu\n", type_info->name, type_info->size);

    // Go through the struct's children
    for (int i = 0; i < structType->getNumElements(); i++) {
      Type *child_type = structType->getTypeAtIndex(i);
      uint64_t offset = structLayout->getElementOffset(i);
      struct type_info *child_type_info =
          extract_types(dataLayout, types, child_type);
      saveChildType(child_types, child_type_info, offset);
    }
  } else if (type->isArrayTy()) {
    strcpy(type_info->name, "array");

    ArrayType *array_type = (ArrayType *)type;
    Type *child_type = array_type->getElementType();
    uint64_t num_elements = array_type->getNumElements();
    size_t child_size = 0;
    if (child_type->isSized())
      child_size = dataLayout.getTypeAllocSize(child_type);

    for (int i = 0; i < num_elements; i++) {
      uint64_t offset = child_size * i;
      struct type_info *child_type_info =
          extract_types(dataLayout, types, child_type);
      saveChildType(child_types, child_type_info, offset);
    }
  } else if (type->isIntegerTy()) {
    IntegerType *integerType = (IntegerType *)type;
    type_info->size = integerType->getBitWidth() / 8;
    if (type_info->size == 1)
      strcpy(type_info->name, "char");
    else if (type_info->size == 2)
      strcpy(type_info->name, "short");
    else if (type_info->size == 4)
      strcpy(type_info->name, "int");
    else if (type_info->size == 8)
      strcpy(type_info->name, "long");
  } else if (type->isFunctionTy()) {
    strcpy(type_info->name, "func");
  }

  return type_info;
}

void make_types_revisions(
  unordered_map<Type *, struct type_info *> &types
) {
  /* Iterate through types */
  for (auto const& [type, type_info] : types) {
    /* If type has some name */
    if (strcmp(type_info->name, "struct.ssl_ctx_st") == 0) {
      /* Find other member */
      for (auto const& [type_2, type_info_2] : types) {
        if (strcmp(type_info_2->name, "pointer.struct.lhash_st") == 0) {
          /* Swap members */
          struct child_type *child_type = (*type_info->child_types)[4];
          strcpy(child_type->name, "pointer.struct.lhash_st");
          child_type->type_info = type_info_2;
        }
      }
    }
  }

  // /* Iterate through types */
  // for (auto const& [type, type_info] : types) {
  //   size_t child_types_size = type_info->child_types->size();
  //   for (int i = 0; i < child_types_size; i++) {
  //     struct child_type *child_type = (*type_info->child_types)[i];
  //     /* If type has some name */
  //     if (strcmp(child_type->type_info->name, "pointer.struct.lhash_st_SSL_SESSION") == 0) {
  //       /* Find other member */
  //       for (auto const& [type_2, type_info_2] : types) {
  //         if (strcmp(type_info_2->name, "pointer.struct.lhash_st") == 0) {
  //           strcpy(child_type->name, "pointer.struct.lhash_st");
  //           child_type->type_info = type_info_2;
  //         }
  //       }
  //     }
  //   }
  // }
}

/*
 * Add detail to the name field of each type_info
 */
void detail_type(set<struct type_info *> entity_processed,
                 struct type_info *type_info) {
  const bool is_in = entity_processed.find(type_info) != entity_processed.end();
  if (is_in)
    return;
  entity_processed.insert(type_info);

  for (int i = 0; i < type_info->child_types->size(); i++) {
    struct child_type *child_type = (*type_info->child_types)[i];
    struct type_info *child_type_info = child_type->type_info;
    detail_type(entity_processed, child_type_info);
    strcpy(child_type->name, child_type_info->name);
  }

  if (type_info->name == NULL) {
    // Do we handle this case?
  } else if (strcmp(type_info->name, "pointer") == 0 ||
             strcmp(type_info->name, "array") == 0) {
    struct child_type *child_type = (*type_info->child_types)[0];
    struct type_info *child_type_info = child_type->type_info;
    if (strcmp(type_info->name, "array") == 0) {
      strcat(type_info->name, "[");
      sprintf(type_info->name + strlen(type_info->name), "%lu",
              type_info->child_types->size());
      strcat(type_info->name, "]");
    }
    strcat(type_info->name, ".");
    strcat(type_info->name, child_type_info->name);
  }
}

void detail_types(unordered_map<Type *, struct type_info *> &types) {
  set<struct type_info *> entity_processed;
  for (auto &t : types) {
    struct type_info *type_info = t.second;

    detail_type(entity_processed, type_info);
  }
}

bool remove_non_ptr_types(
    unordered_map<struct type_info *, bool> &entity_contains_ptr,
    set<struct type_info *> &entity_processed, struct type_info *type_info) {
  unordered_map<struct type_info *, bool>::const_iterator got =
      entity_contains_ptr.find(type_info);
  if (got != entity_contains_ptr.end())
    return got->second;

  const bool is_in = entity_processed.find(type_info) != entity_processed.end();
  if (is_in)
    return true;
  entity_processed.insert(type_info);

  // See which children are ptrs. Delete non-ptr children
  bool contains_ptr = false;
  vector<struct child_type *> *child_types = type_info->child_types;
  vector<struct child_type *>::iterator it;

  if (strcmp(type_info->name, "pointer.func") == 0) {
    for (it = child_types->begin(); it != child_types->end();) {
      struct child_type *child_type = *it;
      it = child_types->erase(it);
    }
    type_info->type = Type::IntegerTyID;
    contains_ptr = true;
  } else {
    for (it = child_types->begin(); it != child_types->end();) {
      struct child_type *child_type = *it;
      if (child_type->type_info == type_info)
        continue;

      bool child_contains_ptr = remove_non_ptr_types(
          entity_contains_ptr, entity_processed, child_type->type_info);
      if (child_contains_ptr || type_info->type == Type::PointerTyID || child_type->type_info->type == 4098) {
      // if (child_contains_ptr || type_info->type == Type::PointerTyID) {
        // Are we a struct/array that contains a ptr, or are we a pointer?
        contains_ptr = true;
        it++;
      } else {
        // If neither, then we don't care about this child
        it = child_types->erase(it);
      }
    }
  }

  // Either a child contains a ptr or we are a pointer
  bool containsPtr = contains_ptr || type_info->type == Type::PointerTyID;
  entity_contains_ptr[type_info] = containsPtr;
  return containsPtr;
}

void extract_ptr_types(
  unordered_map<Type *, struct type_info *> &structs
) {
  unordered_map<struct type_info *, bool> entity_contains_ptr;
  set<struct type_info *> entity_processed;
  for (auto &t : structs) {
    struct type_info *type_info = t.second;

    remove_non_ptr_types(entity_contains_ptr, entity_processed, type_info);
  }
}

bool is_void_ptr(DIType *di_type)
{
  DIDerivedType *di_derived_type = dyn_cast_or_null<DIDerivedType>(di_type);
  if (!(di_derived_type && di_derived_type->getTag() == 15))
    return false;

  DIType *base_type = di_derived_type->getBaseType();
  if (!base_type) {
    return true;
  }

  DIDerivedType *di_derived_type_2 = dyn_cast_or_null<DIDerivedType>(base_type);

  if (di_derived_type_2 && di_derived_type_2->getTag() == 38 &&
      !di_derived_type_2->getBaseType()) {
    return true;
  }

  return false;
}

void get_structs_and_arrays(
  set<MDNode *> &entity_processed,
  unordered_map<string, DICompositeType *> &structs_and_arrs,
  MDNode *m
) {
  const bool is_in = entity_processed.find(m) != entity_processed.end();
  if (is_in)
    return;
  entity_processed.insert(m);

  DICompositeType *compos_type = dyn_cast<DICompositeType>(m);
  if (compos_type) {
    if (compos_type->getTag() == 0x13 && compos_type->getName().data() != NULL) {
      string str = compos_type->getName().data();
      structs_and_arrs[str] = compos_type;
    }    
  }

  for (unsigned i = 0, e = m->getNumOperands(); i!=e; ++i){
    if(MDNode *Op = dyn_cast_or_null<MDNode>(m->getOperand(i))){
      get_structs_and_arrays(entity_processed, structs_and_arrs, Op);
    }
  }
}

void detail_void_ptr_types(
  const Function &lib_func,
  struct type_info *void_ptr_type_info,
  unordered_map<Type *, struct type_info *> &structs)
{
  SmallVector<std::pair<unsigned, MDNode *>, 20> MDs;
  lib_func.getAllMetadata(MDs);

  set<MDNode *> entity_processed;
  unordered_map<string, DICompositeType *> structs_and_arrs;
  for(unsigned i = 0, e = MDs.size(); i!=e; ++i){
    get_structs_and_arrays(entity_processed, structs_and_arrs, MDs[i].second);
  }

  for (auto const &pair: structs_and_arrs) {
    string str = pair.first;
    DICompositeType *m = pair.second;

    struct type_info *type_info_correct = NULL;

    /* Find the corresponding */
    for (auto &t : structs) {
      struct type_info *type_info = t.second;
      if (type_info->type == Type::StructTyID || type_info->type == Type::ArrayTyID) {
        string temp_str;
        if (type_info->type == Type::StructTyID) {
          temp_str = "struct." + str;
        } else {
          temp_str = "array." + str;
        }

        if (strcmp(temp_str.data(), type_info->name) == 0) {
          type_info_correct = type_info;
          break;
        }
      }
    }

    if (!type_info_correct) {
      continue;
    }

    DINodeArray di_node_arr = m->getElements();
    for (int i = 0; i < di_node_arr.size(); i++) {
      DINode *di_node = di_node_arr[i];

      DIDerivedType *di_derived_type = dyn_cast_or_null<DIDerivedType>(di_node);

      DIType *di_type_2 = di_derived_type->getBaseType();
      if (is_void_ptr(di_type_2)) {
        // cout << "   Derived type is " << i << " is " << di_derived_type_2->getTag() << " " << di_derived_type_2->getBaseType() << "\n"; 
        struct child_type *child_type = (*type_info_correct->child_types)[i];
        child_type->type_info = void_ptr_type_info;

        void_ptr_used = true;
      }
    }
  }
}

void populate_type_we_care_about(
  set<struct type_info *> &entity_processed,
  struct type_info *type_info,
  unordered_map<Type *, struct type_info *> &types_we_care_abt
) {
  const bool is_in = entity_processed.find(type_info) != entity_processed.end();
  if (is_in)
    return;

  entity_processed.insert(type_info);
  types_we_care_abt[type_info->type_ptr] = type_info;

  size_t child_types_size = type_info->child_types->size();
  for (int i = 0; i < child_types_size; i++) {
    struct child_type *child_type = (*type_info->child_types)[i];
    populate_type_we_care_about(entity_processed, child_type->type_info, types_we_care_abt);
  }
}

void populate_types_we_care_about(
  unordered_map<Type *, struct type_info *> &types,
  unordered_map<Type *, struct type_info *> &types_we_care_abt,
  set<Type *> &types_we_care_abt_set
) {
  set<struct type_info *> entity_processed;
  set<Type *>::iterator itr;

  for (itr = types_we_care_abt_set.begin();
       itr != types_we_care_abt_set.end();
       itr++) {
    Type *t_as_type = *itr;
    // t_as_type->dump();
    struct type_info *type_info = types[t_as_type];
    populate_type_we_care_about(entity_processed, type_info, types_we_care_abt);
  }
}

/*
 * Determine how many bytes we need for the entity_metadata array
 */
size_t updateSize(set<struct type_info *> &entity_processed, size_t &size,
                  struct type_info *type_info) {
  const bool is_in = entity_processed.find(type_info) != entity_processed.end();
  if (is_in)
    return 0;
  entity_processed.insert(type_info);

  size_t child_types_size = type_info->child_types->size();
  size_t ent_size = 3 + 2 * child_types_size;
  for (int j = 0; j < child_types_size; j++) {
    struct child_type *child_type = (*type_info->child_types)[j];
    size += updateSize(entity_processed, size, child_type->type_info);
  }

  return ent_size;
}

size_t compute_arr_size(unordered_map<Type *, struct type_info *> &structs) {
  size_t size = 0;
  set<struct type_info *> entity_processed;

  for (auto &t : structs) {
    struct type_info *type_info = t.second;

    size += updateSize(entity_processed, size, type_info);
  }
  return size;
}

/*
 * Populate the entity_metadata array with relevant info
 */
int setEntInArray(uint64_t *ent_array,
                  unordered_map<struct type_info *, int> &ent_to_index,
                  int &ind, unordered_map<struct type_info *, int> &ent_to_id,
                  int &id, struct type_info *type_info,
                  unordered_map<int, char *> &ind_to_name) {
  unordered_map<struct type_info *, int>::const_iterator got =
      ent_to_index.find(type_info);
  if (got != ent_to_index.end())
    return got->second;
  ent_to_index[type_info] = ind;
  ent_to_id[type_info] = id++; // ent_to_id is unused now, replaced with mode
  ind_to_name[ind] = (char *)&type_info->name;

  size_t child_types_size = type_info->child_types->size();
  int local_ind = ind;

  if (strcmp(type_info->name, "pointer.void") == 0) {
    ind += 3;

    /* Switch these lines to make void * have mode 4098 */
    // ent_array[local_ind++] = 4098;
    ent_array[local_ind++] = 0;

    ent_array[local_ind++] = type_info->size;
    ent_array[local_ind++] = 0;
  } else if (strcmp(type_info->name, "pointer.func") == 0) {
    ind += 3;
    ent_array[local_ind++] = 4097;
    ent_array[local_ind++] = type_info->size;
    ent_array[local_ind++] = 0;
  } else {
    ind += 3 + 2 * child_types_size;
    // ent_array[local_ind++] = 9999999999999999;
    // ent_array[local_ind++] = ent_to_id[type_info];
    ent_array[local_ind++] = type_info->type == Type::PointerTyID ? 1 : 0;
    ent_array[local_ind++] = type_info->size;
    ent_array[local_ind++] = child_types_size;

    size_t ent_size = 3 + child_types_size;
    for (int j = 0; j < child_types_size; j++) {
      struct child_type *child_type = (*type_info->child_types)[j];
      if (strcmp(type_info->name, "pointer.char") == 0) {
        ent_array[local_ind++] = 4096;
      } else {
        ent_array[local_ind++] = setEntInArray(
          ent_array, ent_to_index, ind, ent_to_id, id, child_type->type_info, ind_to_name);
      }
      ent_array[local_ind++] = child_type->offset;
    }
  }
  return ent_to_index[type_info];
}

unordered_map<struct type_info *, int> *ptrChildTypesToArray(uint64_t *ent_array,
                          unordered_map<int, char *> &ind_to_name,
                          unordered_map<Type *, struct type_info *> &structs) {
  int ind = 0;
  unordered_map<struct type_info *, int> ent_to_id;
  unordered_map<struct type_info *, int> *ent_to_index = new unordered_map<struct type_info *, int>();
  int id = 0;

  for (auto &t : structs) {
    struct type_info *type_info = t.second;

    setEntInArray(ent_array, *ent_to_index, ind, ent_to_id, id, type_info, ind_to_name);
  }
  return ent_to_index;
}

int main(int argc, char **argv) {
  set<string> funcs_we_care_about;
  fstream newfile;
  newfile.open("funcs_we_care_about.txt", ios::in);
  if (newfile.is_open()){
    string tp;
    while(getline(newfile, tp)){
      funcs_we_care_about.insert(tp);
    }
    newfile.close();
  }

  SMDiagnostic Err;

  LLVMContext *C = new LLVMContext();
  Module *mod = parseIRFile("../arm64_bc_apache_and_openssl/all_bc/all_linked.bc", Err, *C).release();
  if (!mod) {
    cout << "File passed in was invalid.";
    return 1;
  }
  DataLayout dataLayout = DataLayout(mod);

  const TargetLibraryInfo *TLI = new TargetLibraryInfo(
      TargetLibraryInfoImpl(Triple(mod->getTargetTriple())));
  LibFunc func;

  unordered_map<Type *, struct type_info *> types;

  for (StructType *type : mod->getIdentifiedStructTypes()) {
    extract_types(dataLayout, types, type);
  }

  for (auto &F : *mod) {
    if (!TLI->getLibFunc(F, func)) {
      const Function &lib_func = F.getFunction();

      FunctionType *functionType = lib_func.getFunctionType();
      Type *returnType = functionType->getReturnType();
      if (!returnType->isVoidTy()) {
        extract_types(dataLayout, types, returnType);
      }

      ArrayRef<Type *> paramTypes = functionType->params();
      for (Type *paramType : paramTypes) {
        if (!paramType->isVoidTy()) {
          extract_types(dataLayout, types, paramType);
        }
      }
    }
  }

  struct type_info *void_ptr_type_info = new struct type_info;
  void_ptr_type_info->type = 4098; // arbitrary, but stands for void *
  memset(void_ptr_type_info->name, 0, 4096);
  strcpy(void_ptr_type_info->name, "pointer.void");
  void_ptr_type_info->size = 8;
  void_ptr_type_info->child_types = new vector<struct child_type *>();
  void_ptr_type_info->type_ptr = (Type *)4098;
  types[(Type *)4098] = void_ptr_type_info;

  for (auto &F : *mod) {
    if (!TLI->getLibFunc(F, func)) {
      const Function &lib_func = F.getFunction();
      detail_void_ptr_types(lib_func, void_ptr_type_info, types);
    }
  }

  detail_types(types);

  make_types_revisions(types);

  extract_ptr_types(types);

  for (auto &F : *mod) {
    if (!TLI->getLibFunc(F, func)) {
      const Function &lib_func = F.getFunction();

      void_ptr_used = false;

      // /* Debugging tool to only generate for one func */
      // if (strcmp("RAND_seed", name.data()) != 0) {
      //   continue;
      // }

      // lib_func.getArgumentList();

      StringRef name = lib_func.getName();
      string name_as_str = string(name.data());
      const bool is_in = funcs_we_care_about.find(name_as_str) !=
        funcs_we_care_about.end();
      if (!is_in) {
        continue;
      } else {
        funcs_we_care_about.erase(name_as_str);
      }

      set<Type *> types_we_care_about_set;
      // unordered_map<Type *, struct type_info *> types_we_care_about;

      FunctionType *functionType = lib_func.getFunctionType();
      Type *returnType = functionType->getReturnType();
      if (!returnType->isVoidTy()) {
        types_we_care_about_set.insert(returnType);
      }

      ArrayRef<Type *> paramTypes = functionType->params();
      for (Type *paramType : paramTypes) {
        if (!paramType->isVoidTy()) {
          // extract_types(dataLayout, types, paramType);
          types_we_care_about_set.insert(paramType);
        }
      }

      types_we_care_about_set.insert((Type *)4098);

      unordered_map<Type *, struct type_info *> types_we_care_about;
      populate_types_we_care_about(types, types_we_care_about, types_we_care_about_set);

      size_t arr_size = compute_arr_size(types_we_care_about);
      uint64_t *ent_array = new uint64_t[arr_size];
      unordered_map<int, char *> ind_to_name;

      unordered_map<struct type_info *, int> *ent_to_index = ptrChildTypesToArray(ent_array, ind_to_name, types_we_care_about);

      int p = 0;
      char *curr_func_name = NULL;
      uint64_t num_children = 0;
      uint64_t num_children_processed = 0;

      char filename[4096];
      sprintf(filename, "bin/%s.entity_metadata", name.data());

      FILE *f = fopen(filename, "w");
      for (int k = 0; k < arr_size; k++) {
        if (p <= 2) {
          fprintf(f, "%lu, ", ent_array[k]);

          if (p == 2) {
            unordered_map<int, char *>::const_iterator got =
                ind_to_name.find(k - 2);
            if (got != ind_to_name.end()) {
              fprintf(f, "/* %d: %s */\n", k - 2, got->second);
            } else {
              fprintf(f, "/* %d: Unnamed */\n", k - 2);
            }

            num_children = ent_array[k];
            if (num_children == 0) {
              p = 0;
              num_children_processed = 0;
              continue;
            }
          }
          p++;
        } else {
          fprintf(f, "\t%lu, ", ent_array[k]);
          k++;
          fprintf(f, "%lu,\n", ent_array[k]);

          num_children_processed++;

          if (num_children == num_children_processed) {
            p = 0;
            num_children_processed = 0;
            continue;
          }
        }
      }

      fclose(f);

      int index;

      DISubprogram *sub = lib_func.getSubprogram();
      // Metadata *type = sub->Type;
      DISubroutineType *sub_routine_type = sub->getType();
      DITypeRefArray sub_routine_type_arr = sub_routine_type->getTypeArray();

      sprintf(filename, "bin/%s.ret_entity_index", name.data());
      f = fopen(filename, "w");
      DIType *ret_type = dyn_cast_or_null<DIType>(sub_routine_type_arr[0]);
      if (!returnType->isVoidTy()) {
        if (is_void_ptr(ret_type)) {
          index = ent_to_index->find(void_ptr_type_info)->second;
          fprintf(f, "%d", index);
          void_ptr_used = true;
        } else {
          struct type_info *type_info = types_we_care_about.find(returnType)->second;
          index = ent_to_index->find(type_info)->second;
          fprintf(f, "%d", index);
        }
      } else {
        fprintf(f, "-1");
      }
      fclose(f);
      sprintf(filename, "bin/%s.arg_entity_index", name.data());
      f = fopen(filename, "w");
      if (paramTypes.size()) {
        int i = 1;
        for (Type *paramType : paramTypes) {
          DIType *param_di_type = dyn_cast_or_null<DIType>(sub_routine_type_arr[i]);
          if (is_void_ptr(param_di_type)) {
            index = ent_to_index->find(void_ptr_type_info)->second;
            fprintf(f, "%d, ", index);
            void_ptr_used = true;
          } else {
            struct type_info *type_info = types_we_care_about.find(paramType)->second;
            index = ent_to_index->find(type_info)->second;
            fprintf(f, "%d, ", index);
          }
          i++;
        }
      } else {
        fprintf(f, "-1");
      }
      fclose(f);

      if (void_ptr_used)
        printf("%s\n", name.data());

    }
  }

  // for (string func_not_processed : funcs_we_care_about)
  // {
  //   std::cout << "Function " << func_not_processed << " was not found.\n";
  // }
}