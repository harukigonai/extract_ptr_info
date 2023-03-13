#include <iostream>

#include <string>
#include <vector>
#include <set>
#include <stdexcept>

#include "struct_info.h"

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/Analysis/TargetLibraryInfo.h>

#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

using std::unique_ptr;
using std::cout;
using std::endl;
using std::unordered_map;
using std::vector;
using std::set;

using llvm::Module;
using llvm::SMDiagnostic;
using llvm::LLVMContext;
using llvm::parseIRFile;
using llvm::StringRef;
using llvm::ExecutionEngine;
using llvm::EngineBuilder;
using llvm::ArrayRef;
using llvm::GenericValue;
using llvm::Function;
using llvm::CallGraph;
using llvm::StructType;
using llvm::DataLayout;
using llvm::Type;
using llvm::PointerType;
using llvm::ArrayType;
using llvm::IntegerType;
using llvm::FunctionType;
using llvm::StructLayout;
using llvm::TargetLibraryInfo;
using llvm::LibFunc;

void print_types_helper(set<struct type_info *> &entity_processed,
  struct type_info *type_info)
{
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
    cout << "Child offset is " << child_type->offset <<  ". ";
    cout << "Child Address is " << child_type->type_info << ". ";
    cout << "Child Name is " << child_type->name << "\n";
  }
  cout << "\n";

  for (int j = 0; j < type_info->child_types->size(); j++) {
    struct child_type *child_type = (*type_info->child_types)[j];
    print_types_helper(entity_processed, child_type->type_info);
  }
}

void print_types(unordered_map<Type *, struct type_info *> &types)
{
  cout << "Size of types is " << types.size() << "\n\n";

  set<struct type_info *> entity_processed;
  for (auto& t : types) {
    struct type_info *type_info = t.second;
    print_types_helper(entity_processed, type_info);
  }
}

void saveChildType(vector<struct child_type *> *child_types,
  struct type_info *child_type_info, size_t offset)
{
  struct child_type *child_type = new struct child_type;
  child_type->offset = offset;
  child_type->type_info = child_type_info;
  child_types->insert(child_types->end(), child_type);
}

struct type_info *extract_types(DataLayout &dataLayout,
  unordered_map<Type *, struct type_info *> &types,
  Type *type)
{
  unordered_map<Type *, struct type_info *>::const_iterator got =
    types.find(type);
  if (got != types.end())
    return got->second;

  // Create new type_info
  struct type_info *type_info = new struct type_info;
  type_info->type = type->getTypeID();
  // printf("a\n");
  memset(type_info->name, 0, 4096);
  // printf("b\n");

  if (type->isSized())
    type_info->size = dataLayout.getTypeAllocSize(type);
  else
    type_info->size = 0;

  type_info->child_types = new vector<struct child_type *>();
  vector<struct child_type *> *child_types = type_info->child_types;
  types[type] = type_info;

  if (type->isPointerTy()) {
    strcpy(type_info->name, "pointer");

    Type *child_type = type->getContainedType(0);
    struct type_info *child_type_info = extract_types(dataLayout, types, child_type);
    saveChildType(child_types, child_type_info, 0);
  } else if (type->isStructTy()) {
    StructType *structType = (StructType *)type;
    const StructLayout *structLayout = dataLayout.getStructLayout(structType);
    if (structType->hasName())
      strcpy(type_info->name, (char *)structType->getName().data());
    else
      strcpy(type_info->name, "struct.unnamed");

    for (int i = 0; i < structType->getNumElements(); i++) {
      Type *child_type = structType->getTypeAtIndex(i);
      uint64_t offset = structLayout->getElementOffset(i);
      struct type_info *child_type_info = extract_types(dataLayout, types, child_type);
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
      struct type_info *child_type_info = extract_types(dataLayout, types, child_type);
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

void detail_type(set<struct type_info *> entity_processed,
  struct type_info *type_info)
{
  const bool is_in = entity_processed.find(type_info) != entity_processed.end();
  if (is_in)
    return;
  entity_processed.insert(type_info);

  // printf("ayo\n");

  for (int i = 0; i < type_info->child_types->size(); i++) {
    struct child_type *child_type = (*type_info->child_types)[i];
    struct type_info *child_type_info = child_type->type_info;
    detail_type(entity_processed, child_type_info);
    strcpy(child_type->name, child_type_info->name);
  }

  if (type_info->name == NULL) {

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

void detail_types(unordered_map<Type *, struct type_info *> &types)
{
  set<struct type_info *> entity_processed;
  for (auto& t : types) {
    struct type_info *type_info = t.second;

    detail_type(entity_processed, type_info);
  }
}

bool remove_non_ptr_types(
  unordered_map<struct type_info *, bool> &entity_contains_ptr,
  set<struct type_info *> &entity_processed,
  struct type_info *type_info)
{
  unordered_map<struct type_info *, bool>::const_iterator got =
    entity_contains_ptr.find(type_info);
  if (got != entity_contains_ptr.end())
    return got->second;

  const bool is_in = entity_processed.find(type_info) != entity_processed.end();
  if (is_in)
    return true;
  entity_processed.insert(type_info);

  bool contains_ptr = false;

  vector<struct child_type *> *child_types = type_info->child_types;
  vector<struct child_type *>::iterator it;
  for (it = child_types->begin(); it != child_types->end();) {
    struct child_type *child_type = *it;
    if (child_type->type_info == type_info)
      continue;

    bool child_contains_ptr = 
      remove_non_ptr_types(entity_contains_ptr, entity_processed, child_type->type_info);
    if (child_contains_ptr) {
      contains_ptr = true;
      it++;
    } else
      it = child_types->erase(it);
  }

  bool containsPtr =
    contains_ptr || type_info->type == Type::PointerTyID;
  entity_contains_ptr[type_info] = containsPtr;
  return containsPtr;
}

void extract_ptr_types(unordered_map<Type *, struct type_info *> &structs)
{
  unordered_map<struct type_info *, bool> entity_contains_ptr;
  set<struct type_info *> entity_processed;
  for (auto& t : structs) {
    struct type_info *type_info = t.second;

    remove_non_ptr_types(entity_contains_ptr, entity_processed, type_info);
  }
}

size_t updateSize(set<struct type_info *> &entity_processed,
  size_t &size,
  struct type_info *type_info)
{
  const bool is_in = entity_processed.find(type_info) != entity_processed.end();
  if (is_in)
    return 0;
  entity_processed.insert(type_info);

  size_t child_types_size = type_info->child_types->size();
  size_t ent_size = 3 + child_types_size;
  for (int j = 0; j < child_types_size; j++) {
    struct child_type *child_type = (*type_info->child_types)[j];
    size += updateSize(entity_processed, size, child_type->type_info);
  }

  return ent_size;
}

size_t compute_arr_size(unordered_map<Type *, struct type_info *> &structs)
{
  size_t size = 0;
  set<struct type_info *> entity_processed;

  for (auto& t : structs) {
    struct type_info *type_info = t.second;

    size += updateSize(entity_processed, size, type_info);
  }
  return size;
}

int setEntInArray(uint64_t *ent_array,
  unordered_map<struct type_info *, int> &ent_to_index, int &ind,
  unordered_map<struct type_info *, int> &ent_to_id, int &id,
  struct type_info *type_info)
{
  unordered_map<struct type_info *, int>::const_iterator got =
    ent_to_index.find(type_info);
  if (got != ent_to_index.end())
    return got->second;
  ent_to_index[type_info] = ind;
  ent_to_id[type_info] = id++;

  size_t child_types_size = type_info->child_types->size();
  int local_ind = ind;
  ind += 3 + child_types_size;

  ent_array[local_ind++] = ent_to_id[type_info];
  ent_array[local_ind++] = type_info->size;
  ent_array[local_ind++] = child_types_size;

  size_t ent_size = 3 + child_types_size;
  for (int j = 0; j < child_types_size; j++) {
    struct child_type *child_type = (*type_info->child_types)[j];
    ent_array[local_ind++] = setEntInArray(ent_array, ent_to_index, ind, ent_to_id, id, child_type->type_info);
  }

  return ent_to_index[type_info];
}

void ptrchild_typesToArray(uint64_t *ent_array,
  unordered_map<Type *, struct type_info *> &structs)
{
  int ind = 0;
  unordered_map<struct type_info *, int> ent_to_id;
  unordered_map<struct type_info *, int> ent_to_index;
  int id = 0;

  for (auto& t : structs) {
    struct type_info *type_info = t.second;

    setEntInArray(ent_array, ent_to_index, ind, ent_to_id, id, type_info);
  }
}

int main(int argc, char **argv)
{
  SMDiagnostic Err;

  LLVMContext *C = new LLVMContext();
  Module *mod = parseIRFile("./bitcode/libssl.so.1.0.0.bc", Err, *C).release();
  DataLayout dataLayout = DataLayout(mod);

  unordered_map<Type *, struct type_info *> types;
  for (StructType *type : mod->getIdentifiedStructTypes()) {
    extract_types(dataLayout, types, type);
  }

  detail_types(types);

  // print_types(types);

  extract_ptr_types(types);

  // print_types(types);

  size_t arr_size = compute_arr_size(types);
  cout << "Arr size is " << arr_size << "\n";

  uint64_t *ent_array = new uint64_t[arr_size];

  ptrchild_typesToArray(ent_array, types);

  FILE *f = fopen("lib_entity.data", "wb");
  fwrite(ent_array, sizeof(uint64_t), arr_size, f);
  fclose(f);

  // get OpenSSL all Functions:
  const TargetLibraryInfo *TLI; 
  LibFunc func;

  for (auto &F : *mod) {
    if (!TLI->getLibFunc(F, func)) {
      cout << F.getFunction().getName().data() << "\n";
      // builtins.insert(F.getFunction().getName());
      const Function &f = F.getFunction();
      FunctionType *functionType = f.getFunctionType();
      Type *returnType = functionType->getReturnType();
      returnType->dump();
      // uint numParams = functionType->getNumParams();

      // ArrayRef<Type *> paramTypes = functionType->params();
      // for (auto ref : paramTypes) {
      //   ref->dump();
      // }
      cout << "\n";
    }
  }
}
