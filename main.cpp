#include <iostream>

#include <string>
#include <vector>
#include <set>
#include <stdexcept>

#include "struct_info.h"

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/SourceMgr.h>

#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/GenericValue.h>
#include <llvm/Analysis/CallGraph.h>

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
using llvm::StructLayout;

void print_structs(unordered_map<Type *, struct entity_info *> &structs)
{
  cout << "Size of structs is " << structs.size() << "\n\n";

  for (auto& t : structs) {
    // std::cout << t.first << " " << t.second << "\n";
    struct entity_info *entity_info = t.second;
    cout << "Address is " << entity_info << "\n";
    if (entity_info->name != NULL)
      cout << "Name is " << entity_info->name << "\n";
    cout << "Size is " << entity_info->size << "\n";
    for (int j = 0; j < entity_info->members->size(); j++) {
      struct member *member = (*entity_info->members)[j];
      cout << "Child offset is " << member->offset <<  ". Address is " << member->entity_info << "\n";
    }
    cout << "\n";
  }
}

struct entity_info *extractTypes(DataLayout &dataLayout,
  unordered_map<Type *, struct entity_info *> &structs,
  Type *type)
{
  unordered_map<Type *, struct entity_info *>::const_iterator got =
    structs.find(type);
  if (got != structs.end())
    return got->second;

  // Save type size
  struct entity_info *entity_info = new struct entity_info;
  entity_info->type = type->getTypeID();

  vector<struct member *> *vec = new vector<struct member *>();
  entity_info->members = vec;
  entity_info->name = "";
  if (type->isSized())
    entity_info->size = dataLayout.getTypeAllocSize(type);
  else
    entity_info->size = 0;
  structs[type] = entity_info;

  if (type->isPointerTy()) {
    entity_info->name = "pointer";

    Type *subType = type->getContainedType(0);
    struct entity_info *subTypeInfo =
      extractTypes(dataLayout, structs, subType);
    struct member *member = new struct member;
    member->offset = 0;
    member->entity_info = subTypeInfo;
    vec->insert(vec->end(), member);
  } else if (type->isStructTy()) {
    StructType *structType = (StructType *)type;
    const StructLayout *structLayout = dataLayout.getStructLayout(structType);
    entity_info->name = (char *)structType->getName().data();

    for (int i = 0; i < structType->getNumElements(); i++) {
      Type *subType = structType->getTypeAtIndex(i);
      uint64_t offset = structLayout->getElementOffset(i);
      struct entity_info *subTypeInfo =
        extractTypes(dataLayout, structs, subType);
      struct member *member = new struct member;
      member->offset = offset;
      member->entity_info = subTypeInfo;
      vec->insert(vec->end(), member);
    }
  } else if (type->isArrayTy()) {
    entity_info->name = "array";

    ArrayType *arrayType = (ArrayType *)type;
    Type *subType = arrayType->getElementType();
    struct entity_info *subTypeInfo =
      extractTypes(dataLayout, structs, subType);
    struct member *member = new struct member;
    member->offset = 0;
    member->entity_info = subTypeInfo;
    vec->insert(vec->end(), member);
  } else if (type->isIntegerTy()) {
    entity_info->name = "int";

    IntegerType *integerType = (IntegerType *)type;
    entity_info->size = integerType->getBitWidth();
  } else if (type->isFunctionTy()) {
    entity_info->name = "func";
  }

  return entity_info;
}

bool removeNonPtrMembers(
  unordered_map<struct entity_info *, bool> &entity_has_ptr_member,
  set<struct entity_info *> &entity_processed,
  struct entity_info *entity_info)
{
  unordered_map<struct entity_info *, bool>::const_iterator got =
    entity_has_ptr_member.find(entity_info);
  if (got != entity_has_ptr_member.end())
    return got->second;

  const bool is_in = entity_processed.find(entity_info) != entity_processed.end();
  if (is_in)
    return true;
  entity_processed.insert(entity_info);

  bool hasPtrMember = false;

  vector<struct member *> *members = entity_info->members;
  vector<struct member *>::iterator it;
  for (it = members->begin(); it != members->end();) {
    struct member *member = *it;
    if (member->entity_info == entity_info)
      continue;

    bool childHasPtrMember = 
      removeNonPtrMembers(entity_has_ptr_member, entity_processed, member->entity_info);
    if (childHasPtrMember) {
      hasPtrMember = true;
      it++;
    } else
      it = members->erase(it);
  }

  bool containsPtrMember =
    hasPtrMember || entity_info->type == Type::PointerTyID;
  entity_has_ptr_member[entity_info] = containsPtrMember;
  return containsPtrMember;
}

void extractPtrMembers(unordered_map<Type *, struct entity_info *> &structs)
{
  unordered_map<struct entity_info *, bool> entity_has_ptr_member;
  set<struct entity_info *> entity_processed;
  for (auto& t : structs) {
    struct entity_info *entity_info = t.second;

    removeNonPtrMembers(entity_has_ptr_member, entity_processed, entity_info);
  }
}

size_t updateSize(set<struct entity_info *> &entity_processed, size_t &size,
  struct entity_info *entity_info)
{
  const bool is_in = entity_processed.find(entity_info) != entity_processed.end();
  if (is_in)
    return 0;
  entity_processed.insert(entity_info);

  size_t members_size = entity_info->members->size();
  size_t ent_size = 3 + members_size;
  for (int j = 0; j < members_size; j++) {
    struct member *member = (*entity_info->members)[j];
    size += updateSize(entity_processed, size, member->entity_info);
  }

  return ent_size;
}

size_t determineArrSize(unordered_map<Type *, struct entity_info *> &structs)
{
  size_t size = 0;
  set<struct entity_info *> entity_processed;

  for (auto& t : structs) {
    struct entity_info *entity_info = t.second;

    size += updateSize(entity_processed, size, entity_info);
  }
  return size;
}

int setEntInArray(uint64_t *ent_array,
  unordered_map<struct entity_info *, int> &ent_to_index, int &ind,
  unordered_map<struct entity_info *, int> &ent_to_id, int &id,
  struct entity_info *entity_info)
{
  unordered_map<struct entity_info *, int>::const_iterator got =
    ent_to_index.find(entity_info);
  if (got != ent_to_index.end())
    return got->second;
  ent_to_index[entity_info] = ind;
  ent_to_id[entity_info] = id++;

  size_t members_size = entity_info->members->size();
  int local_ind = ind;
  ind += 3 + members_size;

  ent_array[local_ind++] = ent_to_id[entity_info];
  ent_array[local_ind++] = entity_info->size;
  ent_array[local_ind++] = members_size;

  size_t ent_size = 3 + members_size;
  for (int j = 0; j < members_size; j++) {
    struct member *member = (*entity_info->members)[j];
    ent_array[local_ind++] = setEntInArray(ent_array, ent_to_index, ind, ent_to_id, id, member->entity_info);
  }

  return ent_to_index[entity_info];
}

void ptrMembersToArray(uint64_t *ent_array,
  unordered_map<Type *, struct entity_info *> &structs)
{
  int ind = 0;
  unordered_map<struct entity_info *, int> ent_to_id;
  unordered_map<struct entity_info *, int> ent_to_index;
  int id = 0;

  for (auto& t : structs) {
    struct entity_info *entity_info = t.second;

    setEntInArray(ent_array, ent_to_index, ind, ent_to_id, id, entity_info);
  }
}

int main(int argc, char **argv)
{
  SMDiagnostic Err;

  LLVMContext *C = new LLVMContext();
  Module *mod = parseIRFile("/home/haruki/libssl.so.1.0.0.bc", Err, *C).release();
  DataLayout dataLayout = DataLayout(mod);

  unordered_map<Type *, struct entity_info *> structs;
  for (StructType *type : mod->getIdentifiedStructTypes()) {
    extractTypes(dataLayout, structs, type);
  }

  extractPtrMembers(structs);

  size_t arr_size = determineArrSize(structs);
  cout << "Arr size is " << arr_size << "\n";

  uint64_t *ent_array = new uint64_t[arr_size];

  ptrMembersToArray(ent_array, structs);

  for (int i = 0; i < arr_size; i++) 
    cout << ent_array[i] << " ";
}