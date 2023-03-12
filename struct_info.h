#ifndef __STRUCT_INFO_H__
#define __STRUCT_INFO_H__

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
using std::tuple;

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

struct member {
    size_t offset;
    struct entity_info *entity_info;
};

struct entity_info {
    char *name;
    Type::TypeID type;
    size_t size;
    vector<struct member *> *members;
};

#endif