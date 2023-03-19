#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/Analysis/TargetLibraryInfo.h>

#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Analysis/TargetLibraryInfo.h>

using llvm::Function;
using llvm::Argument;
using llvm::Module;
using llvm::SMDiagnostic;
using llvm::LLVMContext;
using llvm::parseIRFile;
using llvm::DataLayout;
using llvm::Type;
using llvm::raw_string_ostream;
using llvm::LibFunc;
using llvm::TargetLibraryInfo;
using llvm::TargetLibraryInfoImpl;
using llvm::Triple;
using llvm::Attribute;
// using llvm::CallingConv;

int get_type_str(Type *type, char *buf, bool isConst, int max_len) {
    if (!type) return -1;

    std::string str;
    raw_string_ostream os(str);
    if (isConst) os << "const ";
    type->print(os);

    strncpy(buf, str.c_str(), max_len);
    return strlen(buf);
}

void dumpFuncArgType(char *funcName, int argNo, Type *type, bool isConst) {
    char typeBuf[50] = {0}; // TODO: hardcoded for now, fix
    char outBuf[200] = {0};  // TODO: hardcoded for now, fix
    get_type_str(type, typeBuf, isConst, sizeof(typeBuf));
    sprintf(outBuf, "%s$%02d:%s", funcName, argNo, typeBuf);
    printf("%s\n", outBuf);
}

bool runOnFunction(Function &F) {
    char funcName[100] = {0}; // TODO: hardcoded size for now, fix
    strcpy(funcName, F.getName().str().c_str());

    for (const Argument &arg : F.args()) {
        dumpFuncArgType(funcName, arg.getArgNo(), arg.getType(), arg.onlyReadsMemory()); // arg.hasAttribute(Attribute::ReadOnly));
    }

    bool isRetConst = F.getAttributes().getRetAttributes().hasAttribute(Attribute::ReadOnly); // doesn't currently work, always False
    dumpFuncArgType(funcName, -1, F.getReturnType(), isRetConst);

    return false;
}


int main(int argc, char **argv)
{
    SMDiagnostic Err;

    LLVMContext *C = new LLVMContext();
    Module *mod = parseIRFile("./bitcode/libssl.a.bc", Err, *C).release();
    // Module *mod = parseIRFile("./bitcode/hello.bc", Err, *C).release();
    DataLayout dataLayout = DataLayout(mod);

    const TargetLibraryInfo *TLI = new TargetLibraryInfo(TargetLibraryInfoImpl(Triple(mod->getTargetTriple())));
    LibFunc func;

    for (auto &F : *mod) {
        if (!TLI->getLibFunc(F, func)) {
            Function &f = (Function&)F.getFunction();
            runOnFunction(f);
        }
    }
}
