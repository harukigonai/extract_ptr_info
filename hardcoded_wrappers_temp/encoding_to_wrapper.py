import collections
import os
import sys
import pathlib

headers = """#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ui.h>
#include <openssl/safestack.h>
#include <openssl/ssl.h>
#include <openssl/e_os2.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/srp.h>

#include "../arg_struct.h"

"""

def get_func_dicts(filename):
    f = open(filename, "r")

    funcs = dict()

    l = f.readline()
    while l != "":
        di = dict()
        func_parts = l.strip().split(";")
        if l[0] != "void":
            di["ret"] = func_parts[0]
        else:
            di["ret"] = None
        di["name"] = func_parts[1]
        num_args = 0
        if func_parts[2] != "void":
            di["args"] = []
            for i in range(2, len(func_parts), 2):
                arg_dict = dict()
                arg_dict["type"] = func_parts[i]
                arg_dict["arg"] = func_parts[i + 1]
                num_args += 1

                di["args"].append(arg_dict)
        di["num_args"] = num_args

        funcs[di["name"]] = di

        l = f.readline()
    return funcs

def generate_function_wrappers(funcs, wrapper_output_dir, ent_metadata_dir):
    od = collections.OrderedDict(sorted(funcs.items()))
    for k in od:
        func_dict = od[k]
        generate_function_wrapper(func_dict, wrapper_output_dir, ent_metadata_dir)

def generate_function_wrapper(func_dict, wrapper_output_dir, ent_metadata_dir):
    ret_type = func_dict["ret"]
    func_name = func_dict["name"]

    wrapper_filename = os.path.join(wrapper_output_dir, f"{func_name}_wrapper.c")
    f_out = open(wrapper_filename, "w")

    # write #includes
    f_out.write(headers)

    type_str = ""
    arg_str = ""
    arg_call_str = ""
    num_args = func_dict["num_args"]
    if num_args == 0:
        arg_str = "void"
        type_str = "void"
    else:
        li_of_args = [arg_dict["arg"] for arg_dict in func_dict["args"]]
        arg_str = ",".join(li_of_args)
        li_of_types = [arg_dict["type"] for arg_dict in func_dict["args"]]
        type_str = ",".join(li_of_types)

    # function header
    dlsym_func_ptr_name = f"orig_{func_name}"

    li_of_args_to_pass_in = [f"arg_{num_to_letter(i)}" for i in range(num_args)]
    args_to_pass_in = ",".join(li_of_args_to_pass_in)

    func_text =  f"{ret_type} bb_{func_name}({arg_str});" + "\n"
    func_text += "\n"
    func_text += f"{ret_type} {func_name}({arg_str}) " + "\n"
    func_text +=  "{\n"
    # add print for debugging (remove later)
    func_text +=  "    unsigned long in_lib = syscall(890);\n"
    # func_text += f"    printf(\"{func_name} called\\n\");\n"
    # func_text +=  "    if (!syscall(890))\n"
    func_text += f"    printf(\"{func_name} called %x\\n\", in_lib);\n"
    func_text +=  "    if (!in_lib)\n"

    if ret_type != "void":
        func_text += f"        return bb_{func_name}({args_to_pass_in});\n"
    else:
        func_text += f"        bb_{func_name}({args_to_pass_in});\n"

    func_text +=  "    else {\n"
    func_text += f"        {ret_type} (*{dlsym_func_ptr_name})({type_str});\n"
    func_text += f"        {dlsym_func_ptr_name} = dlsym(RTLD_NEXT, \"{func_name}\");\n"

    if ret_type != "void":
        func_text += f"        return {dlsym_func_ptr_name}({args_to_pass_in});\n"
    else:
        func_text += f"        {dlsym_func_ptr_name}({args_to_pass_in});\n"

    func_text +=  "    }\n"
    func_text +=  "}\n"
    func_text +=  "\n"

    func_text += f"{ret_type} bb_{func_name}({arg_str}) " + "\n"
    func_text += "{\n"

    # declare return variable
    if ret_type != "void":
        func_text += f"    {ret_type} ret;\n\n"
    else:
        pass

    # start struct lib_enter_args
    func_text += "    struct lib_enter_args args = {\n"

    # zero out num_args
    func_text += "        .num_args = 0,\n"

    # start entity_metadata
    func_text += "        .entity_metadata = {\n"
    ent_meta_filename = os.path.join(ent_metadata_dir, f"{func_name}.entity_metadata")
    f_ent_meta = open(ent_meta_filename, "r")
    line = f_ent_meta.readline()
    while line != "":
        func_text += f"            {line}"
        line = f_ent_meta.readline()
    func_text += "        },\n"
    # end entity_metadata

    # start arg_entity_index
    arg_ent_ind_filename = os.path.join(ent_metadata_dir, f"{func_name}.arg_entity_index")
    f_arg_ent_ind = open(arg_ent_ind_filename, "r")
    line = f_arg_ent_ind.readline()
    line = line.strip()
    func_text += "        .arg_entity_index = { " + line + " },\n"
    # end arg_entity_index

    # start ret_entity_index
    ret_ent_ind_filename = os.path.join(ent_metadata_dir, f"{func_name}.ret_entity_index")
    f_ret_ent_ind = open(ret_ent_ind_filename, "r")
    line = f_ret_ent_ind.readline()
    line = line.strip()
    func_text += f"        .ret_entity_index = {line},\n"
    # end ret_entity_index

    func_text += "    };\n"

    # end struct lib_enter_args

    func_text += "    struct lib_enter_args *args_addr = &args;\n"

    # populate args and ret
    for i in range(func_dict["num_args"]):
        let = f"arg_{num_to_letter(i)}"
        func_text += f"    populate_arg(args_addr, {let});\n"

    if ret_type != "void":
        func_text += f"    populate_ret(args_addr, ret);\n"
    else:
        pass

    func_text += "\n"

    # Call syscall 888
    func_text += "    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);\n\n"

    # Get new args from new_args
    if num_args == 0:
        pass
    else:
        li_of_args = [arg_dict["arg"] for arg_dict in func_dict["args"]]
        li_of_types = [arg_dict["type"] for arg_dict in func_dict["args"]]
        for i in range(len(li_of_args)):
            new_arg = li_of_args[i]
            type = li_of_types[i]
            ptr_type = type_to_ptr_type(type)

            arg_let = num_to_letter(i)
            orig_arg_name = f"arg_{arg_let}"
            new_arg_name = f"new_{orig_arg_name}"
            new_arg = new_arg.replace(orig_arg_name, new_arg_name)
            func_text += f"    {new_arg} = *(({ptr_type})new_args->args[{i}]);\n\n"

    # Declare and initialize return value ptr
    if ret_type != "void":
        ret_type_ptr = type_to_ptr_type(ret_type)
        func_text += f"    {ret_type} *new_ret_ptr = ({ret_type_ptr})new_args->ret;\n\n"
    else:
        pass

    # dlsym stuff
    dlsym_func_ptr_name = f"orig_{func_name}"
    func_text += f"    {ret_type} (*{dlsym_func_ptr_name})({type_str});\n"
    func_text += f"    {dlsym_func_ptr_name} = dlsym(RTLD_NEXT, \"{func_name}\");\n"

    # Call the actual library function and assign to *new_ret_ptr
    li_of_args = [f"new_arg_{num_to_letter(i)}" for i in range(num_args)]
    new_arg_str = ",".join(li_of_args)
    func_call = f"(*{dlsym_func_ptr_name})({new_arg_str})"
    if ret_type != "void":
        func_text += f"    *new_ret_ptr = {func_call};\n\n"
    else:
        func_text += f"    {func_call};\n\n"

    # Call syscall 889
    func_text += "    syscall(889);\n\n"

    # Return
    if ret_type != "void":
        func_text += f"    return ret;\n"
    else:
        pass

    func_text += "}\n\n"

    f_out.write(func_text)

def num_to_letter(i):
    return chr(i + ord('a'))

def type_to_ptr_type(type):
    if "(*)" in type:
        ptr_type = type.replace("(*)", "(**)")
    else:
        ptr_type = f"{type} *"
    return ptr_type

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ["clean", "gen"]:
        print("Usage: python3 encoding_to_wrapper.py [clean | gen]")
        return

    cwd = os.getcwd()
    func_info_filename = os.path.join(cwd, "func_info")
    wrapper_output_dir = os.path.join(cwd, "wrapper_library", "generated_wrappers")
    ent_metadata_dir = os.path.join(os.path.dirname(cwd), "entity_metadata_constructor", "bin")

    arg = sys.argv[1]
    if arg == "clean":
        for path in pathlib.Path(wrapper_output_dir).glob("**/*"):
            if path.is_file() and "Makefile" not in path.name:
                path.unlink()
        return

    funcs = get_func_dicts(func_info_filename)
    generate_function_wrappers(funcs, wrapper_output_dir, ent_metadata_dir)

if __name__ == "__main__":
    main()
