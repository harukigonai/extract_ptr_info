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
    func_text = f"{ret_type} {func_name}({arg_str}) " + "\n"
    func_text += "{\n"

    # declare return variable
    if ret_type != "void":
        func_text += f"    {ret_type} ret;\n\n"
    else:
        pass

    # dlsym stuff
    dlsym_func_ptr_name = f"orig_{func_name}"
    func_text += f"    {ret_type} (*{dlsym_func_ptr_name})({type_str});\n"
    func_text += f"    {dlsym_func_ptr_name} = dlsym(RTLD_NEXT, \"{func_name}\");\n"

    # Call the actual library function and assign to *new_ret_ptr
    li_of_args = [f"arg_{num_to_letter(i)}" for i in range(num_args)]
    new_arg_str = ",".join(li_of_args)
    func_call = f"(*{dlsym_func_ptr_name})({new_arg_str})"
    if ret_type != "void":
        func_text += f"    ret = {func_call};\n\n"
    else:
        func_text += f"    {func_call};\n\n"

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
    wrapper_output_dir = os.path.join(cwd, "wrapper_library_ignore", "generated_wrappers")
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
