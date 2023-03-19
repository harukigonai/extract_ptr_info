import sys
from collections import defaultdict
import re
import warnings

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

_IR_to_C_primitive_type_mapping = {
        "i1": "bool",
        "i8": "char",
        "i16": "short",
        "i32": "int",
        "i64": "long",
        "double": "double",
        "fp128": "long double",
        "fp64": "double",  
        "float": "float",
        "void": "void",
}

def _get_IR_to_C_primitive_type_mapping(IR_type):
        if IR_type not in _IR_to_C_primitive_type_mapping:
                raise NotImplementedError(f"The IR type '{IR_type}' has not been mapped to a C mapping. Please ensure that it is a valid IR type, and if so, please update the '_IR_to_C_primitive_type_mapping' dict")
        return _IR_to_C_primitive_type_mapping[IR_type]

def process_const(IR_type):
        if "const " in IR_type:
                assert "*" in IR_type
                return "const "
        return ""

def process_struct(IR_type):
        if f"%struct" in IR_type:
                struct_name = re.search("[^*]*", IR_type[len(f"%struct."):]).group(0) # find name of struct
                if re.search("\.\d+", struct_name):
                        struct_name = struct_name.split(".")[0] # some structs are outputted as 'struct.ssl_st.3566*', get rid of the .3566
                ptrs = "*" * IR_type.count("*") 
                return f"struct {struct_name}{ptrs}"
        return ""

def process_union(IR_type):
        if f"%union" in IR_type:
                struct_name = re.search("[^*]*", IR_type[len(f"%union."):]).group(0) # find name of struct
                ptrs = "*" * IR_type.count("*") 
                return f"union {struct_name}{ptrs}"
        return ""

def process_function(IR_type):
        if f"(" in IR_type and ")" in IR_type and "*" == IR_type[-1]:
                return "FUNCTION:TODO"
        return ""

def process_primitive_type(IR_type):
        IR_type_name = re.search("[^*]*", IR_type).group(0)
        assert IR_type_name
        c_name = _get_IR_to_C_primitive_type_mapping(IR_type_name)
        ptrs = "*" * IR_type.count("*")
        return f"{c_name}{ptrs}"
        
def get_IR_to_C_mapping(IR_type):
        IR_type = IR_type.strip()
        if (c_type := process_const(IR_type)):  # if data type is const
                IR_type = IR_type[len("const "):]

        if (parsed_type := process_function(IR_type)): pass # e.g "double func(void)*"
        elif (parsed_type := process_struct(IR_type)): pass # e.g. "struct my_struct *"
        elif (parsed_type := process_union(IR_type)): pass # e.g. "union my_union *"
        elif (parsed_type := process_primitive_type(IR_type)): pass # e.g "double **"
        else: assert NotImplementedError(f"Cannot parse the IR type {IR_type}")

        c_type += parsed_type
        return c_type

if __name__ == "__main__":
        function_arg_map = defaultdict(list)
        for line in sys.stdin.buffer.readlines():
                try: 
                        line = line.decode('utf-8')
                except UnicodeDecodeError:
                        print(f"{bcolors.WARNING} Can't decode {line}, skipping... {bcolors.ENDC}")
                        continue
                if "$" not in line or ":" not in line:
                        print(f"{bcolors.WARNING} Can't parse IR {line}, skipping... {bcolors.ENDC}")
                        continue
                func_name, arg_info = line.split("$")
                arg_no, arg_type = arg_info.split(":")
                function_arg_map[func_name].append(arg_type.strip())

        print(f"{bcolors.OKGREEN}\n\nGenerated Function Headers:\n{bcolors.ENDC}")
        for func_name, arg_list in function_arg_map.items():
                assert arg_list
                header = ""
                header += get_IR_to_C_mapping(arg_list[-1]) + " "  # return type
                header += func_name + "("
                for i, IR_type in enumerate(arg_list[:-1]): # process func args
                        header += get_IR_to_C_mapping(IR_type)
                        if i != len(arg_list) - 2: # if not the last argument
                                header += ", "
                header += ");\n"
                # print(func_name + " " + str(arg_list))
                print(header)
        









