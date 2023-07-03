# GhidraScript Tool: String Extraction and Merging
# Category: Analysis
# Keybinding: Ctrl+Shift+E
# Menupath: Tools > String Extraction and Merging
# Author: Raeld Zues
# Date: 2023-07-02

import re
import collections
import operator
from ghidra.program.model.listing import CodeUnit


def extract_strings_from_mnemonics(program, mnemonics):
    """
    Extracts strings from instructions with specified mnemonics.

    Args:
        program (ghidra.program.model.listing.Program): The program to extract strings from.
        mnemonics (list[str]): List of mnemonics to filter instructions.

    Returns:
        collections.OrderedDict: A sorted dictionary containing addresses and extracted strings.
    """
    listing = program.getListing()
    pattern = r'\[0x(.*?)\]'
    strings_dict = {}

    instructions = listing.getInstructions(True)
    while instructions.hasNext():
        instruction = instructions.next()
        mnemonic = instruction.getMnemonicString()

        if mnemonic in mnemonics:
            op1 = instruction.getOpObjects(0)
            op2 = instruction.getOpObjects(1)
            matches = re.findall(pattern, str(op2))

            if matches:
                match = matches[0]
                if len(match) % 2 == 0:
                    try:
                        c_string = ""
                        for i in range(0, len(match), 2):
                            value = int(match[i:i + 2], 16)
                            if value == 0:
                                break
                            c_string += chr(value)

                        if c_string:
                            strings_dict[instruction.getAddress()] = c_string

                    except Exception as e:
                        pass

    sorted_dict = collections.OrderedDict(sorted(strings_dict.items(), key=operator.itemgetter(0)))
    return sorted_dict


def merge_strings(sorted_dict):
    """
    Merges contiguous strings and sets pre-comments for specific prefixes.

    Args:
        sorted_dict (collections.OrderedDict): A sorted dictionary of addresses and strings.
    """
    combined_strings = []
    prev_address = None
    prefixes = [
        "Nt", "Zw", "Ldr", "Rtl", "Ex", "Dbg", "Hal", "Io", "Ps", "Se",
        "AdvApi", "Win", "Net", "Crypt", "PE", "MZ"
    ]

    for address, value in sorted_dict.items():
        if prev_address is not None and address.getOffset() - prev_address.getOffset() <= 16:
            if all(0x20 <= ord(c) <= 0x7E for c in value):
                combined_strings.append(value)
            else:
                if combined_strings:
                    combined_string = ''.join(combined_strings[::-1])[::-1]
                    if any(combined_string.startswith(prefix) for prefix in prefixes):
                        set_pre_comment(prev_address, combined_string)
                        print("Combined String (Pre-Comment Added): {}, Address: {}".format(combined_string, prev_address))
                    combined_strings = []
                combined_strings.append(value)
        else:
            if combined_strings:
                combined_string = ''.join(combined_strings[::-1])[::-1]
                if any(combined_string.startswith(prefix) for prefix in prefixes):
                    set_pre_comment(prev_address, combined_string)
                    print("Combined String (Pre-Comment Added): {}, Address: {}".format(combined_string, prev_address))
                combined_strings = []
            combined_strings.append(value)

        prev_address = address

    if combined_strings:
        combined_string = ''.join(combined_strings[::-1])[::-1]
        if any(combined_string.startswith(prefix) for prefix in prefixes):
            set_pre_comment(prev_address, combined_string)
            print("Combined String (Pre-Comment Added): {}, Address: {}".format(combined_string, prev_address))


def set_pre_comment(address, comment):
    """
    Sets the pre-comment for a specified address.

    Args:
        address (ghidra.program.model.address.Address): The address to set the pre-comment.
        comment (str): The pre-comment string.
    """
    listing = currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(address)
    code_unit.setComment(CodeUnit.PRE_COMMENT, comment)


# Script entry point
if __name__ == '__main__':
    # Specify the mnemonics to extract strings from
    mnemonics_to_extract = ["CMP"]

    # Extract strings from the current program
    sorted_dict = extract_strings_from_mnemonics(currentProgram, mnemonics_to_extract)

    # Merge and set pre-comments for the extracted strings
    merge_strings(sorted_dict)
