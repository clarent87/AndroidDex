from dexmodifier import *
import sys


if __name__ == "__main__":
    dm = dexmodifier.DexModifier(".dex")
    for x in  dm._make_class_offset_repo_for_modifier():
        print x

    print dm._find_start_end_index_of_class("R$layout")




