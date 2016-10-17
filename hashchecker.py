#! /usr/bin/python3.5

import hashlib
import sys

hash_options = ["md5", "sha1"]

################################################
# MD5 hash calculator

def calculate_md5_hash(fname):
    m = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            m.update(chunk)
    return m.hexdigest()

################################################
# SHA1 hash calculator

def calculate_sha1_hash(fname):
    m = hashlib.sha1()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()

################################################
# Other helper functions

def print_help():
    print("Usage: hashchecker [hashfunction] [file] [hash]")
    print("i.e. hashchecker md5 test.txt 321168b6c5ce2f4790d3e08a5c9d8bff")

# Check whether the file checksum and the
# the given checksum match.
def check_match(checksum, fname_sum):
    if checksum == fname_sum:
        return True
    else:
        return False

# Check the hashfunction from arguments
def check_hashfunc_from_arg(hashfunction):
    if hashfunction.lower() in hash_options:
        return True

def main(arguments):

    if check_hashfunc_from_arg(sys.argv[1]):
        if sys.argv[1].lower() == "md5":
            calculate_sha1_hash(sys.argv[2])
    else:
        print("\033[1;31m>>\033[1;m Invalid hashfunction")
        print("Please use one of the following options: {}".format(hash_options))


    #print("{} : \t\t{}".format(options.filename,fname_sum))
    #print("Calculated sum : \t{}".format(options.checksum))

    #if check_match(options.checksum, fname_sum):
    #    print("\033[1;32m>>\033[1;m The checksums match!")
    #else:
    #    print("\033[1;31m>>\033[1;m The checksums do not match.")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("\033[1;31m>>\033[1;m Too few arguments. ")
        print_help()
    else:
        main(sys.argv)
