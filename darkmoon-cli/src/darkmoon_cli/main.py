"""This is the main.py file."""

###########
# IMPORTS #
###########

import hashlib
import platform
from pathlib import Path
from typing import Any

import pefile
import requests
import typer
from settings import settings

####################
# GLOBAL VARIABLES #
####################

app = typer.Typer()


#############
# FUNCTIONS #
#############


# function to iterate over files using os


@app.command()
def get_metadata(path: Path) -> None:
    """
    Call all of the metadata functions.

        Parameters:
            path(Path): The path of the file that metadata will be extracted from.
        Returns:
            json(str): The metadata of the file formated in json format.

    """
    # name of the file
    curr_filename = path.name

    # file type
    extension = path.suffix

    # Hashes of the file in list form
    hash_list = get_hashes(path)

    # Operating System
    operating_system = str(platform.platform())

    # Source ISO
    source_iso_data = get_source_iso()

    # Rich PE header hash

    # print statements used for testing
    print("Name:" + curr_filename)
    print("file_extension:" + extension)
    print("Hashes:" + str(hash_list))
    print("OS:" + operating_system)
    print("ISO:" + source_iso_data)

    data_fields = {
        "name": curr_filename,
        "file_extension": extension,
        "hashes": list(hash_list),
        "source_ISO_name": source_iso_data,
        "header_info": {},
    }

    # rich PE header hash
    if extension == ".exe":
        pe_header = get_header_hashes(path)
        pe_sig = get_header_sig(path)
        pe_timestamp = get_time(path)
        pe_mach = get_machine(path)
        pe_comptime = get_compile_time(path)

        exe_metadata = {
            "architecture": pe_mach,
            "timestamp": pe_timestamp,
            "compile_time": pe_comptime,
            "signature": pe_sig,
        }

        data_fields["header_info"] = exe_metadata

        print("rich_pe_header_hash:" + str(pe_header))
        print("PE Signature:" + str(pe_sig))
        print("PE_Timestamp:" + str(pe_timestamp))
        print("Compile Time: " + str(pe_comptime))
        print("Machine: " + str(pe_mach))
    print("\n")

    api_response = requests.post(settings.API_URL + "/incoming-files", json=data_fields)
    api_response.json()
    status = api_response.status_code
    if status == 200:
        print("Working")
    elif status == 404:
        print("Server not found")
    else:
        print("Error: Not working")
    print(status)


@app.command()
def get_hashes(path: Path) -> list[str]:
    """
    Create a list of hashes for files.

    Uses hashlib library.

        Parameters:
            None
        Returns:
            list

    """
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    h_sha512 = hashlib.sha512()

    store_hash = [h_md5, h_sha1, h_sha256, h_sha512]
    all_hashes = []

    with open(path, "rb") as file:
        # read file in chunks and update hash
        while True:
            data = file.read(1024)
            if not data:
                break
            for hash in store_hash:
                hash.update(data)

    for hash in store_hash:
        all_hashes.append(hash.hexdigest())

    # return the hex digest
    return all_hashes


@app.command()
def get_source_iso() -> str:
    """
    Extract source ISO metadata.

        Parameters:
            None
        Returns:
            String

    """
    return "source ISO"


@app.command()
def get_header_hashes(exe_file: Path) -> list[str]:
    """
    Get a list of rich PE hash headers.

    Uses pefile library.

        Parameters:
            None
        Returns:
            list
    """
    # check that it is .exe in main func using glob
    binarymd5 = pefile.PE(exe_file)
    binarysha1 = pefile.PE(exe_file)
    binarysha256 = pefile.PE(exe_file)
    binarysha512 = pefile.PE(exe_file)

    binary_hash = [binarymd5, binarysha1, binarysha256, binarysha512]
    all_header_hash = []
    # adds all PE rich headers to a list

    for hash in binary_hash:
        all_header_hash.append(hash.get_rich_header_hash())

    return all_header_hash


@app.command()
def get_header_sig(exe_file: Path) -> str:
    """
    Get the signature of the .exe file.

    Uses pefile library.

        Parameters:
            .exe file
        Returns:
            string
    """
    sig = pefile.PE(exe_file)
    sig = str(sig.NT_HEADERS)
    sig_list = sig.split()
    signature = sig_list[sig_list.index("Signature:") + 1]
    return signature


@app.command()
def get_time(exe_file: Path) -> Any:
    """
    Get the timestamp of the .exe file.

    Uses pefile library.

        Parameters:
            .exe file
        Returns:
            string
    """
    time = pefile.PE(exe_file)
    time = str(time.FILE_HEADER)
    time_list = time.split()
    timestamp = str(time_list[time_list.index("TimeDateStamp:") + 1])
    for num in range(2, 8):
        timestamp += str(time_list[time_list.index("TimeDateStamp:") + num])

    return timestamp


@app.command()
def get_compile_time(exe_file: Path) -> Any:
    """
    Get the compile time of the .exe file.

    Uses pefile library.

        Parameters:
            .exe file
        Returns:
            string
    """
    compile_time = "Time to compile file"
    return compile_time


@app.command()
def get_machine(exe_file: Path) -> Any:
    """
    Get the architecture of the .exe file.

    Uses pefile library.

        Parameters:
            .exe file
        Returns:
            string
    """
    arch = pefile.PE(exe_file)
    arch = str(arch.FILE_HEADER)
    arch_list = arch.split()
    machine = arch_list[arch_list.index("Machine:") + 1]
    return machine


# function to iterate over files using pathlib
@app.command()
def iterate_files() -> None:
    """
    Iterate over folder and call metadata function for each file.

    Uses Pathlib library to access files.

        Parameters:
            None
        Returns:
            None

    """
    root = Path(settings.FILE_DIRECTORY)

    queue = []
    queue.append(root)

    while queue:
        curr_dir = queue.pop(0)

        for files in curr_dir.glob("*"):
            print(files)
            if files.is_file():
                get_metadata(files)
            else:
                queue.append(files)


if __name__ == "__main__":
    app()
