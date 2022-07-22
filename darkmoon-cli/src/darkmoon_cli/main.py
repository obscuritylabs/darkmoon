"""This is the main.py file."""

###########
# IMPORTS #
###########

import hashlib
import os
import platform
from pathlib import Path
from typing import Any

import pefile
import requests
import typer
from pefile import PEFormatError
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
    Call all of the metadata functions and send data to api endpoint.

        Parameters:
            path(Path): The path of the file that metadata will be extracted from.
        Returns:
            None

    """
    # name of the file
    curr_filename = path.name
    print("Name: " + curr_filename)

    # file type
    extension = path.suffix
    print("file_extension: " + extension)
    # Hashes of the file in list form
    hash_list = get_hashes(path)
    print("Hashes: " + str(hash_list))
    # Operating System
    operating_system = str(platform.platform())
    print("os: " + operating_system)
    # Source ISO
    source_iso_data = get_source_iso()
    print("iso: " + source_iso_data)

    # Rich PE header hash

    # print statements used for testing

    data_fields = {
        "name": curr_filename,
        "file_extension": extension,
        "hashes": list(hash_list),
        "source_ISO_name": source_iso_data,
        "header_info": {},
    }

    try:

        if extension == ".exe" or extension == ".dll":
            pe_header = get_header_hashes(path)
            print("rich_pe_header_hash: " + str(pe_header))
            pe_sig = get_header_sig(path)
            print("PE Signature: " + str(pe_sig))
            pe_timestamp = get_timestamp(path)
            print("PE_Timestamp: " + str(pe_timestamp))
            pe_mach = get_machine(path)
            print("Machine: " + str(pe_mach))
            pe_comptime = get_compile_time(path)
            print("Compile Time: " + str(pe_comptime))

            exe_metadata = {
                "machine_type": pe_mach,
                "timestamp": pe_timestamp,
                "compile_time": pe_comptime,
                "signature": pe_sig,
                "rich_header_hashes": {},
            }

            data_fields["header_info"] = exe_metadata

    except (PEFormatError):
        print("This program cannot read an NE file.")
    print("\n")

    api_response = requests.post(settings.API_URL + "/metadata", json=data_fields)
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
             path (Path): Absolute path of file.
        Returns:
            all_hashes (list[str]): List of all hashes.

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
            data = file.read(65536)
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
def get_all_exe_metadata(exe_file: Path) -> dict[str, Any]:
    """
    Obtain all exe specific metadata and returns in dictionary format.

    Uses pefile library.

        Parameters:
            exe_file (Path): Path to an exe file
        Returns:
            exe_metadata (dict[str, Any]): Dictionary of all exe metadata
    """
    pe_obj = pefile.PE(exe_file)

    # header_hashes
    all_header_hash = {"md5": "", "sha1": "", "sha256": "", "sha512": ""}
    binary_hash = ["md5", "sha1", "sha256", "sha512"]
    for hash in binary_hash:
        all_header_hash[hash] = pe_obj.get_rich_header_hash(algorithm=hash)

    # header_signature
    sig = str(pe_obj.NT_HEADERS)
    sig_list = sig.split()
    signature = sig_list[sig_list.index("Signature:") + 1]

    # compile_time
    compile_time = "Time to compile file"

    # timestamp
    file_header = str(pe_obj.FILE_HEADER)
    file_header_list = file_header.split()
    timestamp = str(file_header_list[file_header_list.index("TimeDateStamp:") + 1])
    for num in range(2, 8):
        timestamp += str(file_header_list[file_header_list.index("TimeDateStamp:") + num])

    # machine_type
    machine = file_header_list[file_header_list.index("Machine:") + 1]

    exe_metadata = {
        "machine_type": machine,
        "timestamp": timestamp,
        "compile_time": compile_time,
        "signature": signature,
        "rich_header_hashes": all_header_hash,
    }
    print(exe_metadata)
    return exe_metadata


@app.command()
def get_header_hashes(exe_file: Path) -> list[str]:
    """
    Get a list of rich PE hash headers.

    Uses pefile library.

        Parameters:
            exe_file (Path): Path to an exe file.
        Returns:
            all_header_hash (list[str]): List of all header hashes.
    """
    # check that it is .exe in main func using glob
    pe_obj = pefile.PE(exe_file)

    binary_hash = ["md5", "sha1", "sha256", "sha512"]
    all_header_hash = []
    # adds all PE rich headers to a list

    for hash in binary_hash:
        all_header_hash.append(pe_obj.get_rich_header_hash(algorithm=hash))

    print(all_header_hash)
    return all_header_hash


@app.command()
def get_header_sig(exe_file: Path) -> str:
    """
    Get the signature of the .exe file.

    Uses pefile library.

        Parameters:
            exe_file (Path): Path to an exe file.
        Returns:
            signature (str): The signature of the exe file.
    """
    sig = pefile.PE(exe_file)
    sig = str(sig.NT_HEADERS)
    sig_list = sig.split()
    signature = sig_list[sig_list.index("Signature:") + 1]
    return signature


@app.command()
def get_timestamp(exe_file: Path) -> str:
    """
    Get the timestamp of the .exe file.

    Uses pefile library.

        Parameters:
            exe_file (Path): Path to an exe file.
        Returns:
            timestamp (str): The timestamp of the exe file.
    """
    time = pefile.PE(exe_file)
    time = str(time.FILE_HEADER)
    time_list = time.split()
    timestamp = str(time_list[time_list.index("TimeDateStamp:") + 1])
    for num in range(2, 8):
        timestamp += str(time_list[time_list.index("TimeDateStamp:") + num])

    return timestamp


@app.command()
def get_compile_time(exe_file: Path) -> str:
    """
    Get the compile time of the .exe file.

        Parameters:
            exe_file (Path): Path to an exe file.
        Returns:
            compile_time (str): The compile time of the exe file.
    """
    compile_time = "Time to compile file"
    return compile_time


@app.command()
def get_machine(exe_file: Path) -> str:
    """
    Get the architecture of the .exe file.

    Uses pefile library.

        Parameters:
            exe_file (Path): Path to an exe file.
        Returns:
            machine (str): The machine type of the exe file.
    """
    arch = pefile.PE(exe_file)
    arch = str(arch.FILE_HEADER)
    arch_list = arch.split()
    machine = arch_list[arch_list.index("Machine:") + 1]
    return machine


@app.command()
def unzip_files(path: Path) -> None:
    """
    Unzip vmdk and put in new folder.

    Uses Pathlib library to access files.

        Parameters:
            path (Path): Absolute path of vmdk folder.
        Returns:
            None

    """
    os.system("mkdir -p unzippedvmdk")
    string_name = "7z x " + str(path) + " -aoa -ounzippedvmdk"
    os.system(string_name)

    print(Path(str(os.getcwd() + "/unzippedvmdk")))

    if path.suffix == ".ntfs":
        os.system("rm " + str(path))
    iterate_files(Path(str(os.getcwd() + "/unzippedvmdk")))

    os.system("rm -r " + str(os.getcwd() + "/unzippedvmdk"))


@app.command()
def iterate_unzip(path: Path) -> None:
    """
    Iterate over vmdk folder and call unzip files function for each vmdk.

    Uses Pathlib library to access files.

        Parameters:
            path (Path): Absolute path of vmdk folder.
        Returns:
            None

    """
    for vmdk in path.glob("*"):
        print(vmdk)
        unzip_files(vmdk)


# function to iterate over files using pathlib
@app.command()
def iterate_files(path: Path) -> None:
    """
    Iterate over folder and call metadata function for each file.

    Uses Pathlib library to access files.

        Parameters:
            path (Path): Absolute path of folder with extracted files from vmdk.
        Returns:
            None

    """
    root = Path(path)

    queue = []
    queue.append(root)

    while queue:
        curr_dir = queue.pop(0)

        for files in curr_dir.glob("*"):
            print(files)
            if files.suffix == ".ntfs":
                unzip_files(files)
            if files.is_file():
                get_metadata(files)
            else:
                queue.append(files)


if __name__ == "__main__":
    app()
