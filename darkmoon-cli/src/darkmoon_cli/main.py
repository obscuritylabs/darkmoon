"""This is the main.py file."""

import hashlib
import os
import platform
from pathlib import Path
from typing import Any, Optional

import pefile
import requests
import typer

app = typer.Typer()


@app.command()
def hello(name: Optional[str] = None) -> None:
    """Hello test example."""
    if name:
        typer.echo(f"Hello {name}")
    else:
        typer.echo("Hello World!")


@app.command()
def bye(name: Optional[str] = None) -> None:
    """Goodbye test example."""
    if name:
        typer.echo(f"Bye {name}")
    else:
        typer.echo("Goodbye!")


# function to iterate over files using os
@app.command()
def test() -> None:
    """
    Iterate over folder and print out metadata for each file in the folder.

    Uses os library to access files.

        Parameters:
            None
        Returns:
            None

    """
    all_files = os.listdir("faker.txt")
    for file in all_files:
        print("size:" + str(os.path.getsize(os.getcwd() + "/testing/" + file)))
        print(file + "metadata:")
        print("last motified:")
        print(str(os.path.getmtime(os.getcwd() + "/testing/" + file)))
        print("creation date:")
        print(str(os.path.getctime(os.getcwd() + "/testing/" + file)))


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
    hash_list = hashes(path)

    # Operating System
    operating_system = str(platform.platform())

    # Source ISO
    source_iso_data = source_iso()

    # Rich PE header hash

    # print statements used for testing
    print("Name:" + curr_filename)
    print("Filetype:" + extension)
    print("Hashes:" + str(hash_list))
    print("OS:" + operating_system)
    print("ISO:" + source_iso_data)

    TODO = {
        "Name": curr_filename,
        "File Extension": extension,
        "Hashes": str(hash_list),
        "OS": operating_system,
        "ISO": source_iso_data,
    }

    # rich PE header hash
    if extension == ".exe":
        pe_header = rich_pe_header_hashes(path)
        pe_sig = pe_header_sig(path)
        pe_timestamp = pe_header_time(path)
        pe_arch = pe_machine(path)
        pe_comptime = pe_header_comptime(path)

        exe_metadata = {
            "architecture": pe_arch,
            "timestamp": pe_timestamp,
            "compile_time": pe_comptime,
            "signature": pe_sig,
        }

        TODO["header_info"] = exe_metadata

        print("rich_pe_header_hash:" + str(pe_header))
        print("PE Signature:" + str(pe_sig))
        print("PE_Timestamp:" + str(pe_timestamp))
        print("Compile Time: " + str(pe_comptime))
        print("Machine: " + str(pe_arch))
    print("\n")

    response = requests.post("mongodb://10.0.8.11:27017/", json=TODO)
    response.json()
    response.status_code


# function to iterate over files using pathlib
@app.command()
def iterate() -> None:
    """
    Iterate over folder and call metadata function for each file.

    Uses Pathlib library to access files.

        Parameters:
            None
        Returns:
            None

    """
    root = Path("/workspaces/darkmoon/darkmoon-cli/src/darkmoon_cli/testing")

    queue = []
    queue.append(root)

    while queue:
        m = queue.pop(0)

        for files in m.glob("*"):
            print(files)
            if files.is_file():
                get_metadata(files)
            else:
                queue.append(files)


@app.command()
def hashes(path: Path) -> list[str]:
    """
    Create a list of hashes for files.

    Uses hashlib library.

        Parameters:
            None
        Returns:
            list

    """
    all_hashes = []
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    h_sha512 = hashlib.sha512()

    with open(path, "rb") as file:
        # read file in chunks and update hash
        while True:
            data = file.read(1024)
            if not data:
                break
            h_md5.update(data)
            h_sha1.update(data)
            h_sha256.update(data)
            h_sha512.update(data)

    all_hashes.append(h_md5.hexdigest())
    all_hashes.append(h_sha1.hexdigest())
    all_hashes.append(h_sha256.hexdigest())
    all_hashes.append(h_sha512.hexdigest())

    # return the hex digest
    return all_hashes


@app.command()
def source_iso() -> str:
    """
    Extract source ISO metadata.

        Parameters:
            None
        Returns:
            String

    """
    return "source ISO"


@app.command()
def source_iso_hash() -> list[str]:
    """
    Extract source ISO hashes metadata.

        Parameters:
            None
        Returns:
            List of strings

    """
    return ["source ISO hash list"]


@app.command()
def rich_pe_header_hashes(exe_file: Path) -> list[str]:
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

    # adds all PE rich headers to a list
    all_pe_header = []
    all_pe_header.append(binarymd5.get_rich_header_hash())
    all_pe_header.append(binarysha1.get_rich_header_hash("sha1"))
    all_pe_header.append(binarysha256.get_rich_header_hash("sha256"))
    all_pe_header.append(binarysha512.get_rich_header_hash("sha512"))

    return all_pe_header


@app.command()
def pe_header_sig(exe_file: Path) -> str:
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
def pe_header_time(exe_file: Path) -> Any:
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
    timestamp += str(time_list[time_list.index("TimeDateStamp:") + 2])
    timestamp += str(time_list[time_list.index("TimeDateStamp:") + 3])
    timestamp += str(time_list[time_list.index("TimeDateStamp:") + 4])
    timestamp += str(time_list[time_list.index("TimeDateStamp:") + 5])
    timestamp += str(time_list[time_list.index("TimeDateStamp:") + 6])
    timestamp += str(time_list[time_list.index("TimeDateStamp:") + 7])

    return timestamp


@app.command()
def pe_header_comptime(exe_file: Path) -> Any:
    """
    Get the compile time of the .exe file.

    Uses pefile library.

        Parameters:
            .exe file
        Returns:
            string
    """
    CompTime = "Time to compile file"
    return CompTime


@app.command()
def pe_machine(exe_file: Path) -> Any:
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


if __name__ == "__main__":
    app()
