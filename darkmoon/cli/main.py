"""This is the main.py file."""

import hashlib
import os
from pathlib import Path
from typing import Annotated, Any

import magic
import pefile
import requests
import typer
from magic import MagicException
from pefile import PEFormatError
from rich import print_json

from darkmoon.cli.settings import settings

app = typer.Typer()


def call_api(data: dict[str, Any]) -> None:
    """Send data to api post endpoint.

    Parameters:
        data (dict): the dictionary that will be sent to the api during the request.
        iso_name (str): The source ISO.

    Returns:
        None

    """
    api_response = requests.post(settings.API_URL + "/metadata", json=data)
    api_response.json()
    status = api_response.status_code
    if status == 200:
        typer.echo("Working")
    elif status == 404:
        typer.echo("Server not found")
    else:
        typer.echo("Error: Not working")
    typer.echo(status)


@app.command()
def get_metadata(
    file: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            writable=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    source_iso: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            writable=False,
            readable=True,
            resolve_path=True,
        ),
    ],
) -> None:
    """Call all of the metadata functions and send data to api endpoint."""
    file_extension = str(file.suffix)
    data_fields = {
        "name": [str(file.name)],
        "file_extension": [file_extension],
        "file_type": [str(get_file_type(file))],
        "hashes": get_hashes(file),
        "source_iso_name": [str(source_iso.name)],
        "operating_system": [str(source_iso.name)],
        "header_info": {},
    }
    if file_extension == ".exe" or file_extension == ".dll":
        try:
            data_fields["header_info"] = get_all_exe_metadata(source_iso)
        except PEFormatError:
            pass
    print_json(data=data_fields, highlight=False, indent=None)


@app.command()
def get_hashes(path: Path) -> dict[str, str]:
    """Create a list of hashes for files.

    Uses hashlib library.

    Parameters:
        path (Path): Absolute path of file.

    Returns:
        hash_dict (dict{str:str}): List of all hashes.

    """
    h_md5 = hashlib.md5()  # noqa S324
    h_sha1 = hashlib.sha1()  # noqa S324
    h_sha256 = hashlib.sha256()
    h_sha512 = hashlib.sha512()

    store_hash = [h_md5, h_sha1, h_sha256, h_sha512]
    all_hashes: dict[str, str] = {}

    with open(path, "rb") as file:
        # read file in chunks and update hash
        while True:
            data = file.read(65536)
            if not data:
                break
            for hash in store_hash:
                hash.update(data)

    all_hashes["md5"] = store_hash[0].hexdigest()
    all_hashes["sha1"] = store_hash[1].hexdigest()
    all_hashes["sha256"] = store_hash[2].hexdigest()
    all_hashes["sha512"] = store_hash[3].hexdigest()

    # return the hex digest
    return all_hashes


@app.command()
def get_file_type(file: Path) -> str:
    """Get the file type of the file.

    Uses magic library.

    Parameters:
        file (Path): Path to file.

    Returns:
        file_type_list[0]: first word of the returned string from the function
    """
    try:
        file_type_string = magic.from_file(file)
        file_type_list = file_type_string.split(",")
        return str(file_type_list[0])
    except MagicException:
        return ""


@app.command()
def get_all_exe_metadata(
    exe_file: Path,
    debug: bool = False,
) -> dict[str, Any]:
    """Obtain all exe specific metadata and returns in dictionary format.

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
        timestamp += str(
            file_header_list[file_header_list.index("TimeDateStamp:") + num],
        )

    # machine_type
    machine = file_header_list[file_header_list.index("Machine:") + 1]

    exe_metadata = {
        "machine_type": machine,
        "timestamp": timestamp,
        "compile_time": compile_time,
        "signature": signature,
        "rich_header_hashes": all_header_hash,
    }
    if debug:
        typer.echo("machine_type: " + str(machine))
        typer.echo("PE_Timestamp: " + str(timestamp))
        typer.echo("compile_time: " + compile_time)
        typer.echo("PE Signature: " + str(signature))
        typer.echo("rich_pe_header_hash: " + str(all_header_hash))
        typer.echo("\n")

    return exe_metadata


def unzip(path: Path) -> None:
    """Extract file.

    Parameters:
        path (Path): Absolute path of vmdk folder.

    Returns:
        None

    """
    os.system("mkdir -p extractedvmdk")
    string_name = "7z x " + str(path) + " -aoa -oextractedvmdk"
    os.system(string_name)


def delete_folder(path: Path) -> None:
    """Delete folder.

    Parameters:
        path (Path): Absolute path of a folder.

    Returns:
        None

    """
    os.system("rm -r " + str(path))


@app.command()
def extract_files(
    path: Path,
    iso_name: str,
    debug: bool = False,
) -> None:
    """Extract vmdk and put in new folder.

    Uses Pathlib library to access files.

    Parameters:
        path (Path): Absolute path of vmdk folder.
        iso_name (str): The source ISO.

    Returns:
        None

    """
    unzip(path)

    if path.suffix == ".ntfs":
        os.system("rm " + str(path))
    iterate_files(Path(str(os.getcwd() + "/extractedvmdk")), iso_name, debug)

    delete_folder(Path(str(os.getcwd() + "/extractedvmdk")))


@app.command()
def iterate_extract(
    path: Path,
    debug: bool = False,
) -> None:
    """Iterate over vmdk folder and extracts files of each vmdk.

    Uses Pathlib library to access files.

    Parameters:
        path (Path): Absolute path of vmdk folder.

    Returns:
        None
    """
    for vmdk in path.glob("*"):
        get_iso = vmdk.name.split(".")
        curr_iso = get_iso[0]
        extract_files(vmdk, curr_iso, debug)


@app.command()
def iterate_files(
    path: Path,
    iso_name: str,
    debug: bool = False,
) -> None:
    """Iterate over folder and call metadata function for each file.

    Uses Pathlib library to access files.

    Parameters:
        path (Path): Absolute path of folder with extracted files from vmdk.
        iso_name (str): The source ISO.

    Returns:
        None

    """
    root = Path(path)

    queue = []
    queue.append(root)
    while queue:
        curr_dir = queue.pop(0)

        for files in curr_dir.glob("*"):
            typer.echo(files)
            if files.suffix == ".ntfs":
                extract_files(files, iso_name, debug)
            if files.is_file():
                metadata = get_metadata(files, Path(iso_name))
                if not debug:
                    call_api(metadata)
            else:
                queue.append(files)


if __name__ == "__main__":
    app()
