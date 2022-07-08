"""This is the main.py file."""
import hashlib
import os
import platform
from pathlib import Path
from typing import Optional

import pefile
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
def get_metadata(path: Path) -> str:
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

    # rich PE header hash
    if extension == ".exe":
        rich_pe_header(curr_filename)

    # print statements used for testing
    print("name:" + curr_filename)
    print("filetype:" + extension)
    print("hashes:" + str(hash_list))
    print("OS:" + operating_system)
    print("ISO:" + source_iso_data)

    json = ""

    return json


# function to iterate over files using pathlib
@app.command()
def path() -> None:
    """
    Iterate over folder and print out metadata for each file in the folder.

    Uses Pathlib library to access files.

        Parameters:
            None
        Returns:
            None

    """
    p = Path("faker.txt")
    get_metadata(p)


@app.command()
def hashes(path: Path) -> list[str]:
    """
    Create a list of hashes for files.

    Uses hashlib library

        Parameters:
            None
        Returns:
            list

    """
    filename = str(path.name)
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    h_sha512 = hashlib.sha512()

    with open(filename, "rb") as file:
        # read file in chunks and update hash
        chunk = b""
        while chunk != b"":
            chunk = file.read(1024)
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)
            h_sha512.update(chunk)

    all_hashes = []
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
def rich_pe_header(exe_file: str) -> list[str]:
    """
    Get a list of rich PE hash headers.

    Uses pefile library

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


if __name__ == "__main__":
    app()
