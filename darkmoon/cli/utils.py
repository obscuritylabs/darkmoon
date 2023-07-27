import hashlib
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import magic
import pefile
import requests
from pefile import PEFormatError


def call_api(url: str, data: dict[str, Any]) -> bool:
    """Send data to api post endpoint."""
    res = requests.post(url + "/metadata", json=data)
    return res.ok


def get_file_type(file: Path) -> str:
    """Get the file type of the file."""
    file_type_string = magic.from_file(file)
    file_type_list = file_type_string.split(",")
    return file_type_list[0]


def get_hashes(file: Path) -> dict[str, Any]:
    """Create a list of hashes for files."""
    h_md5 = hashlib.md5()  # noqa S324
    h_sha1 = hashlib.sha1()  # noqa S324
    h_sha256 = hashlib.sha256()
    h_sha512 = hashlib.sha512()

    store_hash = [h_md5, h_sha1, h_sha256, h_sha512]
    all_hashes: dict[str, str] = {}

    with file.open("rb") as f:
        # read file in chunks and update hash
        while True:
            data = f.read(65536)
            if not data:
                break
            for hash in store_hash:
                hash.update(data)

    all_hashes["md5"] = store_hash[0].hexdigest()
    all_hashes["sha1"] = store_hash[1].hexdigest()
    all_hashes["sha256"] = store_hash[2].hexdigest()
    all_hashes["sha512"] = store_hash[3].hexdigest()

    return all_hashes


def get_all_exe_metadata(file: Path) -> dict[str, Any]:
    """Obtain all exe specific metadata and returns in dictionary format."""
    pe_obj = pefile.PE(file)

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
    return exe_metadata


def get_metadata(file: Path, source_iso: Path) -> dict[str, Any]:
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
            data_fields["header_info"] = get_all_exe_metadata(file)
        except PEFormatError:
            pass
    else:
        data_fields["header_info"] = "Not an EXE or DLL"
    return data_fields


def extract_files(file: Path, source_iso: Path, url: str) -> None:
    """Extract vmdk and put in new folder."""
    with tempfile.TemporaryDirectory() as tmpdirname:
        cmd = ["7z", "x", str(file), "-o" + tmpdirname]
        subprocess.run(cmd, check=True)  # noqa: S603
        iterate_files(Path(tmpdirname), source_iso, url)


def iterate_files(
    path: Path,
    source_iso: Path,
    url: str,
) -> None:
    """Iterate over folder and call metadata function for each file."""
    queue = []
    queue.append(path)
    while queue:
        curr_dir = queue.pop(0)

        for files in curr_dir.glob("*"):
            if files.suffix == ".ntfs":
                extract_files(files, source_iso, url)
            if files.is_file():
                metadata = get_metadata(files, source_iso)
                call_api(url=url, data=metadata)
            else:
                queue.append(files)
