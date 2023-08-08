import hashlib
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import magic
import pefile
from motor.motor_asyncio import AsyncIOMotorCollection
from pefile import PEFormatError

from darkmoon.api.v1.metadata.schema import (
    DocMetadata,
    EXEMetadata,
    Metadata,
    MetadataEntity,
)
from darkmoon.core.schema import (
    DuplicateFileException,
    ExtractionError,
    IncorrectInputException,
    ValidationError,
)


async def upload_metadata_to_database(
    collection: AsyncIOMotorCollection,
    file: Metadata,
) -> Metadata:
    """Docstring."""
    file_metadata = file.dict()["__root__"]

    duplicate_hashes = {
        "hashes.md5": file_metadata["hashes"]["md5"],
        "hashes.sha1": file_metadata["hashes"]["sha1"],
        "hashes.sha256": file_metadata["hashes"]["sha256"],
        "hashes.sha512": file_metadata["hashes"]["sha512"],
    }
    check_dup = {
        "name": file_metadata["name"][0],
        "file_extension": file_metadata["file_extension"][0],
        "file_type": file_metadata["file_type"][0],
        "hashes": file_metadata["hashes"],
        "source_iso_name": file_metadata["source_iso_name"][0],
        "operating_system": file_metadata["operating_system"][0],
    }

    match file.__root__:
        case EXEMetadata():
            check_dup["header_info"] = file_metadata["header_info"]
        case DocMetadata():
            ...
        case _:
            raise IncorrectInputException(
                status_code=422,
                detail="Error validating file",
            )

    dup = await collection.find_one(check_dup)
    if dup:
        raise DuplicateFileException(status_code=409, detail="File is a duplicate.")

    doc = await collection.find_one(duplicate_hashes)
    if doc:
        document = MetadataEntity.parse_obj(doc)

        data_type = [
            document.__root__.name,
            document.__root__.file_extension,
            document.__root__.file_type,
            document.__root__.source_iso_name,
            document.__root__.operating_system,
        ]
        data_type_string = [
            "name",
            "file_extension",
            "file_type",
            "source_iso_name",
            "operating_system",
        ]
        for index in range(len(data_type)):
            if file_metadata[data_type_string[index]][0] not in data_type[index]:
                data_type[index].append(
                    file_metadata[data_type_string[index]][0],
                )

        change = {
            "$set": {
                "name": data_type[0],
                "file_extension": data_type[1],
                "file_type": data_type[2],
                "source_iso_name": data_type[3],
                "operating_system": data_type[4],
            },
        }
        await collection.update_one(duplicate_hashes, change)
        return Metadata.parse_obj(file_metadata)

    else:
        await collection.insert_one(file_metadata)
        return Metadata.parse_obj(file_metadata)


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


def get_metadata(file: Path, source_iso: str) -> dict[str, Any]:
    """Call all of the metadata functions and send data to api endpoint."""
    file_extension = str(file.suffix)

    data_fields = {
        "base_file_type": "doc",
        "name": [str(file.name)],
        "file_extension": [file_extension],
        "file_type": [str(get_file_type(file))],
        "hashes": get_hashes(file),
        "source_iso_name": [source_iso],
        "operating_system": [source_iso],
    }

    if file_extension == ".exe" or file_extension == ".dll":
        try:
            data_fields["base_file_type"] = "exe"
            data_fields["header_info"] = get_all_exe_metadata(file)

        except PEFormatError:
            pass

    return data_fields


async def extract_files(
    file: Path,
    source_iso: str,
    collection: AsyncIOMotorCollection,
) -> None:
    """Extract vmdk and put in new folder."""
    with tempfile.TemporaryDirectory() as tmpdirname:
        cmd = ["7z", "x", str(file), "-o" + tmpdirname]
        result = subprocess.run(cmd)
        if result.returncode != 0:
            raise ExtractionError(str(result.stdout))
        await iterate_files(Path(tmpdirname), source_iso, collection)


async def iterate_files(
    path: Path,
    source_iso: str,
    collection: AsyncIOMotorCollection,
) -> None:
    """Iterate over folder and call metadata function for each file."""
    queue = []

    queue.append(path)

    while queue:
        curr_dir = queue.pop(0)

        for files in curr_dir.glob("*"):
            if files.suffix == ".ntfs":
                await extract_files(files, source_iso, collection)
            if files.is_file():
                metadata_dict = get_metadata(files, source_iso)

                metadata_instance = Metadata.parse_obj(metadata_dict)

                await upload_metadata_to_database(
                    file=metadata_instance,
                    collection=collection,
                )

            else:
                queue.append(files)


def packer_build(template: Path) -> subprocess.Popen[bytes]:
    """Call packer build on a provided template.

    subprocess.run is a blocking function, so this will take awhile
    as packer runs
    """
    valid_cmd = ["packer", "validate", str(template)]
    build_cmd = ["packer", "build", str(template)]
    result = subprocess.run(valid_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise ValidationError(str("\n" + result.stdout))

    process = subprocess.Popen(build_cmd, stdout=subprocess.PIPE)
    return process


def mount_nfs(args: str) -> Path:
    """Attempt to mount the NFS containing the generated disk image.

    Still needs to be implemented.
    """
    return Path("/")
