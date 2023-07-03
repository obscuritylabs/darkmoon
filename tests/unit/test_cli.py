"""This is the unittest_main.py file."""

###########
# IMPORTS #
###########

import hashlib
import os
from pathlib import Path
from typing import Generator

import pytest

from darkmoon.cli.main import (
    get_all_exe_metadata,
    get_file_type,
    get_hashes,
    get_metadata,
    get_source_iso,
)

####################
# GLOBAL VARIABLES #
####################

#############
# FUNCTIONS #
#############


@pytest.fixture()
def dir_path() -> Path:
    """Fixture for testing path returns dictionary."""
    os.system("tar -xf testing3.tar.gz")
    folder = os.getcwd() + "/testing3"

    return Path(folder)


@pytest.fixture()
def get_exe() -> Generator[Path, None, None]:
    """Fixture for testing exe file."""
    os.system("tar -xf testing3.tar.gz")
    yield Path(os.getcwd() + "/testing3/download-example.exe")
    os.system("rm -r " + os.getcwd() + "/testing3")


@pytest.fixture()
def get_dll() -> Generator[Path, None, None]:
    """Fixture for testing exe file."""
    os.system("tar -xf testing3.tar.gz")
    yield Path(os.getcwd() + "/testing3/smalldll.dll")
    os.system("rm -r " + os.getcwd() + "/testing3")


def test_get_metadata(get_exe: Path) -> None:
    """Filler function.

    Parameters:
        None
    Returns:
        None

    """
    sha512_1st = "66bc96640b7eb5bf5b3108220639f01c2b0ffd50458414642263e923fcffabb1"
    sha512_2nd = "f28a7b7fb6e1a1e76f4c60fff78c4e1f3463cc3b2e5c29df7e4b30b525258f52"
    header_1st = "46a0615c724ce72cb1174d4b8fe7f234586ffdc948a5177108c7ab7cc5204"
    header_2nd = "089d253bd1c0b3306f756b79ba8354a5a6f61d38bd137a40d4390d32bb7df3476d8"

    all_hashes = {
        "md5": "ae46070abb66e057b9abd1c1c9f067cf",
        "sha1": "cd44355ed101c6ae97f7999809042353018448e5",
        "sha256": "956535c045d7c4c6fcbe5e71ca8abae4c0706ff28237311459fc6e022212dd08",
        "sha512": sha512_1st + sha512_2nd,
    }
    data_fields = {
        "name": ["download-example.exe"],
        "file_extension": [".exe"],
        "file_type": ["PE32 executable (GUI) Intel 80386"],
        "hashes": all_hashes,
        "source_iso_name": ["unit-test"],
        "operating_system": ["Linux-5.10.104-linuxkit-x86_64-with-glibc2.31"],
        "header_info": {
            "machine_type": "0x14C",
            "timestamp": "0x4ABD129C[FriSep2518:57:322009UTC]",
            "compile_time": "Time to compile file",
            "signature": "0x4550",
            "rich_header_hashes": {
                "md5": "813ee6b4f254f41240e3d493b0153330",
                "sha1": "7a2c09ff3da26cfd692d624de222d623c7593af8",
                "sha256": hashlib.sha256(),
                "sha512": header_1st + header_2nd,
            },
        },
    }
    assert get_metadata(get_exe, "unit-test") == data_fields


def test_get_hashes(get_exe: Path) -> None:
    """Test the get_hashes function.

    Parameters:
        get_exe (Path): Absolute path of the exe file.

    Returns:
        None
    """
    sha512_1st = "66bc96640b7eb5bf5b3108220639f01c2b0ffd50458414642263e923fcffabb1"
    sha512_2nd = "f28a7b7fb6e1a1e76f4c60fff78c4e1f3463cc3b2e5c29df7e4b30b525258f52"
    hash_dict = get_hashes(get_exe)
    assert hash_dict == {
        "md5": "ae46070abb66e057b9abd1c1c9f067cf",
        "sha1": "cd44355ed101c6ae97f7999809042353018448e5",
        "sha256": "956535c045d7c4c6fcbe5e71ca8abae4c0706ff28237311459fc6e022212dd08",
        "sha512": sha512_1st + sha512_2nd,
    }


def test_get_source_iso() -> None:
    """Filler function.

    Parameters:
        None
    Returns:
        None

    """
    assert get_source_iso() == ""


def test_get_file_type(get_exe: Path) -> None:
    """Test the get_file_type function.

    Parameters:
        dir_path (dict[str, str])

    Returns:
        None

    """
    assert get_file_type(Path(get_exe)) == "PE32 executable (GUI) Intel 80386"


def test_get_all_exe_metadata(get_exe: Path) -> None:
    """Test the get_all_exe_metadata function.

    Parameters:
        get_exe (Path): Absolute path of the exe file.

    Returns:
        None

    """
    sha_first = "46a0615c724ce72cb1174d4b8fe7f234586ffdc948a5177108c7ab7cc5204"
    sha_second = "089d253bd1c0b3306f756b79ba8354a5a6f61d38bd137a40d4390d32bb7df3476d8"
    assert get_all_exe_metadata(get_exe) == {
        "machine_type": "0x14C",
        "timestamp": "0x4ABD129C[FriSep2518:57:322009UTC]",
        "compile_time": "Time to compile file",
        "signature": "0x4550",
        "rich_header_hashes": {
            "md5": "813ee6b4f254f41240e3d493b0153330",
            "sha1": "7a2c09ff3da26cfd692d624de222d623c7593af8",
            "sha256": hashlib.sha256(),
            "sha512": sha_first + sha_second,
        },
    }


def test_unzip() -> None:
    """Filler function.

    Parameters:
        None
    Returns:
        None

    """


def test_unzip_files() -> None:
    """Filler function.

    Parameters:
        None
    Returns:
        None

    """


def test_iterate_unzip() -> None:
    """Filler function.

    Parameters:
        None
    Returns:
        None

    """


def test_iterate_files() -> None:
    """Filler function.

    Parameters:
        None
    Returns:
        None
    """
