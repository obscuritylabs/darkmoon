"""This is the unittest_main.py file."""

###########
# IMPORTS #
###########

from pathlib import Path

import pytest

from darkmoon_cli.main import get_all_exe_metadata, get_file_type, get_hashes, get_source_iso

####################
# GLOBAL VARIABLES #
####################

#############
# FUNCTIONS #
#############


@pytest.fixture()
def dir_path() -> dict[str, str]:
    """Fixture for testing path returns dictionary."""
    folder = "/workspaces/darkmoon/darkmoon-cli/src/darkmoon_cli/testing"

    all_files = {
        folder + "bootuwf.dll": "PE32 executable (DLL) Intel 80386",
        folder + "company_research.pptx": "Microsoft PowerPoint 2007+",
        folder + "EmbeddedBrowserWebView.dll": "PE32 executable (DLL) (console) Intel 80386",
        folder + "faker.txt": "ASCII text",
        folder + "igor.png": "PNG image data",
    }

    return all_files


@pytest.fixture()
def get_exe():
    """Fixture for testing exe file."""
    return Path("/workspaces/darkmoon/darkmoon-cli/src/darkmoon_cli/testing/memtest.exe")


def test_get_metadata():
    """
    Filler function.

        Parameters:
            None
        Returns:
            None

    """
    return "Hello"


def test_get_hashes(get_exe):
    """
    Test the get_hashes function.

        Parameters:
            get_exe (Path): Absolute path of the exe file.
        Returns:
            None

    """
    sha512_first = "58b43fdf3bfafb2197f6b781f536024df2b5b1a4b65501e94a6911b0b70a2"
    sha512_second = "7f19023552709bcd297bb9ca3546343dc54e0aa1a8275c1262a2770913f492f701c"
    hash_dict = get_hashes(get_exe)
    assert hash_dict == {
        "md5": "d63b0535e6266211eb8a09f8579f24d2",
        "sha1": "c5ea21645398208e78dc7c963b81563989343b47",
        "sha256": "8fcb3b2e3f22aeae6c136bb6078d8ea4fa3c09062b582fac3f219e9cc535155f",
        "sha512": sha512_first + sha512_second,
    }


def test_get_source_iso():
    """
    Filler function.

        Parameters:
            None
        Returns:
            None

    """
    assert get_source_iso() == ""


def test_get_file_type(dir_path):
    """
    Test the get_file_type function.

        Parameters:
            dir_path (dict[str, str])
        Returns:
            None

    """
    for key in dir_path:
        assert get_file_type(Path(key)) == dir_path[key]


def test_get_all_exe_metadata(get_exe):
    """
    Test the get_all_exe_metadata function.

        Parameters:
            get_exe (Path): Absolute path of the exe file.
        Returns:
            None

    """
    sha_first = "8c1ca4e749c07608fe553be855f8a655da2145ef6306090f8616a4c7148309fe"
    sha_second = "4d59bf292b81045c1edad4c847eba02c1a6fbf4ca53d6c0e68508f4193b347bd"
    assert get_all_exe_metadata(get_exe) == {
        "machine_type": "0x14C",
        "timestamp": "0x710AF9E0[TueFeb517:58:562030UTC]",
        "compile_time": "Time to compile file",
        "signature": "0x4550",
        "rich_header_hashes": {
            "md5": "2b95009155e0f42e197edab0bd27f937",
            "sha1": "882ef7c2fbc3ab77cc8636889a3cc7dcfc1c6c2a",
            "sha256": "e9a8bd4f02d99bc15df08323b0c8edcd5f2d464e656a9c6c53a1e5bf9411d2ef",
            "sha512": sha_first + sha_second,
        },
    }


def test_unzip_files():
    """
    Filler function.

        Parameters:
            None
        Returns:
            None

    """
    return "Hello"


def test_iterate_unzip():
    """
    Filler function.

        Parameters:
            None
        Returns:
            None

    """
    return "Hello"


def test_iterate_files():
    """
    Filler function.

        Parameters:
            None
        Returns:
            None

    """
    return "Hello"
