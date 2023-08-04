import json
from pathlib import Path

from typer.testing import CliRunner

from darkmoon.cli.main import app

runner = CliRunner()


def test_get_metadata_file_data(test_3_first_file: Path, test_3_tar_zip: Path) -> None:
    """Test that the get-metadata command is able to scan individual files."""
    result = runner.invoke(
        app,
        [
            "get-metadata",
            str(test_3_first_file),
            str(test_3_tar_zip),
        ],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "download-example.exe" == data["name"][0]


def test_get_hashes(test_3_first_file: Path) -> None:
    """Test that the get-hashes command is able to get the hash of a file."""
    result = runner.invoke(
        app,
        [
            "get-hashes",
            str(test_3_first_file),
        ],
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert (
        "956535c045d7c4c6fcbe5e71ca8abae4c0706ff28237311459fc6e022212dd08"
        == data["sha256"]
    )


def test_get_file_type(test_3_first_file: Path) -> None:
    """Test that the get-file-type command is able to get the filetype of a file."""
    result = runner.invoke(
        app,
        [
            "get-file-type",
            str(test_3_first_file),
        ],
    )
    assert result.exit_code == 0
    assert "PE32 executable (GUI) Intel 80386" in result.stdout


def test_get_all_exe_metadata(test_3_first_exe: Path) -> None:
    """Test that the get-all-exe-metadata command is able to."""
    result = runner.invoke(
        app,
        [
            "get-all-exe-metadata",
            str(test_3_first_exe),
        ],
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)

    assert (
        "ba0fc8e8944cebce8d34d465df56373d056b316bd9b54329b9c77f070f6c9c62"
        == data["rich_header_hashes"]["sha256"]
    )
