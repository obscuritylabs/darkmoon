import tarfile
from pathlib import Path

import pytest

HERE = Path(__file__).parent


@pytest.fixture()
def test_3_tar_zip() -> Path:
    """Load the test file as a fixture."""
    file = HERE.parent / "testing3.tar.gz"
    assert file.exists()
    return file


@pytest.fixture()
def test_3_files(tmp_path: Path, test_3_tar_zip: Path) -> list[Path]:
    """List of all extracted files from the test 3 tar zip fixture."""
    path = tmp_path / test_3_tar_zip.name.replace(".", "_")
    path.mkdir()
    with tarfile.open(test_3_tar_zip) as f:
        f.extractall(path)
    return sorted(
        i for i in path.rglob("*") if i.is_file() and not i.name.startswith(".")
    )


@pytest.fixture()
def test_3_first_file(test_3_files: list[Path]) -> Path:
    """The first file from the test 3 tar zip fixture."""
    return next(iter(test_3_files))


@pytest.fixture()
def test_3_first_exe(test_3_files: list[Path]) -> Path:
    """The first file from the test 3 tar zip fixture."""
    # Note: The first exe isn't actually a PE
    # so we skip all the files that start with a dot.
    return next(
        iter(
            i for i in test_3_files if i.is_file() and i.suffix.lower().endswith("exe")
        ),
    )
