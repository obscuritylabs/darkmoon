import tarfile
import tempfile
from pathlib import Path
from typing import Annotated

import typer
from cli.main import iterate_files


def extract(
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
    darkmoon_server_url: Path,
) -> None:
    """Extract vmdk and put in new folder."""
    with tempfile.TemporaryDirectory() as tmpdirname:
        with tarfile.open(file) as f:
            f.extractall(tmpdirname)
        iterate_files(Path(tmpdirname), source_iso, darkmoon_server_url)
