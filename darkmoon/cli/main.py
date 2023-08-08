"""This is the main.py file."""

from pathlib import Path
from typing import Annotated

import typer
from motor.motor_asyncio import AsyncIOMotorCollection
from rich import print_json
from rich.progress import track

from darkmoon.common import utils

app = typer.Typer()


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
        str,
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
    data_fields = utils.get_metadata(file, source_iso)
    print_json(data=data_fields, highlight=False, indent=None)


@app.command()
def get_hashes(
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
) -> None:
    """Create a list of hashes for files."""
    print_json(data=utils.get_hashes(file), highlight=False, indent=None)


@app.command()
def get_file_type(
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
) -> None:
    """Get the file type of the file."""
    typer.echo(utils.get_file_type(file))


@app.command()
def get_all_exe_metadata(
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
) -> None:
    """Obtain all exe specific metadata and returns in dictionary format."""
    print_json(data=utils.get_all_exe_metadata(file), highlight=False, indent=None)


@app.command()
async def extract_files(
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
        str,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            writable=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    darkmoon_server_url: str,
    collection: AsyncIOMotorCollection,
) -> None:
    """Extract vmdk and put in new folder."""
    await utils.extract_files(file, str(source_iso), collection)


@app.command()
async def iterate_extract(
    path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=False,
            dir_okay=True,
            writable=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    darkmoon_server_url: str,
    collection: AsyncIOMotorCollection,
) -> None:
    """Iterate over vmdk folder and extracts files of each vmdk."""
    for vmdk in track(path.glob("*"), description="Processing..."):
        await extract_files(vmdk, str(vmdk), darkmoon_server_url, collection)


@app.command()
async def iterate_files(
    path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=False,
            dir_okay=True,
            writable=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    source_iso: Annotated[
        str,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            writable=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    darkmoon_server_url: str,
    collection: AsyncIOMotorCollection,
) -> None:
    """Iterate over folder and call metadata function for each file."""
    await utils.iterate_files(path, source_iso, collection)


if __name__ == "__main__":
    app()
