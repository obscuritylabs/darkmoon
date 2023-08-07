"""This is the main.py file."""

from pathlib import Path
from typing import Annotated

import typer
from rich import print, print_json
from rich.console import Console
from rich.progress import track

from darkmoon.common import utils

console = Console()
console = Console()
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
def extract_files(
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
) -> None:
    """Extract vmdk and put in new folder."""
    utils.extract_files(file, str(source_iso), darkmoon_server_url)


@app.command()
def iterate_extract(
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
) -> None:
    """Iterate over vmdk folder and extracts files of each vmdk."""
    for vmdk in track(path.glob("*"), description="Processing..."):
        extract_files(vmdk, str(vmdk), darkmoon_server_url)


@app.command()
def iterate_files(
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
) -> None:
    """Iterate over folder and call metadata function for each file."""
    utils.iterate_files(path, source_iso, darkmoon_server_url)


@app.command()
def process_iso(
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
    pkr_template: Annotated[
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
    darkmoon_server_url: str,
    mount_args: str,
) -> None:
    """Take in an ISO and a template to build and extract."""
    vmid: int = 0
    with console.status(
        "Building Template (This May Take Awhile)...",
        spinner="aesthetic",
    ):
        build_process = utils.packer_build(pkr_template)
        output = []
        while build_process.poll() is None:
            if build_process.stdout is not None:
                curr = build_process.stdout.readline().decode("utf-8")
                if "A template was created:" in output:
                    vmid = int(curr.split(":")[-1].strip())
                output.append(curr)
        if build_process.poll() != 0:
            print("Error:")
            print(output)
    if vmid == 0:
        print(output)
        raise Exception
    mount_point: Path = utils.mount_nfs(mount_args)
    disk_img = Path.joinpath(mount_point, f"template file for {vmid}")
    utils.extract_files(
        file=disk_img,
        source_iso=source_iso,
        url=darkmoon_server_url,
    )


if __name__ == "__main__":
    app()
