# example from https://typer.tiangolo.com/typer-cli/#sample-script
import os
from pathlib import Path
from typing import Optional

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

    all_files = os.listdir("/workspaces/darkmoon/darkmoon-cli/src/darkmoon_cli/testing")
    for file in all_files:
        print("size:" + str(os.path.getsize(os.getcwd() + "/testing/" + file)))
        print(file + "metadata:")
        print("last motified:")
        print(str(os.path.getmtime(os.getcwd() + "/testing/" + file)))
        print("creation date:")
        print(str(os.path.getctime(os.getcwd() + "/testing/" + file)))


# function to iterate over files using pathlib
@app.command()
def path() -> None:

    p = Path("/workspaces/darkmoon/darkmoon-cli/src/darkmoon_cli/testing")
    size = p.stat().st_size
    print(size)
    for file in p.iterdir():
        t = Path(file)
        print("\n")
        print(t.stem)
        print("size:")
        print(t.stat().st_size)
        print("last motified:")
        print(t.stat().st_atime)
        print("creation time:")
        print(t.stat().st_ctime)


if __name__ == "__main__":
    app()
