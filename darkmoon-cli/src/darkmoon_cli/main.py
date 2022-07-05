# example from https://typer.tiangolo.com/typer-cli/#sample-script
import os
from typing import Optional

import typer

app = typer.Typer()
path = "/Users/pierre.tran/Documents/testing"


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


@app.command()
def test():

    allFiles = os.listdir("/workspaces/darkmoon/darkmoon-cli/src/darkmoon_cli/testing")
    for file in allFiles:

        print("size:" + str(os.path.getsize(os.getcwd() + "/testing/" + file)))
        print(file + "metadata:")
        print("last motified:")
        print(str(os.path.getmtime(os.getcwd() + "/testing/" + file)))
        print("creation date:")
        print(str(os.path.getctime(os.getcwd() + "/testing/" + file)))


if __name__ == "__main__":
    app()
