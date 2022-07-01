# example from https://typer.tiangolo.com/typer-cli/#sample-script
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


if __name__ == "__main__":
    app()
