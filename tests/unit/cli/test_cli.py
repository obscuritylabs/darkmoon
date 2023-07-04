from pathlib import Path

from typer.testing import CliRunner

from darkmoon.cli.main import app

runner = CliRunner()


def test_get_metadata_file(test_3_first_file: Path, test_3_tar_zip: Path) -> None:
    """Test that the get-metadata command is able to."""
    result = runner.invoke(
        app,
        [
            "get-metadata",
            str(test_3_first_file),
            str(test_3_tar_zip),
        ],
    )
    assert result.exit_code == 0
    assert '"name": ["._smalldll.dll"]' in result.stdout
    assert (
        '"sha256": "00737a3a56f0dc2008510640690fc3e3b20bd75790dcaeea76ffa88e0be94052"'
        in result.stdout
    )
