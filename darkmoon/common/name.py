# name.py

from pathlib import Path


def extract_iso_filename(file_path: str) -> str:
    """Extract the filename without extension from the given path."""
    path = Path(file_path)
    return path.stem


def process_vmdk(file_path: str) -> str:
    """Processing vmdk."""
    from pathlib import Path

    path = Path(file_path)
    return f"Results from processing: {path.stem}"
