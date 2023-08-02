import tempfile
from pathlib import Path as PyPath
from typing import Any

from fastapi import APIRouter, File, Query, UploadFile
from fastapi.responses import JSONResponse

from darkmoon.common import utils
from darkmoon.common.utils import (
    get_all_exe_metadata,
    get_file_type,
    get_hashes,
    get_metadata,
)

router = APIRouter(prefix="/endpoints", tags=["endpoints"])


@router.get("/metadata")
async def get_metadata_endpoint(
    file: PyPath = Query(..., description="Path to the file"),
    source_iso: PyPath = Query(..., description="Path to the source ISO"),
) -> dict[str, Any]:
    """Get metadata."""
    return get_metadata(file, source_iso.name)



@router.get("/get-file-type")
async def get_file_type_endpoint(
    file: PyPath = Query(..., description="Path to the file"),
) -> str:
    """Get file."""
    return get_file_type(file)


@router.get("/get-hash")
async def get_hashes_endpoint(
    file: PyPath = Query(..., description="Path to the file"),
) -> dict[str, str]:
    """Get hashes of files."""
    return get_hashes(file)


@router.post("/get-all-exe-metadata", response_class=JSONResponse)
async def get_all_exe_metadata_endpoint(
    file: PyPath = Query(..., description="Path to the file"),
) -> dict[str, Any]:
    """Post the exe metadata."""
    return get_all_exe_metadata(file)


@router.post("/extract_file")
async def extract_files_endpoint(
    file: UploadFile = File(...),
    source_iso: PyPath = PyPath("..."),
    url: PyPath = PyPath("..."),
) -> None:
    """Extract file."""
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        tmpfile.write(await file.read())
        tmp_path = PyPath(tmpfile.name)
        utils.extract_files(tmp_path, source_iso, str(url))


@router.post("/iterate-files")
async def iterate_files_endpoint(
    path: UploadFile = File(...),
    source_iso: PyPath = PyPath("..."),
    url: PyPath = PyPath("..."),
) -> None:
    """Iterate through file."""
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        tmpfile.write(await path.read())
        tmp_path = PyPath(tmpfile.name)
        utils.iterate_files(tmp_path, source_iso, str(url))
