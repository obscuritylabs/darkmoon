import tempfile
from pathlib import Path as PyPath
from typing import Any

from fastapi import APIRouter, File, Query, UploadFile
from fastapi.responses import JSONResponse

from darkmoon.common import utils
from darkmoon.common.utils import (
    call_api,
    get_all_exe_metadata,
    get_file_type,
    get_hashes,
    get_metadata,
)

router = APIRouter()


@router.get("/metadata")
async def get_metadata_endpoint(
    file: PyPath = Query(..., description="Path to the file"),
    source_iso: PyPath = Query(..., description="Path to the source ISO"),
) -> dict[str, Any]:
    """Get metadata."""
    return get_metadata(file, source_iso)


@router.post("/call_api")
async def call_api_endpoint(
    url: PyPath = Query(..., description="API endpoint URL"),
    data: dict[str, Any] = Query(..., description="Data to send as JSON"),
) -> bool:
    """Call api."""
    return call_api(url, data)


@router.get("/get_file_type")
async def get_file_type_endpoint(
    file: PyPath = Query(..., description="Path to the file"),
) -> str:
    """Get file."""
    return get_file_type(file)


@router.get("/get_hash")
async def get_hashes_endpoint(
    file: UploadFile = File(...),
) -> dict[str, str]:
    """Get hash."""
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        tmpfile.write(await file.read())
        tmp_path = PyPath(tmpfile.name)
        upload_hashes = utils.get_hashes(tmp_path)
        tmpfile.unlink()

    return upload_hashes


@router.post("/get_all_exe_metadata", response_class=JSONResponse)
async def get_all_exe_metadata_endpoint(
    file: UploadFile = File(...),
) -> dict[str, Any]:
    """Exe metadata."""
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        tmpfile.write(await file.read())
        tmp_path = PyPath(tmpfile.name)
        get_hashes(tmp_path)
        tmpfile.unlink()

    return get_all_exe_metadata(tmp_path)


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
        utils.extract_files(tmp_path, source_iso, url)


@router.post("/iterate_files")
async def iterate_files_endpoint(
    path: UploadFile = File(...),
    source_iso: PyPath = PyPath("..."),
    url: PyPath = PyPath("..."),
) -> None:
    """Iterate file."""
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        tmpfile.write(await path.read())
        tmp_path = PyPath(tmpfile.name)
        utils.iterate_files(tmp_path, source_iso, url)
