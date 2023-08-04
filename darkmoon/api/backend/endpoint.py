import subprocess
import tempfile
from pathlib import Path as PyPath
from typing import Any

from fastapi import (
    APIRouter,
    File,
    Request,
    UploadFile,
)
from fastapi.responses import JSONResponse

from darkmoon.common import utils
from darkmoon.core.schema import IncorrectInputException

router = APIRouter(prefix="/endpoints", tags=["endpoints"])


async def called_process_error_handler(
    request: Request,
    exc: subprocess.CalledProcessError,
) -> JSONResponse:
    """Docstring."""
    return JSONResponse(
        status_code=422,
        content={"message": f"This file can not be unzipped: {str(exc)}"},
    )


@router.post(
    "/metadata",
    responses={
        400: {"Client Error Response": "Bad Request"},
    },
)
async def get_metadata_endpoint(
    file: UploadFile = File(...),
    source_iso: UploadFile = File(...),
) -> dict[str, Any]:
    """Get metadata."""
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        tmpfile.write(await file.read())
        tmp_path = PyPath(tmpfile.name)

    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        tmpfile.write(await source_iso.read())
        iso_path = PyPath(tmpfile.name)

    return utils.get_metadata(tmp_path, iso_path)


@router.post(
    "/get-file-type",
    responses={
        400: {"Client Error Response": "Bad Request"},
    },
)
async def get_file_type_endpoint(
    file: UploadFile = File(...),
) -> str:
    """Get file."""
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        tmpfile.write(await file.read())
        tmp_path = PyPath(tmpfile.name)
    return utils.get_file_type(tmp_path)


@router.post(
    "/get-hash",
    responses={
        400: {"Client Error Response": "Bad Request"},
    },
)
async def get_hashes_endpoint(
    file: UploadFile = File(...),
) -> dict[str, str]:
    """Get hashes of files."""
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        tmpfile.write(await file.read())
        tmp_path = PyPath(tmpfile.name)
    return utils.get_hashes(tmp_path)


@router.post("/get-all-exe-metadata", response_class=JSONResponse)
async def get_all_exe_metadata_endpoint(
    file: UploadFile = File(...),
) -> dict[str, Any]:
    """Post the exe metadata."""
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        tmpfile.write(await file.read())
        tmp_path = PyPath(tmpfile.name)
    return utils.get_all_exe_metadata(tmp_path)


class ExtractionError(Exception):
    """An error raised when 7zip is unable to extract a file."""


@router.post(
    "/extract-file",
    responses={
        400: {"Client Error Response": "Bad Request"},
        422: {"Client Error Response": "Unprocessable Content"},
        500: {"Server Error Response": "Internal Server Error"},
        504: {"Server Error Response": "Gateway Timeout"},
    },
)
async def extract_files_endpoint(
    file: UploadFile = File(...),  # only vmdks
    source_iso: PyPath = PyPath("..."),
    url: PyPath = PyPath("..."),  # refactor it, so it not being used
) -> None:
    """Extract file."""
    allowed_extensions = [".vmdk"]
    file_extension = file.content_type
    if file_extension not in allowed_extensions:
        IncorrectInputException(status_code=400, detail="Only VMDK files are allowed")
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            tmpfile.write(file.file.read())
            tmp_path = PyPath(tmpfile.name)
            try:
                utils.extract_files(tmp_path, source_iso, str(url))
            except ExtractionError:
                raise IncorrectInputException(
                    status_code=422,
                    detail="Error during extraction",
                )
    except Exception:
        raise IncorrectInputException(status_code=500, detail="Internal Server Error")


@router.post(
    "/iterate-files",
    responses={
        400: {"Client Error Response": "Bad Request"},
    },
)
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
