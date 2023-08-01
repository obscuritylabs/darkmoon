from fastapi import APIRouter, File, Request, UploadFile
from fastapi.responses import HTMLResponse, Response

from darkmoon.api.v1.metadata.views import hash_comparison
from darkmoon.settings import templates

router = APIRouter(prefix="/webpages", tags=["webpages"])


@router.get("", response_class=HTMLResponse)
async def read_item_index(request: Request) -> Response:
    """Read the request from index for response."""
    return templates.TemplateResponse("index.html", {"request": request})


@router.get("/hash-lookup", response_class=HTMLResponse)
async def read_item_hash(request: Request) -> Response:
    """Read the request from hash for response."""
    return templates.TemplateResponse("hash.html", {"request": request})


@router.get("/upload", response_class=HTMLResponse)
async def read_item_upload(request: Request) -> Response:
    """Read the request from upload for response."""
    return templates.TemplateResponse("upload.html", {"request": request})


@router.get("/hashcompare", response_class=HTMLResponse)
async def output_hash(request: Request) -> Response:
    """Read request from fileupload."""
    return templates.TemplateResponse("hash_compare_result.html", {"request": request})


@router.post(
    "/hashcompareresult",
    response_class=HTMLResponse,
)
async def hash_upload(
    file: UploadFile = File(...),
) -> Response:
    """POST file to API."""
    try:
        response = HTMLResponse()
        result = await hash_comparison(response, file)

        return templates.TemplateResponse(
            "hash_compare_result.html",
            {
                "request": file.filename,
                "metadata_list": result,
            },
        )

    except Exception:
        return templates.TemplateResponse(
            "hash_compare_result.html",
            {
                "request": file.filename,
                "metadata_list": "Internal Server Error",
            },
            status_code=500,
        )


"""
@router.post("/upload_files/")
async def upload_files(
    answer_file: UploadFile,
    packer_template: UploadFile,
    iso_file: UploadFile,
) -> Response:
    # Directory to store uploaded files for later use
    upload_directory = Path("/uploads")

    # Create the 'uploads' directory if it doesn't exist
    upload_directory.mkdir(parents=True, exist_ok=True)

    # Save the files in the 'uploads' directory
    answer_file_path = "upload_directory / answer_file.filename"
    packer_template_path = "upload_directory / packer_template.filename"
    iso_file_path = upload_directory + "/" + iso_file.filename

    with answer_file_path.open("wb") as f:
        f.write(await answer_file.read())

    with packer_template_path.open("wb") as f:
        f.write(await packer_template.read())

    with iso_file_path.open("wb") as f:
        f.write(await iso_file.read())

    return {"message": "Files uploaded and saved successfully."}

"""
