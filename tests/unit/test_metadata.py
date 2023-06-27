"""This is the testing area for app.py."""

###########
# IMPORTS #
###########

import hashlib

import pytest
from httpx import AsyncClient

#########
# TESTS #
#########


@pytest.mark.unit
@pytest.mark.asyncio
async def test_list_metadata(client: AsyncClient) -> None:
    """Test the list_metadata function."""
    async with client:

        response = await client.get("/metadata")

    assert response.status_code == 200


# def test_metadata_by_id():
#     """Tests the get_metadata_by_id function."""

#     pass


@pytest.mark.unit
@pytest.mark.asyncio
async def test_upload_metadata(client: AsyncClient) -> None:
    """Tests the upload_metadata function."""
    data = {
        "id": "1",
        "name": ["End_Of_The_World"],
        "file_extension": [".jpeg"],
        "file_type": ["exe"],
        "hashes": {
            "md5": "5d41402abc4b2a76b9719d911017c592",
            "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
            "sha256": hashlib.sha256(),
            "sha512": hashlib.sha512(),
        },
        "source_iso_name": [""],
        "operating_system": ["WindowsXP"],
        "header_info": "",
    }

    response = await client.post("/metadata", json=data)
    assert response.status_code == 200
    assert response.json() == {"None": "None"}
