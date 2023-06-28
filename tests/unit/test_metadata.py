"""This is the testing area for app.py."""

###########
# IMPORTS #
###########


import pytest
from faker import Faker
from httpx import AsyncClient

fake: Faker = Faker()

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
            "md5": fake.md5(raw_output=False),
            "sha1": fake.sha1(raw_output=False),
            "sha256": fake.sha256(raw_output=False),
            "sha512": fake.sha512(raw_output=False),
        },
        "source_iso_name": [""],
        "operating_system": ["WindowsXP"],
        "header_info": "",
    }

    response = await client.post("/metadata", json=data)
    assert response.status_code == 200
    assert response.json() == {"None": "None"}
