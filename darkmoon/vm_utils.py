from proxmoxer import ProxmoxAPI

from darkmoon.settings import Settings

prox = ProxmoxAPI(
    Settings.PROXMOX_HOST,
    user=Settings.PROXMOX_USER,
    password=Settings.PROXMOX_PASS,
    verify_ssl=False,
)


def upload_iso(node: str, storage: str, file_path: str) -> None:
    """Upload a provided iso to a given node and storage."""
    prox.proxmox.nodes(node).storage(storage).upload.post(
        content="iso",
        filename=open(file_path, "rb"),
    )


def display_node(node: str) -> str:
    """Test me."""
    res = prox.proxmox.nodes(node).get()
    return str(res)
