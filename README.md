# Project DarkMoon

This project will catalogue file metadata from multiple Windows operating systems. The data will be available for lookup based on file name or file hashes.

## Project Components

### Command-Line Interface (CLI) Tool

The command-line interface tool will be a Typer CLI based application (Python). This application will be able to crawl through multiple virtual hard disks (VHDs) created from Windows virtual machines and gather metadata from each file. The data will then use the backend to write to the database.

-[Typer CLI](https://typer.tiangolo.com)
-[Example metadata](https://www.virustotal.com/gui/file/79bd6ba26c844639a596241f6a92fb453409738998ca60b79718534f3b0f9e65/details)

## Web API Service

The Web API service will utilize FastAPI. This web service will be un-authenticated and allow for reading and writing. Lookups will be able to search by name or hashes (MD5, SHA1, SHA128, SHA256) utilizing two endpoints (hash or name). The hash endpoint will be able to search by multiple types of hashes. The CLI application will use the write endpoint to save to the database.

-[FastAPI](https://fastapi.tiangolo.com)

## Repository Components

### Pre-Commit Hooks

To ensure consistent and high-quality code that follows standard practices, this repository will use pre-commit hooks. These checks must be passed before code will be able to be pushed to the repository.

### Conventional Commits

To keep a easily readable and clean commit history, conventional commits will be enforced.

-[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)

### Portable Development Containers

VSCode allows for development within a docker container. This project has an already configured dev container that includes all needed dependencies, requirements and settings to begin development. There is also a docker compose file that will run the database and server.

-[Developing inside a Container](https://code.visualstudio.com/docs/remote/containers)
-[Docker](https://www.docker.com/)

## Getting Started

### To Begin Development

- After opening the project in VSCode, a window on the bottom right should pop up asking to "reopen in container", click it. If it does not, click the green button on the bottom left and once the window on top appears, click "reopen in container". This step may take several minutes to set everything up.
- Once the project is opened in the container, click on the darkmoon.code-workspace file in the root directory and click "Open Workspace". This step may take a few minutes.

Once both steps have been completed, and VSCode finishes setting up, development is ready to begin. All dependencies have been installed.

### To Test The Applications

- DarkMoon Web API:

```text
 uvicorn main:app
```

- DarkMoon CLI:

```text
 python main.py (function)
```
