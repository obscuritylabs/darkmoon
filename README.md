# Project DarkMoon

This project will catalogue file metadata from multiple Windows operating systems. The data will be available for lookup based on file name or file hashes.

## Project Components

### Command-Line Interface (CLI) Tool

The command-line interface tool will be a Typer CLI based application (Python). This application will be able to crawl through multiple virtual hard disks (VHDs) created from Windows virtual machines and gather metadata from each file. The data will then use the backend to write to the database.

-[Typer CLI](https://typer.tiangolo.com) -[Example metadata](https://www.virustotal.com/gui/file/79bd6ba26c844639a596241f6a92fb453409738998ca60b79718534f3b0f9e65/details)

### Pre-Commit Hooks

To ensure consistent and high-quality code that follows standard practices, this repository will use pre-commit hooks. These checks must be passed before code will be able to be pushed to the repository.

### Conventional Commits

To keep a easily readable and clean commit history, conventional commits will be enforced.

-[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)

### Portable Development Containers

VSCode allows for development within a docker container. This project has an already configured dev container that includes all needed dependencies, requirements and settings to begin development. There is also a docker compose file that will run the database and server.

-[Developing inside a Container](https://code.visualstudio.com/docs/remote/containers) -[Docker](https://www.docker.com/)


### Prerequisites

Make sure the following dependencies are installed on your system:
- Poetry (1.5.1)
- Visual Studio Code
- Docker
- MongoDB Compass
- 1Password


## Getting Started

### To Begin Development
Follow these steps to set up the development environment after installing the prerequisites.
1. Setting up GitHub SSH Auth and Signing Keys and configure SSH authentication and add your SSh public key to your GitHub account.
    - Open 1pass, go into settings and then click developer and then click on "use the SSH agent", and then follow the direction it gives you to complete the process. Open your SSH client configuration file \~/.ssh/config or C:\Users\YourUsername.ssh\config.
    Open your SSH client configuration file "~/.ssh/config or C:\Users\YourUsername\.ssh\config".
        - If you don't have a SSH cline configuration file, then create one \~/.ssh folder or config file by using this command :
       $ export SSH_AUTH_SOCK=~/Library/Group\ Containers/2BUA8C4S2C.com.1password/t/agent.sock"
    - Then add the IdentityAgent snippet to your ~/.ssh/config file:
        - Host *
            IdentityAgent "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
    - Open 1 pass, and in the right top corner click on new items.
    - Then click on SSH keys, and then add private key.
    - Then click on generate private key.Select an SSH Key > Generate New Key.
    - Select SSH key type: Ed25529, then click generate
    - Once, you got the key copy the public key and go to your github account.
    - Go to settings, click on SSH and GPG keys and click on New SSH Keys.
    - Once you pasted the key, click on key type and click on Authentication.
    - Repeat the steps, and but instead of an Authentication key type, now click signing key.
    - now go into teh signing key, and click in the triple dot menu on eight corner, and then click configure commit signing. and then click edit automatically.
2. Cloning the Repository:
    - Copy the repository's remote URL from GitHub by navigating to the repository and clicking on the "Code" button. Then, click "Clone" and select "SSH" to get the URL in SSH format.
    - clone the repository using SSH:
        `git clone git@github.com:team/repository/.git`

- After opening the project in VSCode, a window on the bottom right should pop up asking to "reopen in container", click it. If it does not, click the green button on the bottom left and once the window on top appears, click "reopen in container". This step may take several minutes to set everything up.
- Once the project is opened in the container, click on the darkmoon.code-workspace file in the root directory and click "Open Workspace". This step may take a few minutes.
### Local Development

Once both steps have been completed, and VSCode finishes setting up, development is ready to begin. All dependencies have been installed.
1. Install project dependencies
    `make install`

### To Test The Applications
### Setting up the dev-container:

1. Run the development environment:
    if using Visual Studio Code: click the "Reopen in Container" option in the bottom left conner. This will set up the development environment using Docker.

### Running the app:

- To run the app in the container:
Using Docker:
    `docker -compose up --build`

- To run the app locally:
For the API app:
    `make run`

- For the CLI commands:
    `poetry run darkmoon --help`

### MongoDB Compass

The database that is used for this project is MongoDB. The file metadata is uploaded to the MongoDB database after the program is run. MongoDB allows for easier lookup and sorting of file metadata.

-[MongoDB](https://www.mongodb.com)

- DarkMoon Web API:
To connect to the MongoDB database used by the API:
1. Launch MongoDB Compass.
2. Use the connection string specified in the `settings.py` file to connect to the database.


# DarkMoon CLI

- DarkMoon CLI:
The DarkMoon CLI subsection of the project scans operating systems, iterates through the files, and sends them through to MongoDB via FastAPI.

Below is a detailed list of the functions found in this section as well as a description of these functions.

## Main Functions
These are the most high-level functions that you will mostly be interacting with.

- get_metadata: Gets the metadata of the files by calling the get metadata function from utils.py. Sends the data to the api endpoint.

- iterate_files: Iterates through the operating systems, obtains the file data, formats the data, and sends it to FastAPI.

## Other Important Functions

While you won't really be interacting directly with these functions, they play an important role in the program.

- get_all_exe_metadata: Obtains and prints all the additional metadata needed for .exe and .dll files.

- get_file_type: Gets and prints the file type of a file.

- get_hashes: Gets and prints the md5, sha1, sha256, and sha512 hashes from a file using the get hashes function from utils.py. Uses hashlib to read chunks of the files and hash them.

- iterate_extract: Iterates through a folder of operating systems and extracts their contents using path.glob.

- extract_files: Extracts the files from an operating system and places them in a new folder.

### To Test The Applications

- All the cli and the static api tests
    `make test`
- Runs all tests including schema tests
    `make test-all`
