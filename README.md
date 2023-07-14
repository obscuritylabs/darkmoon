# Project DarkMoon

This project will catalogue file metadata from multiple Windows operating systems. The data will be available for lookup based on file name or file hashes.

## Project Components

### Command-Line Interface (CLI) Tool

The command-line interface tool will be a Typer CLI based application (Python). This application will be able to crawl through multiple virtual hard disks (VHDs) created from Windows virtual machines and gather metadata from each file. The data will then use the backend to write to the database.

-[Typer CLI](https://typer.tiangolo.com) -[Example metadata](https://www.virustotal.com/gui/file/79bd6ba26c844639a596241f6a92fb453409738998ca60b79718534f3b0f9e65/details)

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

-[Developing inside a Container](https://code.visualstudio.com/docs/remote/containers) -[Docker](https://www.docker.com/)


### Prerequisites

Make sure the following dependencies are installed on your system:
- Poetry (1.5.1)
- Visual Studio Code
- Docker
- MangoDB Compass
- 1Password

## Getting Started

Follow these steps to set up the development environment after installing the prerequisites.
1. Setting up GitHub SSH Auth and Signing Keys:
    - Configure SSH authentication and add your SSh public key to your GitHub account.
2. Cloning the Repository:
    - clone the repository using SSH:
        `git clone git@github.com:team/repository/.git`

### Local Development

1. Install project dependencies
    `make install`
2. Run the development environment:
    if using Visual Studio Code: click the "Reopen in Container" option in the bottom left conner. This will set up the development environment using Docker.

### Running the Environment

To run the project environment:
1. For the API app:
    `make run`
2. Using Docker:
    `docker -compose up --build`
3. For the CLI commands:
    `poetry run darkmoon --help`

### MongoDB Compass

The database that is used for this project is MongoDB. The file metadata is uploaded to the MongoDB database after the program is run. MongoDB allows for easier lookup and sorting of file metadata.

-[MongoDB](https://www.mongodb.com)

To connect to the MongoDB database used by the API:
1. Launch MongoDB Compass.
2. Use the connection string specified in the `settings.py` file to connect to the database.

# DarkMoon CLI

The DarkMoon CLI subsection of the project scans operating systems, iterates through the files, and sends them through to MongoDB via FastAPI.
Below is a detailed list of the functions found in this section, their arguments, results, and purpose.

## Main Functions

These are the most high-level functions that you will mostly be interacting with.

### get_metadata

Calls all of the minor metadata-collecting functions in one place and formats it appropriately.

**Arguments:**

+ File Path (Path)
+ ISO Name (String)
+ Debug (Boolean) | OPTIONAL: Default is FALSE

**Result:**

+ Dictionary (string:Any) with the file metadata formatted for FastAPI POST request

**Example:**


### iterate_files

Iterates through the operating systems, obtains the file data, formats the data, and sends it to FastAPI.

**Arguments:**

+ File Path (Path)
+ ISO Name (String)
+ Debug (Boolean) | OPTIONAL: Default is FALSE

**Results**

+ Returns "None", but sends data over to FastAPI

**Example:**


## Important Functions

While you won't really be interacting directly with these functions, they play an important role in the program.

### call_api

Sends a dictionary to FastAPI. THIS COMMAND CAN _NOT_ BE CALLED IN THE CONSOLE!

**Arguments:**

+ Dictionary

**Results:**

+ Returns nothing; sends the data over to FastAPI

**Example:**


### get_all_exe_metadata

Obtains all the additional metadata needed for .exe and .dll files

**Arguments:**

+ File Path (Path)
+ Debug (Boolean) | OPTIONAL: Default is FALSE

**Results:**

+ A dictionary (string:Any) with all the metadata, including the unique types for .exe and .dll files, is returned

**Example:**


### get_file_type

Gets the file type of a file

**Arguments:**

+ File Path (Path)

**Results:**

+ Returns the file type (the first word from the string returned by the function)

**Example:**


### get_hashes

Gets the md5, sha1, sha256, and sha512 hashes from a file

**Arguments:**

+ File Path (Path)

**Results:**

+ Returns a dictionary (string:string) of the file's hashes.


### iterate_extract

Iterates through a folder of operating systems and extracts their contents.

**Arguments:**

+ File Path (Path)
+ Debug (Boolean) | OPTIONAL: Default is FALSE

**Results:**

+ "None" is returned and the operating systems are unpacked.

**Example:**


## Minor Functions

These are functions that, although playing a part in the program, only serve as helper functions to the other two categories

### delete_folder

Deletes a folder. Used in-program to delete the folder containing the operating systems once all the files have been extracted and placed into another folder.

**Arguments:**

+ File Path (Path)

**Results:**

+ Returns "None"; deletes the specified folder

**Example:**


### extract_files

Extracts the files from an operating system and places them in a new folder

**Arguments:**

+ File Path (Path)
+ ISO Name (String)
+ Debug (Boolean) | OPTIONAL: Default is FALSE

**Results:**

+ Returns "None"; the files are extracted from the operating system and placed in a new folder

**Example:**


### unzip

Unzips the VMDK operating system files.

**Arguments:**

+ File Path (Path)

**Results:**

+ Returns "None"; unzips the operating system's VMDK file

**Example:**


### To Test The Applications

- DarkMoon Web API:

```text
 uvicorn main:app
```

- DarkMoon CLI:

```text
 python main.py (function)
```
