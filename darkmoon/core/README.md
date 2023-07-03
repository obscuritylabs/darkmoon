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
