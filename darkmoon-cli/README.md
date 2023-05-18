# DARKMOON CLI

The DARKMOON CLI subsection of the project scans operating systems, iterates through the files, and sends them through to MongoDB via FastAPI. 
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

+ Dictionary with the file metadata formatted for FastAPI POST request

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



