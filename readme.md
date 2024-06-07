# File Search and Duplicate Removal Utility
This is a C program designed to search for files in a specified directory and its subdirectories, and it can remove duplicate files found within that directory. The program provides functionality to count the number of files of different types in the directory and its subdirectories.

## Features
Multithreaded File Search: The program utilizes pthreads to search for files concurrently, improving search efficiency.
Regex Pattern Matching: It allows users to specify a regex pattern to search for within files.
Duplicate File Removal: Duplicate files found within the specified directory are removed to save disk space.
File Type Counting: The program counts the number of files of different types present in the specified directory and its subdirectories.
Compilation and Execution
To compile the program, use the following command:

Copy code
```gcc -o file_search_and_remove file_search_and_remove.c -lpthread -lcrypto```
To execute the program, run the compiled executable with the following command:


Copy code
```./file_search_and_remove```
The program will prompt you to enter the directory path. After entering the path, it will start searching for files, removing duplicates, and counting file types.

## Dependencies
pthread.h: For multithreading support.
stdio.h, stdlib.h, stdbool.h, string.h: Standard C libraries for I/O, memory allocation, and boolean operations.
unistd.h, dirent.h, sys/types.h, sys/wait.h: Libraries for working with directories and file types.
regex.h: Library for regular expression matching.
sys/mman.h: Library for memory mapping.
time.h: Library for time-related functions.
openssl/md5.h: Library for MD5 hashing.

## Usage
Enter Directory Path: Provide the absolute path of the directory you want to search in.
File Type Counting: After providing the directory path, the program will display the count of different file types present in the directory and its subdirectories.
Duplicate Removal: The program will then search for duplicate files and remove them. Information about duplicate files will be logged to a file named log located at /home/mreza/Desktop/a/log.
Final Directory Size: Finally, the program displays the size of the directory after removing duplicates.

## Author
This program was created by ** Mohamadreza Naderi _ Bahar Hemati **.
