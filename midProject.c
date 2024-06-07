#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <time.h>
#include <openssl/md5.h>

#define MAX_PATH_LENGTH 256
#define MAX_PATTERN_LENGTH 256
#define MAX_LINE_LENGTH 1024
#define HASH_SIZE 10000
#define MAX_FILE_TYPES 100






int *total_files_searched;
int total_matches_found = 0;
const char *pathLog = "/home/mreza/Desktop/a/log";

struct FileTypeCount {
    char type[32];
    int count;
};

struct ThreadArgs {
    char filename[MAX_PATH_LENGTH];
    char pattern[MAX_PATTERN_LENGTH];
    regex_t regex_pattern;
};









void calculate_md5_hash(char *filename, unsigned char hash[MD5_DIGEST_LENGTH]) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }
    MD5_CTX md5Context;
    MD5_Init(&md5Context);
    unsigned char buffer[1024];
    int bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        MD5_Update(&md5Context, buffer, bytesRead);
    }
    MD5_Final(hash, &md5Context);

    fclose(file);
}










void write_duplicate_to_log(const char *path, pid_t process_id, pthread_t thread_id, const char *filename) {
    FILE *log_file = fopen(pathLog, "a"); // Open log file for appending
    if (log_file == NULL) {
        perror("Error opening duplicate log file");
        return;
    }
    // Write information to log file
    fprintf(log_file, "Duplicate File Detected: Path: %s | Process ID: %d | Thread ID: %lu | Filename: %s\n", path, process_id, thread_id, filename);

    fclose(log_file); // Close log file
}









void count_file_types(char *path, struct FileTypeCount *file_types, int *file_types_count) {
    DIR *dir = opendir(path);
    if (dir == NULL) {
        perror("Error opening directory");
        exit(EXIT_FAILURE);
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                char subdir[256];
                snprintf(subdir, sizeof(subdir), "%s/%s", path, entry->d_name);
                count_file_types(subdir, file_types, file_types_count);
            }
        } else if (entry->d_type == DT_REG) {
            char *ext = strrchr(entry->d_name, '.');
            if (ext != NULL) {
                int found = 0;
                for (int i = 0; i < *file_types_count; ++i) {
                    if (strcmp(file_types[i].type, ext + 1) == 0) {
                        file_types[i].count++;
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    strcpy(file_types[*file_types_count].type, ext + 1);
                    file_types[*file_types_count].count = 1;
                    (*file_types_count)++;
                }
            }
        }
    }
    closedir(dir);
}









long int get_directory_size(const char *path) {
    char command[256];
    sprintf(command, "du -s %s | cut -f1", path);
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("Error opening pipe");
        exit(EXIT_FAILURE);
    }
    long int size;
    if (fscanf(fp, "%ld", &size) != 1) {
        perror("Error reading directory size");
        exit(EXIT_FAILURE);
    }
    pclose(fp);
    return size;
}










void remove_duplicate_files(char *path) {
    DIR *dir = opendir(path);
    if (dir == NULL) {
        perror("Error opening directory");
        exit(EXIT_FAILURE);
    }

    // Hash table to store file hashes
    bool hash_table[HASH_SIZE] = {false};
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            char filepath[MAX_PATH_LENGTH];
            snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);

            // Calculate MD5 hash of file
            unsigned char hash[MD5_DIGEST_LENGTH];
            calculate_md5_hash(filepath, hash);

            // Calculate hash table index
            unsigned long hashIndex = 0;
            for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
                hashIndex = (hashIndex * 31 + hash[i]) % HASH_SIZE;
            }

            // If hash exists in hash table, file is a duplicate and is removed
            if (hash_table[hashIndex]) {
                printf("Removing duplicate file: %s\n", filepath);
                remove(filepath);
                write_duplicate_to_log(path, getpid(), pthread_self(), entry->d_name);
            } else {
                hash_table[hashIndex] = true; // Register hash in hash table
            }
        }
    }
    closedir(dir);
}









void *search_file(void *args) {
    struct ThreadArgs *thread_args = (struct ThreadArgs *)args ;
    FILE *file = fopen(thread_args-> filename, "r");

    if (file == NULL )
    {
        perror("ERROR");
        pthread_exit(NULL);
    }

    char line[MAX_LINE_LENGTH];
    int line_number = 0;
    int matches_in_file = 0;
    bool flag = false;
    clock_t start, end ;
    start  = clock();
    while (fgets ( line, sizeof(line), file) != NULL)
    {
        line_number++;

        int status = regexec(&thread_args -> regex_pattern, line , 0,NULL ,0);
        if(status ==0)
        {
            flag = true ; 
            matches_in_file++;
        }
        else if (status != REG_NOMATCH)
        {
            char error_message[100];
            regerror(status , &thread_args-> regex_pattern,error_message, sizeof(error_message));
            fprintf(stderr, "Regex match failed: %s\n" ,error_message);
        }
    }
    fclose(file);
    end = clock();
    regfree(&thread_args->regex_pattern);
    pthread_exit((void *)(intptr_t)matches_in_file)
}








void search_directory(char *path, char *pattern, int pipe_fd) {
    DIR *dir = opendir(path);
    if(dir == NULL)
    {
        perror("Erorr opening dir");
        exit(EXIT_FAILURE);
    }
    struct dirent *entry;
    while((entry = readdir(dir)) != NULL)
    {
        if(entry->d_type == DT_DIR)
        {
            if ( strcmp(entry->d_name, ".") != 0 && strcmp(entry ->d_name, "..") != 0){
                pid_t child_pid = fork();

                if (child_pid == -1)
                {
                    perror("error forking process");
                    exit(EXIT_FAILURE);
                }

                if(child_pid == 0)
                {
                    char subdir[MAX_LINE_LENGTH];
                    snprintf(subdir, sizeof(subdir), "%s/%s",path , entry -> d_name);           
                    remove_duplicate_files(subdir);
                    search_directory(subdir,pattern, pipe_fd);
                    exit(EXIT_SUCCESS);
                }
            }
        }
        else if(entry -> d_type == DT_REG)
        {
            
            pthread_t thread;
            struct ThreadArgs *args = (struct ThreadArgs *)malloc(sizeof(struct ThreadArgs));
            snprintf(args-> filename, sizeof(args-> filename), "%s/%s" , path , entry->d_name);
            // snprintf(args-> pattern, sizeof(args-> pattern), "%s", pattern);

            int regex_flags = REG_EXTENDED | REG_NOSUB;
            int status = regcomp(&args->regex_pattern, pattern, regex_flags);
            if(status != 0)
            {
                char error_message[100];
                regerror(status, &args->regex_pattern, error_message,sizeof(error_message));
                fprintf(stderr, "regex compilation failed: %s \n", error_message);
                free(args);
                continue;
            }
            if(pthread_create(&thread, NULL , search_file, (void *)args)!=0){
                perror("Error creating thread");
                exit(EXIT_FAILURE);
            }

            int matches_in_file;
            pthread_join(thread, (void **)&matches_in_file);
            free(args);
            (*total_files_searched)++;

            write(pipe_fd, &matches_in_file, sizeof(matches_in_file));
        }      
    }
    closedir(dir);
}  











int main() {
    char path[MAX_LINE_LENGTH];
    char pattern[MAX_PATTERN_LENGTH];

    printf("Enter the directory path: ");
    fgets(path, sizeof(path), stdin);

    size_t path_len = strlen(path);
    if (path_len > 0 && path[path_len - 1] == '\n') {
        path[path_len - 1] = '\0';
    }

    fgets(pattern, sizeof(pattern), stdin);

    size_t pattern_len = strlen(pattern);
    if (pattern_len > 0 && pattern[pattern_len - 1] == '\n') {
        pattern[pattern_len - 1] = '\0';
    }

    total_files_searched = (int *)mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    *total_files_searched = 0;

    int pipe_fd[2];
    if (pipe(pipe_fd) == -1) {
        perror("Pipe creation failed");
        exit(EXIT_FAILURE);
    }

    struct FileTypeCount file_types[MAX_FILE_TYPES];
    int file_types_count = 0;

    count_file_types(path, file_types, &file_types_count);

    printf("File types in directory and its subdirectories: \n");
    for (int i = 0; i < file_types_count; ++i) {
        printf("%s: %d\n", file_types[i].type, file_types[i].count);
    }

    long int size_before = get_directory_size(path);
    printf("Size of directory before removing duplicates: %ld bytes\n", size_before);
    search_directory(path, pattern, pipe_fd[1]);

    close(pipe_fd[1]);

    int matches_in_file;
    while (read(pipe_fd[0], &matches_in_file, sizeof(matches_in_file)) > 0) {
        total_matches_found += matches_in_file;
    }
    close(pipe_fd[0]);

    printf("\nTotal files searched: %d\n", *total_files_searched);
    // printf("Total matches found: %d\n", total_matches_found);

    munmap(total_files_searched, sizeof(int));

    remove_duplicate_files(path);

    long int size_after = get_directory_size(path);
    printf("Size of directory after removing duplicates: %ld bytes\n", size_after);

    return 0;
}
