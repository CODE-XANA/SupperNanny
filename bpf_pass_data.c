#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAP_PATH "/sys/fs/bpf/app_file_map"
#define MAX_KEY 32
#define MAX_VALUE 128

int main() {
    int map_fd, file_fd;
    char buffer[1024];
    ssize_t bytes_read;
    char *line, *saveptr;

    // Open the BPF map
    map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        perror("Failed to open BPF map");
        return 1;
    }

    // Open the /proc interface
    file_fd = open("/proc/super_nanny/file_list", O_RDONLY);
    if (file_fd < 0) {
        perror("Failed to open /proc/super_nanny/file_list");
        return 1;
    }

    // Read the contents of /proc/super_nanny/file_list
    bytes_read = read(file_fd, buffer, sizeof(buffer) - 1);
    if (bytes_read < 0) {
        perror("Failed to read file");
        close(file_fd);
        return 1;
    }
    buffer[bytes_read] = '\0'; // Null-terminate the buffer

    // Process each line
    line = strtok_r(buffer, "\n", &saveptr);
    while (line != NULL) {
        char key[MAX_KEY] = {0};
        char value[MAX_VALUE] = {0};
        char *delimiter;

        // Split the line into key and value using ':'
        delimiter = strchr(line, ':');
        if (!delimiter) {
            fprintf(stderr, "Invalid format in line: %s\n", line);
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        // Extract key (process) and value (file path)
        strncpy(key, line, delimiter - line);
        key[delimiter - line] = '\0'; // Null-terminate the key
        strncpy(value, delimiter + 1, MAX_VALUE - 1);
        value[MAX_VALUE - 1] = '\0'; // Ensure null termination

        // Update the BPF map
        if (bpf_map_update_elem(map_fd, key, value, BPF_ANY) < 0) {
            perror("Failed to update BPF map");
            close(file_fd);
            return 1;
        }

        printf("Added key=%s, value=%s to BPF map\n", key, value);

        line = strtok_r(NULL, "\n", &saveptr);
    }

    close(file_fd);
    close(map_fd);
    return 0;
}
