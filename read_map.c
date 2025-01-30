#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h> // Include for close()
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAP_PATH "/sys/fs/bpf/app_file_map"
#define MAX_KEY 32
#define MAX_VALUE 128

int main() {
    int map_fd;
    char key[MAX_KEY] = {0};
    char next_key[MAX_KEY] = {0};
    char value[MAX_VALUE] = {0};

    // Open the BPF map
    map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        perror("Failed to open BPF map");
        return 1;
    }

    printf("Reading BPF map contents:\n");

    // Iterate over the map and print all key-value pairs
    while (bpf_map_get_next_key(map_fd, key, next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, next_key, value) == 0) {
            printf("Key: %s, Value: %s\n", next_key, value);
        } else {
            perror("Failed to lookup element in BPF map");
        }
        // Move to the next key
        memcpy(key, next_key, MAX_KEY);
    }

    if (errno && errno != ENOENT) {
        perror("Error iterating over BPF map");
    }

    close(map_fd);
    return 0;
}
