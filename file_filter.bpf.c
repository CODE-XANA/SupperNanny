#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

#define MAX_KEY_LEN 32
#define MAX_VALUE_LEN 128

// Map to store app-to-file restrictions
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[MAX_KEY_LEN]);    // Process name
    __type(value, char[MAX_VALUE_LEN]); // Restricted file path
    __uint(max_entries, 1024);
} app_file_map SEC(".maps");

// Temporary map to pass data between tracepoint and kprobe
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);   // Process ID (PID)
    __type(value, char[MAX_VALUE_LEN]); // File path
    __uint(max_entries, 1024);
} current_task_map SEC(".maps");

// Map to track parent-child relationships
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32); // Child PID
    __type(value, u32); // Parent PID
    __uint(max_entries, 1024);
} parent_map SEC(".maps");

// Helper function to determine if a process or its ancestors are restricted
static __always_inline int is_restricted_process(u32 pid, char *restricted_file_path) {
    u32 current_pid = pid;

    // Traverse the process hierarchy
    while (true) {
        char *restricted_path = bpf_map_lookup_elem(&app_file_map, &current_pid);
        if (restricted_path) {
            // Found a restricted process in the hierarchy
            if (__builtin_memcmp(restricted_path, restricted_file_path, MAX_VALUE_LEN) == 0) {
                return 1; // Restriction applies
            }
        }

        // Move to the parent process
        u32 *parent_pid = bpf_map_lookup_elem(&parent_map, &current_pid);
        if (!parent_pid) {
            break; // No more parent processes
        }
        current_pid = *parent_pid;
    }

    return 0; // No restriction found
}

// Tracepoint: Extracts and stores syscall arguments
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    char file_path[MAX_VALUE_LEN] = {0};
    char app_name[MAX_KEY_LEN] = {0};
    const char *user_file_path = (const char *)ctx->args[1];
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 ppid = 0; // Parent PID
    struct task_struct *task = NULL;
    struct task_struct *real_parent = NULL;

    bpf_printk("TRACEPOINT: Entered tracepoint_sys_enter_openat\n");

    // Get the current process name
    if (bpf_get_current_comm(app_name, sizeof(app_name)) == 0) {
        bpf_printk("TRACEPOINT: Process name: %s\n", app_name);
    } else {
        bpf_printk("TRACEPOINT: Failed to get process name\n");
        return 0; // Allow syscall
    }

    // Read the file path from syscall arguments
    if (user_file_path) {
        if (bpf_probe_read_user_str(file_path, sizeof(file_path), user_file_path) > 0) {
            bpf_printk("TRACEPOINT: File path: %s\n", file_path);
        } else {
            bpf_printk("TRACEPOINT: Failed to read file path\n");
            return 0; // Allow syscall
        }
    } else {
        bpf_printk("TRACEPOINT: File path argument is NULL\n");
        return 0; // Allow syscall
    }

    // Safely read the task struct
    task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        // Read the real_parent pointer
        bpf_probe_read(&real_parent, sizeof(real_parent), &task->real_parent);

        // Read the parent PID (tgid) from the real_parent task_struct
        if (real_parent) {
            bpf_probe_read(&ppid, sizeof(ppid), &real_parent->tgid);
            bpf_printk("TRACEPOINT: PID: %d, Parent PID: %d\n", pid, ppid);

            // Update the parent map
            bpf_map_update_elem(&parent_map, &pid, &ppid, BPF_ANY);
        } else {
            bpf_printk("TRACEPOINT: Failed to read real_parent pointer\n");
        }
    } else {
        bpf_printk("TRACEPOINT: Failed to get task_struct\n");
    }

    // Store the file path in the temporary map
    bpf_map_update_elem(&current_task_map, &pid, file_path, BPF_ANY);

    return 0; // Allow syscall
}

// Kprobe: Enforces restrictions based on the data from the tracepoint
SEC("kprobe/__x64_sys_openat")
int kprobe__sys_openat(struct pt_regs *ctx) {
    char file_path[MAX_VALUE_LEN] = {0};
    char app_name[MAX_KEY_LEN] = {0};
    char *restricted_path;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 key = pid; // Declare a proper key variable for the map lookup

    bpf_printk("KPROBE: Entered kprobe__sys_openat\n");

    // Get the current process name
    if (bpf_get_current_comm(app_name, sizeof(app_name)) == 0) {
        bpf_printk("KPROBE: Process name: %s\n", app_name);
    } else {
        bpf_printk("KPROBE: Failed to get process name\n");
        return 0; // Allow syscall
    }

    // Retrieve the file path from the temporary map
    char *tmp_file_path = bpf_map_lookup_elem(&current_task_map, &key);
    if (!tmp_file_path) {
        bpf_printk("KPROBE: No file path found for PID: %d\n", pid);
        return 0; // Allow syscall
    }

    // Copy the file path to local memory
    if (bpf_probe_read(file_path, sizeof(file_path), tmp_file_path) != 0) {
        bpf_printk("KPROBE: Failed to read file path from map\n");
        return 0; // Allow syscall
    }

    // Check if the process or its ancestors are restricted
    restricted_path = bpf_map_lookup_elem(&app_file_map, app_name);
    if (restricted_path) {
        if (__builtin_memcmp(restricted_path, file_path, MAX_VALUE_LEN) == 0) {
            bpf_printk("KPROBE: Blocking access to %s for process %s or its ancestor\n", file_path, app_name);
            bpf_override_return(ctx, -EACCES); // Deny access
            return 0;
        } else {
            bpf_printk("KPROBE: Allowed access to %s for process %s\n", file_path, app_name);
        }
    } else {
        bpf_printk("KPROBE: No restriction found for process: %s\n", app_name);
    }

    return 0; // Allow syscall
}

char LICENSE[] SEC("license") = "GPL";
