// src/ebpf/kern/exec_intercept.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_ARGS 8
#define ARG_LEN 64

char LICENSE[] SEC("license") = "GPL";

struct exec_event_t {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[16];
    char filename[256];
    __u32 argc;
    char argv[MAX_ARGS][ARG_LEN];
} __attribute__((aligned(4)));

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct exec_event_t));
    __uint(max_entries, 1);
} TMP_EVENT SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} EXEC_EVENTS SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int exec_intercept(struct trace_event_raw_sys_enter *ctx) {
    u32 key = 0;
    struct exec_event_t *event = bpf_map_lookup_elem(&TMP_EVENT, &key);
    if (!event)
        return 0;

    // Nettoyage sécurisé
    __builtin_memset(event, 0, sizeof(*event));

    // Infos basiques
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->gid = bpf_get_current_uid_gid() >> 32;

    // Parent PID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        if (parent)
            event->ppid = BPF_CORE_READ(parent, tgid);
    }

    // Nom du processus
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Nom complet du binaire (argv[0])
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename),
                            (const char *)ctx->args[0]);
    bpf_printk("📦 filename: %s\n", event->filename);

    // Lecture des arguments
    const char *const *argv_ptr = (const char *const *)ctx->args[1];
    int argc = 0;

#pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;
        int ret = bpf_probe_read_user(&argp, sizeof(argp), &argv_ptr[i]);
        if (ret < 0 || !argp) {
            bpf_printk("❌ argv[%d] ptr read failed (ret=%d)\n", i, ret);
            break;
        }

        int len = bpf_probe_read_user_str(event->argv[i], ARG_LEN, argp);
        if (len <= 1) {
            bpf_printk("⚠️  argv[%d] empty or failed (len=%d)\n", i, len);
            break;
        }

        bpf_printk("✅ argv[%d]: %s\n", i, event->argv[i]);
        argc++;
    }

    event->argc = argc;

    // Envoi à l'espace utilisateur
    return bpf_perf_event_output(ctx, &EXEC_EVENTS,
                                 BPF_F_CURRENT_CPU, event,
                                 sizeof(*event));
}
