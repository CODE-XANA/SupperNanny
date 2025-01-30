#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define PROC_DIR_NAME "super_nanny"
#define PROC_FILE_NAME "file_list"

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_file;
static char *file_buffer;
static size_t buffer_size = 0;

static int super_nanny_proc_show(struct seq_file *m, void *v) {
    if (file_buffer) {
        seq_printf(m, "%s", file_buffer);
    } else {
        seq_printf(m, "No data stored.\n");
    }
    return 0;
}

static int super_nanny_proc_open(struct inode *inode, struct file *file) {
    return single_open(file, super_nanny_proc_show, NULL);
}

static ssize_t super_nanny_proc_write(struct file *file, const char __user *buffer, size_t len, loff_t *off) {
    if (len + buffer_size > PAGE_SIZE) {
        printk(KERN_ALERT "Buffer overflow prevented\n");
        return -ENOMEM;
    }

    if (copy_from_user(file_buffer + buffer_size, buffer, len)) {
        return -EFAULT;
    }
    
    buffer_size += len;

    file_buffer[buffer_size] = '\0';

    return len;
}

static const struct proc_ops super_nanny_proc_fops = {
    .proc_open = super_nanny_proc_open,
    .proc_read = seq_read,
    .proc_write = super_nanny_proc_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init super_nanny_init(void) {
    proc_dir = proc_mkdir(PROC_DIR_NAME, NULL);
    if (!proc_dir) {
        printk(KERN_ALERT "Failed to create /proc/super_nanny\n");
        return -ENOMEM;
    }

    file_buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!file_buffer) {
        printk(KERN_ALERT "Failed to allocate memory for file buffer\n");
        return -ENOMEM;
    }

    proc_file = proc_create(PROC_FILE_NAME, 0666, proc_dir, &super_nanny_proc_fops);
    if (!proc_file) {
        printk(KERN_ALERT "Failed to create /proc/super_nanny/file_list\n");
        kfree(file_buffer);
        return -ENOMEM;
    }

    printk(KERN_INFO "Module loaded: /proc/super_nanny/file_list\n");
    return 0;
}

static void __exit super_nanny_exit(void) {
    proc_remove(proc_file);
    proc_remove(proc_dir);

    kfree(file_buffer);

    printk(KERN_INFO "Module unloaded\n");
}

module_init(super_nanny_init);
module_exit(super_nanny_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexender");
MODULE_DESCRIPTION("A simple kernel module");
