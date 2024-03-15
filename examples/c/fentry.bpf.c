// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <linux/errno.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_PATH_COMPONENT_SIZE 256
#define MAX_DENTRY_PATH_ITER 32

// Alway ensure this a little bit larger than
// the MAX_PATH_ITER macros so the max buffer size
// may increase appropriately.
#define HARD_MAX_PATH_ITER 42

#define MAX_BUFFER_SIZE (MAX_PATH_COMPONENT_SIZE * HARD_MAX_PATH_ITER)

struct path_data_x {
	char   name[MAX_PATH_COMPONENT_SIZE];
    size_t len;
};

struct data_x {
    char buffer[MAX_BUFFER_SIZE];
	char reserved; // force a null to the buffer
};

// Declare a scratch pad to store path elements
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_DENTRY_PATH_ITER);
    __type(key, u32);
    __type(value, struct path_data_x);
} dentry_cache SEC(".maps");

// Declare scratchpad for a buffer (one object per CPU)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct data_x);
} buffer_cache SEC(".maps");

static struct data_x empty_dummy = {};

static __always_inline struct data_x *__get_buffer(u32 index)
{
    // hack to hopefully reset the data to zero
    (void)bpf_map_update_elem(&buffer_cache, &index, &empty_dummy, BPF_ANY);

    struct data_x *data = bpf_map_lookup_elem(&buffer_cache, &index);

	if (data)
	{
		data->reserved = 0;
	}

    return data;
}

struct file_ctx_x
{
	struct dentry *dentry;
    struct dentry *mnt_root;
	struct vfsmount *vfsmnt;
    struct mount *real_mount;
	size_t total_len;
};

static __always_inline int __get_next_parent_dentry(struct dentry **dentry, struct dentry **parent_dentry, struct file_ctx_x  *ctx)
{
    int retVal = 0;
    struct mount *mnt_parent = NULL;

	bpf_core_read(parent_dentry, sizeof(struct dentry *), &(*dentry)->d_parent);

    // bpf_core_read(parent_dentry, sizeof(struct dentry *), &(*dentry)->d_parent);

	// /mnt_root should be NULL in the raw dentry case
    if (*dentry == ctx->mnt_root || *dentry == *parent_dentry)
	{
		// real_mount should be NULL in the raw dentry case
		if (ctx->real_mount != NULL)
		{
			// TODO: This logic should be able to traverse complicated mounts, but it is not working
    		// struct mount *mnt_parent = NULL;
			// bpf_core_read(&mnt_parent, sizeof(struct mount *), &ctx->real_mount->mnt_parent);
			// if (*dentry != ctx->mnt_root)
			// {
			// 	// We reached root, but not mount root - escaped?
			// 	retVal = ENOENT;
			// }
			// else if (ctx->real_mount != mnt_parent)
			// {
			// 	// We reached root, but not global root - continue with mount point path
			// 	bpf_core_read(dentry, sizeof(struct dentry *), &ctx->real_mount->mnt_mountpoint);
			// 	bpf_core_read(&ctx->real_mount, sizeof(struct mount *), &ctx->real_mount->mnt_parent);
			// 	ctx->vfsmnt = &ctx->real_mount->mnt;
			// 	bpf_core_read(&ctx->mnt_root, sizeof(struct dentry *), &ctx->vfsmnt->mnt_root);
			// 	retVal = EAGAIN;
			// }
			// else
			{
				// Global root - path fully parsed
				retVal = ENOENT;
			}
        }
		else
		{
            // Global root - path fully parsed
            retVal = ENOENT;
        }
    }

    return retVal;
}

// Iterator function
// Note, this can produce a truncated path since we are limiting the recursion depth by the map size
static long __get_path_element(struct bpf_map *map, const void *key, void *_value, void *_ctx)
{
	if (!key || !_value || !_ctx)
	{
		bpf_printk("__get_path_element: bad input");
		return 1;
	}

	struct path_data_x *path_data = _value;
	struct file_ctx_x  *ctx = _ctx;
	u32    index = *(u32*)key;

	// bpf_printk("__get_path_element: index = %d", index);

	// Store the current values
    struct dentry *parent_dentry = NULL;
    struct dentry *dentry = ctx->dentry;

	// Ensure the length is 0 in case we exit before writing something
	//  We will use this to indicate that there are no more path nodes in the cache
	path_data->len = 0;

	int retVal = __get_next_parent_dentry(&dentry, &parent_dentry, ctx);

	if (retVal == EAGAIN) {
		// Try the next dentry
		return 0;
	}

	if (retVal == ENOENT) {
		// We are done
		return 1;
	}

	// Copy the name into the current cache entry
	size_t len = bpf_probe_read_str(&path_data->name, MAX_PATH_COMPONENT_SIZE,
                                 BPF_CORE_READ(dentry, d_name.name));

	// If this item is longer than the max we need to stop
	if (len > MAX_PATH_COMPONENT_SIZE) {
		return 1;
	}

	// bpf_printk("__get_path_element: name = %s, len = %d", path_data->name, len);

	// Store the length for later
	path_data->len = len;

	// Store the total length so we know where to start the buffer offset later
	ctx->total_len += len;

	// Store the dentry for the next iteration
	ctx->dentry = parent_dentry;

	return 0;
}

struct path_ctx_x
{
	struct data_x *data;
	size_t total_len;
};

static long __store_path(struct bpf_map *map, const void *key, void *_value, void *_ctx)
{
	if (!key || !_value || !_ctx)
	{
		bpf_printk("__store_path: bad input");
		return 1;
	}
	struct path_data_x *path_data = _value;
	struct path_ctx_x  *ctx = _ctx;
	u32    index = *(u32*)key;
	size_t len = path_data->len;

	// bpf_printk("__store_path: index = %d, len = %d", index, len);

	if (len <= 0)
	{
		return 1;
	}
	// bpf_printk("__store_path: name = %s", path_data->name);

	// Subtract the length of this element, and calculate the buffer offset
	// The "& 0x1ff" trick below forces the compiler to believe the offset is not negative
	//  The Error: R2 min value is negative, either use unsigned or 'var &= const'
	ctx->total_len -= len;
	size_t offset = ctx->total_len & 0x1ff;

	// Set the buffer to where we want to start writing
	char *buffer = ctx->data->buffer + offset;

	// add a leading "/""
	bpf_probe_read(buffer, 1, "/");

	// Copy in the path without the trailing NULL
	len -= 1;
	len &= 0x1ff;
	bpf_probe_read(&(buffer[1]), len, path_data->name);

	// bpf_printk("__store_path: buffer = %s", buffer);

	return 0;
}

// collects the path is reverse order
static size_t __do_dentry_path(struct dentry *dentry, struct data_x *data)
{
	// bpf_printk("__do_dentry_path_x: enter");
	if (!dentry || !data)
	{
		return 0;
	}

	struct file_ctx_x dentry_ctx = {
		dentry,
		NULL,
		NULL,
		NULL,
		0
	};

	// Iterate over the map elements to MAX_DENTRY_PATH_ITER
	//  This artificially limits the max path we will collect.
	//  After this dentry_cache will hold the path in reverse order
	bpf_for_each_map_elem(&dentry_cache, __get_path_element, &dentry_ctx, 0);

	// Record the total length that was calculated
	size_t total_buffer_len = dentry_ctx.total_len;

	// bpf_printk("__do_dentry_path_x: total_buffer_len = %d", total_buffer_len);

	// If we actually collected a path, we need to iterate over the map again and build an actual path
	//  which is then stored in data->buffer
	if (total_buffer_len > 0)
	{
		struct path_ctx_x path_ctx = {
			data,
			total_buffer_len
		};

		bpf_for_each_map_elem(&dentry_cache, __store_path, &path_ctx, 0);
	}

	return total_buffer_len;
}

static size_t __do_file_path(struct dentry *dentry, struct vfsmount *vfsmnt, struct data_x *data)
{
	// bpf_printk("__do_file_path: enter");
	if (!dentry || !vfsmnt || !data)
	{
		return 0;
	}


    struct mount *real_mount;
    struct dentry *mnt_root;

	bpf_core_read(&mnt_root, sizeof(struct dentry *), &vfsmnt->mnt_root);

    // poorman's container_of
	bpf_core_read(&real_mount, sizeof(struct dentry *), &vfsmnt->mnt_root);
    real_mount = ((void *)vfsmnt) - offsetof(struct mount, mnt);

	struct file_ctx_x file_ctx = {
		dentry,
		mnt_root,
		vfsmnt,
		real_mount,
		0
	};


	// Iterate over the map elements to MAX_DENTRY_PATH_ITER
	//  This artificially limits the max path we will collect.
	//  After this dentry_cache will hold the path in reverse order
	bpf_for_each_map_elem(&dentry_cache, __get_path_element, &file_ctx, 0);

	// Record the total length that was calculated
	size_t total_buffer_len = file_ctx.total_len;

	// bpf_printk("__do_file_path: total_buffer_len = %d", total_buffer_len);

	// If we actually collected a path, we need to iterate over the map again and build an actual path
	//  which is then stored in data->buffer
	if (total_buffer_len > 0)
	{
		struct path_ctx_x path_ctx = {
			data,
			total_buffer_len
		};

		bpf_for_each_map_elem(&dentry_cache, __store_path, &path_ctx, 0);
	}

	return total_buffer_len;
}

/* File is opened for execution with sys_execve / sys_uselib */
#define FMODE_EXEC      ((fmode_t)0x20)
#define FMODE_CREATED   ((fmode_t)0x100000)
#define FMODE_NONOTIFY  ((fmode_t)0x4000000)
#define FMODE_NOACCOUNT ((fmode_t)0x20000000)

#define O_ACCMODE       00000003
#define O_RDONLY        00000000
#define O_WRONLY        00000001
#define O_RDWR          00000002

enum event_type
{
	EVENT_PROCESS_EXEC_PATH,
    EVENT_FILE_READ,
    EVENT_FILE_WRITE,
    EVENT_FILE_CREATE,
    EVENT_FILE_DELETE,
    EVENT_FILE_CLOSE,
    EVENT_FILE_RENAME
};

// with CONFIG_SECURITY_PATH enabled.
// SEC("fentry/security_path_unlink")
// int BPF_PROG(on_security_path_unlink, const struct path *dir, struct dentry *dentry)

SEC("fentry/security_inode_unlink")
int BPF_PROG(on_security_inode_unlink, struct inode *dir, struct dentry *dentry)
{
	// bpf_printk("on_security_inode_unlink: enter");
	pid_t pid;
    struct data_x *data_x = NULL;
    u16 buffer_size;

	pid = bpf_get_current_pid_tgid() >> 32;

	// Get a buffer to store the path
	data_x = __get_buffer(0);
    if (!data_x) {
        return 0;
    }

    // We need to walk the dentry back to the root node to collect the path
	//  This will end up looping twice and copying the path name twice.
	//  This is unfortunate but needed since there is no strlen 
    buffer_size = __do_dentry_path(dentry, data_x);

	bpf_printk("delete: pid = %d, filename = %s, length = %d", pid, data_x->buffer, buffer_size);

	return 0;
}

SEC("fentry/security_file_open")
int BPF_PROG(on_security_file_open, struct file *file)
{
	// bpf_printk("on_security_file_open: enter");
    unsigned long f_flags = 0;
    fmode_t f_mode = 0;

	if (!file)
	{
		return 0;
	}

    BPF_CORE_READ_INTO(&f_flags, file, f_flags);
    BPF_CORE_READ_INTO(&f_mode, file, f_mode);

	u8 type;
    if (f_flags & FMODE_EXEC) {
        type = EVENT_PROCESS_EXEC_PATH;
    } else if (f_mode & FMODE_CREATED) {
        // create intent may be grabbed sooner via security_path_mknod
        // with CONFIG_SECURITY_PATH enabled.
        type = EVENT_FILE_CREATE;
    } else if (f_flags & O_ACCMODE){
        type = EVENT_FILE_WRITE;
    } else {
        type = EVENT_FILE_READ;
    }

	pid_t pid;
    struct data_x *data_x = NULL;
    u16 buffer_size;

	// I only care about write and create right now
	if (type == EVENT_FILE_WRITE || type == EVENT_FILE_CREATE)
	{
		// bpf_printk("on_security_file_open: do_work");
		pid = bpf_get_current_pid_tgid() >> 32;

		// Get a buffer to store the path
		data_x = __get_buffer(0);
		if (!data_x) {
			return 0;
		}

		// We need to walk the dentry back to the root node to collect the path
		//  We also need to account for the mount point in this case because it may not be the root
		//  This will end up looping twice and copying the path name twice.
		//  This is unfortunate but needed since there is no strlen 
		buffer_size = __do_file_path(BPF_CORE_READ(file, f_path.dentry), BPF_CORE_READ(file, f_path.mnt), data_x);

		if (type == EVENT_FILE_WRITE)
		{
			bpf_printk("write: pid = %d, filename = %s, length = %d", pid, data_x->buffer, buffer_size);
		}
		else
		{
			bpf_printk("create: pid = %d, filename = %s, length = %d", pid, data_x->buffer, buffer_size);
		}
	}

	return 0;
}



// Old fentry example
// SEC("fentry/do_unlinkat")
// int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
// {
// 	pid_t pid;

// 	pid = bpf_get_current_pid_tgid() >> 32;
// 	bpf_printk("fentry: pid = %d, filename = %s", pid, name->name);
// 	return 0;
// }

// SEC("fexit/do_unlinkat")
// int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
// {
// 	pid_t pid;

// 	pid = bpf_get_current_pid_tgid() >> 32;
// 	bpf_printk("fexit: pid = %d, filename = %s, ret = %ld", pid, name->name, ret);
// 	return 0;
// }
