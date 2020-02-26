#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/ctype.h>
#include <linux/limits.h>
#include <linux/utsname.h>
#include <linux/err.h>
#include <linux/fs_struct.h>
#include <linux/thread_info.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/dirent.h>
#include <linux/fdtable.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <asm/ptrace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Du Jiajun");
MODULE_DESCRIPTION("File Strongbox");

typedef asmlinkage int (*original_openat_t)(struct pt_regs *regs);     //const char __user *filename, int flags, umode_t mode
typedef asmlinkage ssize_t (*original_read_t)(struct pt_regs *regs);   //int __fd, void* __buf, size_t __nbytes
typedef asmlinkage ssize_t (*original_write_t)(struct pt_regs *regs);  //int __fd, const void* __buf, size_t __n
typedef asmlinkage int (*original_getdents64_t)(struct pt_regs *regs); //unsigned int fd, struct linux_dirent64 *dirp, unsigned int count
typedef asmlinkage int (*original_linkat_t)(struct pt_regs *regs);     //int olddirfd,const char *oldpath,int newdirfd,const char *newpath,int flags
typedef asmlinkage int (*original_unlinkat_t)(struct pt_regs *regs);   //int dirfd, const char* pathname, int flags

original_openat_t original_openat;
original_write_t original_write;
original_read_t original_read;
original_getdents64_t original_getdents64;
original_linkat_t original_linkat;
original_unlinkat_t original_unlinkat;

typedef void (*sys_call_ptr_t)(void);

//配置文件内容为一行目录，即加密文件夹位置。目录须以/结尾
#define CONFIG_PATH "/etc/strongbox.cnf"
#define TMP_KEY_PATH "/tmp/filebox_crypto_key"
#define USER_PROCESS "filebox"
#define MAX_LENGTH 256
#define AES_BLOCK_SIZE (16)
#define AES_IV_SIZE (0)
#define AES_KEY_SIZE (16)
typedef enum
{
    ENCRYPT,
    DECRYPT
} cipher_mode;

bool enable_printk = false;
bool is_filebox_enabled = false;
char path_protected[MAX_LENGTH] = {0};

sys_call_ptr_t *get_sys_call_table(void)
{
    sys_call_ptr_t *_sys_call_table = NULL;
    _sys_call_table = (sys_call_ptr_t *)kallsyms_lookup_name("sys_call_table");
    return _sys_call_table;
}

int read_from_file(char *buf, int buf_size, char *filepath)
{
    struct file *fp = NULL;
    mm_segment_t old_fs;
    loff_t pos;
    fp = filp_open(filepath, O_RDONLY, 0);
    if (IS_ERR(fp))
    {
        printk("Strongbox: %s does not exist!\n", filepath);
        return -1;
    }
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    pos = fp->f_pos;
    vfs_read(fp, buf, buf_size, &pos);
    fp->f_pos = pos;
    set_fs(old_fs);
    if (fp != NULL)
        filp_close(fp, NULL);
    return 0;
}

int crypt_data(u8 *key, u32 key_len, u8 *iv, u32 iv_len, u8 *dst, u32 dst_len, u8 *src, u8 src_len, cipher_mode mode)
{
    struct crypto_blkcipher *blk;
    struct blkcipher_desc desc;
    struct scatterlist sg[2];

    blk = crypto_alloc_blkcipher("ecb(aes)", 0, 0);
    if (IS_ERR(blk))
    {
        printk("Strongbox: Failed to initialize AES\n");
        return -1;
    }

    if (crypto_blkcipher_setkey(blk, key, key_len))
    {
        printk("Strongbox: Failed to set key\n");
        crypto_free_blkcipher(blk);
        return -1;
    }

    crypto_blkcipher_set_iv(blk, iv, iv_len);

    sg_init_one(&sg[0], src, src_len);
    sg_init_one(&sg[1], dst, dst_len);

    desc.tfm = blk;
    desc.flags = 0;

    if (mode == ENCRYPT)
        crypto_blkcipher_encrypt(&desc, &sg[1], &sg[0], src_len);
    else 
        crypto_blkcipher_decrypt(&desc, &sg[1], &sg[0], src_len);
    crypto_free_blkcipher(blk);
    return 0;
}

char *get_path_by_task_and_fd(char *buf, struct task_struct *task, int fd)
{
    struct file *myfile = NULL;
    char *ppath;
    myfile = fget(fd);
    ppath = d_path(&(myfile->f_path), buf, MAX_LENGTH);
    return ppath;
}

void get_fullpath_from_relative(const char *relative_path, char *fullpath)
{
    struct dentry *tmp_dentry = current->fs->pwd.dentry;
    char tmp_path[MAX_LENGTH];
    char local_path[MAX_LENGTH];
    memset(tmp_path, 0, MAX_LENGTH);
    memset(local_path, 0, MAX_LENGTH);

    if (relative_path[0] == '/')
    {
        strcpy(fullpath, relative_path);
        return;
    }

    while (tmp_dentry != NULL)
    {
        if (strcmp(tmp_dentry->d_iname, "/") == 0)
            break;
        strcpy(tmp_path, "/");
        strcat(tmp_path, tmp_dentry->d_iname);
        strcat(tmp_path, local_path);
        strcpy(local_path, tmp_path);
        tmp_dentry = tmp_dentry->d_parent;
    }
    strcpy(fullpath, local_path);
    strcat(fullpath, "/");
    strcat(fullpath, relative_path);
}

bool is_path_in_protected_dir(const char *path)
{
    size_t len = strlen(path_protected);
    if (len == 0)
        return false;
    return strncmp(path, path_protected, len) == 0;
}

pid_t get_pid_by_process_name(const char *process_name)
{
    struct task_struct *p, *ts = &init_task;
    struct list_head *pos;
    list_for_each(pos, &ts->tasks)
    {
        p = list_entry(pos, struct task_struct, tasks);
        if (strcmp(p->parent->parent->comm, process_name) == 0)
            return p->pid;
    }
    ts = &init_task;
    list_for_each(pos, &ts->tasks)
    {
        p = list_entry(pos, struct task_struct, tasks);
        if (strcmp(p->parent->comm, process_name) == 0)
            return p->pid;
    }
    return -1;
}

void is_path_in_filebox_by_relative(char *path, bool *is_in_box, bool *is_config_file)
{
    char *kfilename = NULL, *fullpath = NULL;
    kfilename = (char *)kmalloc(MAX_LENGTH, GFP_KERNEL);
    memset(kfilename, 0, MAX_LENGTH);
    fullpath = (char *)kmalloc(MAX_LENGTH, GFP_KERNEL);
    memset(fullpath, 0, MAX_LENGTH);
    copy_from_user(kfilename, path, MAX_LENGTH);
    get_fullpath_from_relative(kfilename, fullpath);
    //strcat(fullpath, "/");
    if (is_in_box != NULL)
        *is_in_box = is_path_in_protected_dir(fullpath);
    if (is_config_file != NULL)
        *is_config_file = (strcmp(fullpath, CONFIG_PATH) == 0);
    if (kfilename != NULL)
        kfree(kfilename);
    if (fullpath != NULL)
        kfree(fullpath);
}

void is_path_in_filebox_by_fd(int fd, bool *is_in_box, bool *is_config_file)
{
    char *fullpath = NULL, *buf = NULL;
    buf = (char *)kmalloc(MAX_LENGTH, GFP_KERNEL);
    memset(buf, 0, MAX_LENGTH);
    fullpath = get_path_by_task_and_fd(buf, current, fd);
    if (is_in_box != NULL)
        *is_in_box = is_path_in_protected_dir(fullpath);
    if (is_config_file != NULL)
        *is_config_file = (strcmp(fullpath, CONFIG_PATH) == 0);
    if (enable_printk && fd > 2)
    {
        printk("%s %d %d\n", fullpath, *is_in_box, *is_config_file);
    }
    if (buf != NULL)
        kfree(buf);
}

bool is_current_our_process(void)
{
    pid_t pid, our_pid;
    //printk("%s\n",current->comm);
    if (strcmp(current->comm, USER_PROCESS) == 0)
        return true;
    pid = current->pid;
    our_pid = get_pid_by_process_name(USER_PROCESS);
    return pid == our_pid;
}

asmlinkage int hooked_openat(struct pt_regs *regs)
{
    int fd;
    bool is_in_box, is_config_file;
    //Linux参数传递，前6个参数使用寄存器传递，分别的顺序是di,si,dx,cx,r8,r9
    is_path_in_filebox_by_relative((char *)regs->si, &is_in_box, &is_config_file);
    if (is_in_box || is_config_file)
    {
        printk("Strongbox: [openat] FILE IS IN BOX\n");
        if (!is_current_our_process())
        {
            printk("Strongbox: [openat] CURRENT PROCRESS IS NOT OUR PROCESS\n");
            return -1;
        }
        else
        {
            printk("Strongbox: [openat] CURRENT PROCRESS IS OUR PROCESS\n");
        }
    }
    fd = original_openat(regs);
    return fd;
}

asmlinkage ssize_t hooked_read(struct pt_regs *regs)
{
    ssize_t res;
    bool is_in_box, is_config_file;

    int cnt_block, err, i; // number of blocks using AES
    char *ptr_crypt;
    unsigned char *key;
    u8 *iv, *src, *enc;

    enable_printk = is_current_our_process();
    is_path_in_filebox_by_fd(regs->di, &is_in_box, &is_config_file);

    if (is_config_file || is_in_box)
    {
        printk("Strongbox: [read] FILE IS IN BOX\n");
        if (!is_current_our_process())
        {
            printk("Strongbox: [read] CURRENT PROCRESS IS NOT OUR PROCESS\n");
            return -1;
        }
        else
        {
            printk("Strongbox: [read] CURRENT PROCRESS IS OUR PROCESS\n");
            res = original_read(regs);
            cnt_block = res / AES_BLOCK_SIZE;
            if (res != 0)
            {
                ptr_crypt = (char *)kmalloc(res + 1, GFP_KERNEL);
                memset(ptr_crypt, 0, res + 1);
                copy_from_user((char *)ptr_crypt, (char *)regs->si, res);

                //read key from file
                key = (unsigned char *)kmalloc(16, GFP_KERNEL);
                memset(key, 0, 16);
                read_from_file(key, 16, TMP_KEY_PATH);

                iv = (unsigned char *)kmalloc(AES_IV_SIZE, GFP_KERNEL);
                memset(iv, 0, AES_IV_SIZE);
                src = (unsigned char *)kmalloc(cnt_block * AES_BLOCK_SIZE + 1, GFP_KERNEL);
                memset(src, 0, cnt_block * AES_BLOCK_SIZE + 1);
                enc = (unsigned char *)kmalloc(cnt_block * AES_BLOCK_SIZE + 1, GFP_KERNEL);
                memset(enc, 0, cnt_block * AES_BLOCK_SIZE + 1);
                strncpy(enc, ptr_crypt, cnt_block * AES_BLOCK_SIZE);

                err = crypt_data(key, AES_KEY_SIZE, iv, AES_IV_SIZE, src, cnt_block * AES_BLOCK_SIZE, enc, cnt_block * AES_BLOCK_SIZE, DECRYPT);

                for (i = 0; i < res - AES_BLOCK_SIZE * cnt_block; i++)

                    ptr_crypt[AES_BLOCK_SIZE * cnt_block + i] = key[i] ^ ptr_crypt[AES_BLOCK_SIZE * cnt_block + i];

                for (i = 0; i < AES_BLOCK_SIZE * cnt_block; i++)

                    ptr_crypt[i] = src[i];

                copy_to_user((char *)regs->si, ptr_crypt, res);

                kfree(ptr_crypt);
                kfree(key);
                kfree(iv);
                kfree(enc);
                kfree(src);
                return res;
            }
        }
    }
    res = original_read(regs);
    return res;
}

asmlinkage ssize_t hooked_write(struct pt_regs *regs)
{
    ssize_t res, __n;
    bool is_in_box, is_config_file;
    int cnt_block, err, i; // number of blocks using AES
    char *ptr_crypt, *__buf;
    unsigned char *key;
    u8 *iv, *src, *enc;
    mm_segment_t fs;

    enable_printk = is_current_our_process();
    is_path_in_filebox_by_fd(regs->di, &is_in_box, &is_config_file);

    if (is_config_file || is_in_box)
    {
        printk("Strongbox: [write] FILE IS IN BOX\n");
        if (!is_current_our_process())
        {
            printk("Strongbox: [write] CURRENT PROCRESS IS NOT OUR PROCESS\n");
            return -1;
        }
        else
        {
            printk("Strongbox: [write] CURRENT PROCRESS IS OUR PROCESS\n");
            __n = regs->dx;
            __buf = (char *)regs->si;
            cnt_block = __n / AES_BLOCK_SIZE;
            if (__n != 0)
            {
                ptr_crypt = (char *)kmalloc(__n + 1, GFP_KERNEL);
                memset(ptr_crypt, 0, __n + 1);

                copy_from_user((char *)ptr_crypt, (char *)regs->si, __n);

                key = (unsigned char *)kmalloc(16, GFP_KERNEL);
                memset(key, 0, 16);
                read_from_file(key, 16, TMP_KEY_PATH);

                iv = (unsigned char *)kmalloc(AES_IV_SIZE, GFP_KERNEL);
                memset(iv, 0, AES_IV_SIZE);
                enc = (unsigned char *)kmalloc(cnt_block * AES_BLOCK_SIZE + 1, GFP_KERNEL);
                memset(enc, 0, cnt_block * AES_BLOCK_SIZE + 1);
                src = (unsigned char *)kmalloc(cnt_block * AES_BLOCK_SIZE + 1, GFP_KERNEL);
                memset(src, 0, cnt_block * AES_BLOCK_SIZE + 1);

                strncpy(src, ptr_crypt, cnt_block * AES_BLOCK_SIZE);
                err = crypt_data(key, AES_KEY_SIZE, iv, AES_IV_SIZE, enc, cnt_block * AES_BLOCK_SIZE, src, cnt_block * AES_BLOCK_SIZE, ENCRYPT);
                for (i = 0; i < __n - AES_BLOCK_SIZE * cnt_block; i++)

                    ptr_crypt[AES_BLOCK_SIZE * cnt_block + i] = key[i] ^ ptr_crypt[AES_BLOCK_SIZE * cnt_block + i];

                for (i = 0; i < AES_BLOCK_SIZE * cnt_block; i++)

                    ptr_crypt[i] = enc[i];

                fs = get_fs();
                set_fs(KERNEL_DS);
                regs->si = (long unsigned int)ptr_crypt;
                res = original_write(regs);
                regs->si = (long unsigned int)__buf;
                set_fs(fs);

                kfree(ptr_crypt);
                kfree(key);
                kfree(iv);
                kfree(enc);
                kfree(src);
            }
            else
                res = original_write(regs);

            return res;
        }
    }
    res = original_write(regs);

    return res;
}

asmlinkage int hooked_getdents64(struct pt_regs *regs)
{
    int res;
    bool is_in_box, is_config_file;
    enable_printk = is_current_our_process();
    is_path_in_filebox_by_fd(regs->di, &is_in_box, &is_config_file);

    if (is_in_box || is_config_file)
    {
        printk("Strongbox: [getdents64] FILE IS IN BOX\n");
        if (!is_current_our_process())
        {
            printk("Strongbox: [getdents64] CURRENT PROCRESS IS NOT OUR PROCESS\n");
            return -1;
        }
        else
        {
            printk("Strongbox: [getdents64] CURRENT PROCRESS IS OUR PROCESS\n");
        }
    }
    res = original_getdents64(regs);
    return res;
}

asmlinkage int hooked_linkat(struct pt_regs *regs)
{
    int res;
    bool is_in_box_old, is_in_box_new, is_config_file_new, is_config_file_old;
    is_path_in_filebox_by_relative((char *)regs->si, &is_in_box_old, &is_config_file_old);
    is_path_in_filebox_by_relative((char *)regs->cx, &is_in_box_new, &is_config_file_new);
    if (is_in_box_old || is_in_box_new || is_config_file_old || is_config_file_new)
    {
        printk("Strongbox: [linkat] FILE IS IN BOX\n");
        if (!is_current_our_process())
        {
            printk("Strongbox: [linkat] CURRENT PROCRESS IS NOT OUR PROCESS\n");
            return -1;
        }
        else
        {
            printk("Strongbox: [linkat] CURRENT PROCRESS IS OUR PROCESS\n");
        }
    }

    res = original_linkat(regs);
    return res;
}

asmlinkage int hooked_unlinkat(struct pt_regs *regs)
{
    int res;
    bool is_in_box, is_config_file;
    is_path_in_filebox_by_relative((char *)regs->si, &is_in_box, &is_config_file);

    if (is_in_box || is_config_file)
    {
        printk("Strongbox: [unlinkat] FILE IS IN BOX\n");
        if (!is_current_our_process())
        {
            printk("Strongbox: [unlinkat] CURRENT PROCRESS IS NOT OUR PROCESS\n");
            return -1;
        }
        else
        {
            printk("Strongbox: [unlinkat] CURRENT PROCRESS IS OUR PROCESS\n");
        }
    }
    res = original_unlinkat(regs);
    return res;
}

void disable_write_protection(void)
{
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    write_cr0(cr0);
}

void enable_write_protection(void)
{
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    write_cr0(cr0);
}

void load_config(void)
{
    size_t len;
    int res = -1;
    res = read_from_file(path_protected, MAX_LENGTH, CONFIG_PATH);
    if (res == -1)
        return;
    len = strlen(path_protected);
    if (len >= 1 && path_protected[len - 1] == '\n') //清除末尾的换行符
        path_protected[len - 1] = '\0';
    printk("Strongbox: protected path is %s.", path_protected);
    is_filebox_enabled = true;
}

sys_call_ptr_t *sys_call_table = NULL;

static int __init strongbox_init(void)
{
    printk("Strongbox: Init\n");
    load_config();
    if (!is_filebox_enabled)
        return 0;
    sys_call_table = get_sys_call_table();
    printk("Strongbox: sys_call_table found at %lx\n", (unsigned long)sys_call_table);
    original_openat = (original_openat_t)sys_call_table[__NR_openat];
    original_write = (original_write_t)sys_call_table[__NR_write];
    original_read = (original_read_t)sys_call_table[__NR_read];
    original_getdents64 = (original_getdents64_t)sys_call_table[__NR_getdents64];
    original_linkat = (original_linkat_t)sys_call_table[__NR_linkat];
    original_unlinkat = (original_unlinkat_t)sys_call_table[__NR_unlinkat];

    disable_write_protection();
    printk("Strongbox: Disable write-protection of sys_call_table\n");

    sys_call_table[__NR_openat] = (sys_call_ptr_t)hooked_openat;
    sys_call_table[__NR_read] = (sys_call_ptr_t)hooked_read;
    sys_call_table[__NR_write] = (sys_call_ptr_t)hooked_write;
    sys_call_table[__NR_getdents64] = (sys_call_ptr_t)hooked_getdents64;
    sys_call_table[__NR_linkat] = (sys_call_ptr_t)hooked_linkat;
    sys_call_table[__NR_unlinkat] = (sys_call_ptr_t)hooked_unlinkat;
    enable_write_protection();
    printk("Strongbox: sys_call_table hooked!\n");
    return 0;
}

static void __exit strongbox_exit(void)
{
    printk("Strongbox: Exit\n");
    if (!is_filebox_enabled)
        return;
    disable_write_protection();
    sys_call_table[__NR_openat] = (sys_call_ptr_t)original_openat;
    sys_call_table[__NR_read] = (sys_call_ptr_t)original_read;
    sys_call_table[__NR_write] = (sys_call_ptr_t)original_write;
    sys_call_table[__NR_getdents64] = (sys_call_ptr_t)original_getdents64;
    sys_call_table[__NR_linkat] = (sys_call_ptr_t)original_linkat;
    sys_call_table[__NR_unlinkat] = (sys_call_ptr_t)original_unlinkat;
    enable_write_protection();
}

module_init(strongbox_init);
module_exit(strongbox_exit);