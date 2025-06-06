#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "lib/kernel/list.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static bool validate_user_buffer(const void *ptr, size_t size);
static bool validate_user_string(const char *str);

static bool validate_user_buffer(const void *ptr, size_t size) {
    if (size == 0) return true;

    uint8_t *start = (uint8_t *) ptr;
    uint8_t *end = start + size;

    for (uint8_t *p = start; p < end; p = (uint8_t *)((uintptr_t)p + PGSIZE)) {
        if (!is_user_vaddr(p) || pagedir_get_page(thread_current()->pagedir, p) == NULL) {
            return false;
        }
    }

    if (!is_user_vaddr(end - 1) || pagedir_get_page(thread_current()->pagedir, end - 1) == NULL) {
        return false;
    }

    return true;
}

bool validate_user_string(const char *str) {
    while (true) {
        if (!is_user_vaddr(str) || pagedir_get_page(thread_current()->pagedir, str) == NULL)
            return false;
        if (*str == '\0')
            break;
        str++;
    }
    return true;
}

typedef struct ofd {
    struct file *file;
    int fd;
    tid_t pid;
    struct list_elem elem;
} ofd_t;

ofd_t *get_ofd(int fd);

struct list ofd_table;

ofd_t *get_ofd(int fd)
{
    struct list_elem *e;
    for (e = list_begin(&ofd_table); e != list_end(&ofd_table); e = list_next (e))
    {
        ofd_t *ofd = list_entry(e, ofd_t, elem);
        if(ofd->fd == fd) 
        {
            return ofd;
        }
    }
    return NULL;
}

void close_all_fds_for_current(void) {
    struct thread *cur = thread_current();
    tid_t self_tid = cur->tid;

    // go through list of file descriptors
    struct list_elem *e = list_begin(&ofd_table);
    while (e != list_end(&ofd_table)) {
        ofd_t *ofd = list_entry(e, ofd_t, elem);

        // move to next element before we potentially remove the current one
        e = list_next(e);

        if (ofd->pid == self_tid) {
            file_close(ofd->file);
            list_remove(&ofd->elem);
            free(ofd);
        }
    }
}


static void syscall_handler(struct intr_frame *);

void syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    list_init(&ofd_table);
}

static void syscall_handler(struct intr_frame *f UNUSED) {

    if (!validate_user_buffer(f->esp, sizeof(uint32_t))) {
        process_exit_with_code(-1);
    }
    uint32_t *args = ((uint32_t *) f->esp);

    /*
     * The following print statement, if uncommented, will print out the syscall
     * number whenever a process enters a system call. You might find it useful
     * when debugging. It will cause tests to fail, however, so you should not
     * include it in your final submission.
     */

    /* printf("System call number: %d\n", args[0]); */

    if (args[0] == SYS_EXIT) {

        if (!validate_user_buffer(args, sizeof(uint32_t) * 2)) {
            process_exit_with_code(-1);
        }

        f->eax = args[1];
        printf("%s: exit(%d)\n", thread_current()->name, args[1]);

        struct child_info *ci = thread_current()-> my_info;
        if(ci!= NULL){
            ci->has_exited = true; // mark as exited
            ci->exit_status = args[1]; // set exit status
            sema_up(&ci->sema_wait); // signal parent that child has exited
        }

        if(thread_current()->executable_file != NULL) {
            file_allow_write(thread_current()->executable_file);
            file_close(thread_current()->executable_file);
            thread_current()->executable_file = NULL;
        }


        process_exit();
        thread_exit();
    } else if (args[0] == SYS_INCREMENT) {
        f->eax = args[1] + 1;
    } else if (args[0] == SYS_CREATE) {
        if (!validate_user_string((const char *)args[1])) {
            process_exit_with_code(-1);
        }
        const char* file_name = (const char*)args[1];
        unsigned initial_size = args[2];
        f->eax = filesys_create(file_name, initial_size);
    } else if (args[0] == SYS_REMOVE) {
        if (!validate_user_string((const char *)args[1])) {
            process_exit_with_code(-1);
        }
        const char* file_name = (const char*)args[1];
        f->eax = filesys_remove(file_name);
    } else if (args[0] == SYS_OPEN) {
        if (!validate_user_string((const char *)args[1])) {
            process_exit_with_code(-1);
        }
        const char* file_name = (const char*)args[1];
        struct file *file = filesys_open(file_name);

        if(file == NULL) f->eax = -1;
        else
        {
            int fd = list_size(&ofd_table) + 2; // add 2 since 0, 1 are invalid fds

            ofd_t* ofd = malloc(sizeof(ofd_t));
            ofd->fd = fd;
            ofd->file = file;
            ofd->pid = thread_current()->tid;

            list_push_back(&ofd_table, &ofd->elem);
            f->eax = fd;
        }
    } else if (args[0] == SYS_FILESIZE) {
        int fd = args[1];
        f->eax = -1;
        ofd_t *ofd = get_ofd(fd);
        if(ofd != NULL && ofd->pid == thread_current()->tid) f->eax = file_length(ofd->file);
    } else if (args[0] == SYS_READ) {
        if (!validate_user_buffer((void *)args[2], (size_t)args[3])) {
            process_exit_with_code(-1);
        }
        int fd = args[1];
        void *buffer = (void*)args[2];
        unsigned size = args[3];
        ofd_t *ofd = get_ofd(fd);

        if(fd >= 2 && ofd != NULL && ofd->pid == thread_current()->tid) // not stdin/stdout
        {
            off_t bytes_read = file_read(ofd->file, buffer, size);
            f->eax = bytes_read;
        }
    } else if (args[0] == SYS_CLOSE) {
        int fd = args[1];
        ofd_t *ofd = get_ofd(fd);
        if(ofd != NULL && ofd->pid == thread_current()->tid) 
        {
            list_remove(&ofd->elem);
            file_close(ofd->file);
            free(ofd);
        }
    } else if (args[0] == SYS_WRITE) {
        if (!validate_user_buffer((void *)args[2], (size_t)args[3])) {
            process_exit_with_code(-1);
        }
        int fd = args[1];
        const void* buf = (const void*)args[2];
        unsigned size = args[3];
        ofd_t *ofd = get_ofd(fd);

        if(fd == 1)
            putbuf(buf, size);
        else if(fd >= 2 && ofd != NULL && ofd->pid == thread_current()->tid)
        {
            off_t bytes_written = file_write(ofd->file, buf, size);
            f->eax = bytes_written;
        }
    } else if (args[0] == SYS_SEEK) {
        int fd = args[1];
        unsigned position = args[2];
        ofd_t *ofd = get_ofd(fd);
        if(ofd != NULL && ofd->pid == thread_current()->tid) file_seek(ofd->file, position);
    } else if (args[0] == SYS_TELL) {
        int fd = args[1];
        ofd_t *ofd = get_ofd(fd);
        if(ofd != NULL && ofd->pid == thread_current()->tid) f->eax = file_tell(ofd->file);
        else f->eax = -1;
    } else if (args[0] == SYS_WAIT) {
        tid_t pid = (tid_t) args[1];
        f ->eax = process_wait(pid);
    } else if (args[0] == SYS_EXEC) {
        if (!validate_user_buffer(args, sizeof(uint32_t) * 2)) {
        process_exit_with_code(-1);
        }
        const char *user_ptr = (const char *) args[1];

        if (!validate_user_string(user_ptr)) {
            process_exit_with_code(-1);
        }

        char *cmd_copy = palloc_get_page(0);
        if (cmd_copy == NULL) {
            process_exit_with_code(-1);
        }

        strlcpy(cmd_copy, user_ptr, PGSIZE);

        tid_t child_tid = process_execute(cmd_copy);
        if (child_tid == TID_ERROR) {
            palloc_free_page(cmd_copy);  // cleanup on failure
            f->eax = -1;
            return;
        }

        struct thread *child_thread = get_thread_by_tid(child_tid);
        struct child_info *ci = child_thread->my_info;
        sema_down(&ci->sema_load);

        if (!ci->load_success) {
            process_wait(child_tid);
            f->eax = -1;
        } else {
            f->eax = child_tid;
        }
        palloc_free_page(cmd_copy);
    }
}