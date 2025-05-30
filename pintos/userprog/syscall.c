#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "lib/kernel/list.h"

typedef struct ofd {
    struct file *file;
    int fd;
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

static void syscall_handler(struct intr_frame *);

void syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    list_init(&ofd_table);
}

static void syscall_handler(struct intr_frame *f UNUSED) {
    uint32_t *args = ((uint32_t *) f->esp);

    /*
     * The following print statement, if uncommented, will print out the syscall
     * number whenever a process enters a system call. You might find it useful
     * when debugging. It will cause tests to fail, however, so you should not
     * include it in your final submission.
     */

    /* printf("System call number: %d\n", args[0]); */

    if (args[0] == SYS_EXIT) {
        f->eax = args[1];
        printf("%s: exit(%d)\n", thread_current()->name, args[1]);
        thread_exit();
    } else if (args[0] == SYS_INCREMENT) {
        f->eax = args[1] + 1;
    } else if (args[0] == SYS_CREATE) {
        const char* file_name = (const char*)args[1];
        unsigned initial_size = args[2];
        f->eax = filesys_create(file_name, initial_size);
    } else if (args[0] == SYS_REMOVE) {
        const char* file_name = (const char*)args[1];
        f->eax = filesys_remove(file_name);
    } else if (args[0] == SYS_OPEN) {
        const char* file_name = (const char*)args[1];
        struct file *file = filesys_open(file_name);

        if(file == NULL) f->eax = -1;
        else
        {
            int fd = list_size(&ofd_table) + 2; // add 2 since 0, 1 are invalid fds

            ofd_t* ofd = malloc(sizeof(ofd_t));
            ofd->fd = fd;
            ofd->file = file;

            list_push_back(&ofd_table, &ofd->elem);
            f->eax = fd;
        }
    } else if (args[0] == SYS_FILESIZE) {
        int fd = args[1];
        f->eax = -1;
        ofd_t *ofd = get_ofd(fd);
        if(ofd != NULL) f->eax = file_length(ofd->file);
    } else if (args[0] == SYS_READ) {
        int fd = args[1];
        void *buffer = (void*)args[2];
        unsigned size = args[3];
        ofd_t *ofd = get_ofd(fd);

        if(fd >= 2 && ofd != NULL) // not stdin/stdout
        {
            off_t bytes_read = file_read(ofd->file, buffer, size);
            f->eax = bytes_read;
        }
    } else if (args[0] == SYS_CLOSE) {
        int fd = args[1];
        ofd_t *ofd = get_ofd(fd);
        if(ofd != NULL) 
        {
            list_remove(&ofd->elem);
            file_close(ofd->file);
            free(ofd);
        }
    } else if (args[0] == SYS_WRITE) {
        int fd = args[1];
        const void* buf = (const void*)args[2];
        unsigned size = args[3];
        ofd_t *ofd = get_ofd(fd);

        if(fd == 1)
            putbuf(buf, size);
        else if(fd >= 2 && ofd != NULL)
        {
            off_t bytes_written = file_write(ofd->file, buf, size);
            f->eax = bytes_written;
        }
    } else if (args[0] == SYS_SEEK) {
        int fd = args[1];
        unsigned position = args[2];
        ofd_t *ofd = get_ofd(fd);
        if(ofd != NULL) file_seek(ofd->file, position);
    } else if (args[0] == SYS_TELL) {
        int fd = args[1];
        ofd_t *ofd = get_ofd(fd);
        if(ofd != NULL) f->eax = file_tell(ofd->file);
        else f->eax = -1;
    } 
}
