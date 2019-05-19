#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/off_t.h"
#include "kernel/list.h"
//#include "devices/shutdown.h"
typedef void (*CALL_PROC)(struct intr_frame *);
CALL_PROC sys_array[21];

void *check_address(const void *vaddr);

void get_content(int *esp, int *a, int offset)
{
	int *tmp_esp = esp;
	*a = *((int *)check_address(tmp_esp + offset));
}

int exec_process(char *file_name)
{
	acquire_file_lock();
	char *name = malloc(strlen(file_name) + 1);
	strlcpy(name, file_name, strlen(file_name) + 1);

	char *tmp_ptr;
	name = strtok_r(name, " ", &tmp_ptr);
	/* check if the file exist*/
	struct file *f = filesys_open(name);

	if (f == NULL)
	{
		release_file_lock();
		return -1;
	}
	else
	{
		file_close(f);
		release_file_lock();
		return process_execute(file_name);
	}
}

/* exit */
void exit_process(int status)
{
	struct child_process *cp;
	enum intr_level old_level = intr_disable();
	for (struct list_elem *e = list_begin(&thread_current()->parent->children_list); e != list_end(&thread_current()->parent->children_list); e = list_next(e))
	{
		cp = list_entry(e, struct child_process, child_elem);
		if (cp->tid == thread_current()->tid)
		{
			cp->if_waited = true;
			cp->exit_status = status;
		}
	}
	thread_current()->exit_status = status;
	intr_set_level(old_level);

	thread_exit();
}

/* check the address whether valid or not */
void *
check_address(const void *vaddr)
{
	void *page_ptr = NULL;
	if (!is_user_vaddr(vaddr))
	{
		exit_process(-1);
		return 0;
	}
	if(!(page_ptr = pagedir_get_page(thread_current()->pagedir, vaddr))){
		exit_process(-1);
		return 0;
	}
	return page_ptr;
}

/* Find fd and return process file struct in the list, if not exist return NULL. */
struct process_file *
find_one_file(struct list *files, int fd)
{
	struct process_file *f;
	for (struct list_elem *e = list_begin(files); e != list_end(files); e = list_next(e))
	{
		f = list_entry(e, struct process_file, elem);
		if (f->fd == fd)
			return f;
	}
	return NULL;
}

/* close and free specific process files by the given fd in the file list. Firstly, find fd in the list, then remove it. */
void close_single_file(struct list *files, int fd)
{
	struct process_file *proc_f = find_one_file(files, fd);
	if (proc_f != NULL)
	{
		file_close(proc_f->ptr);
		list_remove(&proc_f->elem);
		free(proc_f);
	}
}

/* close and free all process files in the file list */
void close_all_files(struct list *files)
{
	struct process_file *f;
	while (!list_empty(files))
	{
		f = list_entry(list_pop_front(files), struct process_file, elem);
		file_close(f->ptr);
		list_remove(&f->elem);
		free(f);
	}
}

/* halt */
void syscall_halt(struct intr_frame *f)
{
	shutdown_power_off();
}

/* exit */
void syscall_exit(struct intr_frame *f)
{
	int status;
	get_content(f->esp, &status, 1);
	exit_process(status);
}

/* exec */
void syscall_exec(struct intr_frame *f)
{
	char *f_name = NULL;
	get_content(f->esp, &f_name, 1);
	if (!check_address(f_name))
		f->eax = -1;
	else
		f->eax = exec_process(f_name);
}

/* wait */
void syscall_wait(struct intr_frame *f)
{
	tid_t child_tid;
	get_content(f->esp, &child_tid, 1);
	f->eax = process_wait(child_tid);
}
/* get the file size */
void syscall_filesize(struct intr_frame *f)
{
	int ret;
	int fd;
	get_content(f->esp, &fd, 1);
	lock_acquire(&filesys_lock);
	ret = file_length(find_one_file(&thread_current()->opened_files, fd)->ptr);
	lock_release(&filesys_lock);

	f->eax = ret;
}

/* read */
void syscall_read(struct intr_frame *f)
{
	int ret;
	int size;
	void *buffer;
	int fd;

	get_content(f->esp, &size, 7);
	get_content(f->esp, &buffer, 6);
	get_content(f->esp, &fd, 5);

	if (!check_address(buffer) || !check_address(buffer + size))
		ret = -1;

	if (fd == STDIN_FILENO) /* read from std input*/
	{
		int i;
		uint8_t *buffer = buffer;
		for (i = 0; i < size; i++)
			buffer[i] = input_getc();
		ret = size;
	}
	else /* read from file*/
	{
		struct process_file *pf = find_one_file(&thread_current()->opened_files, fd);
		if (pf == NULL)
			ret = -1;
		else
		{
			lock_acquire(&filesys_lock);
			ret = file_read(pf->ptr, buffer, size);
			lock_release(&filesys_lock);
		}
	}

	f->eax = ret;
}

/* create */
void syscall_create(struct intr_frame *f)
{
	int ret;
	off_t initial_size;
	char *name;

	get_content(f->esp, &initial_size, 5);
	get_content(f->esp, &name, 4);
	if (!check_address(name))
		ret = -1;

	lock_acquire(&filesys_lock);
	ret = filesys_create(name, initial_size);
	lock_release(&filesys_lock);
	f->eax = ret;
}

/* remove */
void syscall_remove(struct intr_frame *f)
{
	int ret;
	char *name;

	get_content(f->esp, &name, 1);
	if (!check_address(name))
		ret = -1;

	lock_acquire(&filesys_lock);
	ret = !(filesys_remove(name) == NULL);
	lock_release(&filesys_lock);

	f->eax = ret;
}

/* open the file */
void syscall_open(struct intr_frame *f)
{
	int ret;
	char *name;

	get_content(f->esp, &name, 1);
	if (!check_address(name))
		ret = -1;

	lock_acquire(&filesys_lock);
	struct file *fptr = filesys_open(name);
	lock_release(&filesys_lock);

	if (fptr == NULL)
		ret = -1;
	else
	{
		struct process_file *pf = malloc(sizeof(*pf));
		pf->ptr = fptr;
		pf->fd = thread_current()->fd_count;
		thread_current()->fd_count++;
		list_push_back(&thread_current()->opened_files, &pf->elem);
		ret = pf->fd;
	}
	f->eax = ret;
}


/* write */
void syscall_write(struct intr_frame *f)
{
	int ret;
	int size;
	void *buffer;
	int fd;

	get_content(f->esp, &size, 7);
	get_content(f->esp, &buffer, 6);
	get_content(f->esp, &fd, 5);

	if (!check_address(buffer) || !check_address(buffer + size))
		ret = -1;

	if (fd == 1) /* write to stdout */
	{
		putbuf(buffer, size);
		ret = size;
	}
	else
	{
		/* write to file */
		enum intr_level old_level = intr_disable();
		struct process_file *pf = find_one_file(&thread_current()->opened_files, fd);
		intr_set_level(old_level);

		if (pf == NULL)
			ret = -1;
		else
		{
			lock_acquire(&filesys_lock);
			ret = file_write(pf->ptr, buffer, size);
			lock_release(&filesys_lock);
		}
	}

	f->eax = ret;
}

/* seek */
void syscall_seek(struct intr_frame *f)
{
	int fd;
	int pos;
	get_content(f->esp, &fd, 5);
	get_content(f->esp, &pos, 4);

	lock_acquire(&filesys_lock);
	file_seek(find_one_file(&thread_current()->opened_files, pos)->ptr, fd);
	lock_release(&filesys_lock);
}

/* tell */
void syscall_tell(struct intr_frame *f)
{
	int ret;
	int fd;
	get_content(f->esp, &fd, 1);

	lock_acquire(&filesys_lock);
	ret = file_tell(find_one_file(&thread_current()->opened_files, fd)->ptr);
	lock_release(&filesys_lock);

	f->eax = ret;
}

/* close */
void syscall_close(struct intr_frame *f)
{
	int fd;
	get_content(f->esp, &fd, 1);

	lock_acquire(&filesys_lock);
	close_single_file(&thread_current()->opened_files, fd));
	lock_release(&filesys_lock);
}

/* syscall handler*/
static void
syscall_handler(struct intr_frame *f UNUSED)
{
	int *p = f->esp;
	check_address(p);
	int system_call = *p;
	sys_array[system_call](f);
}

/* initialize the syscall array*/
void syscall_init(void)
{
	intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
	int i;
	for (i = 0; i < 21; i++)
		sys_array[i] = NULL;
	sys_array[SYS_WRITE] = syscall_write;
	sys_array[SYS_EXIT] = syscall_exit;
	sys_array[SYS_CREATE] = syscall_create;
	sys_array[SYS_OPEN] = syscall_open;
	sys_array[SYS_CLOSE] = syscall_close;
	sys_array[SYS_READ] = syscall_read;
	sys_array[SYS_FILESIZE] = syscall_filesize;
	sys_array[SYS_EXEC] = syscall_exec;
	sys_array[SYS_WAIT] = syscall_wait;
	sys_array[SYS_SEEK] = syscall_seek;
	sys_array[SYS_REMOVE] = syscall_remove;
	sys_array[SYS_TELL] = syscall_tell;
	sys_array[SYS_HALT] = syscall_halt;
}
