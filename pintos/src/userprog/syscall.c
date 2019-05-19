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
typedef void (*CALL_PROC)(struct intr_frame*);
CALL_PROC sys_array[21];
static void syscall_handler (struct intr_frame *);
int exec_process(char *file_name);
void exit_process(int status);
void * is_valid_addr(const void *vaddr);
struct process_file* search_one_file(struct list* files, int fd);
void clean_single_file(struct list* files, int fd);
void get_content(int *esp, int *a, int offset){
	int *tmp_esp = esp;
	*a = *((int *)is_valid_addr(tmp_esp + offset));
}
int
exec_process(char *file_name)
{
	acquire_file_lock();
	char * name_tmp = malloc (strlen(file_name)+1);
	strlcpy(name_tmp, file_name, strlen(file_name) + 1);

	char *tmp_ptr;
	name_tmp = strtok_r(name_tmp, " ", &tmp_ptr);
	/* check if the file exist*/
	struct file *f = filesys_open(name_tmp);  

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

void
exit_process(int status)
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

void *
is_valid_addr(const void *vaddr)
{
	void *page_ptr = NULL;
	if (!is_user_vaddr(vaddr) || !(page_ptr = pagedir_get_page(thread_current()->pagedir, vaddr)))
	{
		exit_process(-1);
		return 0;
	}
	return page_ptr;
}

  /* Find fd and return process file struct in the list,
  if not exist return NULL. */
struct process_file *
search_one_file(struct list* files, int fd)
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

  /* close and free specific process files
  by the given fd in the file list. Firstly,
  find fd in the list, then remove it. */
void
clean_single_file(struct list* files, int fd)
{
	struct process_file *proc_f = search_one_file(files,fd);
	if (proc_f != NULL){
		file_close(proc_f->ptr);
		list_remove(&proc_f->elem);
    	free(proc_f);
	}
}

  /* close and free all process files in the file list */
void
clean_all_files(struct list* files)
{
	struct process_file *proc_f;
	while(!list_empty(files))
	{
		proc_f = list_entry (list_pop_front(files), struct process_file, elem);
		file_close(proc_f->ptr);
		list_remove(&proc_f->elem);
		free(proc_f);
	}
}

/* handlers for system calls */
void syscall_halt(struct intr_frame *f ){
	shutdown_power_off();
}
void
syscall_exit(struct intr_frame *f)
{
	int status;
	get_content(f->esp, &status, 1);
	exit_process(status);
}
void
syscall_exec(struct intr_frame *f)
{
	char *file_name = NULL;
	get_content(f->esp, &file_name, 1);
	if (!is_valid_addr(file_name))
		f->eax = -1;
	else
		f->eax = exec_process(file_name);
}
void
syscall_wait(struct intr_frame *f)
{
	tid_t child_tid;
	get_content(f->esp, &child_tid, 1);
	f->eax =  process_wait(child_tid);
}
void
syscall_create(struct intr_frame *f)
{
	int ret;
	off_t initial_size;
	char *name;
	// initial_size = *((int *)is_valid_addr(f->esp + 5));
	get_content(f->esp, &initial_size, 5);
	// name = *((int *)is_valid_addr(f->esp + 4));
	get_content(f->esp, &name, 4);
	if (!is_valid_addr(name))
		ret = -1;

	lock_acquire(&filesys_lock);
	ret = filesys_create(name, initial_size);
	lock_release(&filesys_lock);
	f->eax = ret;
}
void
syscall_remove(struct intr_frame *f)
{
	int ret;
	char *name;

	get_content(f->esp, &name, 1);
	if (!is_valid_addr(name))
		ret = -1;

	lock_acquire(&filesys_lock);
	if (filesys_remove(name) == NULL)
		ret = false;
	else
		ret = true;
	lock_release(&filesys_lock);

	f->eax = ret;
}
void
syscall_open(struct intr_frame *f)
{
	int ret;
	char *name;

	get_content(f->esp, &name, 1);
	if (!is_valid_addr(name))
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
void
syscall_filesize(struct intr_frame *f)
{
	int ret;
	int fd;
	get_content(f->esp, &fd, 1);

	lock_acquire(&filesys_lock);
	ret = file_length(search_one_file(&thread_current()->opened_files, fd)->ptr);
	lock_release(&filesys_lock);

	f->eax = ret;
}
void
syscall_read(struct intr_frame *f)
{
	int ret;
	int size;
	void *buffer;
	int fd;

	get_content(f->esp, &size, 7);
	get_content(f->esp, &buffer, 6);
	get_content(f->esp, &fd, 5);

	// if (!is_valid_addr(buffer))
	// 	ret = -1;

	if (fd == STDIN_FILENO)/* read from std input*/
	{
		int i;
		uint8_t *buffer = buffer;
		for (i = 0; i < size; i++)
			buffer[i] = input_getc();
		ret = size;
	}
	else /* read from file*/
	{
		struct process_file *pf = search_one_file(&thread_current()->opened_files, fd);
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
void
syscall_write(struct intr_frame *f)
{
	int ret;
	int size;
	void *buffer;
	int fd;

	get_content(f->esp, &size, 7);
	get_content(f->esp, &buffer, 6);
	get_content(f->esp, &fd, 5);

	// if (!is_valid_addr(buffer))
	// 	ret = -1;

	if (fd == 1)
	{
		putbuf(buffer, size);
		ret = size;
	}
	else
	{
		enum intr_level old_level = intr_disable();
		struct process_file *pf = search_one_file(&thread_current()->opened_files, fd);
		intr_set_level (old_level);

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
void
syscall_seek(struct intr_frame *f)
{
	int fd;
	int pos;
	get_content(f->esp, &fd, 5);
	get_content(f->esp, &pos, 4);

	lock_acquire(&filesys_lock);
	file_seek(search_one_file(&thread_current()->opened_files, pos)->ptr, fd);
	lock_release(&filesys_lock);
}
void
syscall_tell(struct intr_frame *f)
{
	int ret;
	int fd;
	get_content(f->esp, &fd, 1);

	lock_acquire(&filesys_lock);
	ret = file_tell(search_one_file(&thread_current()->opened_files, fd)->ptr);
	lock_release(&filesys_lock);

	f->eax= ret;
}
void
syscall_close(struct intr_frame *f)
{
	int fd;
	get_content(f->esp, &fd, 1);

	lock_acquire(&filesys_lock);
	clean_single_file(&thread_current()->opened_files, fd);
	lock_release(&filesys_lock);
}
void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  int i;
  for(i=0;i<21;i++)
    sys_array[i]=NULL;
  sys_array[SYS_WRITE]=syscall_write;
  sys_array[SYS_EXIT]=syscall_exit;
  sys_array[SYS_CREATE]=syscall_create;
  sys_array[SYS_OPEN]=syscall_open;
  sys_array[SYS_CLOSE]=syscall_close;
  sys_array[SYS_READ]=syscall_read;
  sys_array[SYS_FILESIZE]=syscall_filesize;
  sys_array[SYS_EXEC]=syscall_exec;
  sys_array[SYS_WAIT]=syscall_wait;
  sys_array[SYS_SEEK]=syscall_seek;
  sys_array[SYS_REMOVE]=syscall_remove;
  sys_array[SYS_TELL]=syscall_tell;
  sys_array[SYS_HALT]=syscall_halt;
}
static void
syscall_handler (struct intr_frame *f UNUSED)
{
  	int *p = f->esp;
	is_valid_addr(p);
  	int system_call = *p;
	sys_array[system_call](f);
}