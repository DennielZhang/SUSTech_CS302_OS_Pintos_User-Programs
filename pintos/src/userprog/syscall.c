#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/off_t.h"
#include "kernel/list.h"
static void syscall_handler(struct intr_frame *);
void *check_addr(const void *addr);
void exit_process(status);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}
void stack_pop(int *esp, int *a, int offset){
	int *tmp_esp = esp;
	*a = *((int *)check_addr(tmp_esp + offset));
}

void 
syscall_exit(struct intr_frame *f)
{
  int status;
  stack_pop(f->esp,&status,1);
  exit_process(status);

}

int exec_proc(struct intr_frame *f)
{
    lock_acquire(&filesys_lock);
    char * fn_cp = malloc (strlen(file_name)+1);
    strlcpy(fn_cp, file_name, strlen(file_name)+1);

    char * save_ptr;
    fn_cp = strtok_r(fn_cp," ",&save_ptr);

    struct file* f = filesys_open (fn_cp);

    if(f==NULL)
    {
        lock_release(&filesys_lock);
        return -1;
    }
    else
    {
        file_close(f);
        lock_release(&filesys_lock);
        return process_execute(file_name);
    }
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  int *call = f->esp;
  check_addr(call);
  int system_call = *call;

  switch (system_call)
  {
  case SYS_HALT: /* Halt the operating system. */
    shutdown_power_off();
    break;
  case SYS_EXIT: /* Terminate this process. */
    syscall_exit(f);
    break;
  case SYS_EXEC: /* Start another process. */
    char *file_name = NULL;
    stack_pop(f->esp, &file_name, 1);
    if (!is_valid_addr(file_name))
      f->eax=-1;
    else:
      f->eax = exec_proc(f);
    break;

  case SYS_WAIT: /* Wait for a child process to die. */
    tid_t c_tid;
	  pop_stack(f->esp, &child_tid, 1);
    f->eax = process_wait(c_tid);
    break;
  default:
    printf("No match\n");
  }

  printf("system call!\n");
  thread_exit();
}

void exit_process(int status)
{
  struct child_process *cp;
  struct thread *cur_thd = thread_current();

  enum intr_level old_level = intr_disable();
  for (struct list_elem *e = list_begin(&cur_thd->parent->children_list); e != list_end(&cur_thd->parent->children_list); e = list_next(e))
  {
    cp = list_entry(e, struct child_process, elem);
    if (cp->tid == cur_thd->tid)
    {
      cp->if_waited = true;
      cp->exit_status = status;
    }
    cur_thd->exit_status = status;
    intr_set_level(old_level);
    thread_exit();
  }
}
void *
check_addr(const void *addr)
{
  void *page_p = NULL;
  if (!is_user_vaddr(addr) || !(page_p == pagedir_get_page(thread_current()->pagedir, addr)))
  {
    exit_process(-1);
    return 0;
  }
  return page_p;
}
