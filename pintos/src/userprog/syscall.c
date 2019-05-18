#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
static void syscall_handler(struct intr_frame *);
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
  process_exit(status);

}

int exec_proc(char *file_name)
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
  int exit_code;

  switch (system_call)
  {
  case SYS_HALT: /* Halt the operating system. */
    shutdown_power_off();

  case SYS_EXIT: /* Terminate this process. */
    syscall_exit(f);

  case SYS_EXEC: /* Start another process. */
    check_addr(call + 1);
    check_addr((void *)*(call + 1));
    f->eax = exec_proc(*(call + 1));
    break;

  case SYS_WAIT: /* Wait for a child process to die. */
    check_addr(call + 1);
    f->eax = process_wait(*(call + 1));
    break;
  default:
    printf("No match\n");
  }

  printf("system call!\n");
  thread_exit();
}

void process_exit(int status)
{
  struct child_process = *cp;
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
    process_exit(-1);
    return 0;
  }
  return page_p;
}