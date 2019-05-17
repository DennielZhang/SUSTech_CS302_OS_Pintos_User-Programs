#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
static void syscall_handler (struct intr_frame *);
typedef void (*CALL_PROC)(struct intr_frame*);
CALL_PROC pfn[MAXCALL];
void IWrite(struct intr_frame*);
void IExit(struct intr_frame *f);
void ExitStatus(int status);
void ICreate(struct intr_frame *f);
void IOpen(struct intr_frame *f);
void IClose(struct intr_frame *f);
void IRead(struct intr_frame *f);
void IFileSize(struct intr_frame *f);
void IExec(struct intr_frame *f);
void IWait(struct intr_frame *f);
void ISeek(struct intr_frame *f);
void IRemove(struct intr_frame *f);
void ITell(struct intr_frame *f);
void IHalt(struct intr_frame *f);
struct file_node *GetFile(struct thread *t,int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  int i;
  for(i=0;i<MAXCALL;i++)
    pfn[i]=NULL;
  pfn[SYS_WRITE]=IWrite;
  pfn[SYS_EXIT]=IExit;
  pfn[SYS_CREATE]=ICreate;
  pfn[SYS_OPEN]=IOpen;
  pfn[SYS_CLOSE]=IClose;
  pfn[SYS_READ]=IRead;
  pfn[SYS_FILESIZE]=IFileSize;
  pfn[SYS_EXEC]=IExec;
  pfn[SYS_WAIT]=IWait;
  pfn[SYS_SEEK]=ISeek;
  pfn[SYS_REMOVE]=IRemove;
  pfn[SYS_TELL]=ITell;
  pfn[SYS_HALT]=IHalt;
}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}
