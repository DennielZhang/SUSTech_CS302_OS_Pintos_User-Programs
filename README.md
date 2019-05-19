# Report 
It is the repository for project2 in Operating System

### Task1: Argument Passing

* Data structure & Function

  * Modified thread.h

    ```c
    struct thread{
        ...
        /* added one attribute */
        struct file *self;  // its executable file
        ...
    }
    ```

  * Modified process.c

    ```c
    tid_t process_execute(const char *file_name){
        /* added code to get name for executable */
    }
    
    ```

    

* Algorithms

* Synchronization

* Rationale  

### Task2: Process Control Syscalls

- Data structure
- Algorithms
- Synchronization 
- Rationale 

### Task3: File Operation Syscalls

- Data structure
- Algorithms
- Synchronization 
- Rationale 