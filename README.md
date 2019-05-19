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

    * modified `process_execute`

    ```c
    tid_t process_execute(const char *file_name){
        /* added code to get the thread name(without arguments) for thread_create() */
    }
    ```

    * modified `load`

    ```c
    bool load(const char *file_name, void (**eip)(void), void **esp)
    {
        /* added code to extract the name for executable */
    }
    ```

    * modified `setup_stack`

    ```c
    static bool setup_stack(void **esp, char *file_name){
        /* added code to split args and push into stack */
    }
    ```

* Algorithms & Implementation

  In first three method mentioned above, we only need to perform spliting on a long char list to get the executable and the args. We mainly leverage function `strtok_r` to split the name. Eg:

  ```c
  oken = strtok_r(file_name, " ", &temp_ptr)
  ```

  In this way, we can easily get the splited part of the file_name.

  In the `setup_stack` method, we need also push the args into stack. We performed it follow the below steps:

  > 1. Split the file_name to get the filename part and args part.
  > 2. we calculate the number of args --> argc.
  > 3. we ask for enough room for args and push them into the stack and make allignment
  > 4. 

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