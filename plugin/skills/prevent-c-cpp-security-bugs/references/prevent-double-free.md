# 防范Double Free（二次释放）安全编码规范

## 什么是Double Free（二次释放）

Double Free（二次释放）是指在 C/C++ 等手动管理内存的编程语言中，对同一块动态分配的内存（即通过 `malloc`、`calloc`、`realloc` 或 `new` 分配的堆内存）调用了两次或多次 `free()` 或 `delete`。

当一块内存被第一次释放后，堆内存管理器（如 ptmalloc、jemalloc 等）会将其回收并加入到空闲链表（Free List）或类似的数据结构中。如果再次对这块已经回收的内存调用释放操作，就会破坏堆管理器的内部数据结构。
**危害**：轻则导致程序触发段错误（Segmentation Fault）崩溃，造成拒绝服务（DoS）；重则被攻击者利用堆布局，覆盖函数指针或返回地址，最终实现任意代码执行（RCE）。

** 典型攻击场景1：复杂的错误处理分支导致重复释放 **
在解析外部输入（如网络报文、JSON/XML、文件等）时，函数往往需要动态分配内存。如果解析过程中遇到错误，开发者在错误处理分支中调用了 `free()` 释放内存，但**未将指针置为 `NULL`**，随后代码逻辑又流转到了函数末尾的“统一清理资源”代码块中，再次对该指针调用了 `free()`，从而引发 Double Free。

** 典型攻击场景2：并发竞争（Race Condition）与对象所有权不清 **
在多线程或多进程的服务中，两个线程共享同一个内存对象的指针。由于缺少正确的加锁同步机制，或者对象生命周期管理混乱，导致两个线程几乎在同一时间或先后认为该对象不再使用，分别对其调用了 `free()`。由于指针在全局或上下文中未被及时清除，第二次释放直接触发漏洞。

---

## 漏洞示例（禁止使用）

### 示例1 （危险）

在以下代码中，程序为加载的数据块分配了堆内存。当遇到输入无效的错误时，程序释放了内存，但随后却因为没有直接 `return` 或忘记将指针置空，导致代码继续向下执行，最终在统一清理出口处发生了 Double Free。

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// 危险示例：由于错误处理逻辑不严谨导致 Double Free
int load_and_process_data(const char *input_data) {
    // 动态分配内存
    char *buffer = (char *)malloc(1024);
    if (buffer == NULL) {
        return -1;
    }

    if (input_data == NULL || strlen(input_data) == 0) {
        printf("Error: Invalid input data.\n");
        // 【危险】：在错误分支中释放了内存，但没有将指针置为 NULL，也没有 return
        free(buffer); 
    } else {
        strncpy(buffer, input_data, 1023);
        buffer[1023] = '\0';
        // 进行进一步的数据处理...
        printf("Processing: %s\n", buffer);
    }

    // ... 其他逻辑 ...

    // 【危险】：如果前面走了 input_data == NULL 的分支，这里的 buffer 已经被释放过一次
    // 此时再次 free(buffer) 将触发 Double Free 漏洞
    free(buffer);
    
    return 0;
}
```

### 并发竞争导致的 Double Free（危险）
在这个示例中，两个线程同时尝试处理并清理一个共享的全局任务数据（shared_task_data）。由于没有加锁，两个线程可能同时越过 != NULL 的检查，从而导致同一块内存被 free 两次。

```C
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

// 全局共享指针
char *shared_task_data = NULL;

void* process_task_danger(void* arg) {
    // 【危险】：检查 (Check)
    if (shared_task_data != NULL) {
        
        // 模拟处理数据耗时，此时另一个线程可能也执行到了这里
        printf("Thread %ld is processing data...\n", (long)pthread_self());
        usleep(1000); 
        
        // 【危险】：使用并释放 (Use & Free)
        // 如果线程A和线程B同时进入了这个 if 块，这里就会发生 Double Free
        free(shared_task_data);
        
        // 即使释放后置空，也太迟了！因为另一个线程已经越过了外层的 != NULL 检查
        shared_task_data = NULL; 
        printf("Thread %ld freed the data.\n", (long)pthread_self());
    }
    return NULL;
}

int main() {
    shared_task_data = (char*)malloc(1024);
    
    pthread_t t1, t2;
    // 启动两个线程同时处理该任务
    pthread_create(&t1, NULL, process_task_danger, NULL);
    pthread_create(&t2, NULL, process_task_danger, NULL);
    
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    
    return 0;
}
```

## 安全编码示例（推荐）
为了防范 Double Free，核心原则是：确保内存在任何执行路径下只被释放一次，且释放后立即废弃指针。在C标准中，free(NULL) 是安全且无副作用的操作。

### 示例1 （推荐：C语言防御规范 - 释放后立即置空）
在C语言中，养成 free() 后紧跟 ptr = NULL 的习惯，配合单一出口（Single Exit）模式，可以消除99%的单线程 Double Free 风险。

```C
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// 安全示例：释放后立即将指针置空，利用 free(NULL) 的安全特性
int load_and_process_data_secure(const char *input_data) {
    char *buffer = (char *)malloc(1024);
    int ret_code = 0;

    if (buffer == NULL) {
        return -1;
    }

    if (input_data == NULL || strlen(input_data) == 0) {
        printf("Error: Invalid input data.\n");
        // 【安全做法】：如果必须在分支中释放，释放后立刻将指针置为 NULL
        free(buffer);
        buffer = NULL;
        ret_code = -1;
        goto cleanup; // 推荐使用 goto 跳转到统一清理出口
    } 
    
    strncpy(buffer, input_data, 1023);
    buffer[1023] = '\0';
    // 进行进一步的数据处理...
    printf("Processing: %s\n", buffer);

cleanup:
    // 【安全做法】：即使 buffer 在前面被释放过并置为了 NULL，
    // free(NULL) 也是绝对安全的，不会产生 Double Free。
    if (buffer != NULL) {
        free(buffer);
        buffer = NULL; // 统一清理处也保持置空的良好习惯
    }
    
    return ret_code;
}

// 推荐使用宏定义来规范团队的释放行为（可选）
#define SAFE_FREE(ptr) do { \
    if ((ptr) != NULL) {    \
        free(ptr);          \
        (ptr) = NULL;       \
    }                       \
} while(0)
```


### 示例2 （推荐：C++防御规范 - 使用 RAII 智能指针）
如果是编写 C++ 程序，绝对不建议使用裸指针（Raw Pointers）进行手动的 new 和 delete。应当使用现代 C++ (C++11 及以上) 提供的智能指针，利用 RAII（资源获取即初始化）机制，由编译器在对象离开作用域时自动释放内存，从根本上杜绝 Double Free 和内存泄漏。

```C
#include <iostream>
#include <string>
#include <memory> // 引入智能指针

// 安全示例：C++ 中使用 std::unique_ptr 消除内存手动管理风险
int process_string_cpp(const std::string& input_data) {
    // 【安全做法】：使用 std::make_unique 分配内存
    // 当 buffer 离开作用域时，内存会自动且仅被释放一次
    auto buffer = std::make_unique<char[]>(1024);

    if (input_data.empty()) {
        std::cerr << "Error: Invalid input data.\n";
        // 无需手动 delete[]，直接 return 即可，智能指针会自动销毁内存
        return -1;
    }

    // 安全的字符串拷贝（实际 C++ 开发中更推荐直接使用 std::string）
    input_data.copy(buffer.get(), 1023);
    buffer[input_data.length() < 1023 ? input_data.length() : 1023] = '\0';

    std::cout << "Processing: " << buffer.get() << "\n";

    // 正常退出，智能指针 buffer 会在此处安全析构
    return 0;
}
```

### 并发环境下引入互斥锁或智能指针
防御并发导致的 Double Free，主要有两种思路：
C语言：引入互斥锁（Mutex），将“检查-处理-释放-置空”打包成一个原子操作。
C++语言：使用 std::shared_ptr，通过引用计数将“所有权”问题交给标准库的原子操作来管理。
方案 A：C语言中使用互斥锁（Mutex）
通过加锁，保证在同一时刻只有一个线程能够检查并释放内存，消除了时间窗口。
```C
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

char *shared_task_data = NULL;
// 【安全做法】：定义互斥锁
pthread_mutex_t task_mutex = PTHREAD_MUTEX_INITIALIZER;

void* process_task_secure_c(void* arg) {
    // 【安全做法】：在检查和释放前加锁，保证操作的原子性
    pthread_mutex_lock(&task_mutex);
    
    if (shared_task_data != NULL) {
        printf("Thread %ld is processing data...\n", (long)pthread_self());
        
        // 安全释放
        free(shared_task_data);
        shared_task_data = NULL; // 置空必须在解锁前完成
        
        printf("Thread %ld freed the data.\n", (long)pthread_self());
    } else {
        printf("Thread %ld found data already freed.\n", (long)pthread_self());
    }
    
    // 【安全做法】：操作完成后解锁
    pthread_mutex_unlock(&task_mutex);
    
    return NULL;
}
```

方案 B：C++语言中使用智能指针（推荐做法）
在现代C++中，解决多线程共享对象生命周期（所有权不清）的最佳实践是使用 std::shared_ptr。
std::shared_ptr 内部维护了一个线程安全的（原子的）引用计数。无论多少个线程持有该对象，只有当最后一个持有该对象的线程将其销毁（引用计数归零）时，内存才会被释放（且仅释放一次）。
```C
#include <iostream>
#include <memory>
#include <thread>
#include <vector>
#include <chrono>

// 【安全做法】：使用 std::shared_ptr 管理堆内存生命周期
// 替代容易出错的裸指针 char*
void process_task_secure_cpp(std::shared_ptr<std::string> task_data, int thread_id) {
    // 只要 task_data 按值传递进来到这个线程，引用计数就会自动 +1，保证对象存活
    if (task_data) {
        std::cout << "Thread " << thread_id << " is processing data: " << *task_data << "\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    
    // 【安全做法】：无需手动 delete 或 free。
    // 当函数结束，局部变量 task_data 离开作用域，引用计数原子性 -1。
    // 当引用计数减到 0 时，底层内存自动释放，绝不会发生 Double Free。
}

int main() {
    // 创建共享数据，初始引用计数为 1
    auto shared_data = std::make_shared<std::string>("Crucial Payload");
    
    std::vector<std::thread> threads;
    
    for (int i = 0; i < 5; ++i) {
        // 将 shared_ptr 按值传入线程，多个线程安全地共享同一个对象
        threads.emplace_back(process_task_secure_cpp, shared_data, i);
    }
    
    // 主线程放弃所有权，引用计数 -1
    shared_data.reset(); 
    
    for (auto& t : threads) {
        t.join();
    }
    
    return 0;
}
```