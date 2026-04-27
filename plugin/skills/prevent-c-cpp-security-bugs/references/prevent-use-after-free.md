


# 防范释放后使用（UAF）安全编码规范

## 什么是释放后使用（UAF）

释放后使用（Use-After-Free，简称 UAF）是指程序在释放了一块动态分配的内存（通过 `free` 或 `delete`）之后，未将指向该内存的指针置空，并在后续的代码逻辑中继续使用该指针（此时该指针被称为“悬垂指针”，Dangling Pointer）进行读写操作的严重安全漏洞。

由于被释放的内存会被操作系统的堆内存管理器回收并可能重新分配给程序的其他部分，如果继续通过原有的悬垂指针访问它，将导致数据损坏或程序崩溃。更致命的是，如果攻击者能够控制这块被重新分配的内存，UAF 漏洞通常会被用来实现内存控制流劫持，导致远程代码执行（RCE）。

** 典型攻击场景1 **
**C++ 虚表劫持（VTable Hijacking）：**
服务端在处理业务时动态创建了一个包含虚函数（Virtual Function）的 C++ 对象。由于逻辑缺陷，该对象在某个错误分支中被 `delete`，但指针未被重置。攻击者随后向服务端发送特定大小的畸形数据包，诱导堆分配器将刚刚释放的这块内存重新分配出来，并用攻击者精心伪造的数据（包含指向恶意代码的伪造虚表指针）进行填充。当服务端后续再次使用悬垂指针调用该对象的虚函数时，CPU 将跳转到攻击者指定的地址执行恶意代码，直接拿下服务器控制权。

** 典型攻击场景2 **
**异步回调与并发环境下的上下文失效：**
在一个基于事件驱动（如 epoll/libevent）或多线程的网络服务中，主处理流程发起了一个异步数据库查询，并将当前的 `UserContext` 结构体指针作为参数传递给异步回调函数。在等待查询结果期间，客户端异常断开连接，主处理流程随即调用 `free(UserContext)` 清理了资源。然而，由于没有取消回调的机制或使用引用计数，当异步查询结束触发回调时，回调函数依然使用了那个已经被释放的 `UserContext` 指针去写入查询结果。这会覆盖恰好刚刚被分配在同一地址的其他用户的敏感数据，导致严重的越界写或信息泄露。


## 漏洞示例（禁止使用）

### 示例1 （危险）：手动管理内存时遗留悬垂指针

在 C 语言中，最经典的 UAF 往往发生在一个复杂的函数逻辑或跨函数的资源管理中，开发者释放了内存但忘记了清理指针。

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char username[32];
    int is_admin;
} UserSession;

void process_user_request() {
    UserSession* session = (UserSession*)malloc(sizeof(UserSession));
    strcpy(session->username, "guest");
    session->is_admin = 0;

    // 假设在某种复杂的错误处理逻辑中，session 被释放了
    int error_occurred = 1;
    if (error_occurred) {
        free(session); 
        // 危险：释放后没有将 session 置为 NULL
    }

    // ... 其他冗长的代码 ...

    // 危险：后续代码没有意识到 session 已经被释放，继续使用悬垂指针
    // 如果这块内存在中间被分配给了另外一个高权限对象，这里就会发生严重的数据污染
    printf("Logging action for user: %s\n", session->username);
    if (session->is_admin) {
        // 执行特权操作
    }
}
```

### 示例2 （危险）：C++ 异步回调中的裸指针捕获

在 C++11 及以上的 Lambda 表达式或异步回调中，直接按值或引用捕获裸指针（Raw Pointer）是极度危险的。

```cpp
#include <iostream>
#include <thread>
#include <chrono>

class Task {
public:
    void execute() { std::cout << "Task executed." << std::endl; }
};

void async_operation_danger() {
    Task* myTask = new Task();

    // 启动一个后台线程异步处理
    std::thread bg_thread([myTask]() {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        // 危险：此时 main 函数中的 myTask 可能已经被 delete 了！
        // 这里发生了典型的多线程 UAF
        myTask->execute(); 
    });

    bg_thread.detach();

    // 主逻辑结束，提前清理资源
    delete myTask; 
    // 危险：后台线程依然持有 myTask 的裸指针
}
```

### 示例3（危险）：在遍历 C++ 容器时直接修改元素导致迭代器失效
当从 std::vector 中过滤掉不符合条件的外部输入时，初级开发者常犯以下致命错误：

```C
#include <iostream>
#include <vector>

void process_and_filter_danger(std::vector<int>& user_data) {
    // 危险：使用迭代器遍历时直接删除元素
    for (auto it = user_data.begin(); it != user_data.end(); ++it) {
        if (*it < 0) {
            // 致命缺陷：erase 会销毁当前节点，释放并移动后续内存。
            // 执行 erase 后，it 迭代器已经完全失效（Use-After-Free 隐患）。
            user_data.erase(it); 
            
            // 循环末尾还会执行 ++it，对已失效的迭代器进行操作，直接导致崩溃或未定义行为
        }
    }
}
```


## 安全编码示例（推荐）

### 示例1：释放后立即置空（防御性编程）

**C语言推荐写法：**
在 C 语言中，防范 UAF 的基本底线是“谁释放，谁置空”。在调用 `free` 后，**必须紧接着**将指针赋值为 `NULL`。这是一种极为有效的防御性编程手段，因为即使后续代码错误地使用了该指针，访问 `NULL` 指针只会导致程序立刻崩溃（段错误），而不会被攻击者利用来执行任意代码或篡改数据。

可以使用宏来强制这种行为。

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 安全：定义安全释放宏，释放后自动将指针置空
#define SAFE_FREE(ptr) do { \
    if ((ptr) != NULL) { \
        free(ptr); \
        (ptr) = NULL; \
    } \
} while(0)

typedef struct {
    char username[32];
    int is_admin;
} UserSession;

void process_user_request_secure() {
    UserSession* session = (UserSession*)malloc(sizeof(UserSession));
    if (!session) return;
    
    strcpy(session->username, "guest");
    session->is_admin = 0;

    int error_occurred = 1;
    if (error_occurred) {
        // 安全：释放内存并立即将 session 置为 NULL
        SAFE_FREE(session); 
    }

    // 安全：后续代码在使用前增加对 NULL 的校验。
    // 即便漏掉了校验，解引用 NULL 也只会导致崩溃（Denial of Service），
    // 阻断了进一步的提权或 RCE 攻击。
    if (session != NULL) {
        printf("Logging action for user: %s\n", session->username);
    } else {
        printf("Session is invalid or expired.\n");
    }
}
```

### 示例2：使用智能指针接管生命周期（RAII 原则）

**C++ 语言推荐写法：**
在现代 C++（C++11 及以上）中，**绝对禁止使用裸指针（Raw Pointer）结合 `new` 和 `delete` 来管理具有所有权的对象**。应该使用 `std::shared_ptr`（基于引用计数）或 `std::unique_ptr`（独占所有权）来接管内存管理。当跨线程或在异步回调中传递对象时，引用计数能从根源上杜绝 UAF。

```cpp
#include <iostream>
#include <thread>
#include <chrono>
#include <memory>

class Task {
public:
    void execute() { std::cout << "Task executed safely." << std::endl; }
};

void async_operation_secure() {
    // 安全：使用 std::shared_ptr 来管理动态分配的内存
    std::shared_ptr<Task> myTask = std::make_shared<Task>();

    // 安全：按值捕获 shared_ptr。这会使 myTask 的引用计数 +1。
    // 只要后台线程的 Lambda 还没有执行完毕，对象的生命周期就不会结束。
    std::thread bg_thread([myTask]() {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        // 安全：无论外部环境如何，此时 myTask 绝对有效
        myTask->execute(); 
        // 线程结束，Lambda 销毁，引用计数 -1。如果降为 0，则自动安全释放。
    });

    bg_thread.detach();

    // 安全：主函数作用域结束，局部变量 myTask 销毁，引用计数 -1。
    // 无需也不能手动 delete，彻底消除了 UAF 风险。
}
```

### 示例3（安全）：正确接管迭代器返回值，或使用现代 C++ 惯用法
C++ 推荐写法 1：利用 erase 的返回值更新迭代器
所有的 STL 容器的 erase 函数都会返回一个指向被删除元素下一个有效元素的新迭代器。必须用这个返回值来更新当前的迭代器。在使用老的C++标准时（< C++11）可以采用这一方法
```C
#include <iostream>
#include <vector>

void process_and_filter_secure_1(std::vector<int>& user_data) {
    for (auto it = user_data.begin(); it != user_data.end(); /* 注意：这里不写 ++it */) {
        if (*it < 0) {
            // 安全：将 erase 返回的新有效迭代器重新赋值给 it
            // 此时 it 指向被删元素的下一个元素，不引发失效
            it = user_data.erase(it); 
        } else {
            // 只有在没有删除元素时，才手动向后移动迭代器
            ++it; 
        }
    }
}
```

C++推荐写法2：在使用 C++11 及以后的C++标准时，强烈建议使用现代C++的标准库函数来管理迭代器
```C
#include <vector>
#include <algorithm>
#include <iostream>

int main() {
    std::vector<int> v = {1, 3, 2, 3, 4, 3, 5};

    // ============================================================
    // 方法 1：Erase-Remove（删除值等于 3 的元素）C++11/14/17
    // ============================================================
    v.erase(
        std::remove(v.begin(), v.end(), 3),  // step1: 逻辑移除
        v.end()                               // step2: 物理删除
    );
    // v = {1, 2, 4, 5}

    // ============================================================
    // 方法 2：Erase-Remove_if（删除满足条件的元素）C++11/14/17
    // ============================================================
    std::vector<int> v2 = {1, 2, 3, 4, 5, 6};
    v2.erase(
        std::remove_if(v2.begin(), v2.end(), [](int x) {
            return x % 2 == 0;  // 删除所有偶数
        }),
        v2.end()
    );
    // v2 = {1, 3, 5}

    // ============================================================
    // 方法 3：std::erase_if（C++20，首选写法，更简洁）
    // ============================================================
    std::vector<int> v3 = {1, 2, 3, 4, 5, 6};
    std::erase_if(v3, [](int x) {
        return x % 2 == 0;  // 删除所有偶数
    });
    // v3 = {1, 3, 5}

    // std::erase 是 C++20 对精确值删除的简化
    std::vector<int> v4 = {1, 3, 2, 3, 4, 3, 5};
    std::erase(v4, 3);  // 删除所有值为 3 的元素
    // v4 = {1, 2, 4, 5}

    return 0;
}
```

