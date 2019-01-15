#ifndef _SOCKETBINDER_OS_THREAD_H
#define _SOCKETBINDER_OS_THREAD_H

#ifdef _WIN32
#include <windows.h>
#else // !WIN32
#include <pthread.h>
#endif

namespace ArmVM {

class Thread
{
public:
    Thread();
    virtual ~Thread();

    virtual int Main() = 0;

    bool start();
    bool  wait(int *exitStatus);
    bool trywait(int *exitStatus);

private:
#ifdef _WIN32
    static DWORD WINAPI thread_main(void *p_arg);
#else // !WIN32
    static void* thread_main(void *p_arg);
#endif

private:
#ifdef _WIN32
    HANDLE m_thread;
    DWORD m_threadId;
#else // !WIN32
    pthread_t m_thread;
    int       m_exitStatus;
    pthread_mutex_t m_lock;
#endif
    bool m_isRunning;
};

} // of namespace osUtils

#endif
