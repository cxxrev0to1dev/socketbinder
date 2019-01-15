#ifndef _SOCKETBINDER_OS_THREAD_UNIX_H
#define _SOCKETBINDER_OS_THREAD_UNIX_H

#include <pthread.h>

namespace ArmVM {

class ThreadUnix
{
public:
	ThreadUnix();
    virtual ~ThreadUnix();

    virtual int Main() = 0;

    bool start();
    bool  wait(int *exitStatus);
    bool trywait(int *exitStatus);

private:
    static void* thread_main(void *p_arg);

private:
    pthread_t m_thread;
    int       m_exitStatus;
    pthread_mutex_t m_lock;
    bool m_isRunning;
};

} // of namespace osUtils

#endif
