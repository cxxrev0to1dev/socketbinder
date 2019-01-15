#ifndef _SOCKETBINDER_OS_PROCESS_H
#define _SOCKETBINDER_OS_PROCESS_H

#ifdef _WIN32
#include <windows.h>
#endif

namespace ArmVM {

class childProcess
{
public:
    static childProcess *create(const char *p_cmdLine, const char *p_startdir);
    ~childProcess();

    int getPID()
    {
#ifdef _WIN32
        return m_proc.dwProcessId;
#else
        return(m_pid);
#endif
    }

    int tryWait(bool& isAlive);
    bool wait(int *exitStatus);

private:
    childProcess() {};

private:
#ifdef _WIN32
    PROCESS_INFORMATION m_proc;
#else
    int m_pid;
#endif
};

int ProcessGetPID();
int ProcessGetTID();
bool ProcessGetName(wchar_t *p_outName, int p_outNameLen);
int KillProcess(int pid, bool wait);
bool isProcessRunning(int pid);

} // of namespace osUtils

#endif
