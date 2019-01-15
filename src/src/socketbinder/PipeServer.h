#ifndef _SOCKETBINDER_PIPE_SERVER_H
#define _SOCKETBINDER_PIPE_SERVER_H

#include "PipeOperationStream.h"
#include "osThread.h"
#include "osThreadUnix.h"

namespace ArmVM{

class PipeServer : public ArmVM::ThreadUnix
{
public:
    static PipeServer *create();
    virtual int Main();
    bool isExiting() const { return m_exiting; }
private:
    PipeServer();
private:
	PipeOperationStream *m_listenSock;
    bool m_exiting;
};

}

#endif
