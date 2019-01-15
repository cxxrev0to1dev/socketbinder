#include "PipeServer.h"
#include <set>
#include "PipeStream.h"
#include "PipeThread.h"
#include "osExecuteWindroy.h"

typedef std::set<ArmVM::PipeThread *> RenderThreadsSet;

namespace ArmVM{
    
PipeServer::PipeServer() :
    m_listenSock(NULL),
    m_exiting(false)
{
}

PipeServer *PipeServer::create()
{
    PipeServer *server = new PipeServer();
    if (!server) {
        return NULL;
    }
    server->m_listenSock = new PipeStream(10240);
	//internal::ExecuteWindroySocketBinder();
	//internal::ExecuteWindroy();
    return server;
}

int PipeServer::Main()
{
    RenderThreadsSet threads;

    while(1) {
		PipeOperationStream *stream = m_listenSock->accept();
        if (!stream) {
            fprintf(stderr,"Error accepting connection, aborting\n");
            break;
        }
		PipeThread *rt = PipeThread::create(stream);
        if (!rt) {
            fprintf(stderr,"Failed to create RenderThread\n");
            delete stream;
        }
        if (!rt->start()) {
            fprintf(stderr,"Failed to start RenderThread\n");
            delete stream;
            delete rt;
        }
		for (RenderThreadsSet::iterator n, t = threads.begin();
			t != threads.end();
			t = n) {
			// first find next iterator
			n = t;
			n++;

			// delete and erase the current iterator
			// if thread is no longer running
			if ((*t)->isFinished()) {
				delete (*t);
				threads.erase(t);
			}
		}
		threads.insert(rt);
    }
    for (RenderThreadsSet::iterator t = threads.begin();
         t != threads.end();
         t++) {
        int exitStatus;
        (*t)->wait(&exitStatus);
        delete (*t);
    }
    threads.clear();
    return 0;
}

}