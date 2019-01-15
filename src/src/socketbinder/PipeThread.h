#ifndef _SOCKETBINDER_PIPE_THREAD_H
#define _SOCKETBINDER_PIPE_THREAD_H

#include "base_io_stream.h"
#include "osThread.h"
#include "osThreadUnix.h"

namespace ArmVM{

class PipeThread : public ArmVM::ThreadUnix
{
public:
    static PipeThread *create(BaseIOStrean *p_stream);
    bool isFinished() const { return m_finished; }
private:
    PipeThread();
	virtual int Main();
	int WorkFunc();
	void* DynamicMallocRead(const uint32_t ext_len);

	inline bool ResponseStatus(long result) {
		return (m_stream->writeFully(&result, sizeof(uint32_t))==0);
	}
	inline int RETURN_ERROR() {
		m_finished = true;
		return -1;
	}
	inline int RETURN_OK() {
		m_finished = true;
		return 0;
	}
private:
    BaseIOStrean *m_stream;
    bool m_finished;
};

}

#endif
