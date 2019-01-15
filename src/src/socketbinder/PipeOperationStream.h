#ifndef _SOCKETBINDER_PIPE_OPERATION_STREAM_STREAM_H
#define _SOCKETBINDER_PIPE_OPERATION_STREAM_STREAM_H

#include <stdlib.h>
#include "base_io_stream.h"

namespace ArmVM {

	class PipeOperationStream : public BaseIOStrean {
	public:
		typedef enum { ERR_INVALID_SOCKET = -1000 } PipeOperationStreamError;

		explicit PipeOperationStream(size_t bufsize = 10000);
		virtual ~PipeOperationStream();

		//virtual int listen(unsigned short port) = 0;
		virtual PipeOperationStream *accept() = 0;
		virtual uint32_t connect() = 0;

		virtual void *allocBuffer(size_t minSize);
		virtual int commitBuffer(size_t size);
		virtual const unsigned char *readFully(void *buf, size_t len);
		virtual const unsigned char *read(void *buf, size_t *inout_len);
		virtual void close();

		bool valid() { return m_sock >= 0; }
		virtual int recv(void *buf, size_t len);
		virtual int writeFully(const void *buf, size_t len);

	protected:
		uint32_t   m_sock;
		size_t         m_bufsize;
		unsigned char *m_buf;

		PipeOperationStream(int sock, size_t bufSize);
	};
}

#endif
