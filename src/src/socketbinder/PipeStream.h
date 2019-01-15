#ifndef _SOCKETBINDER_STREAM_H
#define _SOCKETBINDER_STREAM_H

#include <cstdint>

#include "PipeOperationStream.h"

namespace ArmVM {

	static const char* kPipeServerName = "\\\\.\\pipe\\socketbinderpipe";
	static const char* kPipeConnectName = "\\\\.\\pipe\\socketbinderpip1";
	static const uint32_t kPipeMaxBufferSize = 1024 * 10;

	class PipeStream : public PipeOperationStream {
	public:
		explicit PipeStream(size_t bufsize = kPipeMaxBufferSize);
		virtual PipeOperationStream *accept();
		virtual uint32_t connect();
	private:
		PipeStream(uint32_t sock, size_t bufSize);
	};
}

#endif
