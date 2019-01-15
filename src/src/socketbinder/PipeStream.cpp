/*
* Copyright (C) 2011 The Android Open Source Project
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
#include "PipeStream.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <netinet/tcp.h>
#else
#include <ws2tcpip.h>
#endif

#if 1
#include <sys/types.h>    // for socket
#include <stdio.h>        // for printf
#include <stdlib.h>        // for exit
#include <string.h>        // for bzero
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#ifndef HAVE_WINSOCK
#include <sys/types.h>
#endif
#endif
namespace ArmVM {

	PipeStream::PipeStream(size_t bufSize) :
		PipeOperationStream(bufSize)
	{
	}

	PipeStream::PipeStream(uint32_t sock, size_t bufSize) :
		PipeOperationStream(sock, bufSize)
	{
	}

	PipeOperationStream* PipeStream::accept()
	{
		uint32_t clientPipe = -1;
		while (true) {
			PipeStream *clientStream = NULL;
			clientPipe = reinterpret_cast<uint32_t>(CreateNamedPipeA(kPipeServerName,
				PIPE_ACCESS_DUPLEX, PIPE_WAIT,
				PIPE_UNLIMITED_INSTANCES,
				kPipeMaxBufferSize,
				kPipeMaxBufferSize,
				NMPWAIT_WAIT_FOREVER, 0));
			if (clientPipe == -1) {
				return clientStream;
			}
			if (ConnectNamedPipe((HANDLE)clientPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
				if (clientPipe >= 0) {
					clientStream = new PipeStream(clientPipe, m_bufsize);
				}
				return clientStream;
			}
			else {
				CloseHandle((HANDLE)clientPipe);
				clientPipe = -1;
			}
		}
		return nullptr;
	}
	uint32_t PipeStream::connect() {
		HANDLE file;
		while (true)
		{
			file = CreateFileA(kPipeConnectName, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
			if (file != INVALID_HANDLE_VALUE){
				break;
			}
			if (GetLastError()!= ERROR_PIPE_BUSY){
				return (uint32_t)file;
			}
			if (!WaitNamedPipeA(kPipeConnectName, 0xFFFFFFFF)){
				printf("Could not open pipe: 2 second wait timed out.");
				return (uint32_t)file;
			}
		}
		uint32_t Mode = 0;
		if (!SetNamedPipeHandleState(file, (LPDWORD)&Mode, 0, 0))
		{
			file = (HANDLE)-1;
			printf("SetNamedPipeHandleState failed. errno =%d\n", GetLastError());
		}
		return (uint32_t)file;
	}
}