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
#include "PipeOperationStream.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#else
#include <ws2tcpip.h>
#endif
namespace ArmVM {

	PipeOperationStream::PipeOperationStream(size_t bufSize) :
		BaseIOStrean(bufSize),
		m_sock(-1),
		m_bufsize(bufSize),
		m_buf(NULL)
	{
	}

	PipeOperationStream::PipeOperationStream(int sock, size_t bufSize) :
		BaseIOStrean(bufSize),
		m_sock(sock),
		m_bufsize(bufSize),
		m_buf(NULL)
	{
	}

	PipeOperationStream::~PipeOperationStream()
	{
		if (m_buf != NULL) {
			free(m_buf);
			m_buf = NULL;
		}
	}

	void *PipeOperationStream::allocBuffer(size_t minSize)
	{
		size_t allocSize = (m_bufsize < minSize ? minSize : m_bufsize);
		if (!m_buf) {
			m_buf = (unsigned char *)malloc(allocSize);
		}
		else if (m_bufsize < allocSize) {
			unsigned char *p = (unsigned char *)realloc(m_buf, allocSize);
			if (p != NULL) {
				m_buf = p;
				m_bufsize = allocSize;
			}
			else {
				//LOGD("%s: realloc (%d) failed\n", __FUNCTION__, allocSize);
				free(m_buf);
				m_buf = NULL;
				m_bufsize = 0;
			}
		}

		return m_buf;
	};

	int PipeOperationStream::commitBuffer(size_t size)
	{
		return writeFully(m_buf, size);
	}

	int PipeOperationStream::writeFully(const void* buffer, size_t size)
	{
		if (!valid()) return -1;

		size_t res = size;
		int retval = 0;

		while (res > 0) {
			unsigned int stat;
			WriteFile((HANDLE)m_sock, (LPVOID)((const char *)buffer + (size - res)), res, (LPDWORD)&stat, NULL);
			FlushFileBuffers((HANDLE)m_sock);
			if (stat < 0) {
				if (errno != EINTR) {
					retval = stat;
					break;
				}
			}
			else {
				res -= stat;
			}
		}
		return retval;
	}

	const unsigned char *PipeOperationStream::readFully(void *buf, size_t len)
	{
		const unsigned char* ret = NULL;
		if (!valid()) return NULL;
		if (!buf) {
			return NULL;  // do not allow NULL buf in that implementation
		}
		size_t res = len;
		while (res > 0) {
			unsigned int stat;
			ReadFile((HANDLE)m_sock, (LPVOID)((char *)(buf)+len - res), res, (LPDWORD)&stat, NULL);
			if (stat > 0) {
				res -= stat;
				continue;
			}
			if (stat == 0 || errno != EINTR) { // client shutdown or error
				return NULL;
			}
		}
		return (const unsigned char *)buf;
	}

	const unsigned char *PipeOperationStream::read(void *buf, size_t *inout_len)
	{
		if (!valid()) return NULL;
		if (!buf) {
			return NULL;  // do not allow NULL buf in that implementation
		}

		int n;
		do {
			n = recv(buf, *inout_len);
		} while (n < 0 && errno == EINTR);

		if (n > 0) {
			*inout_len = n;
			return (const unsigned char *)buf;
		}

		return NULL;
	}

	int PipeOperationStream::recv(void *buf, size_t len)
	{
		if (!valid()) return int(ERR_INVALID_SOCKET);
		int res = 0;
		while (true) {
			ReadFile((HANDLE)m_sock, (LPVOID)buf, len,(LPDWORD)&res, nullptr);
			if (res < 0) {
				if (errno == EINTR) {
					continue;
				}
			}
			break;
		}
		return res;
	}
	void PipeOperationStream::close() {
		if (m_sock >= 0) {
			FlushFileBuffers((HANDLE)m_sock);
			DisconnectNamedPipe((HANDLE)m_sock);
			CloseHandle((HANDLE)m_sock);
			m_sock = -1;
		}
	}
}