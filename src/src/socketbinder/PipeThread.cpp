#include "PipeThread.h"
#include <sys/types.h>
#include <vector>
#include <map>
#include <cassert>
#include <pthread.h>
#include "PipeProtocol.h"
#include "binder.h"
#include "glog/logging.h"


#define STREAM_BUFFER_SIZE 4*1024*1024

namespace ArmVM{

PipeThread::PipeThread() :
    ArmVM::ThreadUnix(),
    m_stream(NULL),
    m_finished(false)
{
}
PipeThread *PipeThread::create(BaseIOStrean *p_stream)
{
    PipeThread *rt = new PipeThread();
    if (!rt) {
        return NULL;
    }
    rt->m_stream = p_stream;
    return rt;
}
int PipeThread::Main()
{
	return WorkFunc();
}
int PipeThread::WorkFunc() {
	int result = 0;
	while (result==0)
	{
		ENUM_CALL_TYPE call_type;
		struct base_struct_msg base_struct;
		const unsigned char* null_check = nullptr;
		m_stream->readFully(&call_type, sizeof(uint32_t));
		m_stream->readFully(&base_struct, sizeof(struct base_struct_msg));
		if (call_type == kSockBinderOpen) {
			uint32_t fd = 0;
			CHECK_NE(m_stream->readFully(&fd, sizeof(uint32_t)), null_check);
			struct struct_open_msg open_msg = { { call_type,base_struct.pid,base_struct.tid,base_struct.uid,base_struct.ext_len }, fd };
			static int once = 1;
			if (once)
			{
				/*Sleep(8000);*/
				once = 0;
			}
			result = binder_open(open_msg.msg.pid, open_msg.msg.uid, open_msg.fd);
			CHECK_GE(result, 0);
			CHECK_EQ(ResponseStatus(result), true);
		}
		else if (call_type == kSockBinderClose) {
			struct struct_close_msg close_msg = { { call_type,base_struct.pid,base_struct.tid,base_struct.uid,base_struct.ext_len } };
			CHECK_EQ(binder_flush(base_struct.pid), 0);
			CHECK_EQ(binder_release(base_struct.pid), 0);
			break;
		}
		else if (call_type == kSockBinderMMap) {
			struct struct_mmap_info map_info = { 0, nullptr };
			{
				struct struct_mmap_info* p = nullptr;
				p = reinterpret_cast<struct struct_mmap_info*>(DynamicMallocRead(base_struct.ext_len));
				CHECK_NOTNULL(p);
				memmove(&map_info, p, base_struct.ext_len);
				free(p);
// 				CHECK_NE(m_stream->readFully(&map_info, sizeof(struct struct_mmap_info)), null_check);
			}
			struct struct_mmap_msg mmap_msg = { { call_type,base_struct.pid,base_struct.tid,base_struct.uid,base_struct.ext_len }, map_info };
			result = binder_mmap(base_struct.pid, map_info.map_size, map_info.map_addr);
			CHECK_GE(result, 0);
			CHECK_EQ(ResponseStatus(result), true);
		}
		else if (call_type == kSockBinderIoctl) {
			struct_ioctl_info ioctl_info;
			int bytes_available = base_struct.ext_len;
#define BINDER_WRITE_READ_WINDROY
#ifdef BINDER_WRITE_READ_WINDROY
			uint8_t* xxxx = reinterpret_cast<uint8_t*>(DynamicMallocRead(base_struct.ext_len));
			{
				uint8_t* read_buf = xxxx;
				memmove(&ioctl_info, &xxxx[0], sizeof(struct struct_ioctl_info));
				bytes_available -= sizeof(struct struct_ioctl_info);
				if (ioctl_info.ioctl_code == kBINDER_WRITE_READ) {
					struct struct_ioctl_msg_parse* parsse_ioctl_proto = reinterpret_cast<struct_ioctl_msg_parse*>(read_buf);
					struct binder_write_read wrbuf;
					memmove(&wrbuf, &parsse_ioctl_proto->bwr, sizeof(struct binder_write_read));
					unsigned long wb_addr = wrbuf.write_buffer;
					unsigned long rb_addr = wrbuf.read_buffer;
					if (wrbuf.write_size){
						wrbuf.write_buffer = (unsigned long)((struct struct_ioctl_msg_parse*)&parsse_ioctl_proto[1]);
					}
					if (wrbuf.read_size){
						wrbuf.read_buffer = (unsigned long)malloc(wrbuf.read_size);
						memset((void*)wrbuf.read_buffer, 0, wrbuf.read_size);
					}
					result = binder_ioctl(ioctl_info.ioctl_code, (unsigned long)&wrbuf, ioctl_info.arg, base_struct.pid, base_struct.tid);
					CHECK_EQ(result, 0);
					CHECK_EQ(ResponseStatus(result), true);
					{
						uint32_t v17 = wrbuf.read_size + 0x18;
						struct binder_write_read* v18 = (struct binder_write_read *)malloc(wrbuf.read_size + 0x18);
						struct binder_write_read v19;
						if (!v18) {
							abort();
						}
						memset(v18, 0, v17);
						memmove(v18, &wrbuf, sizeof(struct binder_write_read));
						memmove(&v19, &wrbuf, sizeof(struct binder_write_read));
// 						v19.write_buffer = wb_addr;
// 						v19.read_buffer = rb_addr;
// 						char ssssssss[128] = { 0 };
// 						sprintf(ssssssss, "wb_addr:%p rb_addr:%p", wb_addr, rb_addr);
// 						OutputDebugStringA(ssssssss);
						if (m_stream->writeFully(&v19, sizeof(struct binder_write_read)) != 0)
						{
							LOG(ERROR) << "process_binder_ioctl:writePipe writing bwr, errno = " << GetLastError();
							break;
						}
						else
						{
							if (wrbuf.read_consumed > 0)
							{
								memcpy(&v18[1], (const void *)wrbuf.read_buffer, wrbuf.read_consumed);
								if (m_stream->writeFully(&v18[1], wrbuf.read_consumed) != 0) {
									LOG(ERROR) << "process_binder_ioctl:writePipe response, errno = " << GetLastError();
									break;
								}
							}
						}
						if (wrbuf.read_buffer)
							free((void *)wrbuf.read_buffer);
						if (v18)
							free(v18);
					}
				}
			}
#else
			std::vector<uint8_t> xxxx;
			xxxx.resize(bytes_available);
			CHECK_NE(m_stream->readFully(&xxxx[0], bytes_available), null_check);
			memmove(&ioctl_info, &xxxx[0], sizeof(struct struct_ioctl_info));
			bytes_available -= sizeof(struct struct_ioctl_info);
#endif
			struct struct_ioctl_msg ioctl_msg = { { call_type,base_struct.pid,base_struct.tid,base_struct.uid,base_struct.ext_len }, ioctl_info,{ 0 } };

			if (ioctl_info.ioctl_code == kBINDER_WRITE_READ) {
#ifdef BINDER_WRITE_READ_WINDROY
				for(;;)
					break;
#else
				binder_write_read bwr = { 0 };
				memmove(&bwr, &xxxx[sizeof(struct struct_ioctl_info)], sizeof(struct binder_write_read));
				bytes_available -= sizeof(struct binder_write_read);
				if (bwr.write_size) {
					bwr.write_buffer = (unsigned long)malloc(bwr.write_size);
					memset((void*)bwr.write_buffer, 0, bwr.write_size);
					memmove((void*)bwr.write_buffer, &xxxx[base_struct.ext_len - bytes_available], bytes_available);
					bytes_available -= bwr.write_size;
				}


				if (bwr.read_size) {
					bwr.read_buffer = (unsigned long)malloc(bwr.read_size);
					memset((void*)bwr.read_buffer, 0, bwr.read_size);
				}
				result = binder_ioctl(ioctl_info.ioctl_code, (unsigned long)&bwr, ioctl_info.arg, base_struct.tid);
				CHECK_EQ(result, 0);
				CHECK_EQ(ResponseStatus(result), true);
				CHECK_EQ(m_stream->writeFully(&bwr, sizeof(binder_write_read)), 0);
				if (bwr.read_consumed > 0 && !result) {
					CHECK_EQ(m_stream->writeFully((void*)(void*)bwr.read_buffer, bwr.read_consumed), 0);
				}
				free((void*)bwr.write_buffer);
				free((void*)bwr.read_buffer);
#endif
			}
			else if (ioctl_info.ioctl_code == kBINDER_SET_MAX_THREADS) {
				uint32_t max_threads = 0;
				if(bytes_available==sizeof(uint32_t))
					memmove(&max_threads, &xxxx[sizeof(struct struct_ioctl_info)], sizeof(uint32_t));

				result = binder_set_max_threads(BINDER_SET_MAX_THREADS, (unsigned long)&max_threads, 0, base_struct.pid, base_struct.tid);
				CHECK_GE(result, 0);
				CHECK_EQ(ResponseStatus(result), true);
				CHECK_EQ(m_stream->writeFully(&max_threads, sizeof(unsigned long)), 0);
			}
			else if (ioctl_info.ioctl_code == kBINDER_THREAD_EXIT) {
				uint32_t exit_threads = 0;
				if (bytes_available == sizeof(uint32_t))
					memmove(&exit_threads, &xxxx[sizeof(struct struct_ioctl_info)], sizeof(uint32_t));

				result = binder_thread_exit(BINDER_THREAD_EXIT, 0, 0, base_struct.pid, base_struct.tid);
				CHECK_GE(result, 0);
				CHECK_EQ(ResponseStatus(result), true);
				CHECK_EQ(ResponseStatus(result), true);
			}
			else if (ioctl_info.ioctl_code == kBINDER_SET_CONTEXT_MGR)
			{
				uint32_t set_context_mgr = 0;
				if (bytes_available == sizeof(uint32_t))
					memmove(&set_context_mgr, &xxxx[sizeof(struct struct_ioctl_info)], sizeof(uint32_t));

				result = binder_set_context_mgr(BINDER_SET_CONTEXT_MGR, (unsigned long)&set_context_mgr, 0, base_struct.pid, base_struct.tid);
				CHECK_GE(result, 0);
				CHECK_EQ(ResponseStatus(result), true);
				CHECK_EQ(m_stream->writeFully(&set_context_mgr, sizeof(unsigned long)), 0);
			}
			else {
				uint32_t version_data = 0;
				if (bytes_available == sizeof(uint32_t))
					memmove(&version_data, &xxxx[sizeof(struct struct_ioctl_info)], sizeof(uint32_t));

				result = binder_binder_version(BINDER_VERSION, (unsigned long)&version_data, 0, base_struct.pid, base_struct.tid);
				CHECK_GE(result, 0);
				CHECK_EQ(ResponseStatus(result), true);
				CHECK_EQ(m_stream->writeFully(&version_data, sizeof(unsigned long)), 0);
			}
#ifdef BINDER_WRITE_READ_WINDROY
			if (xxxx)
				free(xxxx);
#endif
		}
	}
	m_stream->close();
	m_finished = true;
	return 0;
}
void* PipeThread::DynamicMallocRead(const uint32_t len) {

	{
		uint32_t v7 = (uint32_t)((char *)len + 0xFF);
		if ((uint32_t)len >= 0)
			v7 = len;
		uint32_t v26 = len;
		uint32_t v27 = (signed int)v7 >> 8;// NOTE:It must be like this
		if ((signed int)v7 >> 8 > 0){// NOTE:It must be like this
			//OutputDebugStringA("1111111111111111");
		}
		else{
			//OutputDebugStringA("1111111111111111");
		}
	}
	{
		signed int ext_len = len;
		signed int* v1 = (signed int *)malloc(len + 0x10);
		memset(v1, 0, len + 0x10);
		int v2 = ext_len + 0xFF;
		if (ext_len >= 0)
			v2 = ext_len;
		signed int *v28 = v1;
		uint32_t v3 = (signed int)v2 >> 8;// NOTE:It must be like this
		if ((signed int)v2 >> 8 > 0)// NOTE:It must be like this
		{
			unsigned __int8 *v4 = (unsigned __int8 *)v1;
			int v5 = 0;
			while (1)
			{
				size_t lllll1 = 0x100;
				if (m_stream->read(v4, &lllll1) && lllll1 != 0x100)
					break;
				v4 += 256;
				if (++v5 == v3)
					break;
			}
		}
		unsigned __int8 *v4 = (unsigned __int8 *)v1;
		unsigned int v8 = (unsigned int)(ext_len >> 31) >> 0x18;
		int v9 = (unsigned __int8)(v8 + ext_len) - v8;
		size_t v10 = v9;
		if (v9 > 0 && (m_stream->read(v4, &v10) && v10 == v9)) {
			return v1;
		}
		return v1;
	}
}
}
