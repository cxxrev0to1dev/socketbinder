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
#include "osThreadUnix.h"

namespace ArmVM {

ThreadUnix::ThreadUnix() :
	m_thread( {nullptr,0}),
    m_exitStatus(0),
    m_isRunning(false)
{
    pthread_mutex_init(&m_lock, NULL);
}

ThreadUnix::~ThreadUnix()
{
    pthread_mutex_destroy(&m_lock);
}

bool
ThreadUnix::start()
{
    pthread_mutex_lock(&m_lock);
    m_isRunning = true;
    int ret = pthread_create(&m_thread, NULL, ThreadUnix::thread_main, this);
    if(ret) {
        m_isRunning = false;
    }
    pthread_mutex_unlock(&m_lock);
    return m_isRunning;
}

bool
ThreadUnix::wait(int *exitStatus)
{
    if (!m_isRunning) {
        return false;
    }

    void *retval;
    if (pthread_join(m_thread,&retval)) {
        return false;
    }

    long long int ret=(long long int)retval;
    if (exitStatus) {
        *exitStatus = (int)ret;
    }
    return true;
}

bool
ThreadUnix::trywait(int *exitStatus)
{
    bool ret = false;

    pthread_mutex_lock(&m_lock);
    if (!m_isRunning) {
        *exitStatus = m_exitStatus;
        ret = true;
    }
    pthread_mutex_unlock(&m_lock);
    return ret;
}

void *
ThreadUnix::thread_main(void *p_arg)
{
    ThreadUnix *self = (ThreadUnix *)p_arg;
    void *ret = (void *)self->Main();

    pthread_mutex_lock(&self->m_lock);
    self->m_isRunning = false;
    self->m_exitStatus = (int)ret;
    pthread_mutex_unlock(&self->m_lock);

    return ret;
}

} // of namespace osUtils

