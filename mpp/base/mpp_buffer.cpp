/*
 * Copyright 2015 Rockchip Electronics Co. LTD
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define MODULE_TAG "mpp_buffer"

#include <string.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include "mpp_log.h"
#include "mpp_mem.h"
#include "mpp_buffer.h"
#include "rk_mpi_mb_cmd.h"

struct MppBufferImpl {
    MppBufferInfo info;
    size_t offset;
    size_t buf_size;
    RK_S32 ref_count;
    RK_U32 buf_import;
    struct valloc_mb vmb;
};

class MpibufService
{
private:
    // avoid any unwanted function
    MpibufService() {
        mb_fd = -1;
        mb_fd = open("/dev/mpi/valloc", O_RDWR | O_CLOEXEC);
        if (mb_fd < 0) {
            mpp_err("open mb malloc fail");
        }
    };

    ~MpibufService() {
        if (mb_fd >= 0) {
            close(mb_fd);
        }
    };
    MpibufService(const MpibufService &);
    MpibufService &operator=(const MpibufService &);

    RK_S32 mb_fd;

public:
    static MpibufService *get() {
        static MpibufService instance;
        return &instance;
    }

    MPP_RET mb_buf_malloc(struct valloc_mb **mb) {
        struct valloc_mb *vmb = *mb;
        RK_S32 ret = 0;
        if (mb_fd < 0) {
            return MPP_NOK;
        }
        ret = ioctl(mb_fd, VALLOC_IOCTL_MB_CREATE, vmb);
        if (ret) {
            return MPP_NOK;
        }

        ret = ioctl(mb_fd, VALLOC_IOCTL_MB_GET_FD, vmb);
        mpp_log("mpi_buf_id = %d, dma_buf_fd = %d", vmb->mpi_buf_id, vmb->dma_buf_fd);


        if (ret) {
            return MPP_NOK;
        }
        return MPP_OK;
    };

    MPP_RET mb_buf_free(struct valloc_mb *mb) {
        RK_S32 ret = 0;
        if (mb_fd < 0) {
            return MPP_NOK;
        }
        ret = ioctl(mb_fd, VALLOC_IOCTL_MB_DELETE, mb);
        if (ret) {
            return MPP_NOK;
        }
        return MPP_OK;

    };
};

MPP_RET mpp_mpi_buf_alloc(struct valloc_mb **mb)
{
    return MpibufService::get()->mb_buf_malloc(mb);
}

MPP_RET mpp_mpi_buf_free(struct valloc_mb *mb)
{
    return MpibufService::get()->mb_buf_free(mb);
}

MPP_RET mpp_buffer_import_with_tag(MppBufferGroup group, MppBufferInfo * info,
                                   MppBuffer * buffer, const char *tag,
                                   const char *caller)
{
    (void)group;
    (void)tag;
    (void)caller;

    MPP_RET ret = MPP_OK;
    struct MppBufferImpl *buf_impl = NULL;
    struct valloc_mb *vmb = NULL;
    buf_impl = mpp_calloc(struct MppBufferImpl, 1);
    if (NULL == buf_impl) {
        mpp_err("mpp_buffer_import : group %p buffer %p fd %d from %s\n",
                group, buffer, (RK_U32)info->fd, caller);
        return MPP_ERR_UNKNOW;
    }

    buf_impl->buf_size = info->size;
    buf_impl->vmb.size = info->size;

    vmb = &buf_impl->vmb;

    vmb->dma_buf_fd = info->fd;
    buf_impl->buf_import = 1;
    buf_impl->ref_count++;
    *buffer = buf_impl;
    return ret;
}


MPP_RET mpp_buffer_get_with_tag(MppBufferGroup group, MppBuffer * buffer,
                                size_t size, const char *tag,
                                const char *caller)
{
    MPP_RET ret = MPP_OK;
    struct MppBufferImpl *buf_impl = NULL;
    struct valloc_mb *vmb = NULL;
    (void)tag;
    buf_impl = mpp_calloc(struct MppBufferImpl, 1);
    if (NULL == buf_impl) {
        mpp_err
        ("buf impl malloc fail : group %p buffer %p size %u from %s\n",
         group, buffer, (RK_U32) size, caller);
        return MPP_ERR_UNKNOW;
    }
    buf_impl->buf_size = size;
    buf_impl->vmb.size = size;
    vmb = &buf_impl->vmb;
    vmb->dma_buf_fd = -1;
    vmb->struct_size = sizeof(struct valloc_mb);
    ret = mpp_mpi_buf_alloc(&vmb);
    if (ret) {
        return MPP_NOK;
    }
    buf_impl->ref_count++;
    *buffer = buf_impl;
    return (buf_impl) ? (MPP_OK) : (MPP_NOK);
}

MPP_RET mpp_buffer_put_with_caller(MppBuffer buffer, const char *caller)
{
    struct MppBufferImpl *buf_impl = (struct MppBufferImpl *)buffer;


    if (NULL == buf_impl) {
        mpp_err("mpp_buffer_put invalid input: buffer NULL from %s\n",
                caller);
        return MPP_ERR_UNKNOW;
    }
    buf_impl->ref_count--;
    if (!buf_impl->ref_count) {
        if (buf_impl->info.ptr) {
            munmap(buf_impl->info.ptr, buf_impl->buf_size);
            buf_impl->info.ptr = NULL;
        }
        if (buf_impl->vmb.dma_buf_fd >= 0) {
            close(buf_impl->vmb.dma_buf_fd);
        }

        if (!buf_impl->buf_import)
            mpp_mpi_buf_free(&buf_impl->vmb);

        mpp_free(buf_impl);
    }
    return MPP_OK;
}

MPP_RET mpp_buffer_inc_ref_with_caller(MppBuffer buffer, const char *caller)
{
    struct MppBufferImpl *buf_impl = (struct MppBufferImpl *)buffer;

    if (NULL == buf_impl) {
        mpp_err
        ("mpp_buffer_inc_ref invalid input: buffer NULL from %s\n",
         caller);
        return MPP_ERR_UNKNOW;
    }
    buf_impl->ref_count++;
    return MPP_OK;
}

MPP_RET mpp_buffer_read_with_caller(MppBuffer buffer, size_t offset, void *data,
                                    size_t size, const char *caller)
{
    struct MppBufferImpl *p = (struct MppBufferImpl *)buffer;
    void *src = NULL;

    if (NULL == p || NULL == data) {
        mpp_err
        ("mpp_buffer_read invalid input: buffer %p data %p from %s\n",
         buffer, data, caller);
        return MPP_ERR_UNKNOW;
    }

    if (0 == size)
        return MPP_OK;

    if (NULL == p->info.ptr)
        p->info.ptr = mmap(NULL, p->buf_size, PROT_READ | PROT_WRITE , MAP_SHARED, p->vmb.dma_buf_fd, 0);

    src = p->info.ptr;
    mpp_assert(src != NULL);
    if (src)
        memcpy(data, (char *)src + offset, size);

    return MPP_OK;
}

MPP_RET mpp_buffer_write_with_caller(MppBuffer buffer, size_t offset,
                                     void *data, size_t size,
                                     const char *caller)
{
    struct MppBufferImpl *p = (struct MppBufferImpl *)buffer;
    void *dst = NULL;

    if (NULL == p || NULL == data) {
        mpp_err
        ("mpp_buffer_write invalid input: buffer %p data %p from %s\n",
         buffer, data, caller);
        return MPP_ERR_UNKNOW;
    }

    if (0 == size)
        return MPP_OK;

    if (offset + size > p->info.size)
        return MPP_ERR_VALUE;

    if (NULL == p->info.ptr)
        p->info.ptr = mmap(NULL, p->buf_size, PROT_READ | PROT_WRITE , MAP_SHARED, p->vmb.dma_buf_fd, 0);


    dst = p->info.ptr;
    mpp_assert(dst != NULL);
    if (dst)
        memcpy((char *)dst + offset, data, size);

    return MPP_OK;
}

void *mpp_buffer_get_ptr_with_caller(MppBuffer buffer, const char *caller)
{
    struct MppBufferImpl *p = (struct MppBufferImpl *)buffer;

    if (NULL == p) {
        mpp_err("mpp_buffer_get_ptr invalid NULL input from %s\n",
                caller);
        return NULL;
    }

    if (NULL == p->info.ptr) {
        p->info.ptr = mmap(NULL, p->buf_size, PROT_READ | PROT_WRITE , MAP_SHARED, p->vmb.dma_buf_fd, 0);
    }


    mpp_assert(p->info.ptr != NULL);
    memset(p->info.ptr, 0 , p->buf_size);
    if (NULL == p->info.ptr)
        mpp_err("mpp_buffer_get_ptr buffer %p ret NULL from %s\n",
                buffer, caller);

    return p->info.ptr;
}

int mpp_buffer_get_fd_with_caller(MppBuffer buffer, const char *caller)
{
    struct MppBufferImpl *p = (struct MppBufferImpl *)buffer;
    int fd = -1;

    if (p->info.fd > 0) {
        return p->info.fd;
    }
    if (NULL == p) {
        mpp_err("mpp_buffer_get_fd invalid NULL input from %s\n",
                caller);
        return -1;
    }
    fd = p->vmb.dma_buf_fd;
    mpp_assert(fd >= 0);
    if (fd < 0)
        mpp_err("mpp_buffer_get_fd buffer %p fd %d from %s\n", buffer,
                fd, caller);

    p->info.fd = fd;
    return fd;
}



size_t mpp_buffer_get_size_with_caller(MppBuffer buffer, const char *caller)
{
    struct MppBufferImpl *p = (struct MppBufferImpl *)buffer;
    if (NULL == p) {
        mpp_err("mpp_buffer_get_size invalid NULL input from %s\n",
                caller);
        return 0;
    }
    if (p->info.size == 0)
        mpp_err("mpp_buffer_get_size buffer %p ret zero size from %s\n",
                buffer, caller);

    return p->info.size;
}

int mpp_buffer_get_index_with_caller(MppBuffer buffer, const char *caller)
{
    struct MppBufferImpl *p = (struct MppBufferImpl *)buffer;
    if (NULL == p) {
        mpp_err("mpp_buffer_get_index invalid NULL input from %s\n",
                caller);
        return -1;
    }

    return p->info.index;
}

MPP_RET mpp_buffer_set_index_with_caller(MppBuffer buffer, int index,
                                         const char *caller)
{
    struct MppBufferImpl *p = (struct MppBufferImpl *)buffer;
    if (NULL == p) {
        mpp_err("mpp_buffer_set_index invalid NULL input from %s\n",
                caller);
        return MPP_ERR_UNKNOW;
    }

    p->info.index = index;
    return MPP_OK;
}

size_t mpp_buffer_get_offset_with_caller(MppBuffer buffer, const char *caller)
{
    struct MppBufferImpl *p = (struct MppBufferImpl *)buffer;

    if (NULL == p) {
        mpp_err("mpp_buffer_get_offset invalid NULL input from %s\n",
                caller);
        return -1;
    }

    return p->offset;
}

MPP_RET mpp_buffer_set_offset_with_caller(MppBuffer buffer, size_t offset,
                                          const char *caller)
{
    struct MppBufferImpl *p = (struct MppBufferImpl *)buffer;
    if (NULL == p) {
        mpp_err("mpp_buffer_set_offset invalid NULL input from %s\n",
                caller);
        return MPP_ERR_UNKNOW;
    }

    p->offset = offset;
    return MPP_OK;
}

MPP_RET mpp_buffer_info_get_with_caller(MppBuffer buffer, MppBufferInfo * info,
                                        const char *caller)
{
    struct MppBufferImpl *p = (struct MppBufferImpl *)buffer;
    if (NULL == buffer || NULL == info) {
        mpp_err
        ("mpp_buffer_info_get invalid input buffer %p info %p from %s\n",
         buffer, info, caller);
        return MPP_ERR_UNKNOW;
    }

    if (NULL == p->info.ptr)
        p->info.ptr = mmap(NULL, p->buf_size, PROT_READ | PROT_WRITE , MAP_SHARED, p->vmb.dma_buf_fd, 0);

    *info = p->info;
    return MPP_OK;
}

MPP_RET mpp_buffer_group_get(MppBufferGroup *group, MppBufferType type, MppBufferMode mode,
                             const char *tag, const char *caller)
{
    if (NULL == group ||
        mode >= MPP_BUFFER_MODE_BUTT ||
        (type & MPP_BUFFER_TYPE_MASK) >= MPP_BUFFER_TYPE_BUTT) {
        mpp_err_f("input invalid group %p mode %d type %d from %s\n",
                  group, mode, type, caller);
        return MPP_ERR_UNKNOW;
    }

    (void)tag;
    return MPP_OK;
}

MPP_RET mpp_buffer_group_put(MppBufferGroup group)
{
    if (NULL == group) {
        mpp_err_f("input invalid group %p\n", group);
        return MPP_NOK;
    }

    return MPP_OK;
}

MPP_RET mpp_buffer_group_clear(MppBufferGroup group)
{
    if (NULL == group) {
        mpp_err_f("input invalid group %p\n", group);
        return MPP_NOK;
    }

    return MPP_OK;
}

RK_S32  mpp_buffer_group_unused(MppBufferGroup group)
{
    if (NULL == group) {
        mpp_err_f("input invalid group %p\n", group);
        return MPP_NOK;
    }

    RK_S32 unused = 0;
    return unused;
}

size_t mpp_buffer_group_usage(MppBufferGroup group)
{
    if (NULL == group) {
        mpp_err_f("input invalid group %p\n", group);
        return MPP_BUFFER_MODE_BUTT;
    }

    return 0;
}

MppBufferMode mpp_buffer_group_mode(MppBufferGroup group)
{
    if (NULL == group) {
        mpp_err_f("input invalid group %p\n", group);
        return MPP_BUFFER_MODE_BUTT;
    }

    return MPP_BUFFER_INTERNAL;
}

MppBufferType mpp_buffer_group_type(MppBufferGroup group)
{
    if (NULL == group) {
        mpp_err_f("input invalid group %p\n", group);
        return MPP_BUFFER_TYPE_BUTT;
    }

    return MPP_BUFFER_TYPE_EXT_DMA;
}

MPP_RET mpp_buffer_group_limit_config(MppBufferGroup group, size_t size, RK_S32 count)
{
    if (NULL == group) {
        mpp_err_f("input invalid group %p\n", group);
        return MPP_NOK;
    }
    (void)group;
    (void)size;
    (void)count;
    return MPP_OK;
}

