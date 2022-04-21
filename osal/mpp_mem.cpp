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

#define MODULE_TAG "mpp_mem"

#include <string.h>

#include "rk_type.h"
#include "mpp_err.h"

#include "mpp_log.h"
#include "mpp_env.h"
#include "mpp_mem.h"
#include "mpp_list.h"
#include "mpp_common.h"

#include "os_mem.h"

// mpp_mem_debug bit mask
#define MEM_DEBUG_EN            (0x00000001)
// NOTE: runtime log need debug enable
#define MEM_RUNTIME_LOG         (0x00000002)
#define MEM_NODE_LOG            (0x00000004)
#define MEM_EXT_ROOM            (0x00000010)
#define MEM_POISON              (0x00000020)

// default memory align size is set to 32
#define MEM_MAX_INDEX           (0x7fffffff)
#define MEM_ALIGN               32
#define MEM_ALIGN_MASK          (MEM_ALIGN - 1)
#define MEM_ALIGNED(x)          (((x) + MEM_ALIGN) & (~MEM_ALIGN_MASK))
#define MEM_HEAD_ROOM(debug)    ((debug & MEM_EXT_ROOM) ? (MEM_ALIGN) : (0))
#define MEM_NODE_MAX            (1024)
#define MEM_FREE_MAX            (512)
#define MEM_LOG_MAX             (1024)
#define MEM_CHECK_MARK          (0xdd)
#define MEM_HEAD_MASK           (0xab)
#define MEM_TAIL_MASK           (0xcd)

#define MPP_MEM_ASSERT(cond) \
    do { \
        if (!(cond)) { \
            mpp_err("found mpp_mem assert failed, start dumping:\n"); \
            service.dump(__FUNCTION__); \
            mpp_assert(cond); \
        } \
    } while (0)

typedef enum MppMemOps_e {
    MEM_MALLOC,
    MEM_REALLOC,
    MEM_FREE,
    MEM_FREE_DELAY,

    MEM_OPS_BUTT,
} MppMemOps;

void *mpp_osal_malloc(const char *caller, size_t size)
{
    size_t size_align = MEM_ALIGNED(size);
    size_t size_real = size_align;
    void *ptr;

    os_malloc(&ptr, MEM_ALIGN, size_real);

    return ptr;
}

void *mpp_osal_calloc(const char *caller, size_t size)
{
    void *ptr = mpp_osal_malloc(caller, size);
    if (ptr)
        memset(ptr, 0, size);
    return ptr;
}

void *mpp_osal_realloc(const char *caller, void *ptr, size_t size)
{
    void *ret;

    if (NULL == ptr)
        return mpp_osal_malloc(caller, size);

    if (0 == size) {
        mpp_err("warning: realloc %p to zero size\n", ptr);
        return NULL;
    }

    size_t size_align = MEM_ALIGNED(size);
    size_t size_real = size_align;
    void *ptr_real = (RK_U8 *)ptr;

    os_realloc(ptr_real, &ret, MEM_ALIGN, size_align);

    if (NULL == ret) {
        // if realloc fail the original buffer will be kept the same.
        mpp_err("mpp_realloc ptr %p to size %d failed\n", ptr, size);
    }

    return ret;
}

void mpp_osal_free(const char *caller, void *ptr)
{
    if (NULL == ptr)
        return;

    os_free(ptr);
    return ;
}
