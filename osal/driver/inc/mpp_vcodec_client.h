/*
 * Copyright 2020 Rockchip Electronics Co. LTD
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

#ifndef __mpp_vcodec_client_H__
#define __mpp_vcodec_client_H__

#include <asm/ioctl.h>
#include "rk_type.h"
#include "mpp_err.h"

#define VOCDEC_IOC_MAGIC        'V'
#define VOCDEC_IOC_CFG  _IOW(VOCDEC_IOC_MAGIC, 1, unsigned int)

typedef struct vocdec_req_t {
    RK_U32 cmd;
    RK_U32 ctrl_cmd;
    RK_U32 size;
    RK_U64 data;
} vocdec_req;

#if __SIZEOF_POINTER__ == 4
#define REQ_DATA_PTR(ptr) ((RK_U32)ptr)
#elif __SIZEOF_POINTER__ == 8
#define REQ_DATA_PTR(ptr) ((RK_U64)ptr)
#endif

#define VCODEC_ID_BASE_COMMON       (0x00000000)
#define VCODEC_ID_BASE_STATE        (0x00000100)
#define VCODEC_ID_BASE_FLOW         (0x00000200)

#define VCODEC_ID_BASE_INPUT        (0x00000400)
#define VCODEC_ID_BASE_INPUT_ACK    (0x00000500)

#define VCODEC_ID_BASE_OUTPUT       (0x00000600)
#define VCODEC_ID_BASE_OUTPUT_ACK   (0x00000700)

/*
 * Event call flow definition
 *
 *
 *  prev module          vcodec module           next module
 *      |                     |                      |
 *      |                     |                      |
 *      |   input event       |                      |
 *      +-------------------->|                      |
 *      |                     |                      |
 *      |   input ack event   |                      |
 *      |<--------------------+                      |
 *      |                     |                      |
 *      |                     |   output event       |
 *      |                     +--------------------->|
 *      |                     |                      |
 *      |                     |   output ack event   |
 *      |                     +<---------------------|
 *      |                     |                      |
 *      |                     |                      |
 */

enum vcodec_event_id {
    /* channel comment event */
    VCODEC_CHAN_CREATE      = VCODEC_ID_BASE_COMMON,
    VCODEC_CHAN_DESTROY,
    VCODEC_CHAN_RESET,
    VCODEC_CHAN_CONTROL,

    /* channel state change event */
    VCODEC_CHAN_START       = VCODEC_ID_BASE_STATE,
    VCODEC_CHAN_STOP,
    VCODEC_CHAN_PAUSE,
    VCODEC_CHAN_RESUME,

    /* channel data flow event */
    VCODEC_CHAN_BIND        = VCODEC_ID_BASE_FLOW,
    VCODEC_CHAN_UNBIND,

    /* channel input side io event from external module */
    VCODEC_CHAN_IN_FRM_RDY  = VCODEC_ID_BASE_INPUT,
    VCODEC_CHAN_IN_FRM_START,
    VCODEC_CHAN_IN_FRM_EARLY_END,
    VCODEC_CHAN_IN_FRM_END,

    /* channel input side ack event from vcodec module */
    VCODEC_CHAN_IN_BLOCK        = VCODEC_ID_BASE_INPUT_ACK,

    /* channel output side io event from vcodec module */
    VCODEC_CHAN_OUT_STRM_Q_FULL = VCODEC_ID_BASE_OUTPUT,
    VCODEC_CHAN_OUT_STRM_BUF_RDY,
    VCODEC_CHAN_OUT_STRM_END,
    VCODEC_CHAN_OUT_STRM_INFO,

    /* channel input side ack event from external module */
    VCODEC_CHAN_OUT_BLOCK       = VCODEC_ID_BASE_OUTPUT_ACK,

} ;

#ifdef  __cplusplus
extern "C" {
#endif

RK_S32 mpp_vcodec_open(void);
MPP_RET mpp_vcodec_ioctl(RK_S32 fd, RK_U32 cmd, RK_U32 ctrl_cmd, RK_U32 size, void *param);
MPP_RET mpp_vcodec_close(RK_S32 fd);

#ifdef  __cplusplus
}
#endif

#endif
