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

#define  MODULE_TAG "mpp"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include "rk_mpi.h"

#include "mpp_log.h"
#include "mpp_mem.h"
#include "mpp_env.h"
#include "mpp_time.h"
#include "mpp_impl.h"
#include "mpp_2str.h"

#include "mpp.h"
#include "mpp_soc.h"
#include "mpp_chan.h"
#include "mpp_task_impl.h"
#include "mpp_buffer_impl.h"
#include "mpp_frame_impl.h"
#include "mpp_packet_impl.h"

#include "mpp_vcodec_clinet.h"
#include "mpp_enc_cfg_impl.h"

#define MPP_TEST_FRAME_SIZE     SZ_1M
#define MPP_TEST_PACKET_SIZE    SZ_512K

static void mpp_notify_by_buffer_group(void *arg, void *group)
{
    Mpp *mpp = (Mpp *)arg;

    mpp->notify((MppBufferGroup) group);
}

Mpp::Mpp(MppCtx ctx = NULL)
    : mPackets(NULL),
      mCtx(ctx),
      mEncVersion(0),
      mType(MPP_CTX_BUTT),
      mCoding(MPP_VIDEO_CodingUnused),
      mChanDup(0),
      mClinetFd(-1),
      mExtraPacket(NULL),
      mDump(NULL),
      mInitDone(0)
{
    mpp_env_get_u32("mpp_debug", &mpp_debug, 0);
    mOutputTimeout = MPP_POLL_BLOCK;
    mTimeout.tv_sec  = 0;
    mTimeout.tv_usec = 100000;

}

MPP_RET Mpp::init(MppCtxType type, MppCodingType coding)
{
    MPP_RET ret = MPP_NOK;
    vcodec_attr attr;
    memset(&attr, 0, sizeof(vcodec_attr));
    if (mpp_check_support_format(type, coding)) {
        mpp_err("unable to create %s %s for mpp unsupported\n",
                strof_ctx_type(type), strof_coding_type(coding));
        return MPP_NOK;
    }

    attr.chan_id = mpp_set_chan(this, type);
    if (attr.chan_id < 0) {
        mpp_log("chan is big max chan num");
        return MPP_NOK;
    }
    attr.coding = coding;
    attr.type = type;
    attr.online = 0;
    attr.shared_buf_en = 0;
    if (mClinetFd < 0) {
        mClinetFd = mpp_vcodec_open();
        if (mClinetFd < 0) {
            mpp_err("mpp_vcodec dev open fail");
            return MPP_NOK;
        }
    }

    mpp_log("mClinetFd %d open ok attr.chan_id %d", mClinetFd, attr.chan_id);
    ret = mpp_vcodec_ioctl(mClinetFd, VCODEC_CHAN_CREATE, 0, sizeof(attr), &attr);
    if (ret) {
        mpp_err("VCODEC_CHAN_CREATE channel fail \n");
    }

    ret = mpp_vcodec_ioctl(mClinetFd, VCODEC_CHAN_START, 0, 0, 0);
    if (ret) {
        mpp_err("VCODEC_CHAN_CREATE channel fail \n");
    }

    mInitDone = 1;
    mChanId = attr.chan_id;
    mType = type;
    return ret;
}

MPP_RET Mpp::open_client(void)
{
    mClinetFd = mpp_vcodec_open();
    if (mClinetFd < 0) {
        mpp_err("mpp_vcodec dev open fail");
        return MPP_NOK;
    }
    return MPP_OK;
}

MPP_RET Mpp::init_ext(vcodec_attr *attr)
{
    MPP_RET ret = MPP_NOK;

    if (mpp_check_support_format(attr->type, attr->coding)) {
        mpp_err("unable to create %s %s for mpp unsupported\n",
                strof_ctx_type(attr->type), strof_coding_type(attr->coding));
        return MPP_NOK;
    }

    if (mClinetFd < 0) {
        mClinetFd = mpp_vcodec_open();
        if (mClinetFd < 0) {
            mpp_err("mpp_vcodec dev open fail");
            return MPP_NOK;
        }
    }
    mpp_dbg_info("mClinetFd %d open ok attr.chan_id %d", mClinetFd, attr->chan_id);
    ret = mpp_vcodec_ioctl(mClinetFd, VCODEC_CHAN_CREATE, 0, sizeof(*attr), attr);
    if (ret) {
        mpp_err("VCODEC_CHAN_CREATE channel %d fail \n", attr->chan_id);
    }

    if (!attr->chan_dup) {
        ret = mpp_vcodec_ioctl(mClinetFd, VCODEC_CHAN_START, 0, 0, 0);
        if (ret) {
            mpp_err("VCODEC_CHAN_CREATE channel %d fail \n", attr->chan_id);
        }
    }

    mInitDone = 1;
    mChanId = attr->chan_id;
    mType = attr->type;
    mChanDup = attr->chan_dup;
    return ret;
}

Mpp::~Mpp ()
{
    clear();
}

void Mpp::clear()
{
    if (!mChanDup) {
        MPP_RET ret = MPP_OK;
        ret = mpp_vcodec_ioctl(mClinetFd, VCODEC_CHAN_DESTROY, 0, 0, 0);
        if (ret) {
            mpp_err("VCODEC_CHAN_DESTROY channel fail \n");
        }
    }

    if (mClinetFd >= 0)
        mpp_vcodec_close(mClinetFd);


    if (!mChanDup)
        mpp_free_chan(this, mType);
}

MPP_RET Mpp::start()
{
    if (mChanDup)
        return MPP_OK;
    MPP_RET ret = MPP_OK;
    ret = mpp_vcodec_ioctl(mClinetFd, VCODEC_CHAN_START, 0, 0, 0);
    if (ret) {
        mpp_err("VCODEC_CHAN_START channel fail \n");
    }
    return ret;
}

MPP_RET Mpp::stop()
{
    if (mChanDup)
        return MPP_OK;
    MPP_RET ret = MPP_OK;
    ret = mpp_vcodec_ioctl(mClinetFd, VCODEC_CHAN_START, 0, 0, 0);
    if (ret) {
        mpp_err("VCODEC_CHAN_START channel fail \n");
    }
    return ret;
}

MPP_RET Mpp::pause()
{
    if (mChanDup)
        return MPP_OK;
    MPP_RET ret = MPP_OK;
    ret = mpp_vcodec_ioctl(mClinetFd, VCODEC_CHAN_PAUSE, 0, 0, 0);
    if (ret) {
        mpp_err("VCODEC_CHAN_PAUSE channel fail \n");
    }
    return ret;
}

MPP_RET Mpp::resume()
{
    if (mChanDup)
        return MPP_OK;
    MPP_RET ret = MPP_OK;
    ret = mpp_vcodec_ioctl(mClinetFd, VCODEC_CHAN_RESUME, 0, 0, 0);
    if (ret) {
        mpp_err("VCODEC_CHAN_RESUME channel fail \n");
    }
    return ret;
}

MPP_RET Mpp::put_packet(MppPacket packet)
{
    (void) packet;
    MPP_RET ret = MPP_OK;

    if (!mInitDone)
        return MPP_ERR_INIT;



    return ret;
}

MPP_RET Mpp::get_frame(MppFrame *frame)
{
    (void)frame;
    if (!mInitDone)
        return MPP_ERR_INIT;

    return MPP_OK;
}

MPP_RET Mpp::put_frame(MppFrame frame)
{
    mpp_frame_infos frame_info;
    MppBuffer buf = NULL;
    MPP_RET ret = MPP_OK;

    if (!mInitDone)
        return MPP_ERR_INIT;

    buf = mpp_frame_get_buffer(frame);
    frame_info.width = mpp_frame_get_width(frame);
    frame_info.height = mpp_frame_get_height(frame);
    frame_info.hor_stride = mpp_frame_get_hor_stride(frame);
    frame_info.ver_stride = mpp_frame_get_ver_stride(frame);
    frame_info.hor_stride_pixel = mpp_frame_get_hor_stride_pixel(frame);
    frame_info.offset_x = mpp_frame_get_offset_x(frame);
    frame_info.offset_y = mpp_frame_get_offset_y(frame);
    frame_info.fmt = mpp_frame_get_fmt(frame);
    frame_info.fd = mpp_buffer_get_fd(buf);
    frame_info.pts = mpp_frame_get_pts(frame);
    frame_info.jpeg_chan_id = mpp_frame_get_jpege_chan_id(frame);
    ret = mpp_vcodec_ioctl(mClinetFd, VCODEC_CHAN_IN_FRM_RDY, 0, sizeof(frame_info), &frame_info);
    if (ret) {
        mpp_err("VCODEC_CHAN_IN_FRM_RDY  fail \n");
    }
    return ret;
}

#if __SIZEOF_POINTER__ == 4
#define REQ_DATA_PTR(ptr) ((RK_U32)ptr)
#elif __SIZEOF_POINTER__ == 8
#define REQ_DATA_PTR(ptr) ((RK_U64)ptr)
#endif

MPP_RET Mpp::get_packet(MppPacket *packet)
{
    if (!mInitDone)
        return MPP_ERR_INIT;
    RK_S32 ret;
    venc_packet *enc_packet  = (venc_packet *)*packet;

    if (*packet == NULL) {
        return MPP_NOK;
    }

    struct timeval timeout;

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(mClinetFd, &read_fds);

    memset(enc_packet, 0, sizeof(venc_packet));
    memcpy(&timeout, &mTimeout, sizeof(timeout));
    ret = select(mClinetFd + 1, &read_fds, NULL, NULL, &timeout);
    if (ret < 0) {
        mpp_err("select failed!\n");
        return MPP_NOK;
    } else if (ret == 0) {
        // mpp_err("get venc stream time out\n");
        return MPP_NOK;
    } else {
        if (FD_ISSET(mClinetFd, &read_fds)) {
            //void *dst_ptr = mpp_packet_get_pos(*packet);
            //enc_packet.buf_size = mpp_packet_get_size(*packet);
            //enc_packet.u64vir_addr = REQ_DATA_PTR(ptr);
            ret = mpp_vcodec_ioctl(mClinetFd, VCODEC_CHAN_OUT_STRM_BUF_RDY, 0, sizeof(*enc_packet), enc_packet);
            if (ret) {
                mpp_err("VCODEC_CHAN_OUT_STRM_BUF_RDY fail \n");
                return MPP_NOK;
            }
        }
    }
    return MPP_OK;
}

MPP_RET Mpp::release_packet(MppPacket *packet)
{
    MPP_RET ret = MPP_OK;
    if (!mInitDone)
        return MPP_ERR_INIT;

    venc_packet *enc_packet  = (venc_packet *) *packet;
    if (*packet == NULL) {
        return MPP_NOK;
    }

    if (mClinetFd >= 0) {
        ret = mpp_vcodec_ioctl(mClinetFd, VCODEC_CHAN_OUT_STRM_END, 0, sizeof(*enc_packet), enc_packet);
    }
    return ret;
}


MPP_RET Mpp::poll(MppPortType type, MppPollType timeout)
{
    (void)type;
    (void)timeout;
    if (!mInitDone)
        return MPP_ERR_INIT;

    MPP_RET ret = MPP_NOK;

    return ret;
}

MPP_RET Mpp::dequeue(MppPortType type, MppTask *task)
{
    (void)type;
    (void)task;

    if (!mInitDone)
        return MPP_ERR_INIT;

    MPP_RET ret = MPP_NOK;

    return ret;
}

MPP_RET Mpp::enqueue(MppPortType type, MppTask task)
{
    (void)type;
    (void)task;

    if (!mInitDone)
        return MPP_ERR_INIT;

    MPP_RET ret = MPP_NOK;


    return ret;
}

MPP_RET Mpp::control(MpiCmd cmd, MppParam param)
{
    MPP_RET ret = MPP_NOK;

    RK_U32 size = 0;
    switch (cmd) {
    case MPP_ENC_SET_CFG :
    case MPP_ENC_GET_CFG : {
        size = sizeof(MppEncCfgImpl);
    } break;
    case MPP_ENC_SET_HEADER_MODE :
    case MPP_ENC_SET_SEI_CFG : {
        size = sizeof(RK_U32);
    } break;
    case MPP_ENC_GET_REF_CFG :
    case MPP_ENC_SET_REF_CFG : {
        size = sizeof(MppEncRefParam);
    } break;
    case MPP_ENC_GET_ROI_CFG:
    case MPP_ENC_SET_ROI_CFG: {
        size = sizeof(MppEncROICfg);
    } break;
    case MPP_ENC_SET_OSD_DATA_CFG: {
        size = sizeof(MppEncOSDData3);
    } break;
    case MPP_ENC_INSRT_USERDATA: {
        size = sizeof(MppEncUserData);
    } break;
    case MPP_ENC_SET_CHANGE_STREAM_TYPE : {
        size = sizeof(vcodec_attr);
    } break;
    case MPP_SET_SELECT_TIMEOUT: {
        struct timeval *p = (struct timeval *)param;
        mTimeout.tv_sec = p->tv_sec;
        mTimeout.tv_usec = p->tv_usec;
        return MPP_OK;
    } break;

    default : {
        size = 0;
    } break;
    }
    ret = mpp_vcodec_ioctl(mClinetFd, VCODEC_CHAN_CONTROL, cmd, size, param);
    if (ret) {
        mpp_err("mClinetFd %d VCODEC_CHAN_CONTROL channel fail \n", mClinetFd);
    }
    return ret;
}

MPP_RET Mpp::reset()
{
    if (mChanDup)
        return MPP_OK;
    if (!mInitDone)
        return MPP_ERR_INIT;

    MPP_RET ret = MPP_OK;
    ret = mpp_vcodec_ioctl(mClinetFd, VCODEC_CHAN_RESET, 0, 0, 0);
    if (ret) {
        mpp_err("VCODEC_CHAN_RESET channel fail \n");
    }
    return ret;
}

MPP_RET Mpp::control_mpp(MpiCmd cmd, MppParam param)
{
    MPP_RET ret = MPP_OK;

    switch (cmd) {
    case MPP_SET_INPUT_BLOCK :
    case MPP_SET_OUTPUT_BLOCK :
    case MPP_SET_INTPUT_BLOCK_TIMEOUT :
    case MPP_SET_OUTPUT_BLOCK_TIMEOUT : {
        MppPollType block = (param) ? *((MppPollType *)param) : MPP_POLL_NON_BLOCK;

        if (block <= MPP_POLL_BUTT || block > MPP_POLL_MAX) {
            mpp_err("invalid output timeout type %d should be in range [%d, %d]\n",
                    block, MPP_POLL_BUTT, MPP_POLL_MAX);
            ret = MPP_ERR_VALUE;
            break;
        }
        if (cmd == MPP_SET_INPUT_BLOCK || cmd == MPP_SET_INTPUT_BLOCK_TIMEOUT)
            mInputTimeout = block;
        else
            mOutputTimeout = block;

        mpp_log("deprecated block control, use timeout control instead\n");
    } break;

    case MPP_SET_INPUT_TIMEOUT:
    case MPP_SET_OUTPUT_TIMEOUT: {
        MppPollType timeout = (param) ? *((MppPollType *)param) : MPP_POLL_NON_BLOCK;

        if (timeout <= MPP_POLL_BUTT || timeout > MPP_POLL_MAX) {
            mpp_err("invalid output timeout type %d should be in range [%d, %d]\n",
                    timeout, MPP_POLL_BUTT, MPP_POLL_MAX);
            ret = MPP_ERR_VALUE;
            break;
        }

        if (cmd == MPP_SET_INPUT_TIMEOUT)
            mInputTimeout = timeout;
        else
            mOutputTimeout = timeout;
    } break;

    case MPP_START : {
        start();
    } break;
    case MPP_STOP : {
        stop();
    } break;

    case MPP_PAUSE : {
        pause();
    } break;
    case MPP_RESUME : {
        resume();
    } break;

    default : {
        ret = MPP_NOK;
    } break;
    }
    return ret;
}

MPP_RET Mpp::control_osal(MpiCmd cmd, MppParam param)
{
    MPP_RET ret = MPP_NOK;

    mpp_assert(cmd > MPP_OSAL_CMD_BASE);
    mpp_assert(cmd < MPP_OSAL_CMD_END);

    (void)cmd;
    (void)param;
    return ret;
}

MPP_RET Mpp::control_codec(MpiCmd cmd, MppParam param)
{
    MPP_RET ret = MPP_NOK;

    (void)cmd;
    (void)param;
    return ret;
}

MPP_RET Mpp::control_dec(MpiCmd cmd, MppParam param)
{
    MPP_RET ret = MPP_NOK;
    (void)cmd;
    (void)param;

    return ret;
}

MPP_RET Mpp::control_enc(MpiCmd cmd, MppParam param)
{
    //mpp_assert(mEnc);
    (void)cmd;
    (void)param;
    return MPP_OK;
    // return mpp_enc_control_v2(mEnc, cmd, param);
}

MPP_RET Mpp::control_isp(MpiCmd cmd, MppParam param)
{
    MPP_RET ret = MPP_NOK;

    mpp_assert(cmd > MPP_ISP_CMD_BASE);
    mpp_assert(cmd < MPP_ISP_CMD_END);

    (void)cmd;
    (void)param;
    return ret;
}

MPP_RET Mpp::notify(RK_U32 flag)
{
    return MPP_NOK;
}

MPP_RET Mpp::notify(MppBufferGroup group)
{
    MPP_RET ret = MPP_NOK;

    switch (mType) {
    case MPP_CTX_DEC : {
        if (group == mFrameGroup)
            ret = notify(MPP_DEC_NOTIFY_BUFFER_VALID |
                         MPP_DEC_NOTIFY_BUFFER_MATCH);
    } break;
    default : {
    } break;
    }

    return ret;
}

MPP_RET Mpp::get_fd(RK_S32 *fd)
{
    MPP_RET ret = MPP_OK;

    if (mClinetFd >= 0)
        *fd = dup(mClinetFd);
    else
        *fd = -1;

    if (*fd < 0)
        ret = MPP_NOK;
    return ret;
}

MPP_RET Mpp::close_fd(RK_S32 fd)
{
    if (fd >= 0)
        close(fd);
    return MPP_OK;
}
