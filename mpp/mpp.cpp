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

#include "mpp_dec_cfg_impl.h"
#include "mpp_vcodec_clinet.h"
#include "mpp_enc_cfg_impl.h"

#define MPP_TEST_FRAME_SIZE     SZ_1M
#define MPP_TEST_PACKET_SIZE    SZ_512K

static void mpp_notify_by_buffer_group(void *arg, void *group)
{
    Mpp *mpp = (Mpp *)arg;

    mpp->notify((MppBufferGroup) group);
}

static void *list_wraper_packet(void *arg)
{
    mpp_packet_deinit((MppPacket *)arg);
    return NULL;
}

static void *list_wraper_frame(void *arg)
{
    mpp_frame_deinit((MppFrame *)arg);
    return NULL;
}

Mpp::Mpp(MppCtx ctx = NULL)
    : mPackets(NULL),
      mCtx(ctx),
      mEncVersion(0),
      mType(MPP_CTX_BUTT),
      mCoding(MPP_VIDEO_CodingUnused),
      mClinetFd(-1),
      mExtraPacket(NULL),
      mDump(NULL)
{
    mpp_env_get_u32("mpp_debug", &mpp_debug, 0);
    memset(&mDecInitcfg, 0, sizeof(mDecInitcfg));
    mpp_dec_cfg_set_default(&mDecInitcfg);
    mDecInitcfg.base.enable_vproc = 1;
    mDecInitcfg.base.change  |= MPP_DEC_CFG_CHANGE_ENABLE_VPROC;
    mOutputTimeout = MPP_POLL_BLOCK;

    mpp_dump_init(&mDump);
}

MPP_RET Mpp::init(MppCtxType type, MppCodingType coding)
{
    MPP_RET ret = MPP_NOK;
    vcodec_attr attr;



    if (!mpp_check_soc_cap(type, coding)) {
        mpp_err("unable to create %s %s for soc %s unsupported\n",
                strof_ctx_type(type), strof_coding_type(coding),
                mpp_get_soc_info()->compatible);
        return MPP_NOK;
    }

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
    mClinetFd = mpp_vcodec_open();
    if (mClinetFd < 0) {
        mpp_err("mpp_vcodec dev open fail");
        return MPP_NOK;
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

Mpp::~Mpp ()
{
    clear();
}

void Mpp::clear()
{

    MPP_RET ret = MPP_OK;
    ret = mpp_vcodec_ioctl(mClinetFd, VCODEC_CHAN_DESTROY, 0, 0, 0);
    if (ret) {
        mpp_err("VCODEC_CHAN_DESTROY channel fail \n");
    }
    mpp_dump_deinit(&mDump);
    mpp_free_chan(this, mType);
}

MPP_RET Mpp::start()
{
    MPP_RET ret = MPP_OK;
    ret = mpp_vcodec_ioctl(mClinetFd, VCODEC_CHAN_START, 0, 0, 0);
    if (ret) {
        mpp_err("VCODEC_CHAN_START channel fail \n");
    }
    return ret;
}

MPP_RET Mpp::stop()
{
    MPP_RET ret = MPP_OK;
    ret = mpp_vcodec_ioctl(mClinetFd, VCODEC_CHAN_START, 0, 0, 0);
    if (ret) {
        mpp_err("VCODEC_CHAN_START channel fail \n");
    }
    return ret;
}

MPP_RET Mpp::pause()
{
    MPP_RET ret = MPP_OK;
    ret = mpp_vcodec_ioctl(mClinetFd, VCODEC_CHAN_PAUSE, 0, 0, 0);
    if (ret) {
        mpp_err("VCODEC_CHAN_PAUSE channel fail \n");
    }
    return ret;
}

MPP_RET Mpp::resume()
{
    MPP_RET ret = MPP_OK;
    ret = mpp_vcodec_ioctl(mClinetFd, VCODEC_CHAN_RESUME, 0, 0, 0);
    if (ret) {
        mpp_err("VCODEC_CHAN_RESUME channel fail \n");
    }
    return ret;
}

MPP_RET Mpp::put_packet(MppPacket packet)
{
    if (!mInitDone)
        return MPP_ERR_INIT;

    MPP_RET ret = MPP_NOK;
    MppPollType timeout = mInputTimeout;
    MppTask task_dequeue = NULL;
    RK_U32 pkt_copy = 0;

    if (mExtraPacket) {
        MppPacket extra = mExtraPacket;

        mExtraPacket = NULL;
        put_packet(extra);
    }

    if (!mEosTask) {
        /* handle eos packet on block mode */
        ret = poll(MPP_PORT_INPUT, MPP_POLL_BLOCK);
        if (ret < 0)
            goto RET;

        dequeue(MPP_PORT_INPUT, &mEosTask);
        if (NULL == mEosTask) {
            mpp_err_f("fail to reserve eos task\n", ret);
            ret = MPP_NOK;
            goto RET;
        }
    }

    if (mpp_packet_get_eos(packet)) {
        mpp_assert(mEosTask);
        task_dequeue = mEosTask;
        mEosTask = NULL;
    }

    /* Use reserved task to send eos packet */
    if (mInputTask && !task_dequeue) {
        task_dequeue = mInputTask;
        mInputTask = NULL;
    }

    if (NULL == task_dequeue) {
        ret = poll(MPP_PORT_INPUT, timeout);
        if (ret < 0) {
            ret = MPP_ERR_BUFFER_FULL;
            goto RET;
        }

        /* do not pull here to avoid block wait */
        dequeue(MPP_PORT_INPUT, &task_dequeue);
        if (NULL == task_dequeue) {
            mpp_err_f("fail to get task on poll ret %d\n", ret);
            ret = MPP_NOK;
            goto RET;
        }
    }

    if (NULL == mpp_packet_get_buffer(packet)) {
        /* packet copy path */
        MppPacket pkt_in = NULL;

        mpp_packet_copy_init(&pkt_in, packet);
        mpp_packet_set_length(packet, 0);
        pkt_copy = 1;
        packet = pkt_in;
        ret = MPP_OK;
    } else {
        /* packet zero copy path */
        mpp_log_f("not support zero copy path\n");
        timeout = MPP_POLL_BLOCK;
    }

    /* setup task */
    ret = mpp_task_meta_set_packet(task_dequeue, KEY_INPUT_PACKET, packet);
    if (ret) {
        mpp_err_f("set input frame to task ret %d\n", ret);
        /* keep current task for next */
        mInputTask = task_dequeue;
        goto RET;
    }

    mpp_ops_dec_put_pkt(mDump, packet);

    /* enqueue valid task to decoder */
    ret = enqueue(MPP_PORT_INPUT, task_dequeue);
    if (ret) {
        mpp_err_f("enqueue ret %d\n", ret);
        goto RET;
    }

    mPacketPutCount++;

    if (timeout && !pkt_copy)
        ret = poll(MPP_PORT_INPUT, timeout);

RET:
    /* wait enqueued task finished */
    if (NULL == mInputTask) {
        MPP_RET cnt = poll(MPP_PORT_INPUT, MPP_POLL_NON_BLOCK);
        /* reserve one task for eos block mode */
        if (cnt >= 0) {
            dequeue(MPP_PORT_INPUT, &mInputTask);
            mpp_assert(mInputTask);
        }
    }

    return ret;
}

MPP_RET Mpp::get_frame(MppFrame *frame)
{
    if (!mInitDone)
        return MPP_ERR_INIT;

    AutoMutex autoFrameLock(mFrames->mutex());
    MppFrame first = NULL;

    if (0 == mFrames->list_size()) {
        if (mOutputTimeout) {
            if (mOutputTimeout < 0) {
                /* block wait */
                mFrames->wait();
            } else {
                RK_S32 ret = mFrames->wait(mOutputTimeout);
                if (ret) {
                    if (ret == ETIMEDOUT)
                        return MPP_ERR_TIMEOUT;
                    else
                        return MPP_NOK;
                }
            }
        } else {
            /* NOTE: in non-block mode the sleep is to avoid user's dead loop */
            msleep(1);
        }
    }

    if (mFrames->list_size()) {
        mFrames->del_at_head(&first, sizeof(frame));
        mFrameGetCount++;
        notify(MPP_OUTPUT_DEQUEUE);

        if (mMultiFrame) {
            MppFrame prev = first;
            MppFrame next = NULL;
            while (mFrames->list_size()) {
                mFrames->del_at_head(&next, sizeof(frame));
                mFrameGetCount++;
                notify(MPP_OUTPUT_DEQUEUE);
                mpp_frame_set_next(prev, next);
                prev = next;
            }
        }
    } else {
        // NOTE: Add signal here is not efficient
        // This is for fix bug of stucking on decoder parser thread
        // When decoder parser thread is block by info change and enter waiting.
        // There is no way to wake up parser thread to continue decoding.
        // The put_packet only signal sem on may be it better to use sem on info
        // change too.
        AutoMutex autoPacketLock(mPackets->mutex());
        if (mPackets->list_size())
            notify(MPP_INPUT_ENQUEUE);
    }

    *frame = first;

    // dump output
    mpp_ops_dec_get_frm(mDump, first);

    return MPP_OK;
}

MPP_RET Mpp::put_frame(MppFrame frame)
{
    mpp_frame_infos frame_info;
    MppBuffer buf = NULL;
    MPP_RET ret = MPP_OK;
    MppStopwatch stopwatch = NULL;

    if (!mInitDone)
        return MPP_ERR_INIT;
    mpp_log("put_frame");
    if (mpp_debug & MPP_DBG_TIMING) {
        mpp_frame_set_stopwatch_enable(frame, 1);
        stopwatch = mpp_frame_get_stopwatch(frame);
    }
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

    mpp_log("ioctl cmd VCODEC_CHAN_IN_FRM_RDY in");
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
    MppTask task = NULL;
    venc_packet enc_packet;
    struct timeval timeout;

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(mClinetFd, &read_fds);

    if (*packet == NULL) {
        mpp_err("mpp buffer need alloc");
        return MPP_NOK;
    }

    timeout.tv_sec  = 2;
    timeout.tv_usec = 0;
    ret = select(mClinetFd + 1, &read_fds, NULL, NULL, &timeout);
    if (ret < 0) {
        mpp_err("select failed!\n");
        return MPP_NOK;
    } else if (ret == 0) {
        mpp_err("get venc stream time out \n");
        return MPP_NOK;
    } else {
        if (FD_ISSET(mClinetFd, &read_fds)) {
            MppMeta meta = mpp_packet_get_meta(*packet);
            void *ptr = mpp_packet_get_pos(*packet);
            enc_packet.buf_size = mpp_packet_get_size(*packet);
            enc_packet.u64vir_addr = REQ_DATA_PTR(ptr);
            ret = mpp_vcodec_ioctl(mClinetFd, VCODEC_CHAN_OUT_STRM_BUF_RDY, 0, sizeof(enc_packet), &enc_packet);
            if (ret) {
                mpp_err("VCODEC_CHAN_OUT_STRM_BUF_RDY fail \n");
                return MPP_NOK;
            }
            mpp_meta_set_s32(meta, KEY_TEMPORAL_ID, enc_packet.temporal_id);
            mpp_meta_set_s32(meta, KEY_OUTPUT_INTRA, enc_packet.flag);
            mpp_packet_set_length(*packet, enc_packet.len);
            mpp_packet_set_dts(*packet, enc_packet.u64pts);
            mpp_packet_set_pts(*packet, enc_packet.u64pts);
        }
    }
    return MPP_OK;
}

MPP_RET Mpp::poll(MppPortType type, MppPollType timeout)
{
    if (!mInitDone)
        return MPP_ERR_INIT;

    MPP_RET ret = MPP_NOK;
    MppTaskQueue port = NULL;

    switch (type) {
    case MPP_PORT_INPUT : {
        port = mUsrInPort;
    } break;
    case MPP_PORT_OUTPUT : {
        port = mUsrOutPort;
    } break;
    default : {
    } break;
    }

    if (port)
        ret = mpp_port_poll(port, timeout);

    return ret;
}

MPP_RET Mpp::dequeue(MppPortType type, MppTask *task)
{
    if (!mInitDone)
        return MPP_ERR_INIT;

    MPP_RET ret = MPP_NOK;
    MppTaskQueue port = NULL;
    RK_U32 notify_flag = 0;

    switch (type) {
    case MPP_PORT_INPUT : {
        port = mUsrInPort;
        notify_flag = MPP_INPUT_DEQUEUE;
    } break;
    case MPP_PORT_OUTPUT : {
        port = mUsrOutPort;
        notify_flag = MPP_OUTPUT_DEQUEUE;
    } break;
    default : {
    } break;
    }

    if (port) {
        ret = mpp_port_dequeue(port, task);
        if (MPP_OK == ret)
            notify(notify_flag);
    }

    return ret;
}

MPP_RET Mpp::enqueue(MppPortType type, MppTask task)
{
    if (!mInitDone)
        return MPP_ERR_INIT;

    MPP_RET ret = MPP_NOK;
    MppTaskQueue port = NULL;
    RK_U32 notify_flag = 0;

    switch (type) {
    case MPP_PORT_INPUT : {
        port = mUsrInPort;
        notify_flag = MPP_INPUT_ENQUEUE;
    } break;
    case MPP_PORT_OUTPUT : {
        port = mUsrOutPort;
        notify_flag = MPP_OUTPUT_ENQUEUE;
    } break;
    default : {
    } break;
    }

    if (port) {
        ret = mpp_port_enqueue(port, task);
        // if enqueue success wait up thread
        if (MPP_OK == ret)
            notify(notify_flag);
    }

    return ret;
}

MPP_RET Mpp::control(MpiCmd cmd, MppParam param)
{
    MPP_RET ret = MPP_NOK;

    mpp_ops_ctrl(mDump, cmd);
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
    case MPP_ENC_SET_REF_CFG : {
        size = sizeof(MppEncRefParam);
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
    if (!mInitDone)
        return MPP_ERR_INIT;

    mpp_ops_reset(mDump);

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

    switch (cmd) {
    case MPP_DEC_SET_FRAME_INFO: {
        ;//ret = mpp_dec_control(mDec, cmd, param);
    } break;
    case MPP_DEC_SET_EXT_BUF_GROUP: {
        mFrameGroup = (MppBufferGroup)param;
        if (param) {
            mExternalFrameGroup = 1;

            mpp_dbg_info("using external buffer group %p\n", mFrameGroup);

            if (mInitDone) {
                ret = mpp_buffer_group_set_callback((MppBufferGroupImpl *)param,
                                                    mpp_notify_by_buffer_group,
                                                    (void *)this);

                notify(MPP_DEC_NOTIFY_EXT_BUF_GRP_READY);
            } else {
                /*
                 * NOTE: If frame buffer group is configured before decoder init
                 * then the buffer limitation maybe not be correctly setup
                 * without infomation from InfoChange frame.
                 * And the thread signal connection may not be setup here. It
                 * may have a bad effect on MPP efficiency.
                 */
                mpp_err("WARNING: setup buffer group before decoder init\n");
            }
        } else {
            /* The buffer group should be destroyed before */
            mExternalFrameGroup = 0;
            ret = MPP_OK;
        }
    } break;
    case MPP_DEC_SET_INFO_CHANGE_READY: {
        mpp_dbg_info("set info change ready\n");

        //ret = mpp_dec_control(mDec, cmd, param);
        notify(MPP_DEC_NOTIFY_INFO_CHG_DONE | MPP_DEC_NOTIFY_BUFFER_MATCH);
    } break;
    case MPP_DEC_SET_PRESENT_TIME_ORDER :
    case MPP_DEC_SET_PARSER_SPLIT_MODE :
    case MPP_DEC_SET_PARSER_FAST_MODE :
    case MPP_DEC_SET_IMMEDIATE_OUT :
    case MPP_DEC_SET_DISABLE_ERROR :
    case MPP_DEC_SET_ENABLE_DEINTERLACE : {
        /*
         * These control may be set before mpp_init
         * When this case happen record the config and wait for decoder init
         */
        ;
    } break;
    case MPP_DEC_GET_STREAM_COUNT: {
        AutoMutex autoLock(mPackets->mutex());
        *((RK_S32 *)param) = mPackets->list_size();
        ret = MPP_OK;
    } break;
    case MPP_DEC_GET_VPUMEM_USED_COUNT :
    case MPP_DEC_SET_OUTPUT_FORMAT :
    case MPP_DEC_QUERY : {
        ;//ret = mpp_dec_control(mDec, cmd, param);
    } break;
    case MPP_DEC_SET_CFG : {
        /*if (mDec)
            ret = mpp_dec_control(mDec, cmd, param);
        else if (param) {
            MppDecCfgImpl *dec_cfg = (MppDecCfgImpl *)param;

            ret = mpp_dec_set_cfg(&mDecInitcfg, &dec_cfg->cfg);
        }*/
    } break;
    case MPP_DEC_GET_CFG : {
        /* if (mDec)
             ret = mpp_dec_control(mDec, cmd, param);
         else if (param) {
             MppDecCfgImpl *dec_cfg = (MppDecCfgImpl *)param;

             memcpy(&dec_cfg->cfg, &mDecInitcfg, sizeof(dec_cfg->cfg));
             ret = MPP_OK;
         }*/
    } break;
    default : {
    } break;
    }
    return ret;
}

MPP_RET Mpp::control_enc(MpiCmd cmd, MppParam param)
{
    //mpp_assert(mEnc);
    // return MPP_OK;
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
