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

#if defined(_WIN32)
#include "vld.h"
#endif

#define MODULE_TAG "mpi_enc_test"

#include <string.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include "rk_mpi.h"

#include "mpp_env.h"
#include "mpp_mem.h"
#include "mpp_log.h"
#include "mpp_time.h"
#include "mpp_common.h"

#include "utils.h"
#include "mpi_enc_utils.h"
#include "camera_source.h"
#include "rk_mpi_mb_cmd.h"




typedef struct {
    // global flow control flag
    RK_U32 frm_eos;
    RK_U32 pkt_eos;
    RK_U32 frm_pkt_cnt;
    RK_S32 frame_count;
    RK_S32 jpeg_cnt;
    RK_U64 stream_size;

    // src and dst
    FILE *fp_input;
    FILE *fp_output;

    // base flow context
    MppCtx ctx;
    MppApi *mpi;
    MppEncCfg cfg;


    MppCtx ctx_jpeg;
    MppApi *mpi_jpeg;
    MppEncCfg cfg_jpeg;

    MppEncOSDData3   osd_data_v3;
    MppEncROIRegion roi_region[3];
    MppEncROICfg    roi_cfg;

    // input / output
    MppBufferGroup buf_grp;
    MppBuffer frm_buf;
    MppBuffer pkt_buf;

    MppBuffer osd_buf;
    MppEncSeiMode sei_mode;
    MppEncHeaderMode header_mode;

    // paramter for resource malloc
    RK_U32 width;
    RK_U32 height;
    RK_U32 hor_stride;
    RK_U32 ver_stride;
    MppFrameFormat fmt;
    MppCodingType type;
    RK_S32 num_frames;
    RK_S32 loop_times;
    CamSource *cam_ctx;

    // resources
    size_t header_size;
    size_t frame_size;
    /* NOTE: packet buffer may overflow */
    size_t packet_size;

    RK_U32 osd_enable;
    RK_U32 osd_mode;
    RK_U32 split_mode;
    RK_U32 split_arg;

    RK_U32 user_data_enable;
    RK_U32 roi_enable;

    // rate control runtime parameter

    RK_S32 fps_in_flex;
    RK_S32 fps_in_den;
    RK_S32 fps_in_num;
    RK_S32 fps_out_flex;
    RK_S32 fps_out_den;
    RK_S32 fps_out_num;
    RK_S32 bps;
    RK_S32 bps_max;
    RK_S32 bps_min;
    RK_S32 rc_mode;
    RK_S32 gop_mode;
    RK_S32 gop_len;
    RK_S32 vi_len;
    RK_S32 mem_fd;
    RK_U32 jpeg_combo_en;
    RK_U32 jpeg_combo_id;
    RK_U32 chan_id;
} MpiEncTestData;

MPP_RET test_ctx_init(MpiEncTestData **data, MpiEncTestArgs *cmd)
{
    MpiEncTestData *p = NULL;
    MPP_RET ret = MPP_OK;

    if (!data || !cmd) {
        mpp_err_f("invalid input data %p cmd %p\n", data, cmd);
        return MPP_ERR_NULL_PTR;
    }

    p = mpp_calloc(MpiEncTestData, 1);
    if (!p) {
        mpp_err_f("create MpiEncTestData failed\n");
        ret = MPP_ERR_MALLOC;
        goto RET;
    }

    // get paramter from cmd
    p->width        = cmd->width;
    p->height       = cmd->height;
    p->hor_stride   = (cmd->hor_stride) ? (cmd->hor_stride) :
                      (MPP_ALIGN(cmd->width, 16));
    p->ver_stride   = (cmd->ver_stride) ? (cmd->ver_stride) :
                      (MPP_ALIGN(cmd->height, 16));
    p->fmt          = cmd->format;
    p->type         = cmd->type;
    p->bps          = cmd->bps_target;
    p->bps_min      = cmd->bps_min;
    p->bps_max      = cmd->bps_max;
    p->rc_mode      = cmd->rc_mode;
    p->num_frames   = cmd->num_frames;
    if (cmd->type == MPP_VIDEO_CodingMJPEG && p->num_frames == 0) {
        mpp_log("jpege default encode only one frame. Use -n [num] for rc case\n");
        p->num_frames   = 1;
    }
    p->gop_mode     = cmd->gop_mode;
    p->gop_len      = cmd->gop_len;
    p->vi_len       = cmd->vi_len;

    p->fps_in_flex  = cmd->fps_in_flex;
    p->fps_in_den   = cmd->fps_in_den;
    p->fps_in_num   = cmd->fps_in_num;
    p->fps_out_flex = cmd->fps_out_flex;
    p->fps_out_den  = cmd->fps_out_den;
    p->fps_out_num  = cmd->fps_out_num;
    p->chan_id      = cmd->chan_id;


    p->mem_fd = open("/dev/mpi/valloc", O_RDWR | O_CLOEXEC);

    if (p->mem_fd < 0) {
        mpp_err("mpi mb valloc fail");
        return MPP_NOK;
    }

    if (cmd->file_input) {
        if (!strncmp(cmd->file_input, "/dev/video", 10)) {
            mpp_log("open camera device");
            p->cam_ctx = camera_source_init(cmd->file_input, 4, p->width, p->height, p->fmt);
            mpp_log("new framecap ok");
            if (p->cam_ctx == NULL)
                mpp_err("open %s fail", cmd->file_input);
        } else {
            p->fp_input = fopen(cmd->file_input, "rb");
            if (NULL == p->fp_input) {
                mpp_err("failed to open input file %s\n", cmd->file_input);
                mpp_err("create default yuv image for test\n");
            }
        }
    }

    if (cmd->file_output) {
        p->fp_output = fopen(cmd->file_output, "w+b");
        if (NULL == p->fp_output) {
            mpp_err("failed to open output file %s\n", cmd->file_output);
            ret = MPP_ERR_OPEN_FILE;
        }
    }

    // update resource parameter
    switch (p->fmt & MPP_FRAME_FMT_MASK) {
    case MPP_FMT_YUV420SP:
    case MPP_FMT_YUV420P: {
        p->frame_size = MPP_ALIGN(p->hor_stride, 64) * MPP_ALIGN(p->ver_stride, 64) * 3 / 2;
    } break;

    case MPP_FMT_YUV422_YUYV :
    case MPP_FMT_YUV422_YVYU :
    case MPP_FMT_YUV422_UYVY :
    case MPP_FMT_YUV422_VYUY :
    case MPP_FMT_YUV422P :
    case MPP_FMT_YUV422SP :
    case MPP_FMT_RGB444 :
    case MPP_FMT_BGR444 :
    case MPP_FMT_RGB555 :
    case MPP_FMT_BGR555 :
    case MPP_FMT_RGB565 :
    case MPP_FMT_BGR565 : {
        p->frame_size = MPP_ALIGN(p->hor_stride, 64) * MPP_ALIGN(p->ver_stride, 64) * 2;
    } break;

    default: {
        p->frame_size = MPP_ALIGN(p->hor_stride, 64) * MPP_ALIGN(p->ver_stride, 64) * 4;
    } break;
    }

    if (MPP_FRAME_FMT_IS_FBC(p->fmt))
        p->header_size = MPP_ALIGN(MPP_ALIGN(p->width, 16) * MPP_ALIGN(p->height, 16) / 16, SZ_4K);
    else
        p->header_size = 0;

RET:
    *data = p;
    return ret;
}

MPP_RET test_ctx_deinit(MpiEncTestData **data)
{
    MpiEncTestData *p = NULL;

    if (!data) {
        mpp_err_f("invalid input data %p\n", data);
        return MPP_ERR_NULL_PTR;
    }
    p = *data;

    if (p->mem_fd) {
        close(p->mem_fd);
    }
    if (p) {
        if (p->cam_ctx) {
            camera_source_deinit(p->cam_ctx);
            p->cam_ctx = NULL;
        }
        if (p->fp_input) {
            fclose(p->fp_input);
            p->fp_input = NULL;
        }
        if (p->fp_output) {
            fclose(p->fp_output);
            p->fp_output = NULL;
        }
        MPP_FREE(p);
        *data = NULL;
    }
    return MPP_OK;
}

MPP_RET test_mpp_enc_cfg_setup(MpiEncTestData *p)
{
    MPP_RET ret;
    MppApi *mpi;
    MppCtx ctx;
    MppEncCfg cfg;

    if (NULL == p)
        return MPP_ERR_NULL_PTR;
    mpi = p->mpi;
    ctx = p->ctx;
    cfg = p->cfg;


    if (p->type == MPP_VIDEO_CodingMJPEG && p->jpeg_combo_en) {
        mpi = p->mpi_jpeg;
        ctx = p->ctx_jpeg;
        cfg = p->cfg_jpeg;
    }

    /* setup default parameter */
    if (p->fps_in_den == 0)
        p->fps_in_den = 1;
    if (p->fps_in_num == 0)
        p->fps_in_num = 30;
    if (p->fps_out_den == 0)
        p->fps_out_den = 1;
    if (p->fps_out_num == 0)
        p->fps_out_num = 30;

    if (!p->bps)
        p->bps = p->width * p->height / 8 * (p->fps_out_num / p->fps_out_den);

    mpp_enc_cfg_set_s32(cfg, "prep:width", p->width);
    mpp_enc_cfg_set_s32(cfg, "prep:height", p->height);
    mpp_enc_cfg_set_s32(cfg, "prep:hor_stride", p->hor_stride);
    mpp_enc_cfg_set_s32(cfg, "prep:ver_stride", p->ver_stride);
    mpp_enc_cfg_set_s32(cfg, "prep:format", p->fmt);

    mpp_enc_cfg_set_s32(cfg, "rc:mode", p->rc_mode);

    /* fix input / output frame rate */
    mpp_enc_cfg_set_s32(cfg, "rc:fps_in_flex", p->fps_in_flex);
    mpp_enc_cfg_set_s32(cfg, "rc:fps_in_num", p->fps_in_num);
    mpp_enc_cfg_set_s32(cfg, "rc:fps_in_denorm", p->fps_in_den);
    mpp_enc_cfg_set_s32(cfg, "rc:fps_out_flex", p->fps_out_flex);
    mpp_enc_cfg_set_s32(cfg, "rc:fps_out_num", p->fps_out_num);
    mpp_enc_cfg_set_s32(cfg, "rc:fps_out_denorm", p->fps_out_den);
    mpp_enc_cfg_set_s32(cfg, "rc:gop", p->gop_len ? p->gop_len : p->fps_out_num * 2);

    /* drop frame or not when bitrate overflow */
    mpp_enc_cfg_set_u32(cfg, "rc:drop_mode", MPP_ENC_RC_DROP_FRM_DISABLED);
    mpp_enc_cfg_set_u32(cfg, "rc:drop_thd", 20);        /* 20% of max bps */
    mpp_enc_cfg_set_u32(cfg, "rc:drop_gap", 1);         /* Do not continuous drop frame */

    /* setup bitrate for different rc_mode */
    mpp_enc_cfg_set_s32(cfg, "rc:bps_target", p->bps);
    switch (p->rc_mode) {
    case MPP_ENC_RC_MODE_FIXQP : {
        /* do not setup bitrate on FIXQP mode */
    } break;
    case MPP_ENC_RC_MODE_CBR : {
        /* CBR mode has narrow bound */
        mpp_enc_cfg_set_s32(cfg, "rc:bps_max", p->bps_max ? p->bps_max : p->bps * 17 / 16);
        mpp_enc_cfg_set_s32(cfg, "rc:bps_min", p->bps_min ? p->bps_min : p->bps * 15 / 16);
    } break;
    case MPP_ENC_RC_MODE_VBR :
    case MPP_ENC_RC_MODE_AVBR : {
        /* VBR mode has wide bound */
        mpp_enc_cfg_set_s32(cfg, "rc:bps_max", p->bps_max ? p->bps_max : p->bps * 17 / 16);
        mpp_enc_cfg_set_s32(cfg, "rc:bps_min", p->bps_min ? p->bps_min : p->bps * 1 / 16);
    } break;
    default : {
        /* default use CBR mode */
        mpp_enc_cfg_set_s32(cfg, "rc:bps_max", p->bps_max ? p->bps_max : p->bps * 17 / 16);
        mpp_enc_cfg_set_s32(cfg, "rc:bps_min", p->bps_min ? p->bps_min : p->bps * 15 / 16);
    } break;
    }

    /* setup qp for different codec and rc_mode */
    switch (p->type) {
    case MPP_VIDEO_CodingAVC :
    case MPP_VIDEO_CodingHEVC : {
        switch (p->rc_mode) {
        case MPP_ENC_RC_MODE_FIXQP : {
            mpp_enc_cfg_set_s32(cfg, "rc:qp_init", 20);
            mpp_enc_cfg_set_s32(cfg, "rc:qp_max", 20);
            mpp_enc_cfg_set_s32(cfg, "rc:qp_min", 20);
            mpp_enc_cfg_set_s32(cfg, "rc:qp_max_i", 20);
            mpp_enc_cfg_set_s32(cfg, "rc:qp_min_i", 20);
            mpp_enc_cfg_set_s32(cfg, "rc:qp_ip", 2);
        } break;
        case MPP_ENC_RC_MODE_CBR :
        case MPP_ENC_RC_MODE_VBR :
        case MPP_ENC_RC_MODE_AVBR : {
            mpp_enc_cfg_set_s32(cfg, "rc:qp_init", 26);
            mpp_enc_cfg_set_s32(cfg, "rc:qp_max", 51);
            mpp_enc_cfg_set_s32(cfg, "rc:qp_min", 10);
            mpp_enc_cfg_set_s32(cfg, "rc:qp_max_i", 51);
            mpp_enc_cfg_set_s32(cfg, "rc:qp_min_i", 10);
            mpp_enc_cfg_set_s32(cfg, "rc:qp_ip", 2);
        } break;
        default : {
            mpp_err_f("unsupport encoder rc mode %d\n", p->rc_mode);
        } break;
        }
    } break;
    case MPP_VIDEO_CodingVP8 : {
        /* vp8 only setup base qp range */
        mpp_enc_cfg_set_s32(cfg, "rc:qp_init", 40);
        mpp_enc_cfg_set_s32(cfg, "rc:qp_max",  127);
        mpp_enc_cfg_set_s32(cfg, "rc:qp_min",  0);
        mpp_enc_cfg_set_s32(cfg, "rc:qp_max_i", 127);
        mpp_enc_cfg_set_s32(cfg, "rc:qp_min_i", 0);
        mpp_enc_cfg_set_s32(cfg, "rc:qp_ip", 6);
    } break;
    case MPP_VIDEO_CodingMJPEG : {
        /* jpeg use special codec config to control qtable */
        mpp_enc_cfg_set_s32(cfg, "jpeg:q_factor", 80);
        mpp_enc_cfg_set_s32(cfg, "jpeg:qf_max", 99);
        mpp_enc_cfg_set_s32(cfg, "jpeg:qf_min", 1);
    } break;
    default : {
    } break;
    }

    /* setup codec  */
    mpp_enc_cfg_set_s32(cfg, "codec:type", p->type);
    switch (p->type) {
    case MPP_VIDEO_CodingAVC : {
        /*
         * H.264 profile_idc parameter
         * 66  - Baseline profile
         * 77  - Main profile
         * 100 - High profile
         */
        mpp_enc_cfg_set_s32(cfg, "h264:profile", 100);
        /*
         * H.264 level_idc parameter
         * 10 / 11 / 12 / 13    - qcif@15fps / cif@7.5fps / cif@15fps / cif@30fps
         * 20 / 21 / 22         - cif@30fps / half-D1@@25fps / D1@12.5fps
         * 30 / 31 / 32         - D1@25fps / 720p@30fps / 720p@60fps
         * 40 / 41 / 42         - 1080p@30fps / 1080p@30fps / 1080p@60fps
         * 50 / 51 / 52         - 4K@30fps
         */
        mpp_enc_cfg_set_s32(cfg, "h264:level", 40);
        mpp_enc_cfg_set_s32(cfg, "h264:cabac_en", 1);
        mpp_enc_cfg_set_s32(cfg, "h264:cabac_idc", 0);
        mpp_enc_cfg_set_s32(cfg, "h264:trans8x8", 1);
    } break;
    case MPP_VIDEO_CodingHEVC :
    case MPP_VIDEO_CodingMJPEG :
    case MPP_VIDEO_CodingVP8 : {
    } break;
    default : {
        mpp_err_f("unsupport encoder coding type %d\n", p->type);
    } break;
    }

    p->split_mode = 0;
    p->split_arg = 0;

    mpp_env_get_u32("split_mode", &p->split_mode, MPP_ENC_SPLIT_NONE);
    mpp_env_get_u32("split_arg", &p->split_arg, 0);

    if (p->split_mode) {
        mpp_log("%p split_mode %d split_arg %d\n", ctx, p->split_mode, p->split_arg);
        mpp_enc_cfg_set_s32(cfg, "split:mode", p->split_mode);
        mpp_enc_cfg_set_s32(cfg, "split:arg", p->split_arg);
    }

    ret = mpi->control(ctx, MPP_ENC_SET_CFG, cfg);
    if (ret) {
        mpp_err("mpi control enc set cfg failed ret %d\n", ret);
        goto RET;
    }

    /* optional */
    p->sei_mode = MPP_ENC_SEI_MODE_ONE_FRAME;
    ret = mpi->control(ctx, MPP_ENC_SET_SEI_CFG, &p->sei_mode);
    if (ret) {
        mpp_err("mpi control enc set sei cfg failed ret %d\n", ret);
        goto RET;
    }

    if (p->type == MPP_VIDEO_CodingAVC || p->type == MPP_VIDEO_CodingHEVC) {
        p->header_mode = MPP_ENC_HEADER_MODE_EACH_IDR;
        ret = mpi->control(ctx, MPP_ENC_SET_HEADER_MODE, &p->header_mode);
        if (ret) {
            mpp_err("mpi control enc set header mode failed ret %d\n", ret);
            goto RET;
        }
    }

    RK_U32 gop_mode = p->gop_mode;

    mpp_env_get_u32("gop_mode", &gop_mode, gop_mode);
    if (gop_mode) {
        mpp_log("cfg gopmod %d", gop_mode);
        MppEncRefParam param;
        param.cfg_mode = (MppEncRefCfgMode)p->gop_mode;
        param.gop_len = p->gop_len;
        param.vi_len = p->vi_len;
        param.base_N = 0;
        param.enh_M = 0;
        param.pre_en = 0;
        ret = mpi->control(ctx, MPP_ENC_SET_REF_CFG, &param);
        if (ret) {
            mpp_err("mpi control enc set ref cfg failed ret %d\n", ret);
            goto RET;
        }
    }

    /* setup test mode by env */
    mpp_env_get_u32("osd_enable", &p->osd_enable, 0);
    mpp_env_get_u32("osd_mode", &p->osd_mode, MPP_ENC_OSD_PLT_TYPE_DEFAULT);
    mpp_env_get_u32("roi_enable", &p->roi_enable, 0);
    mpp_env_get_u32("user_data_enable", &p->user_data_enable, 0);

RET:
    return ret;
}

void save_to_file(char *name, void *ptr, size_t size)
{
    FILE *fp = fopen(name, "w+b");
    if (fp) {
        fwrite(ptr, 1, size, fp);
        fclose(fp);
    } else
        mpp_err("create file %s failed\n", name);
}


MPP_RET jpeg_comb_get_packet(MpiEncTestData *p)
{
    MppApi *jpeg_mpi;
    MppCtx jpeg_ctx;
    MppPacket packet = NULL;
    MPP_RET ret = MPP_OK;
    struct venc_packet enc_packet;
    memset(&enc_packet, 0, sizeof(enc_packet));
    RK_S32 pid = getpid();
    char name[128];
    size_t name_len = sizeof(name) - 1;

    packet = &enc_packet;

    if (NULL == p)
        return MPP_ERR_NULL_PTR;
    jpeg_mpi = p->mpi_jpeg;
    jpeg_ctx = p->ctx_jpeg;
    {

        ret = jpeg_mpi->encode_get_packet(jpeg_ctx, &packet);
        size_t len  = enc_packet.len;
        if (len) {
            void *src_ptr = NULL;
            struct valloc_mb mb;
            memset(&mb, 0, sizeof(mb));
            mb.mpi_buf_id = enc_packet.u64priv_data;
            mb.struct_size = sizeof(mb);
            ioctl(p->mem_fd, VALLOC_IOCTL_MB_GET_FD, &mb);
            mpp_log("jpeg mb->mpi_buf_id %d", mb.mpi_buf_id);
            mpp_log("jpeg buf_size %d, info.fd %d enc_packet.len %d", enc_packet.buf_size, mb.dma_buf_fd, enc_packet.len);
            src_ptr = mmap(NULL, enc_packet.buf_size, PROT_READ, MAP_SHARED, mb.dma_buf_fd, 0);
            snprintf(name, name_len, "/sdcard/jpegen_out_%d_frm%d.jpeg", pid, p->jpeg_cnt++);
            mpp_log("get a jpeg stream size %d file %s", len, name);
            save_to_file(name, src_ptr, len);

            if (src_ptr)
                munmap(src_ptr, enc_packet.buf_size);
            close(mb.dma_buf_fd);
        }
        jpeg_mpi->encode_release_packet(jpeg_ctx, &packet);
    }
    return ret;
}

MPP_RET test_mpp_run(MpiEncTestData *p)
{
    MPP_RET ret = MPP_OK;
    MppApi *mpi;
    MppCtx ctx;
    RK_U32 cap_num = 0;
    RK_U64  pts = 0;
    if (NULL == p)
        return MPP_ERR_NULL_PTR;

    mpi = p->mpi;
    ctx = p->ctx;

    while (!p->pkt_eos) {
        MppFrame frame = NULL;
        MppPacket packet = NULL;
        struct venc_packet enc_packet;
        memset(&enc_packet, 0, sizeof(enc_packet));
        void *buf = mpp_buffer_get_ptr(p->frm_buf);
        RK_S32 cam_frm_idx = -1;
        MppBuffer cam_buf = NULL;
        RK_U32 eoi = 1;
        RK_U32 jpeg_snap = 0;
        packet = &enc_packet;

        if (p->fp_input) {
            ret = read_image(buf, p->fp_input, p->width, p->height,
                             p->hor_stride, p->ver_stride, p->fmt);
            if (ret == MPP_NOK || feof(p->fp_input)) {
                p->frm_eos = 1;

                if (p->num_frames < 0 || p->frame_count < p->num_frames) {
                    clearerr(p->fp_input);
                    rewind(p->fp_input);
                    p->frm_eos = 0;
                    mpp_log("%p loop times %d\n", ctx, ++p->loop_times);
                    continue;
                }
                mpp_log("%p found last frame. feof %d\n", ctx, feof(p->fp_input));
            } else if (ret == MPP_ERR_VALUE)
                goto RET;
        } else {
            if (p->cam_ctx == NULL) {
                ret = fill_image(buf, p->width, p->height, p->hor_stride,
                                 p->ver_stride, p->fmt, p->frame_count);
                if (ret)
                    goto RET;
            } else {
                cam_frm_idx = camera_source_get_frame(p->cam_ctx);
                mpp_assert(cam_frm_idx >= 0);

                /* skip unstable frames */
                if (cap_num++ < 50) {
                    camera_source_put_frame(p->cam_ctx, cam_frm_idx);
                    continue;
                }

                cam_buf = camera_frame_to_buf(p->cam_ctx, cam_frm_idx);
                mpp_assert(cam_buf);
            }
        }

        ret = mpp_frame_init(&frame);
        if (ret) {
            mpp_err_f("mpp_frame_init failed\n");
            goto RET;
        }

        mpp_frame_set_width(frame, p->width);
        mpp_frame_set_height(frame, p->height);
        mpp_frame_set_hor_stride(frame, p->hor_stride);
        mpp_frame_set_ver_stride(frame, p->ver_stride);
        mpp_frame_set_fmt(frame, p->fmt);

        mpp_frame_set_pts(frame, pts);
        mpp_frame_set_eos(frame, p->frm_eos);
        mpp_frame_set_jpege_chan_id(frame, -1);
        pts += 33000;
        if (!(p->frame_count % 10) && p->jpeg_combo_en) {
            jpeg_snap = 1;
            mpp_frame_set_jpege_chan_id(frame, p->jpeg_combo_id);
        }

        if (p->fp_input && feof(p->fp_input))
            mpp_frame_set_buffer(frame, NULL);
        else if (cam_buf)
            mpp_frame_set_buffer(frame, cam_buf);
        else
            mpp_frame_set_buffer(frame, p->frm_buf);

        if (p->osd_enable || p->user_data_enable || p->roi_enable) {
            if (p->user_data_enable) {
                MppEncUserData user_data;
                char *str = "this is user data\n";

                if ((p->frame_count & 10) == 0) {
                    user_data.pdata = str;
                    user_data.len = strlen(str) + 1;
                    ret = mpi->control(ctx, MPP_ENC_INSRT_USERDATA, &user_data);
                }

            }

            if (p->osd_enable) {
                p->osd_data_v3.change = 1;

                mpi_enc_gen_osd_data3(&p->osd_data_v3, &p->osd_buf, p->width,
                                      p->height, (RK_U32)p->frame_count);
                ret = mpi->control(ctx, MPP_ENC_SET_OSD_DATA_CFG, &p->osd_data_v3);
            }

            if (p->roi_enable) {
                MppEncROIRegion *region = p->roi_region;

                /* calculated in pixels */
                region->x = 304;
                region->y = 480;
                region->w = 1344;
                region->h = 600;
                region->intra = 0;              /* flag of forced intra macroblock */
                region->quality = 24;           /* qp of macroblock */
                region->abs_qp_en = 1;
                region->area_map_en = 1;
                region->qp_area_idx = 0;

                region++;
                region->x = region->y = 16;
                region->w = region->h = 64;    /* 16-pixel aligned is better */
                region->intra = 1;              /* flag of forced intra macroblock */
                region->quality = 10;           /* qp of macroblock */
                region->abs_qp_en = 1;
                region->area_map_en = 1;
                region->qp_area_idx = 1;

                p->roi_cfg.number = 2;
                p->roi_cfg.change = 1;

                memcpy(p->roi_cfg.regions, p->roi_region, p->roi_cfg.number * sizeof(MppEncROIRegion));

                ret = mpi->control(ctx, MPP_ENC_SET_ROI_CFG, &p->roi_cfg);

            }
        }

        /*
         * NOTE: in non-block mode the frame can be resent.
         * The default input timeout mode is block.
         *
         * User should release the input frame to meet the requirements of
         * resource creator must be the resource destroyer.
         */
        ret = mpi->encode_put_frame(ctx, frame);
        if (ret) {
            mpp_err("mpp encode put frame failed\n");
            mpp_frame_deinit(&frame);
            goto RET;
        }
        mpp_frame_deinit(&frame);

        do {
            ret = mpi->encode_get_packet(ctx, &packet);
            if (ret) {
                goto RET;
            }
            if (enc_packet.len) {
                // write packet to file here
                void *src_ptr = NULL;
                size_t len  = enc_packet.len;
                struct valloc_mb mb;
                memset(&mb, 0, sizeof(mb));
                mb.struct_size = sizeof(mb);
                mb.mpi_buf_id = enc_packet.u64priv_data;
                ioctl(p->mem_fd, VALLOC_IOCTL_MB_GET_FD, &mb);
                mpp_log("mb->mpi_buf_id %d", mb.mpi_buf_id);
                mpp_log("buf_size %d, info.fd %d enc_packet.len %d", enc_packet.buf_size, mb.dma_buf_fd, enc_packet.len);
                src_ptr = mmap(NULL, enc_packet.buf_size, PROT_READ, MAP_SHARED, mb.dma_buf_fd, 0);
                mpp_log("src_ptr %p enc_packet.offset %d", src_ptr, enc_packet.offset);
                p->pkt_eos = 0;

                if (p->fp_output && src_ptr) {
                    fwrite(src_ptr + enc_packet.offset, 1, len, p->fp_output);
                    fflush(p->fp_output);
                }

                if (src_ptr)
                    munmap(src_ptr, enc_packet.buf_size);
                close(mb.dma_buf_fd);
                p->stream_size += len;
                p->frame_count ++;
                eoi = 1;

                if (p->pkt_eos) {
                    mpp_log("%p found last packet\n", ctx);
                    mpp_assert(p->frm_eos);
                }

                ret = mpi->encode_release_packet(ctx, &packet);
            }
        } while (!eoi);

        if (p->jpeg_combo_en && jpeg_snap) {
            mpp_log("jpeg snap get packet");
            jpeg_comb_get_packet(p);
        }

        if (cam_frm_idx >= 0)
            camera_source_put_frame(p->cam_ctx, cam_frm_idx);

        if (p->num_frames > 0 && p->frame_count >= p->num_frames) {
            mpp_log("%p encode max %d frames", ctx, p->frame_count);
            break;
        }

        if (p->frm_eos && p->pkt_eos)
            break;
    }
RET:
    return ret;
}

int mpi_enc_create_jpegcomb(MpiEncTestData *p)
{
    MPP_RET ret = MPP_OK;
    vcodec_attr attr;
    memset(&attr, 0 , sizeof(attr));
    ret = mpp_create(&p->ctx_jpeg, &p->mpi_jpeg);
    if (ret) {
        mpp_err("mpp_create failed ret %d\n", ret);
        return ret;
    }


    mpp_log("%p mpi_enc_test encoder test start w %d h %d type %d\n",
            p->ctx, p->width, p->height, p->type);

    attr.chan_id = 6;
    p->jpeg_combo_id = attr.chan_id;
    attr.coding = MPP_VIDEO_CodingMJPEG;
    attr.type = MPP_CTX_ENC;

    ret = mpp_init_ext(p->ctx_jpeg, &attr);

    if (ret) {
        mpp_err("mpp_init failed ret %d\n", ret);
        return ret;
    }
    ret = mpp_enc_cfg_init(&p->cfg_jpeg);
    if (ret) {
        mpp_err_f("mpp_enc_cfg_init failed ret %d\n", ret);
        return ret;
    }

    ret = test_mpp_enc_cfg_setup(p);
    if (ret) {
        mpp_err_f("test mpp setup failed ret %d\n", ret);
        return ret;
    }
    return ret;

}

int mpi_enc_test(MpiEncTestArgs *cmd)
{
    MPP_RET ret = MPP_OK;
    MpiEncTestData *p = NULL;
    vcodec_attr attr;
    memset(&attr, 0 , sizeof(attr));

    mpp_log("mpi_enc_test start\n");

    ret = test_ctx_init(&p, cmd);

    mpp_env_get_u32("combo_en", &p->jpeg_combo_en, 0);
    if (ret) {
        mpp_err_f("test data init failed ret %d\n", ret);
        goto MPP_TEST_OUT;
    }
    ret = mpp_buffer_get(p->buf_grp, &p->frm_buf, p->frame_size + p->header_size);
    if (ret) {
        mpp_err_f("failed to get buffer for input frame ret %d\n", ret);
        goto MPP_TEST_OUT;
    }

    ret = mpp_buffer_get(p->buf_grp, &p->pkt_buf, p->frame_size);
    if (ret) {
        mpp_err_f("failed to get buffer for output packet ret %d\n", ret);
        goto MPP_TEST_OUT;
    }

    // chl0
    ret = mpp_create(&p->ctx, &p->mpi);
    if (ret) {
        mpp_err("mpp_create failed ret %d\n", ret);
        goto MPP_TEST_OUT;
    }

    mpp_log("%p mpi_enc_test encoder test start w %d h %d type %d\n",
            p->ctx, p->width, p->height, p->type);

    /* ret = p->mpi->control(p->ctx, MPP_SET_OUTPUT_TIMEOUT, &timeout);
     if (MPP_OK != ret) {
         mpp_err("mpi control set output timeout %d ret %d\n", timeout, ret);
         goto MPP_TEST_OUT;
     }*/

    attr.chan_id = p->chan_id;
    attr.coding = p->type;
    attr.type = MPP_CTX_ENC;

    ret = mpp_init_ext(p->ctx, &attr);

    if (ret) {
        mpp_err("mpp_init failed ret %d\n", ret);
        goto MPP_TEST_OUT;
    }

    ret = mpp_enc_cfg_init(&p->cfg);
    if (ret) {
        mpp_err_f("mpp_enc_cfg_init failed ret %d\n", ret);
        goto MPP_TEST_OUT;
    }

    ret = test_mpp_enc_cfg_setup(p);
    if (ret) {
        mpp_err_f("test mpp setup failed ret %d\n", ret);
        goto MPP_TEST_OUT;
    }

    //ch1
    if (p->jpeg_combo_en) {
        ret = mpi_enc_create_jpegcomb(p);
        if (ret) {
            mpp_err_f("mpi_enc_create_jpegcomb ret %d\n", ret);
            goto MPP_TEST_OUT;
        }
    }
    ret = test_mpp_run(p);
    if (ret) {
        mpp_err_f("test mpp run failed ret %d\n", ret);
        goto MPP_TEST_OUT;
    }

    ret = p->mpi->reset(p->ctx);
    if (ret) {
        mpp_err("mpi->reset failed\n");
        goto MPP_TEST_OUT;
    }

    if (p->ctx_jpeg) {
        ret = p->mpi->reset(p->ctx_jpeg);
        if (ret) {
            mpp_err("mpi->reset failed\n");
            goto MPP_TEST_OUT;
        }
    }

MPP_TEST_OUT:
    if (MPP_OK == ret)
        mpp_log("%p mpi_enc_test success total frame %d bps %lld\n",
                p->ctx, p->frame_count,
                (RK_U64)((p->stream_size * 8 * (p->fps_out_num / p->fps_out_den)) / p->frame_count));
    else
        mpp_err("%p mpi_enc_test failed ret %d\n", p->ctx, ret);

    if (p->ctx) {
        mpp_destroy(p->ctx);
        p->ctx = NULL;
    }

    if (p->cfg) {
        mpp_enc_cfg_deinit(p->cfg);
        p->cfg = NULL;
    }

    if (p->ctx_jpeg) {
        mpp_destroy(p->ctx_jpeg);
        p->ctx_jpeg = NULL;
    }

    if (p->cfg_jpeg) {
        mpp_enc_cfg_deinit(p->cfg_jpeg);
        p->cfg_jpeg = NULL;
    }

    if (p->frm_buf) {
        mpp_buffer_put(p->frm_buf);
        p->frm_buf = NULL;
    }

    if (p->pkt_buf) {
        mpp_buffer_put(p->pkt_buf);
        p->pkt_buf = NULL;
    }

    if (p->osd_buf) {
        mpp_buffer_put(p->osd_buf);
        p->osd_buf = NULL;
    }
    test_ctx_deinit(&p);

    return ret;
}

int main(int argc, char **argv)
{
    RK_S32 ret = MPP_NOK;
    MpiEncTestArgs* cmd = mpi_enc_test_cmd_get();
    memset((void*)cmd, 0, sizeof(*cmd));

    // parse the cmd option
    if (argc > 1)
        ret = mpi_enc_test_cmd_update_by_args(cmd, argc, argv);

    if (ret) {
        mpi_enc_test_help();
        goto DONE;
    }

    mpi_enc_test_cmd_show_opt(cmd);

    ret = mpi_enc_test(cmd);

DONE:
    mpi_enc_test_cmd_put(cmd);

    return ret;
}

