#define MODULE_TAG "OSD_TEST"

#include <ctype.h>
#include <string.h>

#include "osd_test.h"

#include "mpp_mem.h"
#include "mpp_log.h"
#include "mpp_lock.h"
#include "mpp_time.h"
#include "mpp_common.h"
#include "utils.h"

/**
 * @brief Generate horizontal SMPTE test pattern in ARGB inteleaved format.
 * Test pattern bar color:
 *  {255, 255, 255},    // White
 *  {254, 255, 0},      // Yelow
 *  {0, 254, 255},      // Cyan
 *  {255, 0, 0},        // Red
 *  {0, 255, 0},        // Green
 *  {0, 0, 255},        // Blue
 *  {191, 191, 191},    // 75% White
 *  {0, 0, 0,}          // Black
 *  TODO Add RGB to YUV translation
 *
 * @param dst buffer should be at the size of (bar_width * bar_height * 8 * 4)
 * @param bar_width each bar width
 * @param bar_heigt each bar height
 */
MPP_RET gen_smpte_bar_argb(RK_U8 **dst, RK_U32 bar_width, RK_U32 bar_height)
{
    MPP_RET ret = MPP_OK;
    RK_U32 i, j, k = 0;
    FILE *fp = NULL;
    RK_U8 smpte_bar[8][3] = {
        {255, 255, 255},    // White
        {254, 255, 0},      // Yelow
        {0, 254, 255},      // Cyan
        {255, 0, 0},        // Red
        {0, 255, 0},        // Green
        {0, 0, 255},        // Blue
        {191, 191, 191},    // 75% White
        {0, 0, 0,}          // Black
    };
    RK_U8 *base = malloc(bar_width * bar_height * SMPTE_BAR_CNT * 4);
    *dst = base;
    fp = fopen("/userdata/wind_ABGR8888.ABGR8888", "rb");
    if (!fp) {
        for (k = 0; k < SMPTE_BAR_CNT; k++) {
            for (j = 0; j < bar_height; j++) {
                for (i = 0; i < bar_width; i++) {
                    base[i * 4] = 0xff;
                    base[i * 4 + 1] = smpte_bar[k][0];
                    base[i * 4 + 2] = smpte_bar[k][1];
                    base[i * 4 + 3] = smpte_bar[k][2];
                }
                base += bar_width * 4;
            }
        }
    } else {
        fread(base, 1, 128 * 128 * 4, fp);
        fclose(fp);
    }

    return ret;
}

MPP_RET translate_argb(RK_U8 *src, RK_U8 *dst, RK_U32 width, RK_U32 height,
                       RK_U32 fmt_idx, MppEncOSDRegion3 *cfg)
{
    MPP_RET ret = MPP_OK;
    RK_U32 i = 0;
    RK_U32 j = 0;
    RK_U16 *tmp_u16 = NULL;

    RK_U8 tmp_r = 0;
    RK_U8 tmp_g = 0;
    RK_U8 tmp_b = 0;

    RK_S16 tmp_y = 0;

    RK_S16 y_r = 54;
    RK_S16 y_g = 183;
    RK_S16 y_b = 18;
    RK_S16 y_o = 0;

    RK_S16 u_r = -29;
    RK_S16 u_g = -99;
    RK_S16 u_b = 128;
    RK_S16 u_o = 128;

    RK_S16 v_r = 128;
    RK_S16 v_g = -116;
    RK_S16 v_b = -12;
    RK_S16 v_o = 128;

    if (fmt_idx == 0) {
        // HW_COLOR_FMT_ARGB8888;
        cfg->fmt = MPP_FMT_ARGB8888;
        cfg->alpha_cfg.alpha_swap = 1;
        cfg->rbuv_swap = 1;
        cfg->stride = width * 4;
        memcpy(dst, src, width * height * 4);
    } else if (fmt_idx == 1) {
        // HW_COLOR_FMT_ARGB8888;
        cfg->fmt = MPP_FMT_ARGB8888;
        cfg->alpha_cfg.alpha_swap = 1;
        cfg->rbuv_swap = 0;
        cfg->stride = width * 4;
        for (j = 0; j < height; j++) {
            for (i = 0; i < width; i++) {
                dst[j * width * 4 + i * 4 + 0] = src[j * width * 4 + i * 4 + 0];
                dst[j * width * 4 + i * 4 + 1] = src[j * width * 4 + i * 4 + 3];
                dst[j * width * 4 + i * 4 + 2] = src[j * width * 4 + i * 4 + 2];
                dst[j * width * 4 + i * 4 + 3] = src[j * width * 4 + i * 4 + 1];
            }
        }
    } else if (fmt_idx == 2) {
        // HW_COLOR_FMT_ARGB8888;
        cfg->fmt = MPP_FMT_ARGB8888;
        cfg->alpha_cfg.alpha_swap = 0;
        cfg->rbuv_swap = 0;
        cfg->stride = width * 4;
        for (j = 0; j < height; j++) {
            for (i = 0; i < width; i++) {
                dst[j * width * 4 + i * 4 + 0] = src[j * width * 4 + i * 4 + 3];
                dst[j * width * 4 + i * 4 + 1] = src[j * width * 4 + i * 4 + 2];
                dst[j * width * 4 + i * 4 + 2] = src[j * width * 4 + i * 4 + 1];
                dst[j * width * 4 + i * 4 + 3] = src[j * width * 4 + i * 4 + 0];
            }
        }
    } else if (fmt_idx == 3) {
        // HW_COLOR_FMT_ARGB8888;
        cfg->fmt = MPP_FMT_ARGB8888;
        cfg->alpha_cfg.alpha_swap = 0;
        cfg->rbuv_swap = 1;
        cfg->stride = width * 4;
        for (j = 0; j < height; j++) {
            for (i = 0; i < width; i++) {
                dst[j * width * 4 + i * 4 + 0] = src[j * width * 4 + i * 4 + 1];
                dst[j * width * 4 + i * 4 + 1] = src[j * width * 4 + i * 4 + 2];
                dst[j * width * 4 + i * 4 + 2] = src[j * width * 4 + i * 4 + 3];
                dst[j * width * 4 + i * 4 + 3] = src[j * width * 4 + i * 4 + 0];
            }
        }
    } else if (fmt_idx == 4) {
        // HW_COLOR_FMT_ARGB1555;
        cfg->fmt = MPP_FMT_ARGB1555;
        cfg->alpha_cfg.alpha_swap = 0;
        cfg->rbuv_swap = 0;
        cfg->stride = width * 2;
        tmp_u16 = (RK_U16 *)dst;
        for (j = 0; j < height; j++) {
            for (i = 0; i < width; i++) {
                tmp_r = src[j * width * 4 + i * 4 + 1];
                tmp_g = src[j * width * 4 + i * 4 + 2];
                tmp_b = src[j * width * 4 + i * 4 + 3];
                tmp_u16[j * width + i] = ((tmp_r >> 3) << 10) +
                                         ((tmp_g >> 3) << 5) +
                                         ((tmp_b >> 3) | 0x8000);
            }
        }
    } else if (fmt_idx == 5) {
        // HW_COLOR_FMT_ARGB1555;
        cfg->fmt = MPP_FMT_ARGB1555;
        cfg->alpha_cfg.alpha_swap = 0;
        cfg->rbuv_swap = 1;
        cfg->stride = width * 2;
        tmp_u16 = (RK_U16 *)dst;
        for (j = 0; j < height; j++) {
            for (i = 0; i < width; i++) {
                tmp_r = src[j * width * 4 + i * 4 + 1];
                tmp_g = src[j * width * 4 + i * 4 + 2];
                tmp_b = src[j * width * 4 + i * 4 + 3];
                tmp_u16[j * width + i] = ((tmp_b >> 3) << 10) +
                                         ((tmp_g >> 3) << 5) +
                                         ((tmp_r >> 3) | 0x8000);
            }
        }
    } else if (fmt_idx == 6) {
        // HW_COLOR_FMT_ARGB1555;
        cfg->fmt = MPP_FMT_ARGB1555;
        cfg->alpha_cfg.alpha_swap = 1;
        cfg->rbuv_swap = 0;
        cfg->stride = width * 2;
        tmp_u16 = (RK_U16 *)dst;
        for (j = 0; j < height; j++) {
            for (i = 0; i < width; i++) {
                tmp_r = src[j * width * 4 + i * 4 + 1];
                tmp_g = src[j * width * 4 + i * 4 + 2];
                tmp_b = src[j * width * 4 + i * 4 + 3];
                tmp_u16[j * width + i] = ((tmp_r >> 3) << 11) +
                                         ((tmp_g >> 3) << 6) +
                                         ((tmp_b >> 3) << 1) + 1;
            }
        }
    } else if (fmt_idx == 7) {
        // HW_COLOR_FMT_ARGB1555;
        cfg->fmt = MPP_FMT_ARGB1555;
        cfg->alpha_cfg.alpha_swap = 1;
        cfg->rbuv_swap = 1;
        cfg->stride = width * 2;
        tmp_u16 = (RK_U16 *)dst;
        for (j = 0; j < height; j++) {
            for (i = 0; i < width; i++) {
                tmp_r = src[j * width * 4 + i * 4 + 1];
                tmp_g = src[j * width * 4 + i * 4 + 2];
                tmp_b = src[j * width * 4 + i * 4 + 3];
                tmp_u16[j * width + i] = ((tmp_b >> 3) << 11) +
                                         ((tmp_g >> 3) << 6) +
                                         ((tmp_r >> 3) << 1) + 1;
            }
        }
    } else if (fmt_idx == 8) {
        // HW_COLOR_FMT_ARGB4444;
        cfg->fmt = MPP_FMT_ARGB4444;
        cfg->alpha_cfg.alpha_swap = 0;
        cfg->rbuv_swap = 0;
        cfg->stride = width * 2;
        tmp_u16 = (RK_U16 *)dst;
        for (j = 0; j < height; j++) {
            for (i = 0; i < width; i++) {
                tmp_r = src[j * width * 4 + i * 4 + 1];
                tmp_g = src[j * width * 4 + i * 4 + 2];
                tmp_b = src[j * width * 4 + i * 4 + 3];
                tmp_u16[j * width + i] = ((tmp_r >> 4) << 8) +
                                         ((tmp_g >> 4) << 4) +
                                         ((tmp_b >> 4) | 0xf000);
            }
        }
    } else if (fmt_idx == 9) {
        // HW_COLOR_FMT_ARGB4444;
        cfg->fmt = MPP_FMT_ARGB4444;
        cfg->alpha_cfg.alpha_swap = 0;
        cfg->rbuv_swap = 1;
        cfg->stride = width * 2;
        tmp_u16 = (RK_U16 *)dst;
        for (j = 0; j < height; j++) {
            for (i = 0; i < width; i++) {
                tmp_r = src[j * width * 4 + i * 4 + 1];
                tmp_g = src[j * width * 4 + i * 4 + 2];
                tmp_b = src[j * width * 4 + i * 4 + 3];
                tmp_u16[j * width + i] = ((tmp_b >> 4) << 8) +
                                         ((tmp_g >> 4) << 4) +
                                         ((tmp_r >> 4) | 0xf000);
            }
        }
    } else if (fmt_idx == 10) {
        // HW_COLOR_FMT_ARGB4444;
        cfg->fmt = MPP_FMT_ARGB4444;
        cfg->alpha_cfg.alpha_swap = 1;
        cfg->rbuv_swap = 0;
        cfg->stride = width * 2;
        tmp_u16 = (RK_U16 *)dst;
        for (j = 0; j < height; j++) {
            for (i = 0; i < width; i++) {
                tmp_r = src[j * width * 4 + i * 4 + 1];
                tmp_g = src[j * width * 4 + i * 4 + 2];
                tmp_b = src[j * width * 4 + i * 4 + 3];
                tmp_u16[j * width + i] = ((tmp_r >> 4) << 12) +
                                         ((tmp_g >> 4) << 8) +
                                         ((tmp_b >> 4) << 4) + 0x0f;
            }
        }
    } else if (fmt_idx == 11) {
        // HW_COLOR_FMT_ARGB4444;
        cfg->fmt = MPP_FMT_ARGB4444;
        cfg->alpha_cfg.alpha_swap = 1;
        cfg->rbuv_swap = 1;
        cfg->stride = width * 2;
        tmp_u16 = (RK_U16 *)dst;
        for (j = 0; j < height; j++) {
            for (i = 0; i < width; i++) {
                tmp_r = src[j * width * 4 + i * 4 + 1];
                tmp_g = src[j * width * 4 + i * 4 + 2];
                tmp_b = src[j * width * 4 + i * 4 + 3];
                tmp_u16[j * width + i] = ((tmp_b >> 4) << 12) +
                                         ((tmp_g >> 4) << 8) +
                                         ((tmp_r >> 4) << 4) + 0x0f;
            }
        }
    } else if (fmt_idx == 12) {
        // HW_COLOR_FMT_AYUV2BPP;
        cfg->fmt = MPP_FMT_AYUV2BPP;
        cfg->rbuv_swap = 0;
        cfg->alpha_cfg.alpha_swap = 0;
        cfg->stride = width / 4;
        for (j = 0; j < height; j++) {
            for (i = 0; i < width; i++) {
                tmp_r = src[j * width * 4 + i * 4 + 1];
                tmp_g = src[j * width * 4 + i * 4 + 2];
                tmp_b = src[j * width * 4 + i * 4 + 3];

                tmp_y = ((y_r * tmp_r + y_g * tmp_g + y_b * tmp_b + 128) >> 8) + y_o;
                tmp_y = (tmp_y > 16) ? 1 : 0;
                dst[j * width / 4 + i / 4] |= (1 << 1 | tmp_y) << ((3 - (i % 4)) * 2);
            }
        }
    } else if (fmt_idx == 13) {
        // HW_COLOR_FMT_AYUV2BPP;
        cfg->fmt = MPP_FMT_AYUV2BPP;
        cfg->rbuv_swap = 0;
        cfg->alpha_cfg.alpha_swap = 1;
        cfg->stride = width / 4;
        for (j = 0; j < height; j++) {
            for (i = 0; i < width; i++) {
                tmp_r = src[j * width * 4 + i * 4 + 1];
                tmp_g = src[j * width * 4 + i * 4 + 2];
                tmp_b = src[j * width * 4 + i * 4 + 3];

                tmp_y = ((y_r * tmp_r + y_g * tmp_g + y_b * tmp_b + 128) >> 8) + y_o;
                tmp_y = (tmp_y > 16) ? 1 : 0;
                dst[j * width / 4 + i / 4] |= (1 | tmp_y << 1) << ((3 - (i % 4)) * 2);
            }
        }
    }

    return ret;
}

static RK_U32 get_frame_size_by_format(MppFrameFormat fmt, RK_U32 width, RK_U32 height)
{
    switch (fmt) {
    case MPP_FMT_ARGB8888:
    case MPP_FMT_ABGR8888:
    case MPP_FMT_RGBA8888:
    case MPP_FMT_BGRA8888:
        return width * height * 4;
    case MPP_FMT_RGB888:
    case MPP_FMT_BGR888:
        return width * height * 3;
    case MPP_FMT_BGR565:
    case MPP_FMT_RGB565:
    case MPP_FMT_RGB444:
    case MPP_FMT_BGR444:
    case MPP_FMT_BGR555:
    case MPP_FMT_RGB555:
    case MPP_FMT_ARGB1555:
    case MPP_FMT_ARGB4444:
        return width * height * 2;
    case MPP_FMT_YUV444P:
    case MPP_FMT_YUV444SP:
        return width * height * 3;
    case MPP_FMT_YUV422SP:
    case MPP_FMT_YUV422SP_VU:
    case MPP_FMT_YUV422P:
    case MPP_FMT_YUV422_YVYU:
    case MPP_FMT_YUV422_YUYV:
    case MPP_FMT_YUV422_UYVY:
    case MPP_FMT_YUV422_VYUY:
        return width * height * 2;
    case MPP_FMT_YUV400:
        return width * height;
    case MPP_FMT_AYUV2BPP:
        return width * height / 4;
    default:
        return 0;
    }
}

MPP_RET osd3_get_test_case(MppEncOSDData3 *osd_data, MppBuffer osd_buf[MAX_REGION_CNT],
                           MppBuffer inv_buf[MAX_REGION_CNT], RK_U8 *base_pattern,
                           RK_U32 region_width, RK_U32 region_height, RK_U32 case_idx)
{
    MPP_RET ret = MPP_OK;
    RK_U32 buffer_size = 0;
    RK_U8 *dst_ptr =  NULL;
    MppEncOSDRegion3 *region = NULL;
    RK_U32 fmt_idx = 0;
    RK_U32 inv_blk_width = 0;
    RK_U32 i = 0;
    RK_U8 *inv_ptr = NULL;
    RK_U32 inv_stride = 0;
    RK_U32 inv_data_w = 0;
    RK_U32 inv_data_h = 0;
    MppFrameFormat osd_test_fmts[14] = { MPP_FMT_ARGB8888, MPP_FMT_ABGR8888,
                                         MPP_FMT_BGRA8888, MPP_FMT_RGBA8888,
                                         MPP_FMT_ARGB1555, MPP_FMT_ARGB1555,
                                         MPP_FMT_ARGB1555, MPP_FMT_ARGB1555,
                                         MPP_FMT_ARGB4444, MPP_FMT_ARGB4444,
                                         MPP_FMT_ARGB4444, MPP_FMT_ARGB4444,
                                         MPP_FMT_AYUV2BPP, MPP_FMT_AYUV2BPP
                                       };
    RK_U8 fmt_str[14][9] = {"argb8888", "rgba8888", "bgra8888", "abgr8888",
                            "argb1555", "abgr1555", "rgba5551", "bgra5551",
                            "argb4444", "abgr4444", "rgba4444", "bgra4444",
                            "ayuv2bpp", "yuva2bpp"
                           };

    if (!osd_data)
        return MPP_ERR_NOMEM;

    // color format test
    region = &osd_data->region[0];
    memset(region, 0, sizeof(MppEncOSDRegion3));
    if (case_idx < 14) {                    // argbxxxx, alpha from DDR, ayuv2bpp, alpha from lut
        fmt_idx = case_idx;
        if (case_idx < 12) {
            region->alpha_cfg.fg_alpha_sel = FROM_DDR;
        } else {
            region->alpha_cfg.fg_alpha_sel = FROM_LUT;
            // For AYUV2BPP, should have lut configed
            region->lut[0] = 0x80; // v0
            region->lut[1] = 0x80; // u0
            region->lut[2] = 0; // y0
            region->lut[3] = 0x80;  // v1
            region->lut[4] = 0x80;  // u1
            region->lut[5] = 0xff;  // y1
            region->lut[6] = 0x80;  // a0
            region->lut[7] = 0xff;  // a1
        }
    } else if (case_idx == 14) {            // argb8888, alpha from reg
        fmt_idx = 0;
        region->alpha_cfg.fg_alpha_sel = FROM_REG;
    } else if (case_idx == 15) {            // argb1555, alpha from reg
        fmt_idx = 4;
        region->alpha_cfg.fg_alpha_sel = FROM_REG;
    } else if (case_idx == 16) {            // argb1555, alpha from lut
        fmt_idx = 4;
        region->alpha_cfg.fg_alpha_sel = FROM_LUT;
        // For AYUV2BPP, should have lut configed
        region->lut[0] = 0x80; // v0
        region->lut[1] = 0x80; // u0
        region->lut[2] = 0; // y0
        region->lut[3] = 0x80;  // v1
        region->lut[4] = 0x80;  // u1
        region->lut[5] = 0xff;  // y1
        region->lut[6] = 0x80;  // a0
        region->lut[7] = 0xff;  // a1
    } else if (case_idx == 17) {            // argb4444, alpha from reg
        fmt_idx = 8;
        region->alpha_cfg.fg_alpha_sel = FROM_REG;
    } else if (case_idx == 18) {            // ayuv2bpp, alpha from reg
        fmt_idx = 12;
        region->alpha_cfg.fg_alpha_sel = FROM_REG;
        // For AYUV2BPP, should have lut configed
        region->lut[0] = 0x80; // v0
        region->lut[1] = 0x80; // u0
        region->lut[2] = 0; // y0
        region->lut[3] = 0x80;  // v1
        region->lut[4] = 0x80;  // u1
        region->lut[5] = 0xff;  // y1
        region->lut[6] = 0x80;  // a0
        region->lut[7] = 0xff;  // a1
    } else if (case_idx == 19) {            // Downsample test, with discard UV
        fmt_idx = 0;
        region->alpha_cfg.fg_alpha_sel = FROM_DDR;
        region->ch_ds_mode = DROP;
    } else if (case_idx == 20) {            // Range Translation
        fmt_idx = 12;
        region->alpha_cfg.fg_alpha_sel = FROM_LUT;
        region->range_trns_sel = FULL_TO_LIMIT;
        region->range_trns_en = 1;

        region->lut[0] = 0x80; // v0
        region->lut[1] = 0x80; // u0
        region->lut[2] = 0; // y0
        region->lut[3] = 0x80;  // v1
        region->lut[4] = 0x80;  // u1
        region->lut[5] = 0xff;  // y1
        region->lut[6] = 0xff;  // a0
        region->lut[7] = 0xff;  // a1
    } else if (case_idx == 21) {
        fmt_idx = 12;
        region->alpha_cfg.fg_alpha_sel = FROM_LUT;
        region->range_trns_sel = LIMIT_TO_FULL;
        region->range_trns_en = 1;
        region->lut[0] = 0x80; // v0
        region->lut[1] = 0x80; // u0
        region->lut[2] = 0x10; // y0
        region->lut[3] = 0x80;  // v1
        region->lut[4] = 0x80;  // u1
        region->lut[5] = 0xeb;  // y1
        region->lut[6] = 0xff;  // a0
        region->lut[7] = 0xff;  // a1
    } else if (case_idx == 22) {
        fmt_idx = 0;
        region->alpha_cfg.fg_alpha_sel = FROM_DDR;
        region->range_trns_sel = FULL_TO_LIMIT;
        region->range_trns_en = 1;
    } else if (case_idx == 23) {
        fmt_idx = 0;
        region->alpha_cfg.fg_alpha_sel = FROM_DDR;
        region->range_trns_sel = LIMIT_TO_FULL;
        region->range_trns_en = 1;
    } else if (case_idx < 30) {
        fmt_idx = 0;
        region->alpha_cfg.fg_alpha_sel = FROM_DDR;

        if (case_idx == 24) {                       // inverse Y
            region->inv_cfg.yg_inv_en = 1;
            region->inv_cfg.uvrb_inv_en = 0;
            inv_blk_width = 16;
        } else if (case_idx == 25) {                // inverse UV
            region->inv_cfg.yg_inv_en = 0;
            region->inv_cfg.uvrb_inv_en = 1;
            inv_blk_width = 16;
        } else if (case_idx < 29) {                 // inverse Y and UV
            region->inv_cfg.yg_inv_en = 1;
            region->inv_cfg.uvrb_inv_en = 1;
            if (case_idx == 26) {                   // inverse Y and UV, block 16x16
                inv_blk_width = 16;
            } else if (case_idx == 27) {            // inverse Y and UV, block 32x32
                inv_blk_width = 32;
            } else if (case_idx == 28) {            // inverse Y and UV, block 64x64
                inv_blk_width = 64;
            }
        } else if (case_idx == 29) {                // invese Y, block 16x16, at 2BPP
            region->inv_cfg.yg_inv_en = 1;
            region->inv_cfg.uvrb_inv_en = 0;
            inv_blk_width = 16;
            fmt_idx = 12;
            region->alpha_cfg.fg_alpha_sel = FROM_LUT;
            region->lut[0] = 0x80; // v0
            region->lut[1] = 0x80; // u0
            region->lut[2] = 0; // y0
            region->lut[3] = 0x80;  // v1
            region->lut[4] = 0x80;  // u1
            region->lut[5] = 0xff;  // y1
            region->lut[6] = 0xff;  // a0
            region->lut[7] = 0xff;  // a1
        }

        region->inv_cfg.inv_sel = INVERSE_YUV;      // support inverse at YUV space only
        region->inv_cfg.uv_sw_inv_en = 0;       // not support
        inv_data_w = MPP_ALIGN(region_width / inv_blk_width, 8) / 8;
        inv_data_h = MPP_ALIGN(region_height / inv_blk_width, 8);
        inv_stride = inv_data_w;
        region->inv_cfg.inv_stride = inv_stride;
        region->inv_cfg.inv_size = inv_blk_width / 16 - 1;

        if (inv_buf[0]) {
            mpp_buffer_put(inv_buf[0]);
        }

        mpp_buffer_get(NULL, &inv_buf[0], MPP_ALIGN(inv_stride * inv_data_h, 16));
        region->inv_cfg.inv_buf.fd = mpp_buffer_get_fd(inv_buf[0]);
        inv_ptr = mpp_buffer_get_ptr(inv_buf[0]);
        for (i = 0; i < inv_data_h; i++) {
            inv_ptr[inv_stride * i] = (0x1 << (i % 8));
        }
    }

    if (osd_buf[0]) {
        mpp_buffer_put(osd_buf[0]);
    }

    buffer_size = get_frame_size_by_format(osd_test_fmts[fmt_idx], region_width, region_height);
    mpp_buffer_get(NULL, &osd_buf[0], MPP_ALIGN(buffer_size, 16));

    mpp_log_f("Color format test, test case %d, format %s, buffer_size %d", case_idx, fmt_str[fmt_idx], buffer_size);
    if (!osd_buf[0]) {
        return ret = MPP_ERR_NOMEM;
    }

    dst_ptr = mpp_buffer_get_ptr(osd_buf[0]);
    mpp_assert(dst_ptr);
    region->osd_buf.fd = mpp_buffer_get_fd(osd_buf[0]);
    ret = translate_argb(base_pattern, dst_ptr, region_width, region_height, fmt_idx, region);

    region->lt_x = 0;
    region->lt_y = 0;
    region->rb_x = region->lt_x + region_width - 1;
    region->rb_y = region->lt_y + region_height - 1;
    region->enable = 1;

    osd_data->num_region = 1;

    region->alpha_cfg.bg_alpha = 0xff;      // Useless, no need to configure
    region->alpha_cfg.fg_alpha = 0xff;

    region->qp_cfg.qp_adj_en = 1;
    region->qp_cfg.qp_adj_sel = QP_RELATIVE;
    region->qp_cfg.qp_min = 10;
    region->qp_cfg.qp_max = 51;
    region->qp_cfg.qp = -1;

    if (case_idx == 30) {
        region = &osd_data->region[1];
        memcpy(region, &osd_data->region[0], sizeof(MppEncOSDRegion3));
        region->lt_x = region_width - 16;
        region->lt_y = 16;
        region->rb_x = region->lt_x + region_width - 1;
        region->rb_y = region->lt_y + region_height - 1;

        region = &osd_data->region[2];
        memcpy(region, &osd_data->region[0], sizeof(MppEncOSDRegion3));
        region->lt_x = region_width * 2 - 32;
        region->lt_y = 32;
        region->rb_x = region->lt_x + region_width - 1;
        region->rb_y = region->lt_y + region_height - 1;
        region->alpha_cfg.fg_alpha = 0x80;
        region->alpha_cfg.fg_alpha_sel = FROM_REG;

        osd_data->num_region = 3;
    }

    return ret;
}
