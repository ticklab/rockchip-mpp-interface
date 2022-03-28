#ifndef __OSD_TEST_H__
#define __OSD_TEST_H__

#include <stdio.h>

#include "mpp_log.h"
#include "mpp_frame.h"
#include "rk_venc_cmd.h"

#define SMPTE_BAR_CNT (8)

/**
 * @brief RKV Enc hardware color fmt definition
 * It is matched with *SrcFmt* at vep_hevc_v2 C Model.
 */
typedef enum RkEncColorFmt_t {
    HW_COLOR_FMT_ARGB8888 = 0,  //[31:0] : ARGB
    HW_COLOR_FMT_RGB888,        //[23:0] : BGR
    HW_COLOR_FMT_RGB565,        //[15:0] : BGR
    HW_COLOR_FMT_ARGB1555,      //[15:0] : ARGB
    HW_COLOR_FMT_YUV422SP,
    HW_COLOR_FMT_YUV422P,
    HW_COLOR_FMT_YUV420SP,
    HW_COLOR_FMT_YUV420P,
    HW_COLOR_FMT_YUYV,
    HW_COLOR_FMT_UYVY,
    HW_COLOR_FMT_YUV400,
    HW_COLOR_FMT_AYUV2BPP,
    HW_COLOR_FMT_YUV444SP,
    HW_COLOR_FMT_YUV444P,
    HW_COLOR_FMT_ARGB4444,      //[15:0] : ARGB
    HW_COLOR_FMT_ARGB2BPP,
    HW_COLOR_FMT_BUT
} RkEncColorFmt;

/**
 * @brief Color Range
 * Full Range -- default range, [0, 255], aka pc range, jpeg range
 * Limit Range -- aka tv range. For 8-bit RGB, it is [16,235].
 *                  For YCbCr, Y is [16, 235], Cb/Cr is [16, 240]
 *
 */
typedef enum ColorRange_t {
    FULL_RANGE = 0,
    LIMIT_RANGE = 1,
} ColorRange;

typedef enum RangeTransMode_t {
    FULL_TO_LIMIT = 0,
    LIMIT_TO_FULL = 1,
} RangeTransMode;

/**
 * @brief Clockwise rotation
 */
typedef enum RotationMode_t {
    ROTATE_0 = 0,
    ROTATE_90,
    ROTATE_180,
    ROTATE_270,
} RotationMode;

/**
 * @brief Mirror translation
 * For hardware preprocess, doing rotation before mirror translation.
 */
typedef enum MirrorMode_t {
    MIRROR_NONE = 0,
    MIRROR_X_AXIS = 1,
    MIRROR_Y_AXIS = 2,
} MirrorMode;

typedef enum DownScaleRatio_t {
    DOWN_NONE = 0,
    DOWN_HALF = 1,
    DOWN_QUARTER = 2,
} DownScaleRatio;

typedef enum OsdInverseSize_t {
    INVERSE_16x16 = 0,
    INVERSE_32x32,
    INVERSE_48x48,
    INVERSE_64x64
} OsdInverseSize;

/**
 * @brief Inverse color space selection
 * 0 -- Inverse at color space YUV
 * 1 -- Inverse at color space RGB
 */
typedef enum OsdInverseColorSpace_t {
    INVERSE_YUV = 0,
    INVERSE_RGB,
} OsdInverseColorSpace;

typedef enum OsdQPAdjustMode_t {
    QP_RELATIVE = 0,
    QP_ABSOLUTE,
} OsdQPAdjustMode;

typedef enum OsdAlphaSource_t {
    FROM_DDR = 0,
    FROM_LUT,
    FROM_REG
} OsdAlphaSource;

/**
 * @brief Format translation mode select
 * 0 -- average a 2x2 block
 * 1 -- drop,
 */
typedef enum DownscaleMode_t {
    AVERAGE,
    DROP
} DownsampleMode;

typedef enum EncoderMode_t {
    ENC_AVC,
    ENC_HEVC,
    ENC_JPEG
} EncoderMode;

#define MAX_REGION_CNT (8)
#define OSD3_TEST_CASE_CNT (31)
typedef struct OSD3_Test_Case_t {
    MppFrameFormat format[MAX_REGION_CNT];
    RK_U32 width[MAX_REGION_CNT];
    RK_U32 height[MAX_REGION_CNT];
    MppEncOSDData3 osd_data_v3;
    MppBuffer region_buf[MAX_REGION_CNT];
    MppBuffer inv_buf[MAX_REGION_CNT];
} Osd3TestCase;

MPP_RET gen_smpte_bar_argb(RK_U8 **dst, RK_U32 bar_width, RK_U32 bar_height);
MPP_RET translate_argb(RK_U8 *src, RK_U8 *dst, RK_U32 width, RK_U32 height,
                       RK_U32 fmt_idx, MppEncOSDRegion3 *cfg);
MPP_RET osd3_get_test_case(MppEncOSDData3 *osd_data, MppBuffer osd_buf[MAX_REGION_CNT],
                           MppBuffer inv_buf[MAX_REGION_CNT], RK_U8 *base_pattern,
                           RK_U32 region_width, RK_U32 region_height, RK_U32 case_idx);
#endif /* __OSD_TEST_H__ */