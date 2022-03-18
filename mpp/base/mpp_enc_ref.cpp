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

#define MODULE_TAG "mpp_enc_ref"

#include <string.h>

#include "mpp_env.h"
#include "mpp_log.h"
#include "mpp_mem.h"
#include "mpp_time.h"

#include "mpp_rc_defs.h"
#include "mpp_enc_ref.h"

#define setup_mpp_enc_ref_cfg(ref) \
    ((MppEncRefCfgImpl*)ref)->name = module_name;

static const char *module_name = MODULE_TAG;

MPP_RET _check_is_mpp_enc_ref_cfg(const char *func, void *ref)
{
    (void)ref;
    (void)func;
    return MPP_OK;
}

MPP_RET mpp_enc_ref_cfg_init(MppEncRefCfg *ref)
{


    (void)ref;
    return MPP_OK;
}

MPP_RET mpp_enc_ref_cfg_deinit(MppEncRefCfg *ref)
{

    (void)ref;
    return MPP_OK;
}

MPP_RET mpp_enc_ref_cfg_reset(MppEncRefCfg ref)
{


    (void)ref;
    return MPP_OK;
}

MPP_RET mpp_enc_ref_cfg_set_cfg_cnt(MppEncRefCfg ref, RK_S32 lt_cnt, RK_S32 st_cnt)
{
    (void)ref;
    (void)lt_cnt;
    (void)st_cnt;

    return MPP_OK;
}

MPP_RET mpp_enc_ref_cfg_add_lt_cfg(MppEncRefCfg ref, RK_S32 cnt, MppEncRefLtFrmCfg *frm)
{
    (void)ref;
    (void)cnt;
    (void)frm;
    return MPP_OK;
}

MPP_RET mpp_enc_ref_cfg_add_st_cfg(MppEncRefCfg ref, RK_S32 cnt, MppEncRefStFrmCfg *frm)
{
    (void)ref;
    (void)cnt;
    (void)frm;
    return MPP_OK;
}

MPP_RET mpp_enc_ref_cfg_check(MppEncRefCfg ref)
{

    (void)ref;
    return MPP_OK;
}

MPP_RET mpp_enc_ref_cfg_set_keep_cpb(MppEncRefCfg ref, RK_S32 keep)
{

    (void)ref;
    (void)keep;
    return MPP_OK;
}

MPP_RET mpp_enc_ref_cfg_show(MppEncRefCfg ref)
{


    (void)ref;
    return MPP_OK;
}

MPP_RET mpp_enc_ref_cfg_copy(MppEncRefCfg dst, MppEncRefCfg src)
{

    (void)dst;
    (void)src;

    return MPP_OK;
}

MppEncCpbInfo *mpp_enc_ref_cfg_get_cpb_info(MppEncRefCfg ref)
{
    (void)ref;
    return NULL;
}

static MppEncRefStFrmCfg default_st_ref_cfg = {
    .is_non_ref         = 0,
    .temporal_id        = 0,
    .ref_mode           = REF_TO_PREV_REF_FRM,
    .ref_arg            = 0,
    .repeat             = 0,
};

static const MppEncRefCfgImpl default_ref_cfg = {
    .name               = module_name,
    .ready              = 1,
    .debug              = 0,
    .keep_cpb           = 0,
    .max_lt_cfg         = 0,
    .max_st_cfg         = 1,
    .lt_cfg_cnt         = 0,
    .st_cfg_cnt         = 1,
    .lt_cfg             = NULL,
    .st_cfg             = &default_st_ref_cfg,
    .cpb_info           = { 1, 0, 1, 0, 0, 0, 0 },
};

MppEncRefCfg mpp_enc_ref_default(void)
{
    return (MppEncRefCfg)&default_ref_cfg;
}
