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

#ifndef __MPP_CHAN_H__
#define __MPP_CHAN_H__

#include "rk_type.h"

#ifdef __cplusplus
extern "C" {
#endif

RK_S32 mpp_set_chan(void *ctx, MppCtxType type);
void mpp_free_chan(void *ctx, MppCtxType type);

#ifdef __cplusplus
}
#endif

#endif /*__MPP_CHAN_H__*/
