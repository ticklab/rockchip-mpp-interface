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

#define MODULE_TAG "mpp_vcodec"

#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "mpp_log.h"
#include "mpp_env.h"
#include "mpp_common.h"
#include "mpp_vcodec_clinet.h"

RK_S32 mpp_vcodec_open(void)
{
    RK_S32 fd = -1;
    fd = open("/dev/vcodec", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        mpp_err("open mpp_vcodec failed\n");
        return -1;
    }
    return fd;
}

MPP_RET mpp_vcodec_ioctl(RK_S32 fd, RK_U32 cmd, RK_U32 ctrl_cmd, RK_U32 size, void *param)
{
    vocdec_req req;
    memset(&req, 0, sizeof(req));
    req.cmd = cmd;
    req.ctrl_cmd = ctrl_cmd;
    req.size = size;
    req.data = REQ_DATA_PTR(param);
    return (RK_S32)ioctl(fd, VOCDEC_IOC_CFG, &req);
}

MPP_RET mpp_vcodec_close(RK_S32 fd)
{
    if (fd)
        close(fd);
    return MPP_OK;
}



