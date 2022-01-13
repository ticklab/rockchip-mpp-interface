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

#define MODULE_TAG "mpp_chan"

#include "mpp_log.h"
#include "mpp_common.h"

#include "mpp_chan.h"

#define MAX_DEC_CHN_NUM 64
#define MAX_ENC_CHN_NUM 16

typedef struct ChanIdCtxMap_t {
    RK_S32 chan_id;
    void   *ctx;
    RK_U32 is_valid;
} ChanIdCtxMap;

class MppChanService
{
private:
    // avoid any unwanted function
    MppChanService();
    ~MppChanService() {};
    MppChanService(const MppChanService &);
    MppChanService &operator=(const MppChanService &);

    ChanIdCtxMap  enc_map[MAX_ENC_CHN_NUM];
    ChanIdCtxMap  dec_map[MAX_DEC_CHN_NUM];


public:
    static MppChanService *get() {
        static MppChanService instance;
        return &instance;
    }

    RK_S32 mpp_set_chan(void *ctx, MppCtxType type) {
        RK_U32 i = 0;
        ChanIdCtxMap *idmap = NULL;
        if (type == MPP_CTX_DEC) {
            for (i = 0; i < MAX_DEC_CHN_NUM; i++) {
                idmap = &dec_map[i];
                if (!idmap->is_valid) {
                    idmap->ctx = ctx;
                    idmap->is_valid = 1;
                    return idmap->chan_id;
                }
            }
        } else {
            for (i = 0; i < MAX_ENC_CHN_NUM; i++) {
                idmap = &enc_map[i];
                if (!idmap->is_valid) {
                    idmap->ctx = ctx;
                    idmap->is_valid = 1;
                    return idmap->chan_id;
                }
            }
        }
        return -1;
    };

    void mpp_free_chan(void *ctx, MppCtxType type) {
        RK_U32 i = 0;
        ChanIdCtxMap *idmap = NULL;
        if (type == MPP_CTX_DEC) {
            for (i = 0; i < MAX_DEC_CHN_NUM; i++) {
                idmap = &dec_map[i];
                if (idmap->ctx == ctx) {
                    idmap->is_valid = 0;
                    idmap->ctx = NULL;
                    return;
                }
            }
            mpp_log("ctx is no found in chan server");
        } else {
            for (i = 0; i < MAX_ENC_CHN_NUM; i++) {
                idmap = &enc_map[i];
                if (idmap->ctx == ctx) {
                    idmap->is_valid = 0;
                    idmap->ctx = NULL;
                    return;
                }
            }
            mpp_log("ctx is no found in chan server");
        };

    }

};

MppChanService::MppChanService()
{
    RK_U32 i;
    ChanIdCtxMap *idmap = NULL;
    for (i = 0; i < MAX_DEC_CHN_NUM; i++) {
        idmap = &dec_map[i];
        idmap->ctx = NULL;
        idmap->chan_id = i;
        idmap->is_valid = 0;
    }
    for (i = 0; i < MAX_ENC_CHN_NUM; i++) {
        idmap = &enc_map[i];
        idmap->ctx = NULL;
        idmap->chan_id = i;
        idmap->is_valid = 0;
    }
}

RK_S32 mpp_set_chan(void *ctx, MppCtxType type)
{
    return MppChanService::get()->mpp_set_chan(ctx, type);
}

void mpp_free_chan(void *ctx, MppCtxType type)
{
    MppChanService::get()->mpp_free_chan(ctx, type);
    return;
}
