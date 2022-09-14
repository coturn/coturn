/* Copyright 2022 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ns_turn_utils.h"
#include "apputils.h"
#include "stun_buffer.h"

static SHATYPE shatype = SHATYPE_SHA1;

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {//rfc5769check

    stun_is_command_message_full_check_str((uint8_t *)Data, Size, 1, NULL);

    uint8_t uname[33];
    uint8_t realm[33];
    uint8_t upwd[33];
    strcpy((char*) upwd, "VOkJxbRl1RmTxUk/WvJxBt");
    stun_check_message_integrity_str(TURN_CREDENTIALS_SHORT_TERM,(uint8_t *)Data, Size, uname, realm, upwd, shatype);
    return 0;
}
