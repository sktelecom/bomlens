// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0
#include <stdio.h>
#include <zlib.h>

int main(void)
{
    printf("media-daemon, zlib %s\n", zlibVersion());
    return 0;
}
