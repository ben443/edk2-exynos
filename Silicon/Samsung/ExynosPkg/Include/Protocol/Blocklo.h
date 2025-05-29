/**
  Copyright (c) 2023-2024, EDK2 Contributors
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __EXYNOS_BLOCK_IO_H__
#define __EXYNOS_BLOCK_IO_H__

// Define the Block IO Protocol GUID
// {9588502a-5370-11e3-8f16-00155d2c1be0}
#define EXYNOS_BLOCK_IO_PROTOCOL_GUID \
  { 0x9588502a, 0x5370, 0x11e3, { 0x8f, 0x16, 0x0, 0x15, 0x5d, 0x2c, 0x1b, 0xe0 } }

extern EFI_GUID gExynosBlockIoProtocolGuid;

#endif // __EXYNOS_BLOCK_IO_H__
