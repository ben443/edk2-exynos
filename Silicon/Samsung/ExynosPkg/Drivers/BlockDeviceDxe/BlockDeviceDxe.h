/**
 * Copyright (c) 2023-2024, EDK2 Contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#ifndef _BLOCK_DEVICE_DXE_H_
#define _BLOCK_DEVICE_DXE_H_

#include <Uefi.h>

// Function prototypes
EFI_STATUS
EFIAPI
BlockDeviceInitialize (
  IN EFI_HANDLE         ImageHandle,
  IN EFI_SYSTEM_TABLE   *SystemTable
  );

STATIC EFI_STATUS DetectGptPartitions(BLOCK_DEVICE *Dev);
STATIC EFI_STATUS CreatePartitionDevices(BLOCK_DEVICE *Dev);

#endif /* _BLOCK_DEVICE_DXE_H_ */