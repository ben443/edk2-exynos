/**
 * Copyright (c) 2023-2024, EDK2 Contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#ifndef __BLOCK_DEVICE_DXE_H__
#define __BLOCK_DEVICE_DXE_H__

#include <Uefi.h>

// Defined protocols
extern EFI_GUID gSdhcProtocolGuid;
extern EFI_GUID gEfiCrc32ServiceProtocolGuid;
extern EFI_GUID gEfiPartTypeUnusedGuid;

// Device signature for verification
#define BLOCK_IO_DEVICE_SIGNATURE  SIGNATURE_32('b','l','k','d')

// Helper macro to get block device from BlockIo protocol
#define BLOCK_IO_DEVICE_FROM_BLOCK_IO_THIS(a) \
  CR(a, BLOCK_IO_DEVICE, BlockIo, BLOCK_IO_DEVICE_SIGNATURE)

// Storage device protocol for SDHC controllers
typedef struct _SDHC_PROTOCOL SDHC_PROTOCOL;

// Block I/O device structure forward declaration
typedef struct _BLOCK_IO_DEVICE BLOCK_IO_DEVICE;

// Function prototypes for device-specific operations
typedef
EFI_STATUS
(*BLOCK_DEVICE_READ_BLOCKS) (
  IN  BLOCK_IO_DEVICE   *This,
  IN  UINT32            MediaId,
  IN  EFI_LBA           Lba,
  IN  UINTN             BufferSize,
  OUT VOID              *Buffer
  );

typedef
EFI_STATUS
(*BLOCK_DEVICE_WRITE_BLOCKS) (
  IN BLOCK_IO_DEVICE    *This,
  IN UINT32             MediaId,
  IN EFI_LBA            Lba,
  IN UINTN              BufferSize,
  IN VOID               *Buffer
  );

typedef
EFI_STATUS
(*BLOCK_DEVICE_FLUSH_BLOCKS) (
  IN BLOCK_IO_DEVICE    *This
  );

// SDHC Protocol definition
struct _SDHC_PROTOCOL {
  EFI_STATUS
  (*Initialize) (
    IN SDHC_PROTOCOL    *This
    );

  EFI_STATUS
  (*GetCardInfo) (
    IN  SDHC_PROTOCOL   *This,
    OUT UINT64          *CardSize,
    OUT UINT32          *BlockSize
    );

  EFI_STATUS
  (*ReadBlocks) (
    IN  SDHC_PROTOCOL   *This,
    IN  UINT32          StartBlock,
    IN  UINT32          NumBlocks,
    OUT VOID            *Buffer
    );

  EFI_STATUS
  (*WriteBlocks) (
    IN SDHC_PROTOCOL    *This,
    IN UINT32           StartBlock,
    IN UINT32           NumBlocks,
    IN VOID             *Buffer
    );
};

// Block I/O device structure
struct _BLOCK_IO_DEVICE {
  UINT32                        Signature;
  EFI_HANDLE                    ControllerHandle;
  EFI_BLOCK_IO_PROTOCOL         BlockIo;
  EFI_BLOCK_IO_MEDIA            Media;
  EFI_DEVICE_PATH_PROTOCOL      *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL      *ParentDevicePath;
  EFI_LBA                       StartingLBA;
  
  // Device-specific functions
  BLOCK_DEVICE_READ_BLOCKS      StorageDeviceReadBlocks;
  BLOCK_DEVICE_WRITE_BLOCKS     StorageDeviceWriteBlocks;
  BLOCK_DEVICE_FLUSH_BLOCKS     StorageDeviceFlushBlocks;
  
  // Device-specific data
  SDHC_PROTOCOL                 *SdhcProtocol;
};

// Master Boot Record structure
#pragma pack(1)
typedef struct {
  UINT8   BootCode[440];
  UINT32  UniqueMbrSignature;
  UINT16  Unknown;
  struct {
    UINT8   BootIndicator;
    UINT8   StartHead;
    UINT8   StartSector;
    UINT8   StartTrack;
    UINT8   OSIndicator;
    UINT8   EndHead;
    UINT8   EndSector;
    UINT8   EndTrack;
    UINT32  StartingSector;
    UINT32  TotalSectors;
  } Partition[4];
  UINT16  Signature;
} MASTER_BOOT_RECORD;
#pragma pack()

// Function prototypes
EFI_STATUS
SdhcInitialize (
  IN  SDHC_PROTOCOL     *SdhcProtocol,
  IN  BLOCK_IO_DEVICE   *BlockIoDevice
  );

EFI_STATUS
SdhcReadBlocks (
  IN  BLOCK_IO_DEVICE   *BlockIoDevice,
  IN  UINT32            MediaId,
  IN  EFI_LBA           Lba,
  IN  UINTN             BufferSize,
  OUT VOID              *Buffer
  );

EFI_STATUS
SdhcWriteBlocks (
  IN  BLOCK_IO_DEVICE   *BlockIoDevice,
  IN  UINT32            MediaId,
  IN  EFI_LBA           Lba,
  IN  UINTN             BufferSize,
  IN  VOID              *Buffer
  );

EFI_STATUS
SdhcFlushBlocks (
  IN  BLOCK_IO_DEVICE   *BlockIoDevice
  );

#endif // __BLOCK_DEVICE_DXE_H__