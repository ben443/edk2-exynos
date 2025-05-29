/**
 * Copyright (c) 2023-2024, EDK2 Contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/IoLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DevicePath.h>
#include <Protocol/DiskIo.h>
#include <Guid/PartitionInfo.h>
#include <Library/DevicePathLib.h>

#include "BlockDeviceDxe.h"

// GPT Partition GUID for identifying system partitions
#define ANDROID_SYSTEM_GUID \
  { 0x38f428e6, 0xd326, 0x425d, { 0x9a, 0x40, 0x13, 0xdb, 0x74, 0x5c, 0x66, 0x4a } }

// GPT Partition GUID for identifying userdata partitions
#define ANDROID_USERDATA_GUID \
  { 0x57f8ee2e, 0x4c7c, 0x45dc, { 0x97, 0x59, 0xe8, 0x04, 0xd6, 0x95, 0x0e, 0x88 } }

// GPT Partition GUID for identifying boot partitions
#define ANDROID_BOOT_GUID \
  { 0x20117f86, 0xe985, 0x4357, { 0xb9, 0xee, 0x37, 0x4b, 0xc5, 0x4d, 0x55, 0xaa } }

// GPT Partition GUID for identifying vendor partitions
#define ANDROID_VENDOR_GUID \
  { 0x84b1df1e, 0x111e, 0x4d4d, { 0xba, 0x5a, 0x33, 0xd7, 0x9a, 0x5a, 0x9d, 0xde } }

// GPT Partition GUID for identifying recovery partitions
#define ANDROID_RECOVERY_GUID \
  { 0x7a7ba616, 0xf12c, 0x4b94, { 0x82, 0x20, 0xd3, 0x5d, 0x04, 0xa9, 0x32, 0x9e } }

// UFS device model names for different Exynos devices
#define UFS_DEVICE_EXYNOS990 L"Samsung Exynos 990 UFS"
#define UFS_DEVICE_EXYNOS980 L"Samsung Exynos 980 UFS"

// MediaId values for different partitions
#define MEDIA_ID_UFS        0
#define MEDIA_ID_PARTITION  1

typedef struct {
  VENDOR_DEVICE_PATH                  Vendor;
  EFI_DEVICE_PATH_PROTOCOL            End;
} BLOCK_DEVICE_DEVICE_PATH;

STATIC BLOCK_DEVICE_DEVICE_PATH mDevicePath = {
  {
    {
      HARDWARE_DEVICE_PATH,
      HW_VENDOR_DP,
      {
        (UINT8)(sizeof(VENDOR_DEVICE_PATH)),
        (UINT8)((sizeof(VENDOR_DEVICE_PATH)) >> 8),
      },
    },
    EFI_CALLER_ID_GUID,
  },
  {
    END_DEVICE_PATH_TYPE,
    END_ENTIRE_DEVICE_PATH_SUBTYPE,
    {
      sizeof(EFI_DEVICE_PATH_PROTOCOL),
      0
    }
  }
};

// Enhanced structure for handling partition information
typedef struct {
  UINT64                    StartLBA;
  UINT64                    EndLBA;
  CHAR16                    Name[36];
  EFI_GUID                  TypeGUID;
  EFI_GUID                  UniqueGUID;
  BOOLEAN                   IsActive;
} DETECTED_PARTITION;

// Master Block Device structure
typedef struct {
  UINTN                       Signature;
  EFI_HANDLE                  Handle;
  BOOLEAN                     Initialized;
  EFI_BLOCK_IO_PROTOCOL       BlockIo;
  EFI_BLOCK_IO_MEDIA          Media;
  BLOCK_DEVICE_DEVICE_PATH    DevicePath;
  UINTN                       BlockSize;
  UINTN                       NumBlocks;
  // Fields for managing partitions
  DETECTED_PARTITION          *Partitions;
  UINTN                       PartitionCount;
} BLOCK_DEVICE;

#define BLOCK_DEVICE_SIGNATURE                 SIGNATURE_32('b', 'l', 'k', 'd')
#define BLOCK_DEVICE_FROM_BLOCK_IO_THIS(a)     CR(a, BLOCK_DEVICE, BlockIo, BLOCK_DEVICE_SIGNATURE)

// Partition device structure
typedef struct {
  UINTN                       Signature;
  EFI_HANDLE                  Handle;
  EFI_BLOCK_IO_PROTOCOL       BlockIo;
  EFI_BLOCK_IO_MEDIA          Media;
  EFI_DEVICE_PATH_PROTOCOL    *DevicePath;
  BLOCK_DEVICE                *Parent;
  UINT64                      StartLBA;
  UINT64                      LastLBA;
  CHAR16                      *PartitionName;
} PARTITION_DEVICE;

#define PARTITION_DEVICE_SIGNATURE             SIGNATURE_32('p', 'a', 'r', 't')
#define PARTITION_DEVICE_FROM_BLOCK_IO_THIS(a) CR(a, PARTITION_DEVICE, BlockIo, PARTITION_DEVICE_SIGNATURE)

// GPT Header definition
typedef struct {
  CHAR8     Signature[8];
  UINT32    Revision;
  UINT32    HeaderSize;
  UINT32    HeaderCRC32;
  UINT32    Reserved;
  UINT64    MyLBA;
  UINT64    AlternateLBA;
  UINT64    FirstUsableLBA;
  UINT64    LastUsableLBA;
  EFI_GUID  DiskGUID;
  UINT64    PartitionEntryLBA;
  UINT32    NumberOfPartitionEntries;
  UINT32    SizeOfPartitionEntry;
  UINT32    PartitionEntryArrayCRC32;
} GPT_HEADER;

// GPT Partition Entry definition
typedef struct {
  EFI_GUID  PartitionTypeGUID;
  EFI_GUID  UniquePartitionGUID;
  UINT64    StartingLBA;
  UINT64    EndingLBA;
  UINT64    Attributes;
  CHAR16    PartitionName[36];
} GPT_PARTITION_ENTRY;

// Function Prototypes
STATIC EFI_STATUS EFIAPI BlockIoReset (
  IN EFI_BLOCK_IO_PROTOCOL *This,
  IN BOOLEAN               ExtendedVerification
  );

STATIC EFI_STATUS EFIAPI BlockIoReadBlocks (
  IN EFI_BLOCK_IO_PROTOCOL *This,
  IN UINT32                MediaId,
  IN EFI_LBA               LBA,
  IN UINTN                 BufferSize,
  OUT VOID                 *Buffer
  );

STATIC EFI_STATUS EFIAPI BlockIoWriteBlocks (
  IN EFI_BLOCK_IO_PROTOCOL *This,
  IN UINT32                MediaId,
  IN EFI_LBA               LBA,
  IN UINTN                 BufferSize,
  IN VOID                  *Buffer
  );

STATIC EFI_STATUS EFIAPI BlockIoFlushBlocks (
  IN EFI_BLOCK_IO_PROTOCOL *This
  );

// UFS device detection and initialization
STATIC EFI_STATUS InitializeUfsDevice(BLOCK_DEVICE *Dev) {
  EFI_STATUS Status;
  
  DEBUG((EFI_D_INFO, "BlockDeviceDxe: Initializing UFS device\n"));
  
  // Set up initial values for UFS device
  Dev->BlockSize = 4096;  // Most UFS devices use 4KB blocks
  Dev->NumBlocks = 0x1000000;  // Placeholder, will be updated later
  
  // Set up media information
  Dev->Media.MediaId = MEDIA_ID_UFS;
  Dev->Media.RemovableMedia = FALSE;
  Dev->Media.MediaPresent = TRUE;
  Dev->Media.LogicalPartition = FALSE;
  Dev->Media.ReadOnly = FALSE;
  Dev->Media.WriteCaching = FALSE;
  Dev->Media.BlockSize = Dev->BlockSize;
  Dev->Media.IoAlign = 0;
  Dev->Media.LastBlock = Dev->NumBlocks - 1;
  
  // Initialize partition array
  Dev->Partitions = NULL;
  Dev->PartitionCount = 0;
  
  // Try to detect GPT on the device
  Status = DetectGptPartitions(Dev);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "BlockDeviceDxe: GPT detection failed: %r\n", Status));
    return Status;
  }
  
  Dev->Initialized = TRUE;
  return EFI_SUCCESS;
}

// Function to parse GPT headers and entries
STATIC EFI_STATUS DetectGptPartitions(BLOCK_DEVICE *Dev) {
  EFI_STATUS Status;
  GPT_HEADER GptHeader;
  GPT_PARTITION_ENTRY *PartitionEntries = NULL;
  UINTN PartitionEntriesSize;
  UINT8 *Buffer;
  UINTN i;
  
  DEBUG((EFI_D_INFO, "BlockDeviceDxe: Detecting GPT partitions\n"));
  
  // Read LBA 1 which should contain the GPT header
  Buffer = AllocatePool(Dev->BlockSize);
  if (Buffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  Status = Dev->BlockIo.ReadBlocks(&Dev->BlockIo, Dev->Media.MediaId, 1, Dev->BlockSize, Buffer);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "BlockDeviceDxe: Failed to read GPT header: %r\n", Status));
    FreePool(Buffer);
    return Status;
  }
  
  // Copy and validate GPT header
  CopyMem(&GptHeader, Buffer, sizeof(GPT_HEADER));
  FreePool(Buffer);
  
  if (CompareMem(GptHeader.Signature, "EFI PART", 8) != 0) {
    DEBUG((EFI_D_ERROR, "BlockDeviceDxe: Invalid GPT signature\n"));
    return EFI_DEVICE_ERROR;
  }
  
  DEBUG((EFI_D_INFO, "BlockDeviceDxe: Valid GPT header found\n"));
  DEBUG((EFI_D_INFO, "BlockDeviceDxe: Number of partition entries: %d\n", GptHeader.NumberOfPartitionEntries));
  
  // Allocate memory for partition entries
  PartitionEntriesSize = GptHeader.NumberOfPartitionEntries * GptHeader.SizeOfPartitionEntry;
  PartitionEntries = AllocatePool(PartitionEntriesSize);
  if (PartitionEntries == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  // Read the partition entries
  Buffer = (UINT8*)PartitionEntries;
  for (i = 0; i < (PartitionEntriesSize + Dev->BlockSize - 1) / Dev->BlockSize; i++) {
    Status = Dev->BlockIo.ReadBlocks(
              &Dev->BlockIo,
              Dev->Media.MediaId,
              GptHeader.PartitionEntryLBA + i,
              Dev->BlockSize,
              Buffer + (i * Dev->BlockSize)
            );
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "BlockDeviceDxe: Failed to read partition entries: %r\n", Status));
      FreePool(PartitionEntries);
      return Status;
    }
  }
  
  // Count valid partitions (non-zero type GUID)
  UINTN ValidPartitions = 0;
  EFI_GUID EmptyGuid = {0};
  
  for (i = 0; i < GptHeader.NumberOfPartitionEntries; i++) {
    if (CompareMem(&PartitionEntries[i].PartitionTypeGUID, &EmptyGuid, sizeof(EFI_GUID)) != 0) {
      ValidPartitions++;
    }
  }
  
  DEBUG((EFI_D_INFO, "BlockDeviceDxe: Valid partitions found: %d\n", ValidPartitions));
  
  if (ValidPartitions == 0) {
    FreePool(PartitionEntries);
    return EFI_NOT_FOUND;
  }
  
  // Allocate array for detected partitions
  Dev->Partitions = AllocateZeroPool(ValidPartitions * sizeof(DETECTED_PARTITION));
  if (Dev->Partitions == NULL) {
    FreePool(PartitionEntries);
    return EFI_OUT_OF_RESOURCES;
  }
  
  // Fill in partition information
  Dev->PartitionCount = 0;
  for (i = 0; i < GptHeader.NumberOfPartitionEntries; i++) {
    if (CompareMem(&PartitionEntries[i].PartitionTypeGUID, &EmptyGuid, sizeof(EFI_GUID)) != 0) {
      Dev->Partitions[Dev->PartitionCount].StartLBA = PartitionEntries[i].StartingLBA;
      Dev->Partitions[Dev->PartitionCount].EndLBA = PartitionEntries[i].EndingLBA;
      CopyMem(&Dev->Partitions[Dev->PartitionCount].Name, 
              &PartitionEntries[i].PartitionName, 
              sizeof(PartitionEntries[i].PartitionName));
      CopyMem(&Dev->Partitions[Dev->PartitionCount].TypeGUID, 
              &PartitionEntries[i].PartitionTypeGUID, 
              sizeof(EFI_GUID));
      CopyMem(&Dev->Partitions[Dev->PartitionCount].UniqueGUID, 
              &PartitionEntries[i].UniquePartitionGUID, 
              sizeof(EFI_GUID));
      Dev->Partitions[Dev->PartitionCount].IsActive = TRUE;
      
      DEBUG((EFI_D_INFO, "BlockDeviceDxe: Partition %d: %s (LBA %lx-%lx)\n", 
             Dev->PartitionCount,
             Dev->Partitions[Dev->PartitionCount].Name,
             Dev->Partitions[Dev->PartitionCount].StartLBA,
             Dev->Partitions[Dev->PartitionCount].EndLBA));
      
      Dev->PartitionCount++;
    }
  }
  
  FreePool(PartitionEntries);
  return EFI_SUCCESS;
}

// Create device paths and install protocols for individual partitions
STATIC EFI_STATUS CreatePartitionDevices(BLOCK_DEVICE *Dev) {
  EFI_STATUS Status;
  UINTN i;
  PARTITION_DEVICE *PartitionDev;
  UINTN PartitionNameSize;
  UINTN HandleCount;
  EFI_HANDLE *HandleBuffer;
  
  DEBUG((EFI_D_INFO, "BlockDeviceDxe: Creating partition devices, count: %d\n", Dev->PartitionCount));
  
  // First, check if partition devices are already installed
  Status = gBS->LocateHandleBuffer(
                 ByProtocol,
                 &gEfiBlockIoProtocolGuid,
                 NULL,
                 &HandleCount,
                 &HandleBuffer
               );
  
  if (!EFI_ERROR(Status)) {
    // Free the handle buffer as we don't need it
    FreePool(HandleBuffer);
  }
  
  for (i = 0; i < Dev->PartitionCount; i++) {
    // Skip inactive partitions
    if (!Dev->Partitions[i].IsActive) {
      continue;
    }
    
    // Allocate and initialize the partition device
    PartitionDev = AllocateZeroPool(sizeof(PARTITION_DEVICE));
    if (PartitionDev == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
    
    PartitionDev->Signature = PARTITION_DEVICE_SIGNATURE;
    PartitionDev->Parent = Dev;
    PartitionDev->StartLBA = Dev->Partitions[i].StartLBA;
    PartitionDev->LastLBA = Dev->Partitions[i].EndLBA;
    
    // Copy the BlockIo protocol
    CopyMem(&PartitionDev->BlockIo, &Dev->BlockIo, sizeof(EFI_BLOCK_IO_PROTOCOL));
    PartitionDev->BlockIo.Media = &PartitionDev->Media;
    
    // Set up media information for this partition
    CopyMem(&PartitionDev->Media, &Dev->Media, sizeof(EFI_BLOCK_IO_MEDIA));
    PartitionDev->Media.MediaId = MEDIA_ID_PARTITION;
    PartitionDev->Media.LogicalPartition = TRUE;
    PartitionDev->Media.LastBlock = PartitionDev->LastLBA - PartitionDev->StartLBA;
    
    // Create partition name
    PartitionNameSize = StrSize(Dev->Partitions[i].Name);
    PartitionDev->PartitionName = AllocateZeroPool(PartitionNameSize);
    if (PartitionDev->PartitionName == NULL) {
      FreePool(PartitionDev);
      return EFI_OUT_OF_RESOURCES;
    }
    
    CopyMem(PartitionDev->PartitionName, Dev->Partitions[i].Name, PartitionNameSize);
    
    // Create device path for this partition
    PartitionDev->DevicePath = AppendDevicePathNode(
                                 DevicePathFromHandle(Dev->Handle),
                                 (EFI_DEVICE_PATH_PROTOCOL *)&mDevicePath.Vendor
                               );
    
    if (PartitionDev->DevicePath == NULL) {
      FreePool(PartitionDev->PartitionName);
      FreePool(PartitionDev);
      return EFI_OUT_OF_RESOURCES;
    }
    
    // Install protocols
    Status = gBS->InstallMultipleProtocolInterfaces(
                   &PartitionDev->Handle,
                   &gEfiBlockIoProtocolGuid, &PartitionDev->BlockIo,
                   &gEfiDevicePathProtocolGuid, PartitionDev->DevicePath,
                   NULL
                 );
    
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "BlockDeviceDxe: Failed to install protocols for partition %d: %r\n", i, Status));
      FreePool(PartitionDev->PartitionName);
      FreePool(PartitionDev->DevicePath);
      FreePool(PartitionDev);
      continue; // Try the next partition
    }
    
    DEBUG((EFI_D_INFO, "BlockDeviceDxe: Created partition device: %s\n", PartitionDev->PartitionName));
  }
  
  return EFI_SUCCESS;
}

// Block I/O protocol function implementations
STATIC EFI_STATUS EFIAPI BlockIoReset (
  IN EFI_BLOCK_IO_PROTOCOL *This,
  IN BOOLEAN               ExtendedVerification
  )
{
  return EFI_SUCCESS;
}

STATIC EFI_STATUS EFIAPI BlockIoReadBlocks (
  IN EFI_BLOCK_IO_PROTOCOL *This,
  IN UINT32                MediaId,
  IN EFI_LBA               LBA,
  IN UINTN                 BufferSize,
  OUT VOID                 *Buffer
  )
{
  PARTITION_DEVICE *PartitionDev;
  BLOCK_DEVICE *Dev;
  EFI_LBA DeviceLBA;
  
  if (This == NULL || Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  if (BufferSize == 0) {
    return EFI_SUCCESS;
  }
  
  // Check if this is a request to the main block device or a partition
  if (This->Media->MediaId == MEDIA_ID_UFS) {
    Dev = BLOCK_DEVICE_FROM_BLOCK_IO_THIS(This);
    
    if (MediaId != Dev->Media.MediaId) {
      return EFI_MEDIA_CHANGED;
    }
    
    if (LBA > Dev->Media.LastBlock) {
      return EFI_INVALID_PARAMETER;
    }
    
    if ((BufferSize % Dev->BlockSize) != 0) {
      return EFI_BAD_BUFFER_SIZE;
    }
    
    if (BufferSize > Dev->BlockSize * (Dev->Media.LastBlock - LBA + 1)) {
      return EFI_INVALID_PARAMETER;
    }
    
    // Perform the actual read operation for the main device
    // This is a stub that would be implemented with actual UFS read operations
    SetMem(Buffer, BufferSize, 0xAA); // Placeholder
    return EFI_SUCCESS;
  } else {
    // This is a request to a partition
    PartitionDev = PARTITION_DEVICE_FROM_BLOCK_IO_THIS(This);
    
    if (MediaId != PartitionDev->Media.MediaId) {
      return EFI_MEDIA_CHANGED;
    }
    
    if (LBA > PartitionDev->Media.LastBlock) {
      return EFI_INVALID_PARAMETER;
    }
    
    if ((BufferSize % PartitionDev->Parent->BlockSize) != 0) {
      return EFI_BAD_BUFFER_SIZE;
    }
    
    // Translate LBA from partition-relative to device-absolute
    DeviceLBA = LBA + PartitionDev->StartLBA;
    
    // Forward the read request to the parent device
    return PartitionDev->Parent->BlockIo.ReadBlocks(
             &PartitionDev->Parent->BlockIo,
             PartitionDev->Parent->Media.MediaId,
             DeviceLBA,
             BufferSize,
             Buffer
           );
  }
}

STATIC EFI_STATUS EFIAPI BlockIoWriteBlocks (
  IN EFI_BLOCK_IO_PROTOCOL *This,
  IN UINT32                MediaId,
  IN EFI_LBA               LBA,
  IN UINTN                 BufferSize,
  IN VOID                  *Buffer
  )
{
  PARTITION_DEVICE *PartitionDev;
  BLOCK_DEVICE *Dev;
  EFI_LBA DeviceLBA;
  
  if (This == NULL || Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  if (BufferSize == 0) {
    return EFI_SUCCESS;
  }
  
  // Check if this is a request to the main block device or a partition
  if (This->Media->MediaId == MEDIA_ID_UFS) {
    Dev = BLOCK_DEVICE_FROM_BLOCK_IO_THIS(This);
    
    if (MediaId != Dev->Media.MediaId) {
      return EFI_MEDIA_CHANGED;
    }
    
    if (Dev->Media.ReadOnly) {
      return EFI_WRITE_PROTECTED;
    }
    
    if (LBA > Dev->Media.LastBlock) {
      return EFI_INVALID_PARAMETER;
    }
    
    if ((BufferSize % Dev->BlockSize) != 0) {
      return EFI_BAD_BUFFER_SIZE;
    }
    
    if (BufferSize > Dev->BlockSize * (Dev->Media.LastBlock - LBA + 1)) {
      return EFI_INVALID_PARAMETER;
    }
    
    // Perform the actual write operation for the main device
    // This is a stub that would be implemented with actual UFS write operations
    return EFI_SUCCESS;
  } else {
    // This is a request to a partition
    PartitionDev = PARTITION_DEVICE_FROM_BLOCK_IO_THIS(This);
    
    if (MediaId != PartitionDev->Media.MediaId) {
      return EFI_MEDIA_CHANGED;
    }
    
    if (PartitionDev->Media.ReadOnly) {
      return EFI_WRITE_PROTECTED;
    }
    
    if (LBA > PartitionDev->Media.LastBlock) {
      return EFI_INVALID_PARAMETER;
    }
    
    if ((BufferSize % PartitionDev->Parent->BlockSize) != 0) {
      return EFI_BAD_BUFFER_SIZE;
    }
    
    // Translate LBA from partition-relative to device-absolute
    DeviceLBA = LBA + PartitionDev->StartLBA;
    
    // Forward the write request to the parent device
    return PartitionDev->Parent->BlockIo.WriteBlocks(
             &PartitionDev->Parent->BlockIo,
             PartitionDev->Parent->Media.MediaId,
             DeviceLBA,
             BufferSize,
             Buffer
           );
  }
}

STATIC EFI_STATUS EFIAPI BlockIoFlushBlocks (
  IN EFI_BLOCK_IO_PROTOCOL *This
  )
{
  // Nothing to do for flush blocks operation
  return EFI_SUCCESS;
}

// Main entry point for the driver
EFI_STATUS
EFIAPI
BlockDeviceInitialize (
  IN EFI_HANDLE         ImageHandle,
  IN EFI_SYSTEM_TABLE   *SystemTable
  )
{
  EFI_STATUS Status;
  BLOCK_DEVICE *Dev;
  
  DEBUG((EFI_D_INFO, "BlockDeviceDxe: Entry point\n"));
  
  // Allocate and initialize the block device
  Dev = AllocateZeroPool(sizeof(BLOCK_DEVICE));
  if (Dev == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  Dev->Signature = BLOCK_DEVICE_SIGNATURE;
  
  // Set up the Block I/O protocol
  Dev->BlockIo.Revision = EFI_BLOCK_IO_PROTOCOL_REVISION3;
  Dev->BlockIo.Media = &Dev->Media;
  Dev->BlockIo.Reset = BlockIoReset;
  Dev->BlockIo.ReadBlocks = BlockIoReadBlocks;
  Dev->BlockIo.WriteBlocks = BlockIoWriteBlocks;
  Dev->BlockIo.FlushBlocks = BlockIoFlushBlocks;
  
  // Set up device path
  CopyMem(&Dev->DevicePath, &mDevicePath, sizeof(BLOCK_DEVICE_DEVICE_PATH));
  
  // Initialize the UFS device
  Status = InitializeUfsDevice(Dev);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "BlockDeviceDxe: Failed to initialize UFS device: %r\n", Status));
    FreePool(Dev);
    return Status;
  }
  
  // Install protocols
  Status = gBS->InstallMultipleProtocolInterfaces(
                 &Dev->Handle,
                 &gEfiBlockIoProtocolGuid, &Dev->BlockIo,
                 &gEfiDevicePathProtocolGuid, &Dev->DevicePath,
                 NULL
               );
  
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "BlockDeviceDxe: Failed to install protocols: %r\n", Status));
    FreePool(Dev);
    return Status;
  }
  
  // Create partition devices
  Status = CreatePartitionDevices(Dev);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "BlockDeviceDxe: Failed to create partition devices: %r\n", Status));
    // We continue even if this fails, as the main device is still available
  }
  
  DEBUG((EFI_D_INFO, "BlockDeviceDxe: Initialization complete\n"));
  return EFI_SUCCESS;
}
