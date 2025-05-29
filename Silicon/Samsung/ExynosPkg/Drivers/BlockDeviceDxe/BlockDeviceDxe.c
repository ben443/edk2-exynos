/**
 * Copyright (c) 2023-2024, EDK2 Contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include <Protocol/BlockIo.h>
#include <Protocol/DevicePath.h>
#include <Protocol/Sdhc.h>
#include <Protocol/ComponentName.h>
#include <Protocol/ComponentName2.h>
#include <Protocol/DriverBinding.h>

#include "BlockDeviceDxe.h"

// Debug level configuration
#define DEBUG_BLOCKDEV 1

#if DEBUG_BLOCKDEV
#define BLOCKDEV_DEBUG(x) DEBUG(x)
#else
#define BLOCKDEV_DEBUG(x)
#endif

// Constants for partition scanning
#define GPT_SIGNATURE            0x5452415020494645ULL // "EFI PART"
#define GPT_HEADER_REVISION      0x00010000
#define GPT_MAX_PARTITIONS       128
#define MBR_SIGNATURE            0xAA55
#define KNOWN_PARTITION_TYPES    10

// Common partition type GUIDs
STATIC CONST EFI_GUID gEfiPartTypeSystemPartitionGuid = {
  0xC12A7328, 0xF81F, 0x11D2, {0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B}
};

STATIC CONST EFI_GUID gEfiPartTypeLegacyMbrGuid = {
  0x024DEE41, 0x33E7, 0x11D3, {0x9D, 0x69, 0x00, 0x08, 0xC7, 0x81, 0xF3, 0x9F}
};

// Known partition types commonly found on mobile devices
STATIC CONST EFI_GUID gKnownPartitionTypes[KNOWN_PARTITION_TYPES] = {
  // EFI System partition
  {0xC12A7328, 0xF81F, 0x11D2, {0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B}},
  // Basic data partition
  {0xEBD0A0A2, 0xB9E5, 0x4433, {0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7}},
  // Linux filesystem data
  {0x0FC63DAF, 0x8483, 0x4772, {0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4}},
  // Linux swap
  {0x0657FD6D, 0xA4AB, 0x43C4, {0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F, 0x4F}},
  // Android bootloader
  {0x2568845D, 0x2332, 0x4675, {0xBC, 0x39, 0x8F, 0xA5, 0xA4, 0x74, 0x8D, 0x15}},
  // Android boot
  {0x49A4D17F, 0x93A3, 0x45C1, {0xA0, 0xDE, 0xF5, 0x0B, 0xA6, 0x14, 0x2E, 0xF8}},
  // Android recovery
  {0x4177C722, 0x9E92, 0x4AAB, {0x86, 0x99, 0xF5, 0x12, 0xEE, 0xC0, 0x9F, 0xBD}},
  // Android system
  {0x83BD6B9D, 0x7F4A, 0x11E0, {0xAC, 0xC0, 0x07, 0x00, 0x86, 0x02, 0xEE, 0x7D}},
  // Android userdata
  {0x8F68CC74, 0xC5E5, 0x48DA, {0xBE, 0x91, 0xA0, 0xC8, 0x15, 0x76, 0x21, 0x3F}},
  // Android metadata
  {0x20AC26BE, 0x20B7, 0x11E3, {0x84, 0xC5, 0x6C, 0xFB, 0x7F, 0xCF, 0x0B, 0x23}}
};

// Structure to store partition information
typedef struct {
  EFI_LBA                  StartingLBA;
  EFI_LBA                  EndingLBA;
  EFI_GUID                 PartitionTypeGUID;
  EFI_GUID                 UniquePartitionGUID;
  CHAR16                   PartitionName[36];
  BOOLEAN                  IsValid;
} GPT_PARTITION_ENTRY;

// Additional MBR partition types commonly used on mobile devices
#define MBR_TYPE_EFI_SYSTEM      0xEF
#define MBR_TYPE_LINUX           0x83
#define MBR_TYPE_LINUX_LVM       0x8E
#define MBR_TYPE_LINUX_SWAP      0x82
#define MBR_TYPE_ANDROID_BOOT    0x72
#define MBR_TYPE_ANDROID_SYSTEM  0x74
#define MBR_TYPE_ANDROID_DATA    0x78
#define MBR_TYPE_ANDROID_CACHE   0x76

// Forward declarations
STATIC
EFI_STATUS
EFIAPI
BlockDeviceDriverSupported (
  IN EFI_DRIVER_BINDING_PROTOCOL *This,
  IN EFI_HANDLE                  ControllerHandle,
  IN EFI_DEVICE_PATH_PROTOCOL    *RemainingDevicePath OPTIONAL
  );

STATIC
EFI_STATUS
EFIAPI
BlockDeviceDriverStart (
  IN EFI_DRIVER_BINDING_PROTOCOL *This,
  IN EFI_HANDLE                  ControllerHandle,
  IN EFI_DEVICE_PATH_PROTOCOL    *RemainingDevicePath OPTIONAL
  );

STATIC
EFI_STATUS
EFIAPI
BlockDeviceDriverStop (
  IN  EFI_DRIVER_BINDING_PROTOCOL *This,
  IN  EFI_HANDLE                  ControllerHandle,
  IN  UINTN                       NumberOfChildren,
  IN  EFI_HANDLE                  *ChildHandleBuffer
  );

// Block I/O Protocol function declarations
STATIC
EFI_STATUS
EFIAPI
BlockIoReset (
  IN EFI_BLOCK_IO_PROTOCOL *This,
  IN BOOLEAN               ExtendedVerification
  );

STATIC
EFI_STATUS
EFIAPI
BlockIoReadBlocks (
  IN  EFI_BLOCK_IO_PROTOCOL *This,
  IN  UINT32                MediaId,
  IN  EFI_LBA               LBA,
  IN  UINTN                 BufferSize,
  OUT VOID                  *Buffer
  );

STATIC
EFI_STATUS
EFIAPI
BlockIoWriteBlocks (
  IN EFI_BLOCK_IO_PROTOCOL *This,
  IN UINT32                MediaId,
  IN EFI_LBA               LBA,
  IN UINTN                 BufferSize,
  IN VOID                  *Buffer
  );

STATIC
EFI_STATUS
EFIAPI
BlockIoFlushBlocks (
  IN EFI_BLOCK_IO_PROTOCOL *This
  );

// Block I/O Protocol instance
STATIC EFI_BLOCK_IO_PROTOCOL mBlockIoProtocol = {
  EFI_BLOCK_IO_PROTOCOL_REVISION,
  (EFI_BLOCK_IO_MEDIA *) 0,
  BlockIoReset,
  BlockIoReadBlocks,
  BlockIoWriteBlocks,
  BlockIoFlushBlocks
};

// Driver Binding Protocol instance
STATIC EFI_DRIVER_BINDING_PROTOCOL mDriverBinding = {
  BlockDeviceDriverSupported,
  BlockDeviceDriverStart,
  BlockDeviceDriverStop,
  0x10, // Version
  NULL, // ImageHandle
  NULL  // DriverBindingHandle
};

/**
  Read GPT header and validate it.

  @param  BlockIo              BlockIo interface.
  @param  GptHeader            Buffer to store GPT header.

  @retval EFI_SUCCESS          GPT header read and validated.
  @retval EFI_DEVICE_ERROR     Error reading from the device.
  @retval EFI_CRC_ERROR        CRC check failure.
  @retval EFI_INVALID_PARAMETER Invalid parameters.
**/
STATIC
EFI_STATUS
ReadGptHeader (
  IN  EFI_BLOCK_IO_PROTOCOL   *BlockIo,
  OUT EFI_PARTITION_TABLE_HEADER *GptHeader
  )
{
  EFI_STATUS                  Status;
  UINT32                      BlockSize;
  UINT32                      MediaId;
  EFI_CRC32_SERVICE_PROTOCOL  *Crc32;
  UINT32                      CrcCalc;
  UINT32                      CrcLength;
  UINT32                      CrcOriginal;

  if (BlockIo == NULL || GptHeader == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  BlockSize = BlockIo->Media->BlockSize;
  MediaId   = BlockIo->Media->MediaId;

  // Read the primary GPT header (LBA 1)
  Status = BlockIo->ReadBlocks (
                      BlockIo,
                      MediaId,
                      1,
                      BlockSize,
                      GptHeader
                      );
  if (EFI_ERROR (Status)) {
    BLOCKDEV_DEBUG ((DEBUG_ERROR, "ReadGptHeader: Error reading GPT header: %r\n", Status));
    return Status;
  }

  // Check GPT signature
  if (GptHeader->Header.Signature != GPT_SIGNATURE) {
    BLOCKDEV_DEBUG ((DEBUG_ERROR, "ReadGptHeader: Invalid GPT signature\n"));
    return EFI_DEVICE_ERROR;
  }

  // Check revision
  if (GptHeader->Header.Revision != GPT_HEADER_REVISION) {
    BLOCKDEV_DEBUG ((DEBUG_ERROR, "ReadGptHeader: Unsupported GPT revision\n"));
    return EFI_DEVICE_ERROR;
  }

  // Check header size
  if (GptHeader->Header.HeaderSize < sizeof (EFI_PARTITION_TABLE_HEADER) ||
      GptHeader->Header.HeaderSize > BlockSize) {
    BLOCKDEV_DEBUG ((DEBUG_ERROR, "ReadGptHeader: Invalid header size\n"));
    return EFI_DEVICE_ERROR;
  }

  // Verify the CRC
  CrcLength = GptHeader->Header.HeaderSize;
  CrcOriginal = GptHeader->Header.CRC32;
  GptHeader->Header.CRC32 = 0;

  Status = gBS->LocateProtocol (&gEfiCrc32ServiceProtocolGuid, NULL, (VOID **)&Crc32);
  if (EFI_ERROR (Status)) {
    BLOCKDEV_DEBUG ((DEBUG_ERROR, "ReadGptHeader: Could not locate CRC32 service: %r\n", Status));
    GptHeader->Header.CRC32 = CrcOriginal;
    return Status;
  }

  Status = Crc32->CalculateCrc32 (GptHeader, CrcLength, &CrcCalc);
  GptHeader->Header.CRC32 = CrcOriginal;
  
  if (EFI_ERROR (Status)) {
    BLOCKDEV_DEBUG ((DEBUG_ERROR, "ReadGptHeader: CRC calculation failed: %r\n", Status));
    return Status;
  }

  if (CrcCalc != CrcOriginal) {
    BLOCKDEV_DEBUG ((DEBUG_ERROR, "ReadGptHeader: CRC check failed\n"));
    return EFI_CRC_ERROR;
  }

  return EFI_SUCCESS;
}

/**
  Read GPT partition entries.

  @param  BlockIo              BlockIo interface.
  @param  GptHeader            GPT header structure.
  @param  PartEntries          Buffer to store partition entries.

  @retval EFI_SUCCESS          Partition entries read.
  @retval EFI_DEVICE_ERROR     Error reading from the device.
  @retval EFI_CRC_ERROR        CRC check failure.
  @retval EFI_INVALID_PARAMETER Invalid parameters.
**/
STATIC
EFI_STATUS
ReadGptPartitionEntries (
  IN  EFI_BLOCK_IO_PROTOCOL        *BlockIo,
  IN  EFI_PARTITION_TABLE_HEADER   *GptHeader,
  OUT EFI_PARTITION_ENTRY          *PartEntries
  )
{
  EFI_STATUS                  Status;
  UINTN                       EntriesSize;
  EFI_LBA                     StartLBA;
  UINT32                      MediaId;
  UINT32                      BlockSize;
  EFI_CRC32_SERVICE_PROTOCOL  *Crc32;
  UINT32                      CrcCalc;

  if (BlockIo == NULL || GptHeader == NULL || PartEntries == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  MediaId   = BlockIo->Media->MediaId;
  BlockSize = BlockIo->Media->BlockSize;
  StartLBA  = GptHeader->PartitionEntryLBA;
  EntriesSize = GptHeader->NumberOfPartitionEntries * GptHeader->SizeOfPartitionEntry;

  // Calculate needed blocks to read
  UINTN BlocksToRead = (EntriesSize + BlockSize - 1) / BlockSize;
  
  // Read the partition entries
  Status = BlockIo->ReadBlocks (
                      BlockIo,
                      MediaId,
                      StartLBA,
                      BlocksToRead * BlockSize,
                      PartEntries
                      );
  if (EFI_ERROR (Status)) {
    BLOCKDEV_DEBUG ((DEBUG_ERROR, "ReadGptPartitionEntries: Error reading partition entries: %r\n", Status));
    return Status;
  }

  // Verify the CRC
  Status = gBS->LocateProtocol (&gEfiCrc32ServiceProtocolGuid, NULL, (VOID **)&Crc32);
  if (EFI_ERROR (Status)) {
    BLOCKDEV_DEBUG ((DEBUG_ERROR, "ReadGptPartitionEntries: Could not locate CRC32 service: %r\n", Status));
    return Status;
  }

  Status = Crc32->CalculateCrc32 (PartEntries, EntriesSize, &CrcCalc);
  if (EFI_ERROR (Status)) {
    BLOCKDEV_DEBUG ((DEBUG_ERROR, "ReadGptPartitionEntries: CRC calculation failed: %r\n", Status));
    return Status;
  }

  if (CrcCalc != GptHeader->PartitionEntryArrayCRC32) {
    BLOCKDEV_DEBUG ((DEBUG_ERROR, "ReadGptPartitionEntries: CRC check failed\n"));
    return EFI_CRC_ERROR;
  }

  return EFI_SUCCESS;
}

/**
  Detect and process MBR partition table.

  @param  BlockIo              BlockIo interface.
  @param  ParentDevicePath     Device path of the parent device.
  @param  BlockIoDevice        Block device info structure.

  @retval EFI_SUCCESS          MBR detected and processed.
  @retval Others               Error occurred during detection.
**/
STATIC
EFI_STATUS
DetectMbrPartitions (
  IN  EFI_BLOCK_IO_PROTOCOL     *BlockIo,
  IN  EFI_DEVICE_PATH_PROTOCOL  *ParentDevicePath,
  IN  BLOCK_IO_DEVICE           *BlockIoDevice
  )
{
  EFI_STATUS              Status;
  MASTER_BOOT_RECORD      *Mbr;
  UINT32                  BlockSize;
  UINT32                  MediaId;
  UINT8                   PartCount;
  EFI_PARTITION_ENTRY     *PartEntry;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  EFI_HANDLE              PartitionHandle;
  UINT8                   Index;

  BlockSize = BlockIo->Media->BlockSize;
  MediaId   = BlockIo->Media->MediaId;

  // Allocate buffer for MBR
  Mbr = AllocatePool (BlockSize);
  if (Mbr == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  // Read MBR
  Status = BlockIo->ReadBlocks (
                      BlockIo,
                      MediaId,
                      0,
                      BlockSize,
                      Mbr
                      );
  if (EFI_ERROR (Status)) {
    BLOCKDEV_DEBUG ((DEBUG_ERROR, "DetectMbrPartitions: Error reading MBR: %r\n", Status));
    FreePool (Mbr);
    return Status;
  }

  // Check MBR signature
  if (Mbr->Signature != MBR_SIGNATURE) {
    BLOCKDEV_DEBUG ((DEBUG_ERROR, "DetectMbrPartitions: Invalid MBR signature\n"));
    FreePool (Mbr);
    return EFI_DEVICE_ERROR;
  }

  // Process each partition entry
  PartCount = 0;
  for (Index = 0; Index < 4; Index++) {
    PartEntry = &Mbr->Partition[Index];
    
    // Skip empty partitions
    if (PartEntry->OSIndicator == 0x00) {
      continue;
    }

    // Process protective MBR for GPT
    if (PartEntry->OSIndicator == 0xEE) {
      BLOCKDEV_DEBUG ((DEBUG_INFO, "DetectMbrPartitions: Protective MBR for GPT detected\n"));
      FreePool (Mbr);
      return EFI_NOT_FOUND; // Return to let GPT handler process the disk
    }

    // Process extended partitions (not implemented for simplicity)
    if (PartEntry->OSIndicator == 0x05 || PartEntry->OSIndicator == 0x0F) {
      BLOCKDEV_DEBUG ((DEBUG_INFO, "DetectMbrPartitions: Extended partition detected (not supported yet)\n"));
      continue;
    }

    // Create a child BlockIo device for this partition
    BLOCK_IO_DEVICE *PartitionDevice;
    PartitionDevice = AllocateZeroPool (sizeof (BLOCK_IO_DEVICE));
    if (PartitionDevice == NULL) {
      BLOCKDEV_DEBUG ((DEBUG_ERROR, "DetectMbrPartitions: Out of resources\n"));
      FreePool (Mbr);
      return EFI_OUT_OF_RESOURCES;
    }

    // Set up the partition device
    CopyMem (PartitionDevice, BlockIoDevice, sizeof (BLOCK_IO_DEVICE));
    PartitionDevice->Media.LastBlock = PartEntry->TotalSectors - 1;
    PartitionDevice->Media.BlockSize = BlockSize;
    PartitionDevice->Media.ReadOnly = BlockIo->Media->ReadOnly;
    PartitionDevice->Media.LogicalPartition = TRUE;
    PartitionDevice->Media.MediaId = MediaId;
    PartitionDevice->StartingLBA = PartEntry->StartingSector;
    PartitionDevice->ParentDevicePath = ParentDevicePath;

    // Create device path for this partition
    DevicePath = CreateDeviceNode (
                   HARDWARE_DEVICE_PATH,
                   HW_VENDOR_DP,
                   (UINT16) sizeof (VENDOR_DEVICE_PATH)
                   );
    if (DevicePath == NULL) {
      BLOCKDEV_DEBUG ((DEBUG_ERROR, "DetectMbrPartitions: Failed to create device path\n"));
      FreePool (PartitionDevice);
      continue;
    }

    // Set the partition GUID based on the partition type
    VENDOR_DEVICE_PATH *VendorPath = (VENDOR_DEVICE_PATH *) DevicePath;
    switch (PartEntry->OSIndicator) {
      case MBR_TYPE_EFI_SYSTEM:
        CopyGuid (&VendorPath->Guid, &gEfiPartTypeSystemPartitionGuid);
        break;
      case MBR_TYPE_LINUX:
      case MBR_TYPE_LINUX_LVM:
      case MBR_TYPE_LINUX_SWAP:
      case MBR_TYPE_ANDROID_BOOT:
      case MBR_TYPE_ANDROID_SYSTEM:
      case MBR_TYPE_ANDROID_DATA:
      case MBR_TYPE_ANDROID_CACHE:
        // Create a unique GUID for each partition type
        VendorPath->Guid.Data1 = PartEntry->OSIndicator;
        VendorPath->Guid.Data2 = 0x1234;
        VendorPath->Guid.Data3 = 0x5678;
        VendorPath->Guid.Data4[0] = 0x99;
        VendorPath->Guid.Data4[1] = 0x88;
        VendorPath->Guid.Data4[2] = 0x77;
        VendorPath->Guid.Data4[3] = 0x66;
        VendorPath->Guid.Data4[4] = 0x55;
        VendorPath->Guid.Data4[5] = 0x44;
        VendorPath->Guid.Data4[6] = 0x33;
        VendorPath->Guid.Data4[7] = 0x22;
        break;
      default:
        CopyGuid (&VendorPath->Guid, &gEfiPartTypeLegacyMbrGuid);
        break;
    }

    // Append to parent device path
    PartitionDevice->DevicePath = AppendDevicePath (
                                    ParentDevicePath,
                                    DevicePath
                                    );
    FreePool (DevicePath);

    if (PartitionDevice->DevicePath == NULL) {
      BLOCKDEV_DEBUG ((DEBUG_ERROR, "DetectMbrPartitions: Failed to create full device path\n"));
      FreePool (PartitionDevice);
      continue;
    }

    // Install protocols
    Status = gBS->InstallMultipleProtocolInterfaces (
                    &PartitionHandle,
                    &gEfiBlockIoProtocolGuid,
                    &PartitionDevice->BlockIo,
                    &gEfiDevicePathProtocolGuid,
                    PartitionDevice->DevicePath,
                    NULL
                    );
    if (EFI_ERROR (Status)) {
      BLOCKDEV_DEBUG ((DEBUG_ERROR, "DetectMbrPartitions: Failed to install protocols: %r\n", Status));
      FreePool (PartitionDevice->DevicePath);
      FreePool (PartitionDevice);
      continue;
    }

    BLOCKDEV_DEBUG ((DEBUG_INFO, "DetectMbrPartitions: Installed MBR partition %d, type 0x%02x\n", 
                    Index, PartEntry->OSIndicator));
    PartCount++;
  }

  BLOCKDEV_DEBUG ((DEBUG_INFO, "DetectMbrPartitions: Detected %d MBR partitions\n", PartCount));
  FreePool (Mbr);
  return PartCount > 0 ? EFI_SUCCESS : EFI_NOT_FOUND;
}

/**
  Detect and process GPT partition table.

  @param  BlockIo              BlockIo interface.
  @param  ParentDevicePath     Device path of the parent device.
  @param  BlockIoDevice        Block device info structure.

  @retval EFI_SUCCESS          GPT detected and processed.
  @retval Others               Error occurred during detection.
**/
STATIC
EFI_STATUS
DetectGptPartitions (
  IN  EFI_BLOCK_IO_PROTOCOL     *BlockIo,
  IN  EFI_DEVICE_PATH_PROTOCOL  *ParentDevicePath,
  IN  BLOCK_IO_DEVICE           *BlockIoDevice
  )
{
  EFI_STATUS                  Status;
  EFI_PARTITION_TABLE_HEADER  *GptHeader;
  EFI_PARTITION_ENTRY         *PartEntries;
  UINT32                      BlockSize;
  UINT32                      MediaId;
  UINT32                      Index;
  UINT32                      PartCount;
  EFI_DEVICE_PATH_PROTOCOL    *DevicePath;
  EFI_HANDLE                  PartitionHandle;
  GPT_PARTITION_ENTRY         *PartInfo;

  BlockSize = BlockIo->Media->BlockSize;
  MediaId   = BlockIo->Media->MediaId;

  // Allocate buffer for GPT header
  GptHeader = AllocatePool (BlockSize);
  if (GptHeader == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  // Read and validate the GPT header
  Status = ReadGptHeader (BlockIo, GptHeader);
  if (EFI_ERROR (Status)) {
    BLOCKDEV_DEBUG ((DEBUG_ERROR, "DetectGptPartitions: GPT header validation failed: %r\n", Status));
    
    // Try alternative (backup) GPT header if primary fails
    if (BlockIo->Media->LastBlock > 0) {
      Status = BlockIo->ReadBlocks (
                          BlockIo,
                          MediaId,
                          BlockIo->Media->LastBlock,
                          BlockSize,
                          GptHeader
                          );
      if (EFI_ERROR (Status)) {
        BLOCKDEV_DEBUG ((DEBUG_ERROR, "DetectGptPartitions: Failed to read backup GPT header: %r\n", Status));
        FreePool (GptHeader);
        return Status;
      }
      
      // Validate backup header
      if (GptHeader->Header.Signature != GPT_SIGNATURE) {
        BLOCKDEV_DEBUG ((DEBUG_ERROR, "DetectGptPartitions: Invalid backup GPT signature\n"));
        FreePool (GptHeader);
        return EFI_DEVICE_ERROR;
      }
    } else {
      FreePool (GptHeader);
      return Status;
    }
  }

  // Allocate buffer for partition entries
  UINTN EntriesSize = GptHeader->NumberOfPartitionEntries * GptHeader->SizeOfPartitionEntry;
  PartEntries = AllocatePool (EntriesSize);
  if (PartEntries == NULL) {
    FreePool (GptHeader);
    return EFI_OUT_OF_RESOURCES;
  }

  // Read the partition entries
  Status = ReadGptPartitionEntries (BlockIo, GptHeader, PartEntries);
  if (EFI_ERROR (Status)) {
    BLOCKDEV_DEBUG ((DEBUG_ERROR, "DetectGptPartitions: Failed to read partition entries: %r\n", Status));
    
    // Try reading from backup if primary fails
    if (BlockIo->Media->LastBlock > 0) {
      EFI_LBA BackupEntryLBA = GptHeader->AlternateLBA - 
                               (GptHeader->NumberOfPartitionEntries * GptHeader->SizeOfPartitionEntry + BlockSize - 1) / BlockSize;
      
      Status = BlockIo->ReadBlocks (
                          BlockIo,
                          MediaId,
                          BackupEntryLBA,
                          EntriesSize,
                          PartEntries
                          );
      if (EFI_ERROR (Status)) {
        BLOCKDEV_DEBUG ((DEBUG_ERROR, "DetectGptPartitions: Failed to read backup partition entries: %r\n", Status));
        FreePool (PartEntries);
        FreePool (GptHeader);
        return Status;
      }
    } else {
      FreePool (PartEntries);
      FreePool (GptHeader);
      return Status;
    }
  }

  // Process valid partition entries
  PartCount = 0;
  PartInfo = AllocateZeroPool (sizeof (GPT_PARTITION_ENTRY) * GptHeader->NumberOfPartitionEntries);
  if (PartInfo == NULL) {
    FreePool (PartEntries);
    FreePool (GptHeader);
    return EFI_OUT_OF_RESOURCES;
  }

  // First pass: collect all partition information
  for (Index = 0; Index < GptHeader->NumberOfPartitionEntries; Index++) {
    EFI_PARTITION_ENTRY *Entry = (EFI_PARTITION_ENTRY *)((UINT8 *)PartEntries + Index * GptHeader->SizeOfPartitionEntry);
    
    // Check if this is an empty entry
    if (CompareGuid (&Entry->PartitionTypeGUID, &gEfiPartTypeUnusedGuid)) {
      continue;
    }

    // Store the partition information
    PartInfo[PartCount].StartingLBA = Entry->StartingLBA;
    PartInfo[PartCount].EndingLBA = Entry->EndingLBA;
    CopyGuid (&PartInfo[PartCount].PartitionTypeGUID, &Entry->PartitionTypeGUID);
    CopyGuid (&PartInfo[PartCount].UniquePartitionGUID, &Entry->UniquePartitionGUID);
    
    // Copy partition name (ensure proper null-termination)
    CopyMem (PartInfo[PartCount].PartitionName, Entry->PartitionName, sizeof (Entry->PartitionName));
    PartInfo[PartInfo[PartCount].IsValid = TRUE;

    BLOCKDEV_DEBUG ((DEBUG_INFO, "DetectGptPartitions: Found partition %d: %s\n", 
                     PartCount, PartInfo[PartCount].PartitionName));
    PartCount++;
  }

  BLOCKDEV_DEBUG ((DEBUG_INFO, "DetectGptPartitions: Detected %d GPT partitions\n", PartCount));

  // Second pass: create partition devices
  for (Index = 0; Index < PartCount; Index++) {
    if (!PartInfo[Index].IsValid) {
      continue;
    }

    // Create a child BlockIo device for this partition
    BLOCK_IO_DEVICE *PartitionDevice;
    PartitionDevice = AllocateZeroPool (sizeof (BLOCK_IO_DEVICE));
    if (PartitionDevice == NULL) {
      BLOCKDEV_DEBUG ((DEBUG_ERROR, "DetectGptPartitions: Out of resources\n"));
      continue;
    }

    // Set up the partition device
    CopyMem (PartitionDevice, BlockIoDevice, sizeof (BLOCK_IO_DEVICE));
    PartitionDevice->Media.LastBlock = PartInfo[Index].EndingLBA - PartInfo[Index].StartingLBA;
    PartitionDevice->Media.BlockSize = BlockSize;
    PartitionDevice->Media.ReadOnly = BlockIo->Media->ReadOnly;
    PartitionDevice->Media.LogicalPartition = TRUE;
    PartitionDevice->Media.MediaId = MediaId;
    PartitionDevice->StartingLBA = PartInfo[Index].StartingLBA;
    PartitionDevice->ParentDevicePath = ParentDevicePath;

    // Create device path for this partition
    DevicePath = CreateDeviceNode (
                   MEDIA_DEVICE_PATH,
                   MEDIA_HARDDRIVE_DP,
                   (UINT16) sizeof (HARDDRIVE_DEVICE_PATH)
                   );
    if (DevicePath == NULL) {
      BLOCKDEV_DEBUG ((DEBUG_ERROR, "DetectGptPartitions: Failed to create device path\n"));
      FreePool (PartitionDevice);
      continue;
    }

    // Set up the partition device path
    HARDDRIVE_DEVICE_PATH *HardDrivePath = (HARDDRIVE_DEVICE_PATH *) DevicePath;
    HardDrivePath->PartitionNumber = Index + 1;
    HardDrivePath->PartitionStart = PartInfo[Index].StartingLBA;
    HardDrivePath->PartitionSize = PartInfo[Index].EndingLBA - PartInfo[Index].StartingLBA + 1;
    HardDrivePath->MBRType = MBR_TYPE_EFI_PARTITION_TABLE_HEADER;
    HardDrivePath->SignatureType = SIGNATURE_TYPE_GUID;
    CopyMem (HardDrivePath->Signature, &PartInfo[Index].UniquePartitionGUID, sizeof (EFI_GUID));

    // Append to parent device path
    PartitionDevice->DevicePath = AppendDevicePath (
                                    ParentDevicePath,
                                    DevicePath
                                    );
    FreePool (DevicePath);

    if (PartitionDevice->DevicePath == NULL) {
      BLOCKDEV_DEBUG ((DEBUG_ERROR, "DetectGptPartitions: Failed to create full device path\n"));
      FreePool (PartitionDevice);
      continue;
    }

    // Debug log the partition details
    BLOCKDEV_DEBUG ((DEBUG_INFO, "DetectGptPartitions: Installing partition %d:\n", Index + 1));
    BLOCKDEV_DEBUG ((DEBUG_INFO, "  Name: %s\n", PartInfo[Index].PartitionName));
    BLOCKDEV_DEBUG ((DEBUG_INFO, "  Start LBA: 0x%lx, End LBA: 0x%lx\n", 
                    PartInfo[Index].StartingLBA, PartInfo[Index].EndingLBA));
    BLOCKDEV_DEBUG ((DEBUG_INFO, "  Type: %g\n", &PartInfo[Index].PartitionTypeGUID));
    BLOCKDEV_DEBUG ((DEBUG_INFO, "  GUID: %g\n", &PartInfo[Index].UniquePartitionGUID));

    // Install protocols
    Status = gBS->InstallMultipleProtocolInterfaces (
                    &PartitionHandle,
                    &gEfiBlockIoProtocolGuid,
                    &PartitionDevice->BlockIo,
                    &gEfiDevicePathProtocolGuid,
                    PartitionDevice->DevicePath,
                    NULL
                    );
    if (EFI_ERROR (Status)) {
      BLOCKDEV_DEBUG ((DEBUG_ERROR, "DetectGptPartitions: Failed to install protocols: %r\n", Status));
      FreePool (PartitionDevice->DevicePath);
      FreePool (PartitionDevice);
      continue;
    }
  }

  FreePool (PartInfo);
  FreePool (PartEntries);
  FreePool (GptHeader);
  return PartCount > 0 ? EFI_SUCCESS : EFI_NOT_FOUND;
}

/**
  Detect and handle partitions on the block device.

  @param  BlockIo              BlockIo interface.
  @param  DevicePath           Device path of the device.
  @param  BlockIoDevice        Block device info structure.

  @retval EFI_SUCCESS          Partitions detected and handled.
  @retval Others               Error occurred during detection.
**/
STATIC
EFI_STATUS
DetectPartitions (
  IN  EFI_BLOCK_IO_PROTOCOL     *BlockIo,
  IN  EFI_DEVICE_PATH_PROTOCOL  *DevicePath,
  IN  BLOCK_IO_DEVICE           *BlockIoDevice
  )
{
  EFI_STATUS Status;

  BLOCKDEV_DEBUG ((DEBUG_INFO, "DetectPartitions: Scanning for partitions...\n"));

  // First try to detect GPT partitions
  Status = DetectGptPartitions (BlockIo, DevicePath, BlockIoDevice);
  if (!EFI_ERROR (Status)) {
    BLOCKDEV_DEBUG ((DEBUG_INFO, "DetectPartitions: GPT partitions detected\n"));
    return EFI_SUCCESS;
  }

  // Fall back to MBR partitions if GPT detection fails
  Status = DetectMbrPartitions (BlockIo, DevicePath, BlockIoDevice);
  if (!EFI_ERROR (Status)) {
    BLOCKDEV_DEBUG ((DEBUG_INFO, "DetectPartitions: MBR partitions detected\n"));
    return EFI_SUCCESS;
  }

  // No partitions detected
  BLOCKDEV_DEBUG ((DEBUG_INFO, "DetectPartitions: No partitions detected\n"));
  return EFI_NOT_FOUND;
}

/**
  Reset the Block Device.

  @param  This                 Block IO protocol instance.
  @param  ExtendedVerification Indicates that the driver may perform a more
                               exhaustive verification operation of the device.

  @retval EFI_SUCCESS          The device was reset.
  @retval EFI_DEVICE_ERROR     The device is not functioning properly.

**/
STATIC
EFI_STATUS
EFIAPI
BlockIoReset (
  IN EFI_BLOCK_IO_PROTOCOL *This,
  IN BOOLEAN               ExtendedVerification
  )
{
  BLOCK_IO_DEVICE    *BlockIoDevice;
  
  BlockIoDevice = BLOCK_IO_DEVICE_FROM_BLOCK_IO_THIS (This);
  
  if (BlockIoDevice->Media.LogicalPartition) {
    // For logical partitions, forward the reset to the parent BlockIo
    EFI_BLOCK_IO_PROTOCOL *ParentBlockIo;
    EFI_STATUS Status;
    
    Status = gBS->HandleProtocol (
                    BlockIoDevice->ControllerHandle,
                    &gEfiBlockIoProtocolGuid,
                    (VOID **) &ParentBlockIo
                    );
    if (EFI_ERROR (Status)) {
      return Status;
    }
    
    return ParentBlockIo->Reset (ParentBlockIo, ExtendedVerification);
  }
  
  return EFI_SUCCESS;
}

/**
  Read BufferSize bytes from Lba into Buffer.

  @param  This                 Protocol instance pointer.
  @param  MediaId              Id of the media, changes every time the media is replaced.
  @param  Lba                  The starting Logical Block Address to read from.
  @param  BufferSize           Size of Buffer, must be a multiple of device block size.
  @param  Buffer               A pointer to the destination buffer for the data.

  @retval EFI_SUCCESS          The data was read correctly from the device.
  @retval EFI_DEVICE_ERROR     The device reported an error while performing the read.
  @retval EFI_NO_MEDIA         There is no media in the device.
  @retval EFI_MEDIA_CHANGED    The MediaId does not match the current device.
  @retval EFI_BAD_BUFFER_SIZE  The Buffer was not a multiple of the block size of the device.
  @retval EFI_INVALID_PARAMETER The read request contains LBAs that are not valid,
                               or the buffer is not properly aligned.

**/
STATIC
EFI_STATUS
EFIAPI
BlockIoReadBlocks (
  IN  EFI_BLOCK_IO_PROTOCOL *This,
  IN  UINT32                MediaId,
  IN  EFI_LBA               Lba,
  IN  UINTN                 BufferSize,
  OUT VOID                  *Buffer
  )
{
  BLOCK_IO_DEVICE    *BlockIoDevice;
  EFI_BLOCK_IO_PROTOCOL *ParentBlockIo;
  EFI_STATUS         Status;
  
  if (This == NULL || Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  BlockIoDevice = BLOCK_IO_DEVICE_FROM_BLOCK_IO_THIS (This);
  
  if (MediaId != BlockIoDevice->Media.MediaId) {
    return EFI_MEDIA_CHANGED;
  }
  
  if (BufferSize % BlockIoDevice->Media.BlockSize != 0) {
    return EFI_BAD_BUFFER_SIZE;
  }
  
  if (Lba > BlockIoDevice->Media.LastBlock) {
    return EFI_INVALID_PARAMETER;
  }

  if (BufferSize == 0) {
    return EFI_SUCCESS;
  }

  // Calculate blocks to read
  UINTN BlockCount = BufferSize / BlockIoDevice->Media.BlockSize;
  
  // For logical partitions, adjust LBA and use parent BlockIo
  if (BlockIoDevice->Media.LogicalPartition) {
    Status = gBS->HandleProtocol (
                    BlockIoDevice->ControllerHandle,
                    &gEfiBlockIoProtocolGuid,
                    (VOID **) &ParentBlockIo
                    );
    if (EFI_ERROR (Status)) {
      return Status;
    }
    
    EFI_LBA ParentLba = Lba + BlockIoDevice->StartingLBA;
    
    return ParentBlockIo->ReadBlocks (
                            ParentBlockIo,
                            ParentBlockIo->Media->MediaId,
                            ParentLba,
                            BufferSize,
                            Buffer
                            );
  }
  
  // For physical devices, forward the request to the device-specific implementation
  Status = BlockIoDevice->StorageDeviceReadBlocks (
                            BlockIoDevice,
                            MediaId,
                            Lba,
                            BufferSize,
                            Buffer
                            );
  
  return Status;
}

/**
  Write BufferSize bytes from Lba into Buffer.

  @param  This                 Protocol instance pointer.
  @param  MediaId              The media ID that the write request is for.
  @param  Lba                  The starting logical block address to be written.
  @param  BufferSize           Size of Buffer, must be a multiple of device block size.
  @param  Buffer               A pointer to the source buffer for the data.

  @retval EFI_SUCCESS          The data was written correctly to the device.
  @retval EFI_DEVICE_ERROR     The device reported an error while performing the write.
  @retval EFI_NO_MEDIA         There is no media in the device.
  @retval EFI_MEDIA_CHANGED    The MediaId does not match the current device.
  @retval EFI_BAD_BUFFER_SIZE  The Buffer was not a multiple of the block size of the device.
  @retval EFI_INVALID_PARAMETER The write request contains LBAs that are not valid,
                               or the buffer is not properly aligned.

**/
STATIC
EFI_STATUS
EFIAPI
BlockIoWriteBlocks (
  IN EFI_BLOCK_IO_PROTOCOL *This,
  IN UINT32                MediaId,
  IN EFI_LBA               Lba,
  IN UINTN                 BufferSize,
  IN VOID                  *Buffer
  )
{
  BLOCK_IO_DEVICE    *BlockIoDevice;
  EFI_BLOCK_IO_PROTOCOL *ParentBlockIo;
  EFI_STATUS         Status;
  
  if (This == NULL || Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  BlockIoDevice = BLOCK_IO_DEVICE_FROM_BLOCK_IO_THIS (This);
  
  if (MediaId != BlockIoDevice->Media.MediaId) {
    return EFI_MEDIA_CHANGED;
  }
  
  if (BufferSize % BlockIoDevice->Media.BlockSize != 0) {
    return EFI_BAD_BUFFER_SIZE;
  }
  
  if (Lba > BlockIoDevice->Media.LastBlock) {
    return EFI_INVALID_PARAMETER;
  }
  
  if (BlockIoDevice->Media.ReadOnly) {
    return EFI_WRITE_PROTECTED;
  }

  if (BufferSize == 0) {
    return EFI_SUCCESS;
  }

  // For logical partitions, adjust LBA and use parent BlockIo
  if (BlockIoDevice->Media.LogicalPartition) {
    Status = gBS->HandleProtocol (
                    BlockIoDevice->ControllerHandle,
                    &gEfiBlockIoProtocolGuid,
                    (VOID **) &ParentBlockIo
                    );
    if (EFI_ERROR (Status)) {
      return Status;
    }
    
    EFI_LBA ParentLba = Lba + BlockIoDevice->StartingLBA;
    
    return ParentBlockIo->WriteBlocks (
                             ParentBlockIo,
                             ParentBlockIo->Media->MediaId,
                             ParentLba,
                             BufferSize,
                             Buffer
                             );
  }
  
  // For physical devices, forward the request to the device-specific implementation
  Status = BlockIoDevice->StorageDeviceWriteBlocks (
                            BlockIoDevice,
                            MediaId,
                            Lba,
                            BufferSize,
                            Buffer
                            );
  
  return Status;
}

/**
  Flush the Block Device.

  @param  This                 Protocol instance pointer.

  @retval EFI_SUCCESS          All outstanding data was written to the device.
  @retval EFI_DEVICE_ERROR     The device reported an error while writing back the data.
  @retval EFI_NO_MEDIA         There is no media in the device.

**/
STATIC
EFI_STATUS
EFIAPI
BlockIoFlushBlocks (
  IN EFI_BLOCK_IO_PROTOCOL *This
  )
{
  BLOCK_IO_DEVICE    *BlockIoDevice;
  EFI_BLOCK_IO_PROTOCOL *ParentBlockIo;
  EFI_STATUS         Status;
  
  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  BlockIoDevice = BLOCK_IO_DEVICE_FROM_BLOCK_IO_THIS (This);
  
  // For logical partitions, forward the flush to the parent BlockIo
  if (BlockIoDevice->Media.LogicalPartition) {
    Status = gBS->HandleProtocol (
                    BlockIoDevice->ControllerHandle,
                    &gEfiBlockIoProtocolGuid,
                    (VOID **) &ParentBlockIo
                    );
    if (EFI_ERROR (Status)) {
      return Status;
    }
    
    return ParentBlockIo->FlushBlocks (ParentBlockIo);
  }
  
  // For physical devices, forward the request to the device-specific implementation
  if (BlockIoDevice->StorageDeviceFlushBlocks != NULL) {
    Status = BlockIoDevice->StorageDeviceFlushBlocks (BlockIoDevice);
    return Status;
  }
  
  return EFI_SUCCESS;
}

/**
  Test to see if this driver supports the given controller.

  @param  This                 A pointer to the EFI_DRIVER_BINDING_PROTOCOL instance.
  @param  ControllerHandle     The handle of the controller to test.
  @param  RemainingDevicePath  A pointer to the remaining portion of a device path.

  @retval EFI_SUCCESS          This driver can support the given controller
  @retval Others               This driver cannot support the given controller

**/
STATIC
EFI_STATUS
EFIAPI
BlockDeviceDriverSupported (
  IN EFI_DRIVER_BINDING_PROTOCOL *This,
  IN EFI_HANDLE                  ControllerHandle,
  IN EFI_DEVICE_PATH_PROTOCOL    *RemainingDevicePath OPTIONAL
  )
{
  EFI_STATUS          Status;
  SDHC_PROTOCOL       *SdhcProtocol;

  // Check if SDHC protocol is supported
  Status = gBS->OpenProtocol (
                  ControllerHandle,
                  &gSdhcProtocolGuid,
                  (VOID **) &SdhcProtocol,
                  This->DriverBindingHandle,
                  ControllerHandle,
                  EFI_OPEN_PROTOCOL_BY_DRIVER
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // Close the protocol as we're just checking for its presence
  gBS->CloseProtocol (
         ControllerHandle,
         &gSdhcProtocolGuid,
         This->DriverBindingHandle,
         ControllerHandle
         );

  return EFI_SUCCESS;
}

/**
  Start this driver on the given controller.

  @param  This                 A pointer to the EFI_DRIVER_BINDING_PROTOCOL instance.
  @param  ControllerHandle     The handle of the controller to start.
  @param  RemainingDevicePath  A pointer to the remaining portion of a device path.

  @retval EFI_SUCCESS          This driver is started on ControllerHandle.
  @retval Others               This driver is not started on ControllerHandle.

**/
STATIC
EFI_STATUS
EFIAPI
BlockDeviceDriverStart (
  IN EFI_DRIVER_BINDING_PROTOCOL *This,
  IN EFI_HANDLE                  ControllerHandle,
  IN EFI_DEVICE_PATH_PROTOCOL    *RemainingDevicePath OPTIONAL
  )
{
  EFI_STATUS                Status;
  SDHC_PROTOCOL             *SdhcProtocol;
  BLOCK_IO_DEVICE           *BlockIoDevice;
  EFI_DEVICE_PATH_PROTOCOL  *DevicePath;

  // Open SDHC protocol
  Status = gBS->OpenProtocol (
                  ControllerHandle,
                  &gSdhcProtocolGuid,
                  (VOID **) &SdhcProtocol,
                  This->DriverBindingHandle,
                  ControllerHandle,
                  EFI_OPEN_PROTOCOL_BY_DRIVER
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // Get the device path
  Status = gBS->OpenProtocol (
                  ControllerHandle,
                  &gEfiDevicePathProtocolGuid,
                  (VOID **) &DevicePath,
                  This->DriverBindingHandle,
                  ControllerHandle,
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL
                  );
  if (EFI_ERROR (Status)) {
    DevicePath = NULL;
  }

  // Allocate device instance
  BlockIoDevice = AllocateZeroPool (sizeof (BLOCK_IO_DEVICE));
  if (BlockIoDevice == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto ErrorExit;
  }

  // Initialize the block device
  BlockIoDevice->Signature = BLOCK_IO_DEVICE_SIGNATURE;
  BlockIoDevice->ControllerHandle = ControllerHandle;

  // Copy BlockIo protocol template
  CopyMem (&BlockIoDevice->BlockIo, &mBlockIoProtocol, sizeof (EFI_BLOCK_IO_PROTOCOL));
  
  // Set Media pointer
  BlockIoDevice->BlockIo.Media = &BlockIoDevice->Media;
  
  // Set up the storage device
  Status = SdhcInitialize (SdhcProtocol, BlockIoDevice);
  if (EFI_ERROR (Status)) {
    BLOCKDEV_DEBUG ((DEBUG_ERROR, "BlockDeviceDriverStart: Failed to initialize SDHC device: %r\n", Status));
    goto ErrorExit;
  }

  // Create a device path for this device
  if (DevicePath != NULL) {
    BlockIoDevice->DevicePath = DuplicateDevicePath (DevicePath);
    if (BlockIoDevice->DevicePath == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto ErrorExit;
    }
  } else {
    // Create a minimal device path
    BlockIoDevice->DevicePath = CreateDeviceNode (
                                  HARDWARE_DEVICE_PATH,
                                  HW_VENDOR_DP,
                                  (UINT16) sizeof (VENDOR_DEVICE_PATH)
                                  );
    if (BlockIoDevice->DevicePath == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto ErrorExit;
    }
    
    // Set a unique GUID for the device
    VENDOR_DEVICE_PATH *VendorPath = (VENDOR_DEVICE_PATH *) BlockIoDevice->DevicePath;
    VendorPath->Guid.Data1 = 0xB25C2A96;
    VendorPath->Guid.Data2 = 0xD146;
    VendorPath->Guid.Data3 = 0x4376;
    VendorPath->Guid.Data4[0] = 0xBD;
    VendorPath->Guid.Data4[1] = 0x6D;
    VendorPath->Guid.Data4[2] = 0x4A;
    VendorPath->Guid.Data4[3] = 0x96;
    VendorPath->Guid.Data4[4] = 0xC3;
    VendorPath->Guid.Data4[5] = 0x25;
    VendorPath->Guid.Data4[6] = 0xF5;
    VendorPath->Guid.Data4[7] = 0xE6;
  }

  // Install protocols
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &ControllerHandle,
                  &gEfiBlockIoProtocolGuid,
                  &BlockIoDevice->BlockIo,
                  &gEfiDevicePathProtocolGuid,
                  BlockIoDevice->DevicePath,
                  NULL
                  );
  if (EFI_ERROR (Status)) {
    BLOCKDEV_DEBUG ((DEBUG_ERROR, "BlockDeviceDriverStart: Failed to install protocols: %r\n", Status));
    goto ErrorExit;
  }

  // Detect and handle partitions
  Status = DetectPartitions (
             &BlockIoDevice->BlockIo,
             BlockIoDevice->DevicePath,
             BlockIoDevice
             );
  if (EFI_ERROR (Status) && Status != EFI_NOT_FOUND) {
    BLOCKDEV_DEBUG ((DEBUG_WARN, "BlockDeviceDriverStart: Partition detection failed: %r\n", Status));
    // Continue anyway - we still have the base block device
  }

  BLOCKDEV_DEBUG ((DEBUG_INFO, "BlockDeviceDriverStart: Block device driver started successfully\n"));
  return EFI_SUCCESS;

ErrorExit:
  if (BlockIoDevice != NULL) {
    if (BlockIoDevice->DevicePath != NULL) {
      FreePool (BlockIoDevice->DevicePath);
    }
    FreePool (BlockIoDevice);
  }
  
  gBS->CloseProtocol (
         ControllerHandle,
         &gSdhcProtocolGuid,
         This->DriverBindingHandle,
         ControllerHandle
         );
  
  return Status;
}

/**
  Stop this driver on ControllerHandle.

  @param  This                 A pointer to the EFI_DRIVER_BINDING_PROTOCOL instance.
  @param  ControllerHandle     The handle of the controller to stop.
  @param  NumberOfChildren     The number of child device handles in ChildHandleBuffer.
  @param  ChildHandleBuffer    An array of child handles to be freed.

  @retval EFI_SUCCESS          This driver is removed from ControllerHandle.
  @retval Others               This driver was not removed from ControllerHandle.

**/
STATIC
EFI_STATUS
EFIAPI
BlockDeviceDriverStop (
  IN  EFI_DRIVER_BINDING_PROTOCOL *This,
  IN  EFI_HANDLE                  ControllerHandle,
  IN  UINTN                       NumberOfChildren,
  IN  EFI_HANDLE                  *ChildHandleBuffer
  )
{
  EFI_STATUS                Status;
  EFI_BLOCK_IO_PROTOCOL     *BlockIo;
  BLOCK_IO_DEVICE           *BlockIoDevice;
  UINTN                     Index;

  // Close all child handles first
  for (Index = 0; Index < NumberOfChildren; Index++) {
    Status = gBS->OpenProtocol (
                    ChildHandleBuffer[Index],
                    &gEfiBlockIoProtocolGuid,
                    (VOID **) &BlockIo,
                    This->DriverBindingHandle,
                    ControllerHandle,
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL
                    );
    if (EFI_ERROR (Status)) {
      continue;
    }

    BlockIoDevice = BLOCK_IO_DEVICE_FROM_BLOCK_IO_THIS (BlockIo);

    Status = gBS->UninstallMultipleProtocolInterfaces (
                    ChildHandleBuffer[Index],
                    &gEfiBlockIoProtocolGuid,
                    &BlockIoDevice->BlockIo,
                    &gEfiDevicePathProtocolGuid,
                    BlockIoDevice->DevicePath,
                    NULL
                    );
    if (EFI_ERROR (Status)) {
      continue;
    }

    FreePool (BlockIoDevice->DevicePath);
    FreePool (BlockIoDevice);
  }

  // Now close the controller handle
  Status = gBS->OpenProtocol (
                  ControllerHandle,
                  &gEfiBlockIoProtocolGuid,
                  (VOID **) &BlockIo,
                  This->DriverBindingHandle,
                  ControllerHandle,
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL
                  );
  if (!EFI_ERROR (Status)) {
    BlockIoDevice = BLOCK_IO_DEVICE_FROM_BLOCK_IO_THIS (BlockIo);

    Status = gBS->UninstallMultipleProtocolInterfaces (
                    ControllerHandle,
                    &gEfiBlockIoProtocolGuid,
                    &BlockIoDevice->BlockIo,
                    &gEfiDevicePathProtocolGuid,
                    BlockIoDevice->DevicePath,
                    NULL
                    );
    if (!EFI_ERROR (Status)) {
      FreePool (BlockIoDevice->DevicePath);
      FreePool (BlockIoDevice);
    }
  }

  // Close SDHC protocol
  gBS->CloseProtocol (
         ControllerHandle,
         &gSdhcProtocolGuid,
         This->DriverBindingHandle,
         ControllerHandle
         );

  return EFI_SUCCESS;
}

/**
  Initialize SDHC device.

  @param  SdhcProtocol         Pointer to the SDHC protocol instance.
  @param  BlockIoDevice        Block device info structure.

  @retval EFI_SUCCESS          The SDHC device was initialized successfully.
  @retval Others               The SDHC device failed to initialize.
**/
EFI_STATUS
SdhcInitialize (
  IN  SDHC_PROTOCOL     *SdhcProtocol,
  IN  BLOCK_IO_DEVICE   *BlockIoDevice
  )
{
  EFI_STATUS  Status;
  UINT64      CardSize;
  UINT32      BlockSize;
  
  // Initialize the SD card
  Status = SdhcProtocol->Initialize (SdhcProtocol);
  if (EFI_ERROR (Status)) {
    BLOCKDEV_DEBUG ((DEBUG_ERROR, "SdhcInitialize: SD card initialization failed: %r\n", Status));
    return Status;
  }
  
  // Get card information
  Status = SdhcProtocol->GetCardInfo (
                           SdhcProtocol,
                           &CardSize,
                           &BlockSize
                           );
  if (EFI_ERROR (Status)) {
    BLOCKDEV_DEBUG ((DEBUG_ERROR, "SdhcInitialize: Failed to get card info: %r\n", Status));
    return Status;
  }
  
  // Set up media info
  BlockIoDevice->Media.MediaId = 1;
  BlockIoDevice->Media.RemovableMedia = TRUE;
  BlockIoDevice->Media.MediaPresent = TRUE;
  BlockIoDevice->Media.LogicalPartition = FALSE;
  BlockIoDevice->Media.ReadOnly = FALSE;
  BlockIoDevice->Media.WriteCaching = FALSE;
  BlockIoDevice->Media.BlockSize = BlockSize;
  BlockIoDevice->Media.IoAlign = 4;  // 4 byte alignment
  BlockIoDevice->Media.LastBlock = DivU64x32 (CardSize, BlockSize) - 1;
  
  // Set up device-specific functions
  BlockIoDevice->StorageDeviceReadBlocks = SdhcReadBlocks;
  BlockIoDevice->StorageDeviceWriteBlocks = SdhcWriteBlocks;
  BlockIoDevice->StorageDeviceFlushBlocks = SdhcFlushBlocks;
  
  // Save protocol for later use
  BlockIoDevice->SdhcProtocol = SdhcProtocol;
  
  BLOCKDEV_DEBUG ((DEBUG_INFO, "SdhcInitialize: SD card initialized successfully\n"));
  BLOCKDEV_DEBUG((DEBUG_INFO, "SdhcInitialize: Card size: %ld bytes, block size: %d bytes, last block: %ld\n", 
               CardSize, BlockSize, BlockIoDevice->Media.LastBlock));
  
  return EFI_SUCCESS;
}

/**
  Read blocks from SDHC device.

  @param  BlockIoDevice        Block device info structure.
  @param  MediaId              The media ID.
  @param  Lba                  The logical block address to read from.
  @param  BufferSize           Size of the buffer to read.
  @param  Buffer               Buffer to receive the read data.

  @retval EFI_SUCCESS          The data was read successfully.
  @retval Others               The read operation failed.
**/
EFI_STATUS
SdhcReadBlocks (
  IN  BLOCK_IO_DEVICE   *BlockIoDevice,
  IN  UINT32            MediaId,
  IN  EFI_LBA           Lba,
  IN  UINTN             BufferSize,
  OUT VOID              *Buffer
  )
{
  EFI_STATUS      Status;
  SDHC_PROTOCOL   *SdhcProtocol;
  UINT32          NumBlocks;
  
  if (Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  if (MediaId != BlockIoDevice->Media.MediaId) {
    return EFI_MEDIA_CHANGED;
  }
  
  if (Lba > BlockIoDevice->Media.LastBlock) {
    return EFI_INVALID_PARAMETER;
  }
  
  if (BufferSize % BlockIoDevice->Media.BlockSize != 0) {
    return EFI_BAD_BUFFER_SIZE;
  }
  
  SdhcProtocol = BlockIoDevice->SdhcProtocol;
  NumBlocks = (UINT32)(BufferSize / BlockIoDevice->Media.BlockSize);
  
  BLOCKDEV_DEBUG ((DEBUG_INFO, "SdhcReadBlocks: Reading %d blocks from LBA 0x%lx\n", NumBlocks, Lba));
  
  Status = SdhcProtocol->ReadBlocks (
                           SdhcProtocol,
                           (UINT32)Lba,
                           NumBlocks,
                           Buffer
                           );
  
  return Status;
}

/**
  Write blocks to SDHC device.

  @param  BlockIoDevice        Block device info structure.
  @param  MediaId              The media ID.
  @param  Lba                  The logical block address to write to.
  @param  BufferSize           Size of the buffer to write.
  @param  Buffer               Buffer containing the data to write.

  @retval EFI_SUCCESS          The data was written successfully.
  @retval Others               The write operation failed.
**/
EFI_STATUS
SdhcWriteBlocks (
  IN  BLOCK_IO_DEVICE   *BlockIoDevice,
  IN  UINT32            MediaId,
  IN  EFI_LBA           Lba,
  IN  UINTN             BufferSize,
  IN  VOID              *Buffer
  )
{
  EFI_STATUS      Status;
  SDHC_PROTOCOL   *SdhcProtocol;
  UINT32          NumBlocks;
  
  if (Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  if (MediaId != BlockIoDevice->Media.MediaId) {
    return EFI_MEDIA_CHANGED;
  }
  
  if (Lba > BlockIoDevice->Media.LastBlock) {
    return EFI_INVALID_PARAMETER;
  }
  
  if (BufferSize % BlockIoDevice->Media.BlockSize != 0) {
    return EFI_BAD_BUFFER_SIZE;
  }
  
  if (BlockIoDevice->Media.ReadOnly) {
    return EFI_WRITE_PROTECTED;
  }
  
  SdhcProtocol = BlockIoDevice->SdhcProtocol;
  NumBlocks = (UINT32)(BufferSize / BlockIoDevice->Media.BlockSize);
  
  BLOCKDEV_DEBUG ((DEBUG_INFO, "SdhcWriteBlocks: Writing %d blocks to LBA 0x%lx\n", NumBlocks, Lba));
  
  Status = SdhcProtocol->WriteBlocks (
                            SdhcProtocol,
                            (UINT32)Lba,
                            NumBlocks,
                            Buffer
                            );
  
  return Status;
}

/**
  Flush blocks on SDHC device.

  @param  BlockIoDevice        Block device info structure.

  @retval EFI_SUCCESS          The blocks were flushed successfully.
  @retval Others               The flush operation failed.
**/
EFI_STATUS
SdhcFlushBlocks (
  IN  BLOCK_IO_DEVICE   *BlockIoDevice
  )
{
  // Most SD cards don't require explicit flush
  return EFI_SUCCESS;
}

/**
  Entry point for the Block Device driver.

  @param  ImageHandle          Image handle.
  @param  SystemTable          Pointer to the system table.

  @retval EFI_SUCCESS          Driver loaded successfully.
  @retval Others               Failed to load driver.
**/
EFI_STATUS
EFIAPI
BlockDeviceDxeInitialize (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  // Set driver binding information
  mDriverBinding.ImageHandle = ImageHandle;
  mDriverBinding.DriverBindingHandle = ImageHandle;

  // Install driver binding protocol
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &ImageHandle,
                  &gEfiDriverBindingProtocolGuid,
                  &mDriverBinding,
                  NULL
                  );

  BLOCKDEV_DEBUG ((DEBUG_INFO, "BlockDeviceDxeInitialize: Driver initialized with status %r\n", Status));
  return Status;
}