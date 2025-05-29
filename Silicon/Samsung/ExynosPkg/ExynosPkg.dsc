# Samsung Exynos Platform Package
#
# Copyright (c) 2023-2024, EDK2 Contributors
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

[Defines]
  PLATFORM_NAME                  = ExynosPkg
  PLATFORM_GUID                  = 4eb79aad-4c90-41db-a266-13c35b567a54
  PLATFORM_VERSION               = 0.1
  DSC_SPECIFICATION              = 0x0001001A
  OUTPUT_DIRECTORY               = Build/Exynos
  SUPPORTED_ARCHITECTURES        = AARCH64
  BUILD_TARGETS                  = DEBUG|RELEASE
  SKUID_IDENTIFIER               = DEFAULT

[LibraryClasses]
  # ARM standard libraries
  ArmLib|ArmPkg/Library/ArmLib/ArmBaseLib.inf
  ArmPlatformLib|ArmPlatformPkg/Library/ArmPlatformLibNull/ArmPlatformLibNull.inf
  ArmMmuLib|ArmPkg/Library/ArmMmuLib/ArmMmuBaseLib.inf
  ArmSmcLib|ArmPkg/Library/ArmSmcLib/ArmSmcLib.inf
  ArmDisassemblerLib|ArmPkg/Library/ArmDisassemblerLib/ArmDisassemblerLib.inf

  # Generic UEFI libraries
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  CacheMaintenanceLib|MdePkg/Library/BaseCacheMaintenanceLib/BaseCacheMaintenanceLib.inf
  DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
  DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  DxeServicesTableLib|MdePkg/Library/DxeServicesTableLib/DxeServicesTableLib.inf
  HobLib|MdePkg/Library/DxeHobLib/DxeHobLib.inf
  IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  PeCoffExtraActionLib|MdePkg/Library/BasePeCoffExtraActionLibNull/BasePeCoffExtraActionLibNull.inf
  PeCoffLib|MdePkg/Library/BasePeCoffLib/BasePeCoffLib.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  SerialPortLib|MdePkg/Library/BaseSerialPortLibNull/BaseSerialPortLibNull.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf

  # Platform specific libraries
  ExynosSerialPortLib|ExynosPkg/Library/ExynosSerialPortLib/ExynosSerialPortLib.inf

[Components]
  # Platform drivers
  ExynosPkg/Drivers/UartDxe/UartDxe.inf
  ExynosPkg/Drivers/SdhcDxe/SdhcDxe.inf
  ExynosPkg/Drivers/BlockDeviceDxe/BlockDeviceDxe.inf

  # Standard ARM drivers
  ArmPkg/Drivers/ArmGic/ArmGicDxe.inf
  ArmPkg/Drivers/TimerDxe/TimerDxe.inf
  ArmPkg/Drivers/CpuDxe/CpuDxe.inf

  # Application examples
  ExynosPkg/Applications/HelloWorld/HelloWorld.inf

[PcdsFeatureFlag]
  gExynosPkgTokenSpaceGuid.PcdExynos990SocEnable|TRUE
  gExynosPkgTokenSpaceGuid.PcdEnableMultiUartSupport|TRUE

[PcdsFixedAtBuild]
  gExynosPkgTokenSpaceGuid.PcdUartClkInHz|24000000
  gExynosPkgTokenSpaceGuid.PcdGicDistributorBase|0x10101000
  gExynosPkgTokenSpaceGuid.PcdGicRedistributorsBase|0x10102000
  gExynosPkgTokenSpaceGuid.PcdGicInterruptInterfaceBase|0

  gEfiMdePkgTokenSpaceGuid.PcdMaximumUnicodeStringLength|1000000
  gEfiMdePkgTokenSpaceGuid.PcdMaximumAsciiStringLength|1000000
  gEfiMdePkgTokenSpaceGuid.PcdMaximumLinkedListLength|1000000
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x2F
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x80000040
  gEfiMdePkgTokenSpaceGuid.PcdReportStatusCodePropertyMask|0x07

[BuildOptions]
  GCC:*_*_AARCH64_CC_FLAGS = -DARM_CPU_AARCH64 -D__USES_INITFINI__