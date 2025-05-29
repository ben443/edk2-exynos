## @file
# Samsung Exynos 990 platform description file
#
# Copyright (c) 2023-2024, EDK2 Contributors
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

[Defines]
  PLATFORM_NAME                  = exynos990
  PLATFORM_GUID                  = 8DF7B968-1539-4DFC-93D2-A089CA5DF79E
  PLATFORM_VERSION               = 0.1
  DSC_SPECIFICATION              = 0x0001001A
  OUTPUT_DIRECTORY               = Build/Exynos990
  SUPPORTED_ARCHITECTURES        = AARCH64
  BUILD_TARGETS                  = DEBUG|RELEASE
  SKUID_IDENTIFIER               = DEFAULT

[BuildOptions]
  GCC:*_*_AARCH64_CC_FLAGS = -DARM_CPU_AARCH64 -D__USES_INITFINI__

!include ExynosPkg/ExynosPkg.dsc

[LibraryClasses.common]
  # Platform-specific overrides can be added here
  SerialPortLib|ExynosPkg/Library/ExynosSerialPortLib/ExynosSerialPortLib.inf
  TimerLib|ArmPkg/Library/ArmArchTimerLib/ArmArchTimerLib.inf

[PcdsFixedAtBuild]
  # Platform-specific PCD settings can be added here
  gExynosPkgTokenSpaceGuid.PcdUartClkInHz|26000000
  gExynosPkgTokenSpaceGuid.PcdGicDistributorBase|0x10200000
  gExynosPkgTokenSpaceGuid.PcdGicRedistributorsBase|0x10240000
  
  # Debug output level
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x8000004F

[Components]
  # Platform-specific components
  ExynosPkg/Drivers/BlockDeviceDxe/BlockDeviceDxe.inf
  ExynosPkg/Drivers/SdhcDxe/SdhcDxe.inf
  ExynosPkg/Drivers/UartDxe/UartDxe.inf
  
  # Standard drivers
  ArmPkg/Drivers/ArmGic/ArmGicDxe.inf
  ArmPkg/Drivers/TimerDxe/TimerDxe.inf
  ArmPkg/Drivers/CpuDxe/CpuDxe.inf
  MdeModulePkg/Universal/WatchdogTimerDxe/WatchdogTimer.inf
  MdeModulePkg/Universal/Variable/RuntimeDxe/VariableRuntimeDxe.inf
  MdeModulePkg/Core/Dxe/DxeMain.inf
  
  # UEFI applications
  MdeModulePkg/Application/UiApp/UiApp.inf
  ShellPkg/Application/Shell/Shell.inf
