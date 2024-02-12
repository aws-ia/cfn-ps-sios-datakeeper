# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Amazon Software License (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
# http://aws.amazon.com/asl/
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

<#
.SYNOPSIS

    Initializes disks attached to your EC2 instance.

.DESCRIPTION

##### Dependent Functions that were previously located in C:\Program Data\Amazon\EC2\Windows\Modules\Scripts


#>
param(
  # Scheduling the script as task initializes all disks at startup.
  # If this argument is not provided, script is executed immediately.
  [Parameter(Mandatory = $false)]
  [switch]$Schedule = $false,

  [Parameter(Mandatory = $false)]
  [switch]$EnableTrim
)

function Complete-Log
{
  if ($script:logSettingStack -and $script:logSettingStack.Length -gt 0)
  {
    $script:logSettingStack.pop() | Out-Null
  }
}

function Register-PowershellScheduler
{
  param(
    [Parameter(Mandatory = $true,Position = 0)]
    [string]$Command,

    [Parameter(Mandatory = $true,Position = 1)]
    [string]$ScheduleName,

    [Parameter(Mandatory = $false)]
    [switch]$Unregister = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Disabled = $false
  )

  $taskName = ("Amazon Ec2 Launch - {0}" -f $ScheduleName)

  if ($Unregister)
  {
    $scheduledTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($scheduledTask)
    {
      Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
  }
  else
  {
    # Scheduled task is triggered at start up to execute script as local system with highest priority.
    # The task is disabled by default if Disabled argument is provided.
    $action = New-ScheduledTaskAction -Execute $script:cmdPath -Argument $Command
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DisallowHardTerminate -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -Priority 0
    $settings.Enabled = (-not $Disabled)
    $principal = New-ScheduledTaskPrincipal -UserId S-1-5-18 -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal
    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force
  }
}


function Register-ScriptScheduler
{
  param(
    # this argument must be provided to check and set serial port before starting tasks
    [Parameter(Mandatory = $true,Position = 0)]
    [string]$ScriptPath,

    [Parameter(Mandatory = $false,Position = 1)]
    [string]$Arguments,

    [Parameter(Mandatory = $true,Position = 2)]
    [string]$ScheduleName,

    # This argument ensures the task to be unregistered.
    [Parameter(Mandatory = $false)]
    [switch]$Unregister = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Disabled = $false
  )

  try
  {
    # Script must be exeucted with -NoProfile to reduce the execution delay and -ExecutionPolicy Unrestricted to grant the permission.
    $psCommand = "/C {0} -NoProfile -NonInteractive -NoLogo -ExecutionPolicy Unrestricted -File `"{1}`" {2}" -f $script:psPath,$ScriptPath,$Arguments
    if ($Unregister)
    {
      Register-PowershellScheduler -ScheduleName $ScheduleName -Command $psCommand -Unregister
    }
    elseif ($Disabled)
    {
      Register-PowershellScheduler -ScheduleName $ScheduleName -Command $psCommand -Disabled
    }
    else
    {
      Register-PowershellScheduler -ScheduleName $ScheduleName -Command $psCommand
    }
  }
  catch
  {
    Write-ErrorLog ("Failed to schedule a task: {0}" -f $_.Exception.Message)
  }
}


function Set-Trim
{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $False)]
    [bool]$Enable
  )

  $output = fsutil behavior query DisableDeleteNotify NTFS
  $wasTrimEnabled = $output.Contains("DisableDeleteNotify = 0")

  if ($Enable)
  {
    Write-Log "Enable TRIM"
    fsutil behavior Set-Variable DisableDeleteNotify NTFS 0 | Out-Null
  }
  else
  {
    Write-Log "Disable TRIM"
    fsutil behavior Set-Variable DisableDeleteNotify NTFS 1 | Out-Null
  }

  return $wasTrimEnabled
}


function Set-DriveLetters
{
  $driveLetterMappings = Get-DriveLetterMappingConfig
  if (-not $driveLetterMappings)
  {
    Write-Log "Could not find the drive letter mapping config or it is empty"
    return
  }

  foreach ($driveLetterMapping in $driveLetterMappings)
  {
    $volumeName = $driveLetterMapping.volumeName
    $newDriveLetter = $driveLetterMapping.DriveLetter

    # Verify if the given drive letter is valid.
    if ($newDriveLetter.Length -ne 1)
    {
      Write-Log ("Invalid drive letter '{0}'.. skipping it" -f $newDriveLetter)
      continue
    }

    # Get the disk with given volume name.
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "VolumeName='$volumeName'"
    if (-not $disk -or -not $disk.Name)
    {
      Write-Log ("Volume name `"{0}`" doesn't exist.. skipping it" -f $volumeName)
      continue
    }

    # Get the current drive letter of the volume.
    $currentDriveLetter = $disk.Name
    if ($currentDriveLetter -and $currentDriveLetter.EndsWith(":"))
    {
      $currentDriveLetter = $currentDriveLetter.TrimEnd(":")
    }

    # Verify if the current drive letter of the volume is not same as new drive letter.
    if ($currentDriveLetter -ieq $newDriveLetter)
    {
      Write-Log ("Volume `"{0}`" already has the drive letter '{1}'.. skipping it" -f $volumeName,$newDriveLetter)
      continue
    }

    # Verify if the drive letter is not taken by another disk.
    if (Get-PSDrive -Name $newDriveLetter -ErrorAction SilentlyContinue)
    {
      Write-Log ("Drive letter '{0}' is already taken by another disk.. skipping it" -f $newDriveLetter)
      continue
    }

    try
    {
      Write-Log ("Changing '{0}' to '{1}' for volume `"{2}`"" -f $currentDriveLetter,$newDriveLetter,$volumeName)
      # Finally, set the volume with new drive letter.
      Set-Partition -DriveLetter $currentDriveLetter -NewDriveLetter $newDriveLetter
    }
    catch
    {
      Write-ErrorLog ("Failed to set volume `"{0}`" with new drive letter '{1}': {2}" -f $volumeName,$newDriveLetter,$_.Exception.Message)
    }
  }
}

function Test-EphemeralDisk
{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $False)]
    [int]$DiskIndex,

    [Parameter(Mandatory = $False)]
    [int]$DiskSCSITargetId
  )

  $isEphemeral = $False

  try
  {
    Set-Variable awsSsdSerialNumberPattern -Option Constant -Value "AWS*"

    # Special check: For NVMe disk types, we only want to mark cordite drives as ephemeral
    $disk = Get-Disk | Where-Object { $_.Number -eq $DiskIndex }
    if ($disk.BusType -eq 'NVMe' -and ($disk.SerialNumber -like $awsSsdSerialNumberPattern -or $disk.AdapterSerialNumber -like $awsSsdSerialNumberPattern))
    {
      return $True
    }

    if (-not $script:blockDriveMapping)
    {
      # BlockDriveMapping mapping is used to find if each drive is ephemeral or non-ephemeral.
      Set-Variable blockDriveMapping -Scope Script -Value (Get-BlockDriveMapping)

      if ($script:blockDriveMapping.Length -eq 0)
      {
        throw New-Object System.InvalidOperationException ("Could not get the block drive mapping info from metadata")
      }
    }

    # This is to determine whether disk is ephemeral, which needs to be labeled as temporary storage.
    # BlockDeviceMapping from metadata is used to find this info.
    # But it is only applicable if the system is using Citrix PV Driver.
    $driveName = ""

    if ($DiskIndex -eq 0)
    {
      $driveName = "/dev/sda1"
    }
    else
    {
      $driveName = "xvd"
      $offset = $DiskSCSITargetId

      if ($DiskSCSITargetId -gt 25)
      {
        $math = [int][math]::Floor($DiskSCSITargetId / 26)
        $offset = $DiskSCSITargetId - (26 * $math)
        $driveName += [char](97 + ($math - 1))
      }

      $driveName += [char](97 + $offset)
    }

    $matchingBlockDrive = $script:blockDriveMapping | Where-Object { $_.MountPoint -eq $driveName }
    if ($matchingBlockDrive.Length -ne 0)
    {
      $isEphemeral = $matchingBlockDrive[0].IsEphemeral
    }
    $script:blockDriveMapping = $null
  }
  catch
  {
    Write-ErrorLog ("Failed to test ephemeral disk: {0}" -f $_.Exception.Message)
  }

  return $isEphemeral
}

function Initialize-Ec2Disk
{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $True,Position = 0)]
    [int]$DiskIndex,

    [Parameter(Mandatory = $True,Position = 1)]
    [int]$EphemeralCount,

    [Parameter(Mandatory = $True,Position = 2)]
    [bool]$IsEphemeral = $False
  )

  Write-Log ("Initializing disk {0} begins" -f $DiskIndex)

  $isLargeDisk = $False

  try
  {
    # If the disk size exceeds 2199023255551 bytes (2 TB),
    # the disk must use GPT partition table.
    $disk = Get-Disk -Number $DiskIndex
    if ($disk.Size -gt 2199023255551)
    {
      $isLargeDisk = $True
    }
  }
  catch
  {
    Write-ErrorLog ("Failed to get disk size: {0}" -f $_.Exception.Message)
  }

  try
  {
    Write-Log ("Initializing the disk ...")

    if (-not $isLargeDisk)
    {
      Initialize-Disk -Number $DiskIndex -PartitionStyle MBR | Out-Null
    }
    else
    {
      Initialize-Disk -Number $DiskIndex -PartitionStyle GPT | Out-Null
    }
  }
  catch
  {
    Write-ErrorLog ("Failed to initialize disk: {0}" -f $_.Exception.Message)
  }

  $driveLetter = ""

  try
  {
    Write-Log "Looking for drive letter ..."

    # If the disk is ephmeral (instance storage), drive letter starts from Z.
    # Otherwise, drive letter starts from D.
    if ($IsEphemeral)
    {
      # One-liner to get next available drive letter from Z to A.
      for ($i = 91; Get-PSDrive ($driveLetter = [char] -- $i) 2>$null) {}
    }
    else
    {
      # One-liner to get next available drive letter from A to Z.
      for ($i = 67; Get-PSDrive ($driveLetter = [char]++ $i) 2>$null) {}
    }
  }
  catch
  {
    Write-ErrorLog ("Failed to initialize disk: {0}. There is no available drive letter left to use" -f $DiskIndex)
    return ""
  }

  try
  {
    # Stop Shell HW Detection service to prevent the prompt to pop up.
    Stop-Service -Name ShellHWDetection -ErrorAction SilentlyContinue

    Write-Log ("Creating partition with drive letter {0} ..." -f $driveLetter)

    # Create a partition with the given drive index and letter.
    if (-not $isLargeDisk)
    {
      $partition = New-Partition $DiskIndex -MbrType IFS -DriveLetter $driveLetter -UseMaximumSize -IsActive
    }
    else
    {
      $partition = New-Partition $DiskIndex -GptType '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' -DriveLetter $driveLetter -UseMaximumSize
    }

    # Check if volume is formatted for the disk.
    # If volume is not in OK status, we need to format the volume with given parameters.
    $formatted = Get-Volume -Partition $partition
    if (-not $formatted -or $formatted.OperationalStatus -ne "OK")
    {
      Write-Log "Formatting the volume ..."

      # Format the volume on the created/exsiting partition using the partition reference.
      if ($IsEphemeral)
      {
        $formatted = Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel "Temporary Storage $($EphemeralCount)" -Confirm:$False
      }
      else
      {
        $formatted = Format-Volume -Partition $partition -FileSystem NTFS -Confirm:$False
      }
    }
    else
    {
      throw New-Object System.Exception ("Volume already has been formatted.")
    }

    # This updates the drive info
    Get-PSDrive | Out-Null

    Write-Log ("Disk {0} is successfully initialized, partitioned and formatted" -f $DiskIndex)

    return $driveLetter
  }
  catch
  {
    Write-ErrorLog ("Failed to initialize disk {0}: {1}" -f $DiskIndex,$_.Exception.Message)
  }
  finally
  {
    # Start the service back.
    Start-Service -Name ShellHWDetection -ErrorAction SilentlyContinue
  }

  return ""
}

function Initialize-Log
{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $True)]
    [string]$Filename,

    [Parameter(Mandatory = $False)]
    [switch]$AllowLogToConsole,

    [Parameter(Mandatory = $False)]
    [bool]$RestrictToAdmins = $True,

    [Parameter(Mandatory = $False)]
    [bool]$AllowStandardUserWrite = $False
  )

  # Writes an error message to the Windows Application Event Log.
  function Write-ErrorToEventLog
  {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory = $True)]
      [string]$ErrorMessage
    )

    # Create event Source if it does not already exist.
    if ([System.Diagnostics.EventLog]::SourceExists("EC2Launch") -eq $False)
    {
      New-EventLog -LogName Application -Source "EC2Launch"
    }
    Write-EventLog -LogName Application -Source "EC2Launch" -EventID 3 -EntryType Error -Message $ErrorMessage
  }

  if (-not $logSettingStack)
  {
    Set-Variable logSettingStack -Scope Script -Value (New-Object system.collections.stack)
  }

  try
  {
    # Create the log path if it does not already exist.
    if (-not (Test-Path -Path $script:logPath))
    {
      $null = New-Item -Path $script:logPath -ItemType "directory"
    }

    # Check that the log path is a container.
    if (-not (Test-Path -Path $script:logPath -PathType container))
    {
      Write-ErrorToEventLog "EC2Launch failed to initialize '$Filename'. Log path exists but is not a directory."
      $script:logSettingStack.push($null)
      return
    }

    $filePath = Join-Path -Path $script:logPath -ChildPath $Filename

    # Create the log file if it does not already exist.
    if (-not (Test-Path -Path $filePath))
    {
      $null = New-Item -Path $filePath -ItemType "file"
    }

    # Validate that the path is a file (rather than a directory, for example).
    if (-not (Test-Path -Path $filePath -PathType leaf))
    {
      Write-ErrorToEventLog "EC2Launch failed to initialize log file path. '$Filename' is not a valid file."
      $script:logSettingStack.push($null)
      return
    }

    if ($RestrictToAdmins)
    {
      $acl = Get-Acl -Path $filePath
      $access = $acl.Access

      # `SetAccessRuleProtection` disables the file from inheriting access from the parent folder.
      # Access lists from parents are merged with that of child directories or files by default
      # unless inheritance is turned off. Turning inheritance off deletes all inherited rules from
      # `$acl.Access`.
      $acl.SetAccessRuleProtection($True, $False)
      $userAccess = $access | Where-Object IdentityReference -eq "BUILTIN\Users"
      $nonUserAccess = $access | Where-Object IdentityReference -ne "BUILTIN\USERS"

      # We need to remove any uninherited BUILTIN\Users rules and re-add any of the original rules
      # that do not involve BUILTIN\Users.
      $userAccess | ForEach-Object -Process {$acl.RemoveAccessRule($_)}
      $nonUserAccess | ForEach-Object -Process {$acl.AddAccessRule($_)}
      Set-Acl -Path $filePath -AclObject $acl
    }

    # Allow standard user accounts write access for this log file.
    # If access is restricted to Administrators, write access will not be granted.
    elseif ($AllowStandardUserWrite)
    {
      $acl = Get-Acl -Path $filePath
      $BuiltinUsersSID = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-545'
      $AllowUserWriteRule = New-Object System.Security.AccessControl.FileSystemAccessRule (
        # PARAMETER IdentityReference
        # This rule applies to the BUILTIN\Users group.
        $BuiltinUsersSID,
        # PARAMETER FileSystemRights
        # This rule specifies write access rights only.
        [System.Security.AccessControl.FileSystemRights]::Write,
        # PARAMETER AccessControlType
        # This rule allows the above write access rights.
        [System.Security.AccessControl.AccessControlType]::Allow
      )
      $acl.AddAccessRule($AllowUserWriteRule)
      Set-Acl -Path $filePath -AclObject $acl
    }
  }
  catch
  {
    Write-ErrorToEventLog "EC2Launch failed to restrict '$Filename' permissions to Administrators only: $_"
    $script:logSettingStack.push($null)
    return
  }

  $logSetting = @{
    "LogFilename" = $Filename
    "AllowLogToConsole" = $AllowLogToConsole
  }

  $script:logSettingStack.push($logSetting)
}

function Write-Log
{
  [CmdletBinding()]
  param(
    # Message is a mandatory argument.
    [Parameter(Mandatory = $True,Position = 0)]
    [string]$Message,

    # LogToConsole is to log the message to both file and console.
    [Parameter(Mandatory = $False)]
    [switch]$LogToConsole = $False
  )

  # Initialize-Log function must be called first prior to calling this function.
  if (-not $script:logSettingStack -or $script:logSettingStack.Count -eq 0)
  {
    return
  }

  $logSetting = $script:logSettingStack.Peek()

  if ($null -eq $logSetting)
  {
    return
  }

  $logFilename = $logSetting.LogFilename
  $allowLogToConsole = $logSetting.AllowLogToConsole

  # Set log file path with log filename set by Initialize-Log.
  if (-not (Test-Path $script:logPath))
  {
    New-Item -Path $script:logPath -Type directory | Out-Null
  }
  $filePath = Join-Path $script:logPath -ChildPath $logFilename
  if (-not (Test-Path $filePath))
  {
    New-Item -Path $filePath -Type file | Out-Null
  }

  # Every message must include a timestamp in the following format.
  try
  {
    $newMessage = "{0}: {1}" -f (Get-Date).ToUniversalTime().ToString("yyyy'/'MM'/'dd HH':'mm':'ss'Z'"),$Message
    $newMessage | Out-File -FilePath $filePath -Append
  }
  catch
  {

  }

  # If LogToConsole is allowed and is provided, it displays the message to console.
  if ($allowLogToConsole -and $LogToConsole)
  {
    try
    {
      # Open COM port and write message to console
      Send-Message -Message $newMessage
    }
    catch
    {
      Write-ErrorLog ("Failed to log to console: {0}" -f $_.Exception)
    }
  }
}

function Write-ErrorLog
{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $True,Position = 0)]
    [string]$Message
  )

  Write-Log $Message
}



# Set all necessary constant variables used by helper scripts.
Set-Variable cmdPath -Option Constant -Scope Script -Value (Join-Path $env:SystemRoot -ChildPath "System32\cmd.exe")
Set-Variable psPath -Option Constant -Scope Script -Value (Join-Path $env:SystemRoot -ChildPath "System32\WindowsPowerShell\v1.0\powershell.exe")
Set-Variable rootPath -Option Constant -Scope Script -Value (Join-Path $env:ProgramData -ChildPath "Amazon\EC2-Windows\Launch")
Set-Variable modulePath -Option Constant -Scope Script -Value (Join-Path $script:rootPath -ChildPath "Module")
Set-Variable libraryPath -Option Constant -Scope Script -Value (Join-Path $script:rootPath -ChildPath "Library")
Set-Variable moduleFilePath -Option Constant -Scope Script -Value (Join-Path $script:modulePath -ChildPath "Ec2Launch.psd1")
Set-Variable logPath -Option Constant -Scope Script -Value (Join-Path $script:rootPath -ChildPath "Log")
Set-Variable configPath -Option Constant -Scope Script -Value (Join-Path $script:rootPath -ChildPath "Config")
Set-Variable initWallpaperSetupName -Option Constant -Scope Script -Value "RunWallpaperSetupInit.cmd"
Set-Variable wallpaperSetupName -Option Constant -Scope Script -Value "RunWallpaperSetup.cmd"
Set-Variable originalWallpaperName -Option Constant -Scope Script -Value "Ec2Wallpaper.jpg"
Set-Variable customWallpaperName -Option Constant -Scope Script -Value "Ec2Wallpaper_Info.jpg"
Set-Variable scriptPath -Option Constant -Scope Local -Value (Join-Path $PSScriptRoot -ChildPath $MyInvocation.MyCommand.Name)
Set-Variable scheduleName -Option Constant -Scope Local -Value "Disk Initialization"
Set-Variable shellHwRegPath -Option Constant -Scope Local -Value "HKLM:\SYSTEM\CurrentControlSet\services\ShellHWDetection"


# Before calling any function, initialize the log with filename
Initialize-Log -FileName "DiskInitialization.log" -RestrictToAdmins $false

if ($Schedule)
{
  # Scheduling script with no argument tells script to start normally.
  if ($EnableTrim)
  {
    Register-ScriptScheduler -ScriptPath $scriptPath -ScheduleName $scheduleName -Arguments "-EnableTrim"
  }
  else
  {
    Register-ScriptScheduler -ScriptPath $scriptPath -ScheduleName $scheduleName
  }
  Write-Log "Disk initialization is scheduled successfully"
  Complete-Log
  exit 0
}

try
{
  Write-Log "Initializing disks started"

  # Set TRIM using settings value from userdata.
  # By default, TRIM is disabled before formatting disk.
  $wasTrimEnabled = Set-Trim -Enable $EnableTrim

  # This count is used to label ephemeral disks.
  $ephemeralCount = 0

  $allSucceeded = $true

  # Retrieve and initialize each disk drive.
  foreach ($disk in (Get-CimInstance -ClassName Win32_DiskDrive))
  {
    Write-Log ("Found Disk Name:{0}; Index:{1}; SizeBytes:{2};" -f $disk.Name,$disk.Index,$disk.Size)

    # Disk must not be set to readonly to prevent error during initialization.
    $IsReadOnly = $(Get-Disk $disk.Index).IsReadOnly
    if ($IsReadOnly -eq $True)
    {
      Set-Disk -Number $disk.Index -IsReadonly $False -ErrorAction SilentlyContinue | Out-Null
    }

    # Check if a partition is available for the disk.
    # If no partition is found for the disk, we need to create a new partition.
    $partitioned = Get-Partition $disk.Index -ErrorAction SilentlyContinue
    if ($partitioned)
    {
      Write-Log ("Partition already exists: PartitionNumber {0}; DriverLetter {1}" -f $partitioned.PartitionNumber,$partitioned.DriveLetter)
      continue
    }

    # Find out if the disk is whether ephemeral or not.
    $isEphemeral = $false
    $isEphemeral = Test-EphemeralDisk -DiskIndex $disk.Index -DiskSCSITargetId $disk.SCSITargetId

    # Finally, set the disk and get drive letter for result.
    # If disk is ephemeral, label the disk.
    $driveLetter = Initialize-Ec2Disk -DiskIndex $disk.Index -EphemeralCount $ephemeralCount -IsEphemeral $isEphemeral

    # If disk is successfully loaded, driver letter should be assigned.
    if ($driveLetter)
    {
      # If it was ephemeral, increment the ephemeral count and create a warning file.
      if ($isEphemeral)
      {
        $ephemeralCount++
      }
    }
    else
    {
      # If any disk failed to be initilaized, exitcode needs to be 1.
      $allSucceeded = $false
    }
  }

  # Set drive letters based on drive letter mapping config.
  Set-DriveLetters

  if ($allSucceeded)
  {
    Write-Log "Initializing disks done successfully"
    exit 0
  }
  else
  {
    Write-ErrorLog "Initializing disks done, but with at least one disk failure"
    exit 1
  }
}
catch
{
  Write-ErrorLog ("Failed to initialize drives: {0}" -f $_.Exception.Message)
  exit 1
}
finally
{
  # If TRIM was originally enabled, make sure TRIM is set to be enabled.
  Set-Trim -Enable $wasTrimEnabled | Out-Null

  # Before finishing the script, complete the log.
  Complete-Log
}
