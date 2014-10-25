# Jailbreak - 4.0
Written by: Andreas Junestam, Chris Clark, Jason Copenhaver

Jailbreak exports certificates marked as non-exportable from the Windows 
certificate store.  This can help when you need to extract certificates 
for backup or testing. You must have permissions to use the private key on the 
filesystem in order for jailbreak to work -- Jailbreak cannot export keys stored
on smartcards.

Jailbreak consists of two parts. The jailbreak32.exe launcher program and the
jailbreakhook32.dll function hooking DLL. (64-bit versions exists as well.)
jailbreak32.exe launches any application and injects the jailbreakhook32.dll
into the process. The jailbreakhook32.dll hooks cryptsp.dll!CryptGetKeyParam
function to inform any callers that the certificate is exportable. It also
hooks the rsaenh.dll!CPExportKey function to inform rsaenh.dll that
the certificate is exportable.

### How to use

There are three sample .bat files included.

#### jbcert.bat

1. Run jbcert.bat while running as administrator
2. A mmc with the Local Machine and Current-User Certificate snap-ins will load
3. All certificates are now marked as exportable
4. Use the certificate UI to export certificates and their private keys. 


#### jbcsp.bat

jbcsp exports keys that are contained within the CSP and not associated with a certificate.
jbscp requires .NET Framework 2.0.

Run: 
`jbscp.bat "Key container" "output file name" [-u]`

-u is an optional parameter and will export from the user store instead of the 
machine store.

#### jbstore.bat

JBStore exports all of the certificates in the "MY" user store. This has the 
advantage that it does not require user interaction with MMC.

JBStore can be set to export from either the CURRENT_USER\MY store or the 
LOCAL_MACHINE\MY store.  The default is CURRENT_USER\MY.

To export from the LOCAL_MACHINE\MY store:
`jbstore.bat -a -o <outfile> -p <password>`

To export from the CURRENT_USER\MY store:

`jbstore.bat -s "USER" -o <outfile> -p <password>`

### Acknowledgements

Thank you to those who have performed testing or provided feedback. 
Especially Andreas Klein for the jbcsp suggestions and Tom Aafloen for 
testing it on Vista x64.


(c) 2007-2014 iSEC Partners (https://www.isecpartners.com)
