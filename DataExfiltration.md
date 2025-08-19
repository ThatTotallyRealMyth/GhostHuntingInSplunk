To look for instances in which an attacker may have created staging files, we probably want to hunt across file creation events in which they included .zip and .rar extensions.
A smart way to further filter these out as well is that we can exclude ones with zone Identifier of download. Note that we arent hunting for the threat actor downloading files, we are hunting for
the creation of rar, 7z and zip files on our victims.

```sql
index=* (*.zip OR *.rar OR *.7z OR *.tar OR *.gz OR *.bz OR *.bz2) NOT "Zone.Identifier" (sourcetype=WinEventLog:Security OR sourcetype=WinEventLog:Sysmon OR sourcetype=linux_audit OR sourcetype=syslog) | stats count by _time, host, user, process, file_path | sort -_time
```

Now lets hunt for common use commands that are deployed by threat actors to commonly move files out of systems. This may produce false positives depending on your enviroment; if you have FTP/SFTP in use then I suggest excluding those and so on. You can also focus on more high fidality catches if you so please as this query makes it easier to filter and cut down on noise: 

```sql
index=* (copy OR xcopy OR robocopy OR "copy-item" OR curl OR wget OR scp OR sftp OR rsync OR bitsadmin OR certutil OR ftp OR tftp OR nc OR netcat OR ncat) (CommandLine=* OR command=* OR proc_name=* OR process=*) | regex _raw="(?i)(copy|xcopy|robocopy|copy-item|curl|wget|scp|sftp|rsync|bitsadmin|certutil.*download|ftp|tftp|nc.*-l|netcat|ncat)" | eval transfer_method=case(match(_raw,"(?i)copy-item"),"PowerShell Copy-Item", match(_raw,"(?i)robocopy"),"Robocopy", match(_raw,"(?i)xcopy"),"XCopy", match(_raw,"(?i)\bcopy\b"),"Copy", match(_raw,"(?i)curl"),"cURL", match(_raw,"(?i)wget"),"Wget", match(_raw,"(?i)scp"),"SCP", match(_raw,"(?i)sftp"),"SFTP", match(_raw,"(?i)rsync"),"Rsync", match(_raw,"(?i)bitsadmin"),"BITSAdmin", match(_raw,"(?i)certutil.*download"),"Certutil Download", match(_raw,"(?i)ftp"),"FTP", match(_raw,"(?i)nc|netcat|ncat"),"Netcat", 1=1,"Other") | stats count by _time, host, user, transfer_method, CommandLine | sort -_time
```
