To look for instances in which an attacker may have created staging files, we probably want to hunt across file creation events in which they included .zip and .rar extensions.
A smart way to further filter these out as well is that we can exclude ones with zone Identifier of download. Note that we arent hunting for the threat actor downloading files, we are hunting for
the creation of rar, 7z and zip files on our victims.

```sql
index=* (*.zip OR *.rar OR *.7z OR *.tar OR *.gz OR *.bz OR *.bz2) NOT "Zone.Identifier" (sourcetype=WinEventLog:Security OR sourcetype=WinEventLog:Sysmon OR sourcetype=linux_audit OR sourcetype=syslog) | stats count by _time, host, user, process, file_path | sort -_time
```

