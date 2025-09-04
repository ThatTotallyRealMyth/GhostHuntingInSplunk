Lets say we wanted to create a base of mapping out everyones movement and to where, we can use this query as a sort of birds eye view to allow us to then build towards filtering and cutting down noise until we can get higher fidality look:

```sql
index=* SourceIp=* OR DestinationIp=* OR SourceHostname=* OR DestinationHostname=*
| stats count by SourceIp, SourceHostname, DestinationIp, DestinationHostname
| sort -count
```


We can query for all network connections given by a specific username via: 

```sql
index=* sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 
User="*SomeUser*"
| eval timestamp=strftime(_time, "%Y-%m-%d %H:%M:%S"),
       destination=if(isnotnull(DestinationHostname), DestinationHostname, DestinationIp),
       connection=destination.":".DestinationPort
| table timestamp Computer User Image connection Protocol
| sort _time
```


We can also query network connections made by specified files and delimitating if they are internal, or external

```sql
index=* sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 
Image="*somefile.ps1"
| eval connection_type=case(
    match(DestinationIp, "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"), "Internal",
    match(DestinationIp, "^127\."), "Localhost",
    1=1, "External"
),
direction=case(
    Initiated="true", "Outbound",
    1=1, "Inbound"
)
| table _time Computer User Image connection_type direction DestinationIp DestinationPort DestinationHostname Protocol
| sort _time
```


If we want to see for every unsigned executable, where/when it made any network connections then we could use this query: 

```sql
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=1 OR EventCode=3)
| where NOT match(Company, "(?i)(Microsoft|Google|VMware)")
| eval ProcessGuid=coalesce(ProcessGuid, ProcessGuid)
| stats values(Image) as Process, 
        values(CommandLine) as CommandLine,
        values(Company) as Company,
        values(User) as User,
        values(DestinationIp) as DestIP,
        values(DestinationPort) as DestPort,
        values(DestinationHostname) as DestHost,
        values(SourceIp) as SourceIP,
        values(SourcePort) as SourcePort,
        min(_time) as ProcessStart,
        values(EventCode) as EventCodes
        by ProcessGuid
| where EventCodes="1" AND EventCodes="3"
| table ProcessStart, Process, User, CommandLine, SourceIP, DestIP, DestPort, DestHost, Company
| sort -ProcessStart
```
