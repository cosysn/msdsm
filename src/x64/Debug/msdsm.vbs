REM Note that missing classes in log file mean tthe hat WMI cannot access them.
REM Most likely this indicates a problem with the driver.
REM See %windir%\system32\wbem\wmiprov.log and nt eventlog for more details.
REM You could also delete the line On Error Resume Next and examine the
REM specific VBScript error


On Error Resume Next

Set fso = CreateObject("Scripting.FileSystemObject")
Set a = fso.CreateTextFile(".log", True)
Set Service = GetObject("winmgmts:{impersonationLevel=impersonate}!root/wmi")
Rem MSDSM_DEVICE_PERF - Retrieve MSDSM Performance Information.
Set enumSet = Service.InstancesOf ("MSDSM_DEVICE_PERF")
a.WriteLine("MSDSM_DEVICE_PERF")
for each instance in enumSet
    a.WriteLine("    InstanceName=" & instance.InstanceName)
    a.WriteLine("        instance.NumberPaths=" & instance.NumberPaths)
    for i1 = 0 to (instance.NumberPaths-1)
    a.WriteLine("        instance.PerfInfo("&i1&").PathId=" & instance.PerfInfo(i1).PathId)
    a.WriteLine("        instance.PerfInfo("&i1&").NumberReads=" & instance.PerfInfo(i1).NumberReads)
    a.WriteLine("        instance.PerfInfo("&i1&").NumberWrites=" & instance.PerfInfo(i1).NumberWrites)
    a.WriteLine("        instance.PerfInfo("&i1&").BytesRead=" & instance.PerfInfo(i1).BytesRead)
    a.WriteLine("        instance.PerfInfo("&i1&").BytesWritten=" & instance.PerfInfo(i1).BytesWritten)
    next 'i1
next 'instance

Rem MSDSM_WMI_METHODS - MSDSM WMI Methods
Set enumSet = Service.InstancesOf ("MSDSM_WMI_METHODS")
a.WriteLine("MSDSM_WMI_METHODS")
for each instance in enumSet
    a.WriteLine("    InstanceName=" & instance.InstanceName)
next 'instance

a.Close
Wscript.Echo " Test Completed, see .log for details"
