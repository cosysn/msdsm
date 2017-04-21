REM Note that missing classes in log file mean tthe hat WMI cannot access them.
REM Most likely this indicates a problem with the driver.
REM See %windir%\system32\wbem\wmiprov.log and nt eventlog for more details.
REM You could also delete the line On Error Resume Next and examine the
REM specific VBScript error


On Error Resume Next

Set fso = CreateObject("Scripting.FileSystemObject")
Set a = fso.CreateTextFile(".log", True)
Set Service = GetObject("winmgmts:{impersonationLevel=impersonate}!root/wmi")
Rem MSDSM_DEFAULT_LOAD_BALANCE_POLICY - MSDSM-wide default load balance policies.
Set enumSet = Service.InstancesOf ("MSDSM_DEFAULT_LOAD_BALANCE_POLICY")
a.WriteLine("MSDSM_DEFAULT_LOAD_BALANCE_POLICY")
for each instance in enumSet
    a.WriteLine("    InstanceName=" & instance.InstanceName)
    a.WriteLine("        instance.LoadBalancePolicy=" & instance.LoadBalancePolicy)
    a.WriteLine("        instance.Reserved=" & instance.Reserved)
    a.WriteLine("        instance.PreferredPath=" & instance.PreferredPath)
next 'instance

Rem MSDSM_TARGETS_DEFAULT_LOAD_BALANCE_POLICY - Target-level default load balance policies.
Set enumSet = Service.InstancesOf ("MSDSM_TARGETS_DEFAULT_LOAD_BALANCE_POLICY")
a.WriteLine("MSDSM_TARGETS_DEFAULT_LOAD_BALANCE_POLICY")
for each instance in enumSet
    a.WriteLine("    InstanceName=" & instance.InstanceName)
    a.WriteLine("        instance.NumberDevices=" & instance.NumberDevices)
    a.WriteLine("        instance.Reserved=" & instance.Reserved)
    for i1 = 0 to (instance.NumberDevices-1)
    a.WriteLine("        instance.TargetDefaultPolicyInfo("&i1&").HardwareId=" & instance.TargetDefaultPolicyInfo(i1).HardwareId)
    a.WriteLine("        instance.TargetDefaultPolicyInfo("&i1&").LoadBalancePolicy=" & instance.TargetDefaultPolicyInfo(i1).LoadBalancePolicy)
    a.WriteLine("        instance.TargetDefaultPolicyInfo("&i1&").Reserved=" & instance.TargetDefaultPolicyInfo(i1).Reserved)
    a.WriteLine("        instance.TargetDefaultPolicyInfo("&i1&").PreferredPath=" & instance.TargetDefaultPolicyInfo(i1).PreferredPath)
    next 'i1
next 'instance

Rem MSDSM_SUPPORTED_DEVICES_LIST - Retrieve MSDSM's supported devices list.
Set enumSet = Service.InstancesOf ("MSDSM_SUPPORTED_DEVICES_LIST")
a.WriteLine("MSDSM_SUPPORTED_DEVICES_LIST")
for each instance in enumSet
    a.WriteLine("    InstanceName=" & instance.InstanceName)
    a.WriteLine("        instance.NumberDevices=" & instance.NumberDevices)
    a.WriteLine("        instance.Reserved=" & instance.Reserved)
    for i1 = 0 to (instance.NumberDevices-1)
    a.WriteLine("        instance.DeviceId("&i1&")=" & instance.DeviceId(i1))
    next 'i1
next 'instance

a.Close
Wscript.Echo " Test Completed, see .log for details"
