#!/usr/bin/python
import netsnmp
import os

# --------------------------
snmpserver = "192.168.2.246"
# --------------------------

ownpath = os.path.dirname(os.path.realpath(__file__))
os.environ['MIBS'] = 'TRAPEZE-NETWORKS-CLIENT-SESSION-MIB'
os.environ['MIBDIRS'] = ownpath+'/mibs'

def decode_id(str):
    parts = str.split(".")
    mac = "%02x:%02x:%02x:%02x:%02x:%02x" % \
        (int(parts[0]),int(parts[1]),int(parts[2]), \
         int(parts[3]),int(parts[4]),int(parts[5]))
    id = int(parts[6]) if len(parts) >= 7 else 0
    return (mac, id)

vars = netsnmp.VarList(netsnmp.Varbind('trpzClientSessionMib'))
netsnmp.snmpwalk(vars, DestHost=snmpserver, Version=1, Community='public')

sessions = {}

for var in vars:
    if var.tag == "trpzClSessTotalSessions":
        continue

    mac, id = decode_id(var.iid)

    if mac not in sessions:
        sessions[mac] = {"mac": mac}

    elif var.tag == "trpzClSessClientSessIpAddress":
        sessions[mac]["ip"] = var.val
    elif var.tag == "trpzClSessClientSessEncryptionType":
        if int(var.val) == 1:
            sessions[mac]["encryption-type"] = "none"
        elif int(var.val) == 2:
            sessions[mac]["encryption-type"] = "aes-ccm"
        elif int(var.val) == 3:
            sessions[mac]["encryption-type"] = "aes-ocb"
        elif int(var.val) == 4:
            sessions[mac]["encryption-type"] = "tkip"
        elif int(var.val) == 5:
            sessions[mac]["encryption-type"] = "wep-104"
        elif int(var.val) == 6:
            sessions[mac]["encryption-type"] = "wep-40"
        elif int(var.val) == 7:
            sessions[mac]["encryption-type"] = "wep-static"
    elif var.tag == "trpzClSessClientSessVlan":
        sessions[mac]["vlan"] = var.val
    elif var.tag == "trpzClSessClientSessApNum":
        sessions[mac]["ap"] = int(var.val)
    elif var.tag == "trpzClSessClientSessRadioNum":
        sessions[mac]["radio"] = int(var.val)
    elif var.tag == "trpzClSessClientSessSsid":
        sessions[mac]["ssid"] = var.val
    elif var.tag in ["trpzClSessRoamHistApNum", "trpzClSessRoamHistRadioNum", "trpzClSessRoamHistTimeStamp"]:
        if "history" not in sessions[mac]:
            sessions[mac]["history"] = []
        while len(sessions[mac]["history"]) <= id:
            sessions[mac]["history"].append({})
        if var.tag == "trpzClSessRoamHistApNum":
            sessions[mac]["history"][id]["ap"] = int(var.val)
        elif var.tag == "trpzClSessRoamHistRadioNum":
            sessions[mac]["history"][id]["radio"] = int(var.val)
    elif var.tag == "trpzClSessClientSessStatsLastRate":
        sessions[mac]["rate"] = int(var.val)/10
    elif var.tag == "trpzClSessClientSessStatsLastRssi":
        sessions[mac]["rssi"] = int(var.val)
    elif var.tag == "trpzClSessClientSessStatsLastSNR":
        sessions[mac]["snr"] = int(var.val)

print "+-------------------+-----------------+-----+---------------------------+----------+------------+------+------+-----+"
print "|       MAC address |      IP address |  AP |                      SSID |     VLAN | encryption | rate | RSSI | SNR |"
print "+-------------------+-----------------+-----+---------------------------+----------+------------+------+------+-----+"
for client in sessions.values():
    print "| {} | {:>15} | {}-{} | {:>25} | {:>8} | {:>10} | {:>4} | {:>4} | {:>3} |".format(client.get("mac", "??:??:??:??:??:??"), client.get("ip", "0.0.0.0"), client.get("ap", "?"), client.get("radio", "?"), client.get("ssid", ""), client.get("vlan", "?"), client.get("encryption-type", "?"), client.get("rate", "?"), client.get("rssi", "?"), client.get("snr", "?"))
print "+-------------------+-----------------+-----+---------------------------+----------+------------+------+------+-----+"
