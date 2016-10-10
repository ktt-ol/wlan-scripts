#!/usr/bin/python
import netsnmp
import os

# --------------------------
snmpserver = "192.168.2.246"
# --------------------------

ownpath = os.path.dirname(os.path.realpath(__file__))
os.environ['MIBS'] = 'TRAPEZE-NETWORKS-AP-STATUS-MIB'
os.environ['MIBDIRS'] = ownpath+'/mibs'

def decode_ap_id(str):
    parts = str.split(".")
    if parts[0] != "12":
        return str
    result = ""
    for part in parts[1:13]:
        result += chr(int(part))
    return result

def decode_radio_id(str):
    parts = str.split(".")
    if len(parts) < 14:
        return None
    return int(parts[13])-1

def decode_radio_ssid(str):
    parts = str.split(".")
    result = ""
    if len(parts) < 15:
        return None
    for x in parts[15:]:
        result += chr(int(x))
    return result

def convert_mac(str):
    result = ""
    if len(str) != 6:
        return "00:00:00:00:00:00"
    return "%02x:%02x:%02x:%02x:%02x:%02x" % \
        (ord(str[0]), ord(str[1]), ord(str[2]),
        ord(str[3]), ord(str[4]), ord(str[5]))

def convert_state(str):
    if str == "1":
        return "cleared"
    elif str == "2":
        return "init"
    elif str == "3":
        return "booting"
    elif str == "4":
        return "image downloaded"
    elif str == "5":
        return "connection failed"
    elif str == "6":
        return "configuring"
    elif str == "7":
        return "operational"
    elif str == "10":
        return "redundant"
    elif str == "20":
        return "connection outage"
    else:
        return "unknown"

def convert_config_state(str):
    if str == "1":
        return "init"
    elif str == "2":
        return "fail"
    elif str == "3":
        return "ok"
    else:
        return "????"

def convert_phy_type(str):
    if str == "2":
        return "A"
    elif str == "3":
        return "B"
    elif str == "4":
        return "G"
    elif str == "5":
        return "NA"
    elif str == "6":
        return "NG"
    else:
        return "unknown"

def convert_channel_width(str):
    if str == "1":
        return "20 MHz"
    elif str == "2":
        return "40 MHz"
    else:
        return "unknown"

def pretty_uptime(secs):
    s = secs % 60
    m = (secs / 60) % 60
    h = (secs / 3600) % 24
    d = (secs / (24*3600))
    return "{:4d}d {:02d}:{:02d}:{:02d}".format(d,h,m,s)

vars = netsnmp.VarList(netsnmp.Varbind('trpzApStatusMib'))
netsnmp.snmpwalk(vars, DestHost=snmpserver, Version=1, Community='public')

apinfo = {}

for var in vars:
    if var.tag in ["trpzApStatNumAps"]:
        continue
    elif var.tag in ["trpzApStatApStatusBaseMac", "trpzApStatApStatusApState", "trpzApStatApStatusModel", "trpzApStatApStatusApName", "trpzApStatApStatusIpAddress", "trpzApStatApStatusUptimeSecs", "trpzApStatApStatusCpuInfo", "trpzApStatApStatusManufacturerId", "trpzApStatApStatusRamBytes", "trpzApStatApStatusHardwareRev", "trpzApStatApStatusClientSessions", "trpzApStatApStatusSoftwareVer", "trpzApStatApStatusApNum"]:
        ap = decode_ap_id(var.iid)
        if ap not in apinfo:
            apinfo[ap] = {"serial": ap}
        if var.tag == "trpzApStatApStatusBaseMac":
            apinfo[ap]["base-mac"] = convert_mac(var.val)
        elif var.tag == "trpzApStatApStatusApState":
            apinfo[ap]["state"] = convert_state(var.val)
        elif var.tag == "trpzApStatApStatusModel":
            apinfo[ap]["model"] = var.val
        elif var.tag == "trpzApStatApStatusApName":
            apinfo[ap]["name"] = var.val
        elif var.tag == "trpzApStatApStatusIpAddress":
            apinfo[ap]["ip"] = var.val
        elif var.tag == "trpzApStatApStatusUptimeSecs":
            apinfo[ap]["uptime"] = int(var.val)
        elif var.tag == "trpzApStatApStatusCpuInfo":
            apinfo[ap]["cpu-info"] = var.val
        elif var.tag == "trpzApStatApStatusManufacturerId":
            apinfo[ap]["manufacturer"] = var.val
        elif var.tag == "trpzApStatApStatusRamBytes":
            apinfo[ap]["memory"] = int(var.val)
        elif var.tag == "trpzApStatApStatusHardwareRev":
            apinfo[ap]["hw-revision"] = var.val
        elif var.tag == "trpzApStatApStatusClientSessions":
            apinfo[ap]["clients"] = int(var.val)
        elif var.tag == "trpzApStatApStatusSoftwareVer":
            apinfo[ap]["sw-version"] = var.val
        elif var.tag == "trpzApStatApStatusApNum":
            apinfo[ap]["number"] = int(var.val)
    elif var.tag in ["trpzApStatRadioStatusBaseMac", "trpzApStatRadioStatusRadioConfigState", "trpzApStatRadioStatusCurrentPowerLevel", "trpzApStatRadioStatusCurrentChannelNum", "trpzApStatRadioStatusClientSessions", "trpzApStatRadioStatusMaxPowerLevel", "trpzApStatRadioStatusRadioPhyType", "trpzApStatRadioStatusRadioMode", "trpzApStatRadioStatusRadioChannelWidth", "trpzApStatRadioStatusMinPowerLevel"]:
        ap = decode_ap_id(var.iid)
        radio = decode_radio_id(var.iid)
        if ap not in apinfo:
            apinfo[ap] = {"serial": ap}
        if "radio" not in apinfo[ap]:
            apinfo[ap]["radio"] = []
        while radio >= len(apinfo[ap]["radio"]):
            apinfo[ap]["radio"].append({})
        if var.tag == "trpzApStatRadioStatusBaseMac":
            apinfo[ap]["radio"][radio]["base-mac"] = convert_mac(var.val)
        elif var.tag == "trpzApStatRadioStatusRadioConfigState":
            apinfo[ap]["radio"][radio]["state"] = convert_config_state(var.val)
        elif var.tag == "trpzApStatRadioStatusMinPowerLevel":
            apinfo[ap]["radio"][radio]["min-power"] = int(var.val)
        elif var.tag == "trpzApStatRadioStatusMaxPowerLevel":
            apinfo[ap]["radio"][radio]["max-power"] = int(var.val)
        elif var.tag == "trpzApStatRadioStatusCurrentPowerLevel":
            apinfo[ap]["radio"][radio]["power"] = int(var.val)
        elif var.tag == "trpzApStatRadioStatusCurrentChannelNum":
            apinfo[ap]["radio"][radio]["channel"] = int(var.val)
        elif var.tag == "trpzApStatRadioStatusClientSessions":
            apinfo[ap]["radio"][radio]["clients"] = int(var.val)
        elif var.tag == "trpzApStatRadioStatusRadioPhyType":
            apinfo[ap]["radio"][radio]["phy-type"] = convert_phy_type(var.val)
        elif var.tag == "trpzApStatRadioStatusRadioMode":
            if var.val == "1":
                apinfo[ap]["radio"][radio]["enabled"] = "on"
            else:
                apinfo[ap]["radio"][radio]["enabled"] = "off"
        elif var.tag == "trpzApStatRadioStatusRadioChannelWidth":
            apinfo[ap]["radio"][radio]["channel-width"] = convert_channel_width(var.val)
        elif var.tag == "trpzApStatRadioOpStatsResetCount":
            apinfo[ap]["radio"][radio]["reset-counter"] = int(var.val)
        elif var.tag == "trpzApStatRadioOpStatsAutoTuneChannelChangeCount":
            apinfo[ap]["radio"][radio]["channel-changes"] = int(var.val)
        elif var.tag == "trpzApStatRadioOpStatsTxRetriesCount":
            apinfo[ap]["radio"][radio]["tx-retries"] = int(var.val)
        elif var.tag == "trpzApStatRadioOpStatsNoiseFloor":
            apinfo[ap]["radio"][radio]["noise-floor"] = int(var.val)
        elif var.tag == "trpzApStatRadioOpStatsClientAssociations":
            apinfo[ap]["radio"][radio]["client-associations"] = int(var.val)
        elif var.tag == "trpzApStatRadioOpStatsClientFailedAssociations":
            apinfo[ap]["radio"][radio]["client-failed-associations"] = int(var.val)
        elif var.tag == "trpzApStatRadioOpStatsClientReAssociations":
            apinfo[ap]["radio"][radio]["client-reassociations"] = int(var.val)
        elif var.tag == "trpzApStatRadioOpStatsRefusedConnectionCount":
            apinfo[ap]["radio"][radio]["client-refused"] = int(var.val)
    elif var.tag == "trpzApStatRadioServBssid":
        ap = decode_ap_id(var.iid)
        radio = decode_radio_id(var.iid)
        ssid = decode_radio_ssid(var.iid)
        if ap not in apinfo:
            apinfo[ap] = {"serial": ap}
        if "radio" not in apinfo[ap]:
            apinfo[ap]["radio"] = []
        while radio >= len(apinfo[ap]["radio"]):
            apinfo[ap]["radio"] += {}
        if "profiles" not in apinfo[ap]["radio"][radio]:
            apinfo[ap]["radio"][radio]["profiles"] = []

        bssid = convert_mac(var.val)
        apinfo[ap]["radio"][radio]["profiles"].append((bssid, ssid))

# AP info
print "+------+--------------+----------------------+-------------------+-----------------+-------------------+----------------+---------+"
print "|  ID  |       Serial |                 NAME |               MAC |              IP |             State |         Uptime | Clients |"
print "+------+--------------+----------------------+-------------------+-----------------+-------------------+----------------+---------+"
for ap in sorted(apinfo.values(), key=lambda ap: ap["number"]):
    print "| {:>4} | {} | {:>20} | {} | {:>15} | {:>17} | {} | {:7d} |".format(ap["number"], ap["serial"], ap["name"], ap["base-mac"], ap["ip"], ap["state"], pretty_uptime(ap["uptime"]), ap["clients"])
print "+------+--------------+----------------------+-------------------+-----------------+-------------------+----------------+---------+"

print ""

# Radio Interface info
print "+--------+-----+-----+----------+-------+---------+"
print "|AP-RADIO| Phy | Ch. |    State | Power | Clients |"
print "+--------+-----+-----+----------+-------+---------+"
for ap in sorted(apinfo.values(), key=lambda ap: ap["number"]):
    id = 0
    for r in ap["radio"]:
        id += 1
        print "| {:4d}-{:1d} |  {}  | {:3d} | {:>3} {:>4} | {:2d}dbm | {:7d} |".format(ap["number"], id, r["phy-type"], r["channel"], r["enabled"], r["state"], r["power"], r["clients"])
print "+--------+-----+-----+----------+-------+---------+"

print ""

# SSID info
ssids = {}
for ap in sorted(apinfo.values(), key=lambda ap: ap["number"]):
    id = 0
    for r in ap["radio"]:
        id += 1
        for profile in r["profiles"]:
            if profile[1] not in ssids:
                ssids[profile[1]] = []
            ssids[profile[1]].append((ap["number"], id, profile[0]))

print "+---------------------------+--------+-------------------+"
print "|                      SSID |AP-RADIO|             BSSID |"
print "+---------------------------+--------+-------------------+"
for ssid, services in ssids.items():
    for info in services:
        print "| {:>25} | {:4d}-{:1d} | {} |".format(ssid, info[0], info[1], info[2])
print "+---------------------------+--------+-------------------+"
