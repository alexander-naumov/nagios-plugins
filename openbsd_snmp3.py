#!/usr/bin/env python3

from easysnmp import Session
import sys, os, re, argparse
import subprocess as sp

VERSION = 0.1

BSD = {
        "cpu_load"    :"hrProcessorLoad",

        "proc_name"   :"hrSWRunName",
        "proc_pid"    :"hrSWRunIndex",
        "proc_param"  :"hrSWRunParameters",
        "proc_cur"    :"hrSystemProcesses",
        "proc_max"    :"hrSystemMaxProcesses",
        "proc_state"  :"hrSWRunStatus",
        "proc_type"   :"hrSWRunType",

        "mem_total"   :"hrMemorySize",
        "mem_used"    :"hrStorageUsed",

        "iface_index" :"ifIndex",
        "iface_name"  :"ifName",
        "iface_type"  :"ifType",
        "iface_MTU"   :"ifMtu",
        "iface_state" :"ifAdminStatus",
        "iface_mac"   :"ifPhysAddress",
        "iface_iIndex":"ipAdEntIfIndex",
        "iface_dic"   :"ipAdEntAddr",
        "iface_oErr"  :"ifOutErrors",
        "iface_iErr"  :"ifInErrors",
        "iface_conn"  :"ifConnectorPresent",

        "storage"     :"hrStorageDescr",
        "allocation"  :"hrStorageAllocationUnits",
        "used"        :"hrStorageUsed",
        "size"        :"hrStorageSize",
}


def snmpwalk(session, reqinfo):
  #print(reqinfo)
  ret = []
  system_items = session.walk(reqinfo)
  for item in system_items:
    ret.append(item.value)
  return ret
    #print ('{oid}.{oid_index} {snmp_type} = {value}'.format(
    #    oid=item.oid,
    #    oid_index=item.oid_index,
    #    snmp_type=item.snmp_type,
    #    value=item.value
    #))
  #print(session.walk('system'))
  #print(i)



def snmpget(session, reqinfo, oid):
  print(reqinfo)
  print(oid)
  a = session.get((reqinfo, oid))
  print(a)
  return str(a)


def process(session, warning, critical):
  proc_max = int(snmpwalk(session, BSD["proc_max"])[0])
  proc_cur = int(snmpwalk(session, BSD["proc_cur"])[0])
  output = "running %s processes [max %s]|processes=%s;%s;%s;0;0" \
          % (proc_cur, proc_max, proc_cur, warning, critical)

  if proc_cur > critical:
    print ("CRITICAL: " + output)
    sys.exit(2)
  elif proc_cur > warning:
    print ("WARNING: " + output)
    sys.exit(1)
  else:
    print ("OK: " + output)
    sys.exit(0)


def os_info(session):
  print ("\nSystem:  " + snmpwalk(session,"sysDescr")[0])
  print ("Uptime:  " + snmpwalk(session,"hrSystemUptime")[0])# + " days") #[0]).split(" ")[-3:]))
  print ("CPU:     " + snmpwalk(session,"hrDeviceDescr")[0])
  print ("Contact: " + snmpwalk(session,"sysContact")[0] + "\n")
  sys.exit(0)


def storage_list(session):
  LIST_fs, LIST_alloc, LIST_size, LIST_used = ([] for i in range(4))

  for i in snmpwalk(session, BSD["storage"]):
    LIST_fs.append(i)
  for i in snmpwalk(session, BSD["allocation"]):
    LIST_alloc.append(i)
  for i in snmpwalk(session, BSD["size"]):
    LIST_size.append(i)
  for i in snmpwalk(session, BSD["used"]):
    LIST_used.append(i)

  print ("\n    SIZE\t\tUSED\t\t    AVALIABLE\t\tFILE SYSTEM")
  print ("==================================================================================")

  for p in LIST_fs:
    if (len(p)>0 and p[0] == "/"):
      x = LIST_fs.index(p)
      if (LIST_alloc[x] and LIST_size[x] and LIST_used[x]):
        SIZE = int(LIST_alloc[x]) * int(LIST_size[x])
        USED = int(LIST_alloc[x]) * int(LIST_used[x])
        FREE = SIZE - USED

        PERCENT_FREE  = (int(FREE) / float(SIZE)) * 100
        PERCENT_ALLOC = (int(USED) / float(SIZE)) * 100
        print ("%s\t%s (%.2f %%)\t%s (%.2f %%)" % \
                (sizeof(SIZE).rjust(10), \
                sizeof(USED).rjust(10), \
                PERCENT_ALLOC, \
                sizeof(FREE).rjust(10), \
                PERCENT_FREE) \
                + "\t" + p.ljust(30))
  sys.exit(0)


def sizeof(num, suffix='b'):
  for unit in ['','K','M','G','T','P','E','Z']:
    if abs(num) < 1024.0:
      return "%3.1f %s%s" % (num, unit, suffix)
    num /= 1024.0
  return "%.1f %s%s" % (num, 'Yi', suffix)


def storage(session, fsys):
  LIST_fs, LIST_alloc, LIST_size, LIST_used = ([] for i in range(4))

  for i in snmpwalk(session, BSD["storage"]):
    LIST_fs.append(i)

  if len(LIST_fs) == 0:
    print ("UNKNOWN: can't find such information")
    sys.exit(3)

  if fsys in LIST_fs:
    p = LIST_fs.index(fsys)
  else:
    print ("UNKNOWN: can't find such information")
    sys.exit(3)

  for i in snmpwalk(session, BSD["allocation"]):
    LIST_alloc.append(i)
  for i in snmpwalk(session, BSD["size"]):
    LIST_size.append(i)
  for i in snmpwalk(session, BSD["used"]):
    LIST_used.append(i)

  SIZE = int(LIST_alloc[p]) * int(LIST_size[p])
  USED = int(LIST_alloc[p]) * int(LIST_used[p])
  FREE = SIZE - USED

  PERCENT_FREE  = (int(FREE) / float(SIZE)) * 100
  PERCENT_ALLOC = (int(USED) / float(SIZE)) * 100

  if fsys in ["Swap space", "Real memory"]:
    return PERCENT_ALLOC, "%s usage: %.2f %% [ %s / %s ]|usage=%.2f;" % \
            (fsys, PERCENT_ALLOC, sizeof(USED), sizeof(SIZE), PERCENT_ALLOC)
  else:
    return PERCENT_ALLOC, "FS usage: %.2f %% [ %s / %s ]|usage=%.2f;" % \
            (PERCENT_ALLOC, sizeof(USED), sizeof(SIZE), PERCENT_ALLOC)

def main():
  p = argparse.ArgumentParser(
      formatter_class=argparse.RawDescriptionHelpFormatter,
      epilog = '''

      _____                 ____   _____ _____        _____ _   _ __  __ _____       ____  
     / ___ \               |  _ \ / ____|  __ \      / ____| \ | |  \/  |  __ \     |___ \ 
    / /  / /___  ___  ____ | |_) | (___ | |  | |    | (___ |  \| | \  / | |__) |_   ____) |
   / /  / / __ \/ _ \/ __ \|  _ < \___ \| |  | |     \___ \| . ` | |\/| |  ___/\ \ / /__ < 
  / /__/ / /_/ /  __/ / / /| |_) |____) | |__| |     ____) | |\  | |  | | |     \ V /___) |
  \_____/ .___/\___/_/ /_/ |____/|_____/|_____/     |_____/|_| \_|_|  |_|_|      \_/|____/ 
       /_/
              |    .
          .   |L  /|   .         This script uses SNMPv3 to check memory/swap usage, file system
      _ . |\ _| \--+._/| .        space usage and CPU load average on (remote) OpenBSD system.
     / ||\| Y J  )   / |/| ./      It also shows detailed information about all avaliable file
    J  |)'( |        ` F`.'/       systems, and configured NICs, system information about OS
  -<|  F         __     .-<         and list of running processes.                 
    | /       .-'. `.  /-. L___       
    J \      <    \  | | O\|.-'   EXAMPLES:   
  _J \  .-    \/ O | | \  |F      
 '-F  -<_.     \   .-'  `-' L__   Checks FS space usage (in %) on '/var' with 'authPriv' secLevel:
__J  _   _.     >-'  )._.   |-'   > ./openbsd_snmp3.py -H <IP_ADDRESS> -u <secName> -A <authPassword> \  
`-|.'   /_.           \_|   F        -a <authProtocol> -X <privPassword> -x <privProtocol> -O fs:/var \ 
  /.-   .                _.<         -w 80 -c 90
 /'    /.'             .'  `\ 
  /L  /'   |/      _.-'-\         Checks RAM usage  
 /'J       ___.---'\|             > 
   |\  .--' V  | `. `             
   |/`. `-.     `._)              
      / .-.\ 
      \ (  `\                     
       `.\                        
                                  
''')

  p.add_argument('--version',
          action='version',
          version='%(prog)s \nVersion: '+ str(VERSION))

  p.add_argument('-H',
          required=True,
          dest='host',
          help='IP addess or hostname of the target host')

  p.add_argument('-l',
          required=True,
          dest='secLevel',
          help='Set the securityLevel used for SNMPv3 messages \
                  (noAuthNoPriv|authNoPriv|authPriv).')
  p.add_argument('-u',
          required=True,
          dest='secName',
          help='Set the securityName used for authenticated SNMPv3 messages.')
  p.add_argument('-a',
          #required=True,
          dest='authProtocol',
          help='Set the authentication protocol (MD5 or SHA) used for \
                  authenticated SNMPv3 messages.')
  p.add_argument('-A',
          #required=True,
          dest='authPassword',
          help='Set the authentication pass phrase used for authenticated \
                  SNMPv3 messages.')
  p.add_argument('-x',
          #required=True,
          dest='privProtocol',
          help='Set the privacy protocol (DES or AES) used for encrypted \
                  SNMPv3 messages.')
  p.add_argument('-X',
          #required=True,
          dest='privPassword',
          help='Set  the  privacy  pass phrase used for encrypted SNMPv3 \
                  messages.')
  p.add_argument('-O',
          required=True,
          dest='option',
          help='''Check target. This can be "cpu", "mem", "swap", "fs" \
                  or "proc" - number of running processes''')
  p.add_argument('-w',
          dest='warning',
          help='WARNING value')

  p.add_argument('-c',
          dest='critical',
          help='CRITICAL value')

  ARG = p.parse_args()

  if ARG.secLevel == "authPriv":
    if ARG.authProtocol is None or \
       ARG.authPassword is None or \
       ARG.privProtocol is None or \
       ARG.privPassword is None:
         p.error("Security Level 'authPriv' requires authProtocol, \
                 authPassword, privProtocol and privPassword.")
         sys.exit(1)

  elif ARG.secLevel == "authNoPriv":
    pass #TODO

  elif ARG.secLevel == "noAuthNoPriv":
    pass #TODO

  else:
      p.error("secLevel should be 'authPriv', 'authNoPriv' or 'noAuthNoPriv'")
      sys.exit(1)

  session = Session(hostname=ARG.host,
                  version=3,
                  timeout=1,
                  retries=3,
                  remote_port=161,
                  security_level=ARG.secLevel,
                  security_username=ARG.secName,
                  privacy_protocol=ARG.privProtocol,
                  privacy_password=ARG.privPassword,
                  auth_protocol=ARG.authProtocol,
                  auth_password=ARG.authPassword,
                  context_engine_id=u'',
                  security_engine_id=u'',
                  context=u'',
                  engine_boots=0,
                  engine_time=0,
                  our_identity=u'',
                  their_identity=u'',
                  their_hostname=u'',
                  trust_cert=u'',
                  use_long_names=False,
                  use_numeric=False,
                  use_sprint_value=False,
                  use_enums=False,
                  best_guess=0,
                  retry_no_such=False,
                  abort_on_nonexistent=False)


  if (ARG.warning is None and ARG.critical is None):
    if   (ARG.option == "file-systems"): storage_list(session)
    elif (ARG.option == "os"):           os_info     (session)
    elif (ARG.option == "proc"):         proc        (session)
    elif (ARG.option == "interfaces"):   interfaces  (session)
    else: p.parse_args(['-h'])
  else:
    if   (ARG.option == "cpu"):    value, msg = cpu    (session)
    elif (ARG.option == "mem"):    value, msg = storage(session, "Real memory")
    elif (ARG.option == "swap"):   value, msg = storage(session, "Swap space")
    elif (ARG.option == "proc"):   process(session, int(ARG.warning), int(ARG.critical))
    elif (ARG.option[:2] == "fs" and len(ARG.option)>3):
      value, msg = storage(session, ARG.option[3:])
    else: p.parse_args(['-h'])

  if (int(value) >= int(ARG.critical)):
    print("CRITICAL: " + msg + ARG.warning + ";" + ARG.critical + ";0;0")
    sys.exit(2)

  elif (int(value) >= int(ARG.warning)):
    print("WARNING: " + msg + ARG.warning + ";" + ARG.critical + ";0;0")
    sys.exit(1)

  else:
    print("OK: " + msg + ARG.warning + ";" + ARG.critical + ";0;0")
    sys.exit(0)

if __name__ == '__main__':
  main()

