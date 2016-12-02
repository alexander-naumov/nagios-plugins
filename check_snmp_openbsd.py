#!/usr/bin/env python
#
# Author: Alexander Naumov <alexander_naumov@opensuse.org>
#
# Copyright (c) 2016, 2017 Alexander Naumov <alexander_naumov@opensuse.org>, Munich, Germany
#                     All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import sys, os, re, argparse
import subprocess as sp

VERSION = 0.5

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
	"mem_free"    :".1.3.6.1.4.1.11.2.3.1.1.7.0",

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


def snmpwalk(ip, community, OID):
	if (OID == "hrSystemUptime"):
		return sp.Popen(["snmpwalk", "-v2c", "-c", community, ip, "-Ov", OID], stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE).communicate()[0].split("\n")

	if (OID == "sysDescr" or OID == "hrDeviceDescr" or OID == "hrSWRunParameters"):
		return sp.Popen(["snmpwalk", "-v2c", "-c", community, ip, "-Oq", "-Ov", OID], stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE).communicate()[0].split("\n")

	LIST_o = []
	for i in sp.Popen(["snmpwalk", "-v2c", "-c", community, ip, "-Oq", "-Ov", OID], stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE).communicate()[0].split("\n"):
		LIST_o.append(i.split(" ")[0])

	return LIST_o


def os_info(ip, community):
	print "\nUname:   " + snmpwalk(ip, community, "sysDescr")[0]
	print "Uptime:  " + " ".join((snmpwalk(ip, community, "hrSystemUptime")[0]).split(" ")[-3:])
	#print snmpwalk(sys.argv[1], sys.argv[2], "hrStorageType")[0]
	# snmpwalk -v2c -c  hrStorage
	print "CPU:     " + snmpwalk(ip, community, "hrDeviceDescr")[0]
	print "Contact: " + snmpwalk(ip, community, "sysContact")[0] + "\n"

	sys.exit(0)


def usage():
	print "Version: " + str(VERSION)

	print "\nThis script uses 'snmpwalk' to check usage of memory and swap and"
	print "the CPU load average on OpenBSD system. It also shows detailed information about"
	print "file system space usage, operation system and running processes.\n"

	print "Usage:   " + sys.argv[0] + " <IP address> <SNMP community> os"
	print "Usage:   " + sys.argv[0] + " <IP address> <SNMP community> proc"
	print "Usage:   " + sys.argv[0] + " <IP address> <SNMP community> file-systems"
	print "Usage:   " + sys.argv[0] + " <IP address> <SNMP community> interfaces"
	print "Usage:   " + sys.argv[0] + " <IP address> <SNMP community> <cpu|mem|fs|swap|proc> <warning> <critical>\n"

	print "Example: " + sys.argv[0] + " 127.0.0.1 public fs:/var 80  90    checks file system space usage (in %) on /var"
	print "Example: " + sys.argv[0] + " 127.0.0.1 public cpu     5   10    checks CPU load average over the last minute"
	print "Example: " + sys.argv[0] + " 127.0.0.1 public mem     80  90    checks memory usage (in %)"
	print "Example: " + sys.argv[0] + " 127.0.0.1 public swap    80  90    checks swap usage (in %)"
	print "Example: " + sys.argv[0] + " 127.0.0.1 public proc    50  100   checks the number of running processes\n"
	sys.exit(0)

def proc(ip, community):
	LIST_pid, LIST_state, LIST_type, LIST_name, LIST_param = ([] for i in range(5))

	for i in snmpwalk(ip, community, BSD["proc_pid"]):
		LIST_pid.append(i)
	for i in snmpwalk(ip, community, BSD["proc_state"]):
		LIST_state.append(i)
	for i in snmpwalk(ip, community, BSD["proc_type"]):
		LIST_type.append(i)
	for i in snmpwalk(ip, community, BSD["proc_name"]):
		LIST_name.append(i[1:-1])
	for i in snmpwalk(ip, community, BSD["proc_param"]):
		LIST_param.append(i[1:-1])

	print "\nPID        STATE        TYPE            PROC"
	print "================================================================"
	for pid in LIST_pid:
			x = LIST_pid.index(pid)
			print "%s %s %s %s %s" % (pid.ljust(10), LIST_state[x].ljust(12), LIST_type[x].ljust(15), LIST_name[x], LIST_param[x])
	sys.exit(0)


def process(ip, community, warning, critical):
	proc_max = int(snmpwalk(ip, community, BSD["proc_max"])[0])
	proc_cur = int(snmpwalk(ip, community, BSD["proc_cur"])[0])
	output = "running %s processes [max %s]|processes=%s;%s;%s;0;0" % (proc_cur, proc_max, proc_cur, warning, critical)

	if proc_cur > critical:
		print "CRITICAL: " + output
		sys.exit(2)
	elif proc_cur > warning:
		print "WARNING: " + output
		sys.exit(1)
	else:
		print "OK: " + output
		sys.exit(0)

# FROM rfc2790:
# "The average, over the last minute, of the percentage
# of time that this processor was not idle.
# Implementations may approximate this one minute
# smoothing period if necessary."
def cpu(ip, community):
	try:
		load  = snmpwalk(ip, community, BSD["cpu_load"])[0]
	except:
		print "UNKNOWN: No SNMP answer from " + ip
		sys.exit(3)

	if load:
		output = "CPU load average %s %% |'1 min'=%s;" % (load, load)
		return int(load), output
	else:
		print "UNKNOWN: No SNMP answer from " + ip
		sys.exit(3)


def interfaces(ip, community):
	Index, Name, Type, Mtu, State, Mac, OErr, IErr, Conn, Ip, Dic = ([] for i in range(11))

	for i in snmpwalk(ip, community, BSD["iface_index"])[:-1]:
		Index.append(int(i))
	for i in snmpwalk(ip, community, BSD["iface_name"]):
		Name.append(i)
	for i in snmpwalk(ip, community, BSD["iface_type"]):
		Type.append(i)
	for i in snmpwalk(ip, community, BSD["iface_MTU"]):
		Mtu.append(i)
	for i in snmpwalk(ip, community, BSD["iface_state"]):
		State.append(i)
	for i in snmpwalk(ip, community, BSD["iface_mac"]):
		Mac.append(i)
	for i in snmpwalk(ip, community, BSD["iface_oErr"]):
		OErr.append(i)
	for i in snmpwalk(ip, community, BSD["iface_iErr"]):
		IErr.append(i)
	for i in snmpwalk(ip, community, BSD["iface_conn"]):
		Conn.append(i)
	for i in snmpwalk(ip, community, BSD["iface_iIndex"]):
		Ip.append(i)
	for i in snmpwalk(ip, community, BSD["iface_dic"]):
		Dic.append(i)

	Dicto = dict(zip(Ip, Dic))

	print "\nNAME       STATE      IP                 MAC                  MTU        TYPE                 CONNECTOR  I/O ERROR"
	print "==================================================================================================================="
	for i in Index:
		try:
			IP = Dicto[str(i)]
		except:
			IP = ""
		x = Index.index(i)
		print "%s %s %s %s %s %s %s %s/%s" % (Name[x].ljust(10), State[x].ljust(10), IP.ljust(18), Mac[x].ljust(20), Mtu[x].ljust(10), Type[x].ljust(20), Conn[x].ljust(10), OErr[x], IErr[x])
	sys.exit(0)


def storage_list(ip, community):
	LIST_fs, LIST_alloc, LIST_size, LIST_used = ([] for i in range(4))

	for i in snmpwalk(ip, community, BSD["storage"]):
		LIST_fs.append(i)
	for i in snmpwalk(ip, community, BSD["allocation"]):
		LIST_alloc.append(i)
	for i in snmpwalk(ip, community, BSD["size"]):
		LIST_size.append(i)
	for i in snmpwalk(ip, community, BSD["used"]):
		LIST_used.append(i)

	print "\n    SIZE\t\tUSED\t\t    AVALIABLE\t\tFILE SYSTEM"
	print "=================================================================================="
	for p in LIST_fs:
		if (len(p)>0 and p[0] == "/"):
			x = LIST_fs.index(p)
			if (LIST_alloc[x] and LIST_size[x] and LIST_used[x]):
				SIZE = int(LIST_alloc[x]) * int(LIST_size[x])
				USED = int(LIST_alloc[x]) * int(LIST_used[x])
				FREE = SIZE - USED

				PERCENT_FREE  = (int(FREE) / float(SIZE)) * 100
				PERCENT_ALLOC = (int(USED) / float(SIZE)) * 100
				print "%s\t%s (%.2f %%)\t%s (%.2f %%)" % (sizeof(SIZE).rjust(10), sizeof(USED).rjust(10), PERCENT_ALLOC, sizeof(FREE).rjust(10), PERCENT_FREE) + "\t" + p.ljust(30)
	sys.exit(0)


def storage(ip, community, fsys):
	LIST_fs, LIST_alloc, LIST_size, LIST_used = ([] for i in range(4))

	for i in snmpwalk(ip, community, BSD["storage"]):
		LIST_fs.append(i)

	if len(LIST_fs[0]) == 0:
		print "UNKNOWN: can't find such information"
		sys.exit(3)

	if fsys in LIST_fs:
		p = LIST_fs.index(fsys)
	else:
		print "UNKNOWN: can't find such information"
		sys.exit(3)

	for i in snmpwalk(ip, community, BSD["allocation"]):
		LIST_alloc.append(i)
	for i in snmpwalk(ip, community, BSD["size"]):
		LIST_size.append(i)
	for i in snmpwalk(ip, community, BSD["used"]):
		LIST_used.append(i)

	SIZE = int(LIST_alloc[p]) * int(LIST_size[p])
	USED = int(LIST_alloc[p]) * int(LIST_used[p])
	FREE = SIZE - USED

	PERCENT_FREE = (int(FREE) / float(SIZE)) * 100
	PERCENT_ALLOC = (int(USED) / float(SIZE)) * 100

	if fsys == "Swap":
		output = "Swap usage %.2f %% [ %s / %s ]|usage=%.2f;" % (PERCENT_ALLOC, sizeof(USED), sizeof(SIZE), PERCENT_ALLOC)
	elif fsys == "Real":
		output = "Memory usage %.2f %% [ %s / %s ]|usage=%.2f;" % (PERCENT_ALLOC, sizeof(USED), sizeof(SIZE), PERCENT_ALLOC)
	else:
		output = "FS usage %.2f %% [ %s / %s ]|usage=%.2f;" % (PERCENT_ALLOC, sizeof(USED), sizeof(SIZE), PERCENT_ALLOC)
	return PERCENT_ALLOC, output


def sizeof(num, suffix='b'):
	for unit in ['','K','M','G','T','P','E','Z']:
		if abs(num) < 1024.0:
			return "%3.1f %s%s" % (num, unit, suffix)
		num /= 1024.0
	return "%.1f %s%s" % (num, 'Yi', suffix)


def main():
	p = argparse.ArgumentParser(description=
	'''This script uses "snmpwalk" to check usage of memory
	and swap and the CPU load average on OpenBSD system.
	It also shows detailed information about file system
	space usage, operation system and running processes.''')

	p.add_argument('-H',
                  required=True,
                  dest='host',
                  help='IP addess or hostname of the target host')
	p.add_argument('-C',
                  required=True,
                  dest='community',
                  help='SNMPv2 community')
	p.add_argument('-O',
                  required=True,
                  dest='option',
                  help='''What sould be checked. This can be CPU, memory, swap, FS or number of running processes''')
	p.add_argument('-w',
                  dest='warning',
                  help='WARNING value')
	p.add_argument('-c',
                  dest='critical',
                  help='CRITICAL value')

	ARG = p.parse_args()

	if (ARG.warning is None and ARG.critical is None):
		if (ARG.option == "file-systems"): storage_list(ARG.host, ARG.community)
		if (ARG.option == "os"):           os_info     (ARG.host, ARG.community)
		if (ARG.option == "proc"):         proc        (ARG.host, ARG.community)
		if (ARG.option == "interfaces"):   interfaces  (ARG.host, ARG.community)
	else:
		if   (ARG.option == "cpu"):    value, msg = cpu    (ARG.host, ARG.community)
		elif (ARG.option == "mem"):    value, msg = storage(ARG.host, ARG.community, "Real")
		elif (ARG.option == "swap"):   value, msg = storage(ARG.host, ARG.community, "Swap")
		elif (ARG.option == "proc"):   process(ARG.host, ARG.community, int(ARG.warning), int(ARG.critical))
		elif (ARG.option[:2] == "fs"): value, msg = storage(ARG.host, ARG.community, ARG.option[3:])
		else: usage()

	if (int(value) >= int(ARG.critical)):
		print "CRITICAL: " + msg + ARG.warning + ";" + ARG.critical + ";0;0"
		sys.exit(2)
	elif (int(value) >= int(ARG.warning)):
		print "WARNING: " + msg + ARG.warning + ";" + ARG.critical + ";0;0"
		sys.exit(1)
	else:
		print "OK: " + msg + ARG.warning + ";" + ARG.critical + ";0;0"
		sys.exit(0)

if __name__ == '__main__':
	main()
