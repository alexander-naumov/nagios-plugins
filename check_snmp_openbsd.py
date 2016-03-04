#!/usr/bin/env python
#
# Alexander Naumov <alexander.naumov@opensuse.org>, 2016
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program (see the file COPYING); if not, see
# http://www.gnu.org/licenses/, or contact Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
#

import sys, os, re
import subprocess as sp

VERSION = 0.3

BSD = {
	"cpu_load"    :"hrProcessorLoad",

	"proc_name"   :"hrSWRunName",
	"proc_pid"    :"hrSWRunIndex",
	"proc_param"  :"hrSWRunParameters",
	"proc_cur"    :"hrSystemProcesses",
	"proc_max"    :"hrSystemMaxProcesses",

	"mem_total"   :"hrMemorySize",
	"mem_free"    :".1.3.6.1.4.1.11.2.3.1.1.7.0",

	"iface_name"  :"ifName",

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
	print "\nUname:   " + snmpwalk(sys.argv[1], sys.argv[2], "sysDescr")[0]
	print "Uptime:  " + " ".join((snmpwalk(sys.argv[1], sys.argv[2], "hrSystemUptime")[0]).split(" ")[-3:])
	#print snmpwalk(sys.argv[1], sys.argv[2], "hrStorageType")[0]
	# snmpwalk -v2c -c  hrStorage
	print "CPU:     " + snmpwalk(sys.argv[1], sys.argv[2], "hrDeviceDescr")[0]
	print "Contact: " + snmpwalk(sys.argv[1], sys.argv[2], "sysContact")[0] + "\n"

	sys.exit(0)


def usage():
	print "Version: " + str(VERSION)

	print "\nThis script checks the memory usage on the OpenBSD system, the CPU load"
	print "average and the file system usage. It also shows detailed information about"
	print "the file system disk usage, list of running processes and operating system.\n"

	print "Usage:   " + sys.argv[0] + " <IP address> <SNMP community> os"
	print "Usage:   " + sys.argv[0] + " <IP address> <SNMP community> proc"
	print "Usage:   " + sys.argv[0] + " <IP address> <SNMP community> file-systems"
#	print "Usage:   " + sys.argv[0] + " <IP address> <SNMP community> interfaces"
	print "Usage:   " + sys.argv[0] + " <IP address> <SNMP community> <cpu|mem|fs|swap|proc> <warning> <critical>\n"
	print "Example: " + sys.argv[0] + " 127.0.0.1 public fs:/var 80  90    We check file system space usage (in %) on /var"
	print "Example: " + sys.argv[0] + " 127.0.0.1 public cpu     80  90    We check CPU load average over the last minute (in %)"
	print "Example: " + sys.argv[0] + " 127.0.0.1 public mem     80  90    We check memory usage (in %)"
	print "Example: " + sys.argv[0] + " 127.0.0.1 public swap    80  90    We check swap usage (in %)"
	print "Example: " + sys.argv[0] + " 127.0.0.1 public proc    50  100   We check the number of running processes\n"
	sys.exit(0)


def proc(ip, community):
	LIST_pid = []
	for i in snmpwalk(ip, community, BSD["proc_pid"]):
		LIST_pid.append(i)

	LIST_name = []
	for i in snmpwalk(ip, community, BSD["proc_name"]):
		LIST_name.append(i[1:-1])

	LIST_param = []
	for i in snmpwalk(ip, community, BSD["proc_param"]):
		LIST_param.append(i[1:-1])

	print "\nPID\t   PROC"
	print "==============================================="
	for pid in LIST_pid:
			x = LIST_pid.index(pid)
			print "%s %s %s" % (pid.ljust(10), LIST_name[x], LIST_param[x])
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
	LIST_iface = []
	for i in snmpwalk(ip, community, BSD["iface_name"]):
		LIST_iface.append(i)

	print "\nInterface"
	print "=================================================================================="
	for iface in LIST_iface:
		print iface.ljust(10)

	sys.exit(0)


def storage_list(ip, community):
	LIST_fs = []
	for i in snmpwalk(ip, community, BSD["storage"]):
		LIST_fs.append(i)

	LIST_alloc = []
	for i in snmpwalk(ip, community, BSD["allocation"]):
		LIST_alloc.append(i)

	LIST_size = []
	for i in snmpwalk(ip, community, BSD["size"]):
		LIST_size.append(i)

	LIST_used = []
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
	LIST_fs = []
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

	LIST_alloc = []
	for i in snmpwalk(ip, community, BSD["allocation"]):
		LIST_alloc.append(i)

	LIST_size = []
	for i in snmpwalk(ip, community, BSD["size"]):
		LIST_size.append(i)

	LIST_used = []
	for i in snmpwalk(ip, community, BSD["used"]):
		LIST_used.append(i)

	SIZE = int(LIST_alloc[p]) * int(LIST_size[p])
	USED = int(LIST_alloc[p]) * int(LIST_used[p])
	FREE = SIZE - USED

	PERCENT_FREE = (int(FREE) / float(SIZE)) * 100
	PERCENT_ALLOC = (int(USED) / float(SIZE)) * 100

	if fsys == "Swap":
		output = "Swap usage %.2f %% [ %s / %s ]|usage=%s;" % (PERCENT_ALLOC, sizeof(USED), sizeof(SIZE), int(PERCENT_ALLOC))
	elif fsys == "Real":
		output = "Memory usage %.2f %% [ %s / %s ]|usage=%s;" % (PERCENT_ALLOC, sizeof(USED), sizeof(SIZE), int(PERCENT_ALLOC))
	else:
		output = "FS usage %.2f %% [ %s / %s ]|usage=%s;" % (PERCENT_ALLOC, sizeof(USED), sizeof(SIZE), int(PERCENT_ALLOC))
	return int(PERCENT_ALLOC), output


def sizeof(num, suffix='b'):
	for unit in ['','K','M','G','T','P','E','Z']:
		if abs(num) < 1024.0:
			return "%3.1f %s%s" % (num, unit, suffix)
		num /= 1024.0
	return "%.1f %s%s" % (num, 'Yi', suffix)


def main():
	if (len(sys.argv) == 4):
		if (sys.argv[3] == "file-systems"): storage_list(sys.argv[1], sys.argv[2])
		if (sys.argv[3] == "os"):           os_info(sys.argv[1], sys.argv[2])
		if (sys.argv[3] == "proc"):         proc(sys.argv[1], sys.argv[2])
#		if (sys.argv[3] == "interfaces"): interfaces(sys.argv[1], sys.argv[2])

	if (len(sys.argv) == 6):
		if   (sys.argv[3] == "cpu"):      value, msg = cpu(sys.argv[1], sys.argv[2])
		elif (sys.argv[3] == "mem"):      value, msg = storage(sys.argv[1], sys.argv[2], "Real")
		elif (sys.argv[3] == "swap"):     value, msg = storage(sys.argv[1], sys.argv[2], "Swap")
		elif (sys.argv[3] == "proc"):     process(sys.argv[1], sys.argv[2], int(sys.argv[4]), int(sys.argv[5]))
		elif (sys.argv[3][:2] == "fs"):   value, msg = storage(sys.argv[1], sys.argv[2], sys.argv[3][3:])

		else: usage()
	else:	usage()

	if (int(value) >= int(sys.argv[5])):
		print "CRITICAL: " + msg + sys.argv[4] + ";" + sys.argv[5] + ";0;100"
		sys.exit(2)
	elif (int(value) >= int(sys.argv[4])):
		print "WARNING: " + msg + sys.argv[4] + ";" + sys.argv[5] + ";0;100"
		sys.exit(1)
	else:
		print "OK: " + msg + sys.argv[4] + ";" + sys.argv[5] + ";0;100"
		sys.exit(0)

if __name__ == '__main__':
	main()
