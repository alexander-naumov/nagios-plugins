#!/usr/bin/env python
#
# Alexander Naumov <alexander_naumov@opensuse.org>, 2016
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

#
# This script checks the memory on HP-UX system, the CPU load average
# and the file system usage (in %). It also shows detailed information
# about the file system disk space usage and operating system.
#

import sys, os, re
import subprocess as sp

VERSION = 1.0

HP_UX = {
	"cpu_1min":   "1.3.6.1.4.1.11.2.3.1.1.3",
	"cpu_5min":   "1.3.6.1.4.1.11.2.3.1.1.4",
	"cpu_15min":  "1.3.6.1.4.1.11.2.3.1.1.5",

	"mem_total":  ".1.3.6.1.4.1.11.2.3.1.1.8.0",
	"mem_free":   ".1.3.6.1.4.1.11.2.3.1.1.7.0",
	"fs":         ".1.3.6.1.4.1.11.2.3.1.2.2.1.10",
	"allocation": ".1.3.6.1.4.1.11.2.3.1.2.2.1.7",
	"size":       ".1.3.6.1.4.1.11.2.3.1.2.2.1.4",
	"free_space": ".1.3.6.1.4.1.11.2.3.1.2.2.1.5"
}


def snmpwalk(ip, community, OID):
	if (OID == "sysDescr"):
		return sp.Popen(["snmpwalk", "-v2c", "-c", community, ip, "-Oq", "-Ov", OID], stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE).communicate()[0].split("\n")

	LIST_o = []
	for i in sp.Popen(["snmpwalk", "-v2c", "-c", community, ip, "-Oq", "-Ov", OID], stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE).communicate()[0].split("\n"):
		LIST_o.append(i.split(" ")[0])

	return LIST_o


def usage():
	print "Version: " + str(VERSION)

	print "\nThis script checks the memory on HP-UX system, the CPU and the file system usage."
	print "It also shows detailed information about the file system disk usage and operating system.\n"

	print "Usage:   " + sys.argv[0] + " <IP address> <SNMP community> os"
	print "Usage:   " + sys.argv[0] + " <IP address> <SNMP community> file-systems"
	print "Usage:   " + sys.argv[0] + " <IP address> <SNMP community> <cpu|mem|fs> <warning> <critical>\n"
	print "Example: " + sys.argv[0] + " 127.0.0.1 public fs:/var 80 90\t We check FS space usage (in %) on /var"
	print "Example: " + sys.argv[0] + " 127.0.0.1 public cpu     1  2 \t We check CPU load average 5 mins (output includes 1 and 15 mins)"
	print "Example: " + sys.argv[0] + " 127.0.0.1 public mem     80 90\t We check memory usage (in %)"
	sys.exit(0)


def cpu(ip, community, warning, critical):
	try:
		load_1min  = int(snmpwalk(ip, community, HP_UX["cpu_1min"])[0])
		load_5min  = int(snmpwalk(ip, community, HP_UX["cpu_5min"])[0])
		load_15min = int(snmpwalk(ip, community, HP_UX["cpu_15min"])[0])
	except:
		print "UNKNOWN: No SNMP answer from " + ip
		sys.exit(3)

	if load_1min and load_5min and load_15min:
		load_1min  = float(load_1min) / 100
		load_5min  = float(load_5min) / 100
		load_15min = float(load_15min)/ 100

		output = "CPU load average %s, %s, %s |'1 min'=%s;%s;%s;0;0 '5 min'=%s;%s;%s;0;0 '15 min'=%s;%s;%s;0;0" % \
			(load_1min, load_5min, load_15min, \
				load_1min, warning, critical, \
				load_5min, warning, critical, \
				load_15min, warning, critical)
	else:
		print "UNKNOWN: No SNMP answer from " + ip
		sys.exit(3)

	if load_5min > critical:
		print "CRITICAL: " + output
		sys.exit(2)
	elif load_5min > warning:
		print "WARNING: " + output
		sys.exit(1)
	else:
		print "OK: " + output
		sys.exit(0)


def memory(ip, community):
	total = snmpwalk(ip, community, HP_UX["mem_total"])[0]
	free = snmpwalk(ip, community, HP_UX["mem_free"])[0]
	if total and free:
		usage = int(total) - int(free)
		usage_percent = float(usage) * 100 / int(total)

		output = "Memory usage %.2f %% [%s / %s]|usage=%s;" % (usage_percent, sizeof(float(usage) * 1024), sizeof(float(total) * 1024), int(usage_percent))
		return usage_percent, output
	else:
		print "UNKNOWN: No SNMP answer from " + ip
		sys.exit(3)


def storage_list(ip, community):
	LIST_fs = []
	for i in snmpwalk(ip, community, HP_UX["fs"]):
		LIST_fs.append(i[1:-1])

	if len(LIST_fs[0]) == 0:
		print "Sorry, no SNMP (hrStorage) answer from " + ip
		sys.exit(3)

	LIST_alloc = []
	for i in snmpwalk(ip, community, HP_UX["allocation"]):
		LIST_alloc.append(i)

	LIST_size = []
	for i in snmpwalk(ip, community, HP_UX["size"]):
		LIST_size.append(i)

	LIST_free = []
	for i in snmpwalk(ip, community, HP_UX["free_space"]):
		LIST_free.append(i)

	print "\n    SIZE\t\tUSED\t\t    AVALIABLE\t\tFILE SYSTEM"
	print "=================================================================================="

	for p in LIST_fs:
		x = LIST_fs.index(p)
		if (len(LIST_fs[x]) > 0 and LIST_alloc[x] and LIST_size[x] and LIST_free[x]):
			SIZE = int(LIST_alloc[x]) * int(LIST_size[x])
			FREE = int(LIST_alloc[x]) * int(LIST_free[x])
			USED = SIZE - FREE

			PERCENT_FREE  = (int(FREE) / float(SIZE)) * 100
			PERCENT_ALLOC = (int(USED) / float(SIZE)) * 100

			print "%s\t%s (%.2f %%)\t%s (%.2f %%)" % (sizeof(SIZE).rjust(10), sizeof(USED).rjust(10), PERCENT_ALLOC, sizeof(FREE).rjust(10), PERCENT_FREE) + "\t" + p.ljust(30)
	sys.exit(0)


def fs(ip, community, fsys):

	LIST_fs = []
	for i in snmpwalk(ip, community, HP_UX["fs"]):
		LIST_fs.append(i[1:-1])

	if len(LIST_fs[0]) == 0:
		print "UNKNOWN: No SNMP answer from " + ip
		sys.exit(3)

	p = LIST_fs.index(fsys)

	LIST_alloc = []
	for i in snmpwalk(ip, community, HP_UX["allocation"]):
		LIST_alloc.append(i)

	LIST_size = []
	for i in snmpwalk(ip, community, HP_UX["size"]):
		LIST_size.append(i)
	SIZE = int(LIST_alloc[p]) * int(LIST_size[p])

	LIST_free = []
	for i in snmpwalk(ip, community, HP_UX["free_space"]):
		LIST_free.append(i)
	FREE = int(LIST_alloc[p]) * int(LIST_free[p])

	PERCENT_FREE = (int(FREE) / float(SIZE)) * 100
	USED = SIZE - FREE
	PERCENT_ALLOC = (int(USED) / float(SIZE)) * 100

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
		if (sys.argv[3] == "file-systems"):
			storage_list(sys.argv[1], sys.argv[2])
		if (sys.argv[3] == "os"):
			print snmpwalk(sys.argv[1], sys.argv[2], "sysDescr")[0]
			sys.exit(0)

	if (len(sys.argv) == 6):

		if (sys.argv[3] == "cpu"):
			cpu(sys.argv[1], sys.argv[2], float(sys.argv[4]), float(sys.argv[5]))

		elif (sys.argv[3] == "mem"):
			value, msg = memory(sys.argv[1], sys.argv[2])

		elif (sys.argv[3][:2] == "fs"):
			value, msg = fs(sys.argv[1], sys.argv[2], sys.argv[3][3:])

		else:
			usage()

	else:
		usage()

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
