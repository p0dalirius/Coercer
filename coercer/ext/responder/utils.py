#! /usr/bin/env python3
# This file is part of Responder, a network take-over set of tools 
# created and maintained by Laurent Gaffie.
# email: laurent.gaffie@gmail.com
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import os
import sys
import re
import logging
import socket

from coercer.structures import EscapeCodes
from . import settings
import datetime
import codecs
import struct

from calendar import timegm

import psutil
from coercer.core.Reporter import reporter
	
def RandomChallenge():
	if settings.Config.PY2OR3 == "PY3":
		if settings.Config.NumChal == "random":
			from random import getrandbits
			NumChal = b'%016x' % getrandbits(16 * 4)
			Challenge = b''
			for i in range(0, len(NumChal),2):
				Challenge += NumChal[i:i+2]
			return codecs.decode(Challenge, 'hex')
		else:
			return settings.Config.Challenge
	else:
		if settings.Config.NumChal == "random":
			from random import getrandbits
			NumChal = '%016x' % getrandbits(16 * 4)
			Challenge = ''
			for i in range(0, len(NumChal),2):
				Challenge += NumChal[i:i+2].decode("hex")
			return Challenge
		else:
			return settings.Config.Challenge

def HTTPCurrentDate():
	Date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
	return Date

def SMBTime():
    dt = datetime.datetime.now()
    dt = dt.replace(tzinfo=None)
    if settings.Config.PY2OR3 == "PY3":
       return struct.pack("<Q",116444736000000000 + (timegm(dt.timetuple()) * 10000000)).decode('latin-1')
    else:
       return struct.pack("<Q",116444736000000000 + (timegm(dt.timetuple()) * 10000000))

try:
	import sqlite3
except:
	reporter.print_error("Please install python-sqlite3 extension.")
	sys.exit(0)

def color(txt, code = 1, modifier = 0):
	if txt.startswith('[*]'):
		settings.Config.PoisonersLogger.warning(txt)
	elif 'Analyze' in txt:
		settings.Config.AnalyzeLogger.warning(txt)

	if os.name == 'nt':  # No colors for windows...
		return txt
	return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)

def text(txt):
	stripcolors = re.sub(r'\x1b\[([0-9,A-Z]{1,2}(;[0-9]{1,2})?(;[0-9]{3})?)?[m|K]?', '', txt)
	logging.info(stripcolors)
	if os.name == 'nt':
		return txt
	return '\r' + re.sub(r'\[([^]]*)\]', "\033[1;34m[\\1]\033[0m", txt)

def RespondWithIPAton():
	if settings.Config.PY2OR3 == "PY2":
		if settings.Config.ExternalIP:
			return settings.Config.ExternalIPAton
		else:
			return settings.Config.IP_aton
	else:
		if settings.Config.ExternalIP:
			return settings.Config.ExternalIPAton.decode('latin-1')
		else:
			return settings.Config.IP_aton.decode('latin-1')

def RespondWithIPPton():
	if settings.Config.PY2OR3 == "PY2":
		if settings.Config.ExternalIP6:
			return settings.Config.ExternalIP6Pton
		else:
			return settings.Config.IP_Pton6
	else:
		if settings.Config.ExternalIP6:
			return settings.Config.ExternalIP6Pton.decode('latin-1')
		else:
			return settings.Config.IP_Pton6.decode('latin-1')
			
def RespondWithIP():
	if settings.Config.ExternalIP:
		return settings.Config.ExternalIP
	else:
		return settings.Config.Bind_To

def RespondWithIP6():
	if settings.Config.ExternalIP6:
		return settings.Config.ExternalIP6
	else:
		return settings.Config.Bind_To6


def OsInterfaceIsSupported():
	if settings.Config.Interface != "Not set":
		return not IsOsX()
	return False

def IsOsX():
	return sys.platform == "darwin"

def IsIPv6IP(IP):
	if IP == None:
		return False
	regex = "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
	ret  = re.search(regex, IP)
	if ret:
		return True
	else:
		return False	
	
def FindLocalIP(Iface, OURIP, family=socket.AF_INET):
	if family != socket.AF_INET and family != socket.AF_INET6:
		raise ValueError("Provided family must either be AF_INET or AF_INET6")

	if Iface == 'ALL':
		if family == socket.AF_INET:
			return '0.0.0.0'
		else:
			return '::'

	if (family == socket.AF_INET and (IsOsX() or (IsIPv6IP(OURIP) == False and OURIP != None))) or (family == socket.AF_INET6 and IsIPv6IP(OURIP)):
			return OURIP
	
	IP = next((addr.address for addr in psutil.net_if_addrs().get(Iface, []) if addr.family == family), None)
	
	if IP is not None:
		return IP
	else:
		reporter.print_warn("You don't have an %s address assigned." % "IPv4" if family == socket.AF_INET else "IPv6")
		return "127.0.0.1" if family == socket.AF_INET else "::1"
		
# Function used to write captured hashs to a file.
def WriteData(outfile, data, user):
	logging.info("[*] Captured Hash: %s" % data)
	if not os.path.isfile(outfile):
		with open(outfile,"w") as outf:
			outf.write(data + '\n')
		return
	with open(outfile,"r") as filestr:
		if re.search(user.encode('hex'), filestr.read().encode('hex')):
			return False
		elif re.search(re.escape("$"), user):
			return False
	with open(outfile,"a") as outf2:
		outf2.write(data + '\n')

# Function used to write debug config and network info.
def DumpConfig(outfile, data):
	with open(outfile,"a") as dump:
		dump.write(data + '\n')

def StructPython2or3(endian,data):
	#Python2...
	if settings.Config.PY2OR3 == "PY2":
		return struct.pack(endian, len(data))
	#Python3...
	else:
		return struct.pack(endian, len(data)).decode('latin-1')

def StructWithLenPython2or3(endian,data):
	#Python2...
	if settings.Config.PY2OR3 == "PY2":
		return struct.pack(endian, data)
	#Python3...
	else:
		return struct.pack(endian, data).decode('latin-1')

def NetworkSendBufferPython2or3(data):
	if settings.Config.PY2OR3 == "PY2":
		return str(data)
	else:
		return bytes(str(data), 'latin-1')

def NetworkRecvBufferPython2or3(data):
	if settings.Config.PY2OR3 == "PY2":
		return str(data)
	else:
		return str(data.decode('latin-1'))

def SaveToDb(result):

	for k in [ 'module', 'type', 'client', 'hostname', 'user', 'cleartext', 'hash', 'fullhash' ]:
		if not k in result:
			result[k] = ''
	result['client'] = result['client'].replace("::ffff:","")
	if len(result['user']) < 2:
		log_entry = "Skipping one character username: %s" % result['user']
		settings.Config.PoisonersLogger.warning(log_entry)
		reporter.print_info(log_entry)
		return

	cursor = sqlite3.connect(settings.Config.DatabaseFile)
	cursor.text_factory = sqlite3.Binary  # We add a text factory to support different charsets
	
	if len(result['cleartext']):
		fname = '%s-%s-ClearText-%s.txt' % (result['module'], result['type'], result['client'])
		res = cursor.execute("SELECT COUNT(*) AS count FROM responder WHERE module=? AND type=? AND client=? AND LOWER(user)=LOWER(?) AND cleartext=?", (result['module'], result['type'], result['client'], result['user'], result['cleartext']))
	else:
		fname = '%s-%s-%s.txt' % (result['module'], result['type'], result['client'])
		res = cursor.execute("SELECT COUNT(*) AS count FROM responder WHERE module=? AND type=? AND client=? AND LOWER(user)=LOWER(?)", (result['module'], result['type'], result['client'], result['user']))

	(count,) = res.fetchone()
	logfile = os.path.join(settings.Config.ResponderPATH, 'logs', fname)

	if not count:
		with open(logfile,"a") as outf:
			if len(result['cleartext']):  # If we obtained cleartext credentials, write them to file
				outf.write('%s:%s\n' % (result['user'].encode('utf8', 'replace'), result['cleartext'].encode('utf8', 'replace')))
			else:  # Otherwise, write JtR-style hash string to file
				outf.write(result['fullhash'] + '\n')#.encode('utf8', 'replace') + '\n')

		cursor.execute("INSERT INTO responder VALUES(datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?)", (result['module'], result['type'], result['client'], result['hostname'], result['user'], result['cleartext'], result['hash'], result['fullhash']))
		cursor.commit()

	if settings.Config.CaptureMultipleHashFromSameHost:
		with open(logfile,"a") as outf:
			if len(result['cleartext']):  # If we obtained cleartext credentials, write them to file
				outf.write('%s:%s\n' % (result['user'].encode('utf8', 'replace'), result['cleartext'].encode('utf8', 'replace')))
			else:  # Otherwise, write JtR-style hash string to file
				outf.write(result['fullhash'] + '\n')#.encode('utf8', 'replace') + '\n')

	if not count or settings.Config.Verbose:  # Print output
		if len(result['client']):
			reporter.print("%s Client   : " % result['type'], (result['client'], EscapeCodes.BRIGHT_YELLOW), symbol=result['module'])
			text("[%s] %s Client   : %s" % (result['module'], result['type'], color(result['client'], 3)))

		if len(result['hostname']):
			reporter.print("%s Hostname : " % result['type'], (result['hostname'], EscapeCodes.BRIGHT_YELLOW), symbol=result['module'])
			text("[%s] %s Hostname : %s" % (result['module'], result['type'], color(result['hostname'], 3)))

		if len(result['user']):
			reporter.print("%s Username : " % result['type'], (result['user'], EscapeCodes.BRIGHT_YELLOW), symbol=result['module'])
			text("[%s] %s Username : %s" % (result['module'], result['type'], color(result['user'], 3)))

		# Bu order of priority, print cleartext, fullhash, or hash
		if len(result['cleartext']):
			reporter.print("%s Password : " % result['type'], (result['cleartext'], EscapeCodes.BRIGHT_YELLOW), symbol=result['module'])
			text("[%s] %s Password : %s" % (result['module'], result['type'], color(result['cleartext'], 3)))

		elif len(result['fullhash']):
			reporter.print("%s Hash     : " % result['type'], (result['fullhash'], EscapeCodes.BRIGHT_YELLOW), symbol=result['module'])
			text("[%s] %s Hash     : %s" % (result['module'], result['type'], color(result['fullhash'], 3)))

		elif len(result['hash']):
			reporter.print("%s Hash     : " % result['type'], (result['hash'], EscapeCodes.BRIGHT_YELLOW), symbol=result['module'])
			text("[%s] %s Hash     : %s" % (result['module'], result['type'], color(result['hash'], 3)))

		# Appending auto-ignore list if required
		# Except if this is a machine account's hash
		if settings.Config.AutoIgnore and not result['user'].endswith('$'):
			settings.Config.AutoIgnoreList.append(result['client'])
			log_entry = "Adding client %s to auto-ignore list" % result['client']
			reporter.print_info(log_entry)
			settings.Config.PoisonersLogger.warning("[*] " + log_entry)
	elif len(result['cleartext']):
		reporter.print_info("Skipping previously captured cleartext password for %s" % result['user'])
		text('[*] Skipping previously captured cleartext password for %s' % result['user'])
	else:
		reporter.print_info("Skipping previously captured hash for %s" % result['user'])
		text('[*] Skipping previously captured hash for %s' % result['user'])
		cursor.execute("UPDATE responder SET timestamp=datetime('now') WHERE user=? AND client=?", (result['user'], result['client']))
		cursor.commit()
	cursor.close()