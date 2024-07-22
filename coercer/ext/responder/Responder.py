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
import optparse
import ssl
try:
	from SocketServer import TCPServer, UDPServer, ThreadingMixIn
except:
	from socketserver import TCPServer, UDPServer, ThreadingMixIn
from threading import Thread
from .utils import *
import struct


class ThreadingUDPServer(ThreadingMixIn, UDPServer):
	def server_bind(self):
		if OsInterfaceIsSupported():
			try:
				if settings.Config.Bind_To_ALL:
					pass
				else:
					if (sys.version_info > (3, 0)):
						self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
						self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
					else:
						self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Interface+'\0')
						self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
			except:
				pass
		UDPServer.server_bind(self)

class ThreadingTCPServer(ThreadingMixIn, TCPServer):
	def server_bind(self):
		if OsInterfaceIsSupported():
			try:
				if settings.Config.Bind_To_ALL:
					pass
				else:
					if (sys.version_info > (3, 0)):
						self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
						self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
					else:
						self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Interface+'\0')
						self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
			except:
				pass
		TCPServer.server_bind(self)

class ThreadingTCPServerAuth(ThreadingMixIn, TCPServer):
	def server_bind(self):
		if OsInterfaceIsSupported():
			try:
				if settings.Config.Bind_To_ALL:
					pass
				else:
					if (sys.version_info > (3, 0)):
						self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
						self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
					else:
						self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Interface+'\0')
						self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
			except:
				pass
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
		TCPServer.server_bind(self)

class ThreadingUDPMDNSServer(ThreadingMixIn, UDPServer):
	def server_bind(self):
		MADDR = "224.0.0.251"
		MADDR6 = 'ff02::fb'
		self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
		self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
		Join = self.socket.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP, socket.inet_aton(MADDR) + settings.Config.IP_aton)

		#IPV6:
		if (sys.version_info > (3, 0)):
			mreq = socket.inet_pton(socket.AF_INET6, MADDR6) + struct.pack('@I', if_nametoindex2(settings.Config.Interface))
			self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
		else:
			mreq = socket.inet_pton(socket.AF_INET6, MADDR6) + struct.pack('@I', if_nametoindex2(settings.Config.Interface))
			self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
		if OsInterfaceIsSupported():
			try:
				if settings.Config.Bind_To_ALL:
					pass
				else:
					if (sys.version_info > (3, 0)):
						self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
						self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
					else:
						self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Interface+'\0')
						self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
			except:
				pass
		UDPServer.server_bind(self)

class ThreadingUDPLLMNRServer(ThreadingMixIn, UDPServer):
	def server_bind(self):
		MADDR  = '224.0.0.252'
		MADDR6 = 'FF02:0:0:0:0:0:1:3'
		self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)		
		Join = self.socket.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,socket.inet_aton(MADDR) + settings.Config.IP_aton)

		#IPV6:
		mreq = socket.inet_pton(socket.AF_INET6, MADDR6) + struct.pack('@I', if_nametoindex2(settings.Config.Interface))
		self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
		if OsInterfaceIsSupported():
			try:
				if settings.Config.Bind_To_ALL:
					pass
				else:
					if (sys.version_info > (3, 0)):
						self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
						self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
					else:
						self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Interface+'\0')
						self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
			except:
				pass
		UDPServer.server_bind(self)
		

ThreadingUDPServer.allow_reuse_address = 1
ThreadingUDPServer.address_family = socket.AF_INET6

ThreadingTCPServer.allow_reuse_address = 1
ThreadingTCPServer.address_family = socket.AF_INET6

ThreadingUDPMDNSServer.allow_reuse_address = 1
ThreadingUDPMDNSServer.address_family = socket.AF_INET6

ThreadingUDPLLMNRServer.allow_reuse_address = 1
ThreadingUDPLLMNRServer.address_family = socket.AF_INET6

ThreadingTCPServerAuth.allow_reuse_address = 1
ThreadingTCPServerAuth.address_family = socket.AF_INET6

def serve_thread_udp_broadcast(host, port, handler):
	try:
		server = ThreadingUDPServer(('', port), handler)
		server.serve_forever()
	except:
		print(color("[!] ", 1, 1) + "Error starting UDP server on port " + str(port) + ", check permissions or other servers running.")

def serve_NBTNS_poisoner(host, port, handler):
	serve_thread_udp_broadcast('', port, handler)

def serve_MDNS_poisoner(host, port, handler):
	try:
		server = ThreadingUDPMDNSServer(('', port), handler)
		server.serve_forever()
	except:
		print(color("[!] ", 1, 1) + "Error starting UDP server on port " + str(port) + ", check permissions or other servers running.")

def serve_LLMNR_poisoner(host, port, handler):
	try:
		server = ThreadingUDPLLMNRServer(('', port), handler)
		server.serve_forever()
	except:
		print(color("[!] ", 1, 1) + "Error starting UDP server on port " + str(port) + ", check permissions or other servers running.")
		
def serve_thread_udp(host, port, handler):
	try:
		if OsInterfaceIsSupported():
			server = ThreadingUDPServer(('', port), handler)
			server.serve_forever()
		else:
			server = ThreadingUDPServer(('', port), handler)
			server.serve_forever()
	except:
		print(color("[!] ", 1, 1) + "Error starting UDP server on port " + str(port) + ", check permissions or other servers running.")

def serve_thread_tcp(host, port, handler):
	try:
		if OsInterfaceIsSupported():
			server = ThreadingTCPServer(('', port), handler)
			server.serve_forever()
		else:
			server = ThreadingTCPServer(('', port), handler)
			server.serve_forever()
	except:
		print(color("[!] ", 1, 1) + "Error starting TCP server on port " + str(port) + ", check permissions or other servers running.")

def serve_thread_tcp_auth(host, port, handler):
	try:
		if OsInterfaceIsSupported():
			server = ThreadingTCPServerAuth(('', port), handler)
			server.serve_forever()
		else:
			server = ThreadingTCPServerAuth(('', port), handler)
			server.serve_forever()
	except:
		print(color("[!] ", 1, 1) + "Error starting TCP server on port " + str(port) + ", check permissions or other servers running.")

def serve_thread_SSL(host, port, handler):
	try:

		cert = os.path.join(settings.Config.ResponderPATH, settings.Config.SSLCert)
		key =  os.path.join(settings.Config.ResponderPATH, settings.Config.SSLKey)
		context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
		context.load_cert_chain(cert, key)
		if OsInterfaceIsSupported():
			server = ThreadingTCPServer(('', port), handler)
			server.socket = context.wrap_socket(server.socket, server_side=True)
			server.serve_forever()
		else:
			server = ThreadingTCPServer(('', port), handler)
			server.socket = context.wrap_socket(server.socket, server_side=True)
			server.serve_forever()
	except:
		print(color("[!] ", 1, 1) + "Error starting SSL server on port " + str(port) + ", check permissions or other servers running.")


def main():
	try:
		if (sys.version_info < (3, 0)):
			print(color('\n\n[-]', 3, 1) + " Still using python 2? :(")
		print(color('\n[+]', 2, 1) + " Listening for events...\n")
			
		threads = []

		# Load (M)DNS, NBNS and LLMNR Poisoners
		from poisoners.LLMNR import LLMNR
		from poisoners.NBTNS import NBTNS
		from poisoners.MDNS import MDNS
		threads.append(Thread(target=serve_LLMNR_poisoner, args=('', 5355, LLMNR,)))
		threads.append(Thread(target=serve_MDNS_poisoner,  args=('', 5353, MDNS,)))
		threads.append(Thread(target=serve_NBTNS_poisoner, args=('', 137,  NBTNS,)))

		# Load Browser Listener
		from servers.Browser import Browser
		threads.append(Thread(target=serve_thread_udp_broadcast, args=('', 138,  Browser,)))

		if settings.Config.HTTP_On_Off:
			from servers.HTTP import HTTP
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 80, HTTP,)))

		if settings.Config.WinRM_On_Off:
			from servers.WinRM import WinRM
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 5985, WinRM,)))

		if settings.Config.WinRM_On_Off:
			from servers.WinRM import WinRM
			threads.append(Thread(target=serve_thread_SSL, args=(settings.Config.Bind_To, 5986, WinRM,)))

		if settings.Config.SSL_On_Off:
			from servers.HTTP import HTTP
			threads.append(Thread(target=serve_thread_SSL, args=(settings.Config.Bind_To, 443, HTTP,)))

		if settings.Config.RDP_On_Off:
			from servers.RDP import RDP
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 3389, RDP,)))

		if settings.Config.DCERPC_On_Off:
			from servers.RPC import RPCMap, RPCMapper
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 135, RPCMap,)))
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, settings.Config.RPCPort, RPCMapper,)))

		if settings.Config.WPAD_On_Off:
			from servers.HTTP_Proxy import HTTP_Proxy
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 3141, HTTP_Proxy,)))

		if settings.Config.ProxyAuth_On_Off:
		        from servers.Proxy_Auth import Proxy_Auth
		        threads.append(Thread(target=serve_thread_tcp_auth, args=(settings.Config.Bind_To, 3128, Proxy_Auth,)))

		if settings.Config.SMB_On_Off:
			if settings.Config.LM_On_Off:
				from servers.SMB import SMB1LM
				threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 445, SMB1LM,)))
				threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 139, SMB1LM,)))
			else:
				from servers.SMB import SMB1
				threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 445, SMB1,)))
				threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 139, SMB1,)))

		if settings.Config.Krb_On_Off:
			from servers.Kerberos import KerbTCP, KerbUDP
			threads.append(Thread(target=serve_thread_udp, args=('', 88, KerbUDP,)))
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 88, KerbTCP,)))

		if settings.Config.SQL_On_Off:
			from servers.MSSQL import MSSQL, MSSQLBrowser
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 1433, MSSQL,)))
			threads.append(Thread(target=serve_thread_udp_broadcast, args=(settings.Config.Bind_To, 1434, MSSQLBrowser,)))

		if settings.Config.FTP_On_Off:
			from servers.FTP import FTP
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 21, FTP,)))

		if settings.Config.POP_On_Off:
			from servers.POP3 import POP3
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 110, POP3,)))

		if settings.Config.LDAP_On_Off:
			from servers.LDAP import LDAP, CLDAP
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 389, LDAP,)))
			threads.append(Thread(target=serve_thread_udp, args=('', 389, CLDAP,)))

		if settings.Config.SMTP_On_Off:
			from servers.SMTP import ESMTP
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 25,  ESMTP,)))
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 587, ESMTP,)))

		if settings.Config.IMAP_On_Off:
			from servers.IMAP import IMAP
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 143, IMAP,)))

		if settings.Config.DNS_On_Off:
			from servers.DNS import DNS, DNSTCP
			threads.append(Thread(target=serve_thread_udp, args=('', 53, DNS,)))
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 53, DNSTCP,)))

		for thread in threads:
			thread.daemon = True
			thread.start()

		if settings.Config.AnalyzeMode:
			print(color('[+] Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned.', 3, 1))

		if settings.Config.DHCP_On_Off:
			from poisoners.DHCP import DHCP
			DHCP(settings.Config.DHCP_DNS)

		while True:
			time.sleep(1)

	except KeyboardInterrupt:
		sys.exit("\r%s Exiting..." % color('[+]', 2, 1))

if __name__ == '__main__':
	main()
