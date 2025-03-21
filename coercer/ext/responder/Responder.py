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
from socketserver import TCPServer, ThreadingMixIn
from .utils import *


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
	def server_bind(self):
		self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
		if OsInterfaceIsSupported():
			try:
				if settings.Config.Bind_To_ALL:
					pass
				else:
					if sys.platform == "win32":
						self.socket.bind(settings.Config.OURIP)
					else:
						if (sys.version_info > (3, 0)):
							self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
						else:
							self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Interface+'\0')
			except:
				pass
		TCPServer.server_bind(self)

ThreadingTCPServer.allow_reuse_address = 1
ThreadingTCPServer.address_family = socket.AF_INET6