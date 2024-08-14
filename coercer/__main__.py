#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 Sep 2022


import argparse
import os
import sys
from sectools.network.domains import is_fqdn
from sectools.network.ip import is_ipv4_cidr, is_ipv4_addr, is_ipv6_addr, expand_cidr, expand_port_range
from coercer.core.Reporter import Reporter
from coercer.structures.Credentials import Credentials
from coercer.core.modes.scan import action_scan
from coercer.core.modes.coerce import action_coerce
from coercer.core.modes.fuzz import action_fuzz
from coercer.core.loader import find_and_load_coerce_methods
from coercer.network.smb import try_login
from coercer.network.utils import can_listen_on_port


VERSION = "2.4.3"

banner = """       ______
      / ____/___  ___  _____________  _____
     / /   / __ \\/ _ \\/ ___/ ___/ _ \\/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      v%s
    \\____/\\____/\\___/_/   \\___/\\___/_/       by @podalirius_
""" % VERSION


def parseArgs():
    print(banner)
    parser = argparse.ArgumentParser(add_help=True, description="Automatic windows authentication coercer using various methods.")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode (default: False)")
    parser.add_argument("--debug", default=False, action="store_true", help="Debug mode (default: False)")

    # Creating the "scan" subparser ==============================================================================================================
    mode_scan = argparse.ArgumentParser(add_help=False)
    mode_scan.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode (default: False)")
    mode_scan.add_argument("--debug", default=False, action="store_true", help="Debug mode (default: False)")
    # Advanced configuration
    mode_scan_advanced_config = mode_scan.add_argument_group("Advanced options")
    mode_scan_advanced_config.add_argument("--export-json", default=None, type=str, help="Export results to specified JSON file.")
    mode_scan_advanced_config.add_argument("--export-xlsx", default=None, type=str, help="Export results to specified XLSX file.")
    mode_scan_advanced_config.add_argument("--export-sqlite", default=None, type=str, help="Export results to specified SQLITE3 database file.")
    mode_scan_advanced_config.add_argument("--delay", default=None, type=int, help="Delay between attempts (in seconds)")
    mode_scan_advanced_config.add_argument("--min-http-port", default=64000, type=int, help="Verbose mode (default: False)")
    mode_scan_advanced_config.add_argument("--max-http-port", default=65000, type=int, help="Verbose mode (default: False)")
    mode_scan_advanced_config.add_argument("--http-port", default=80, type=int, help="HTTP port (default: 80)")
    mode_scan_advanced_config.add_argument("--smb-port", default=445, type=int, help="SMB port (default: 445)")
    mode_scan_advanced_config.add_argument("--dce-port", default=135, type=int, help="DCERPC port (default: 135)")
    mode_scan_advanced_config.add_argument("--dce-ports", default=[], nargs='+', type=int, help="DCERPC ports")
    mode_scan_advanced_config.add_argument("--auth-type", default=None, type=str, help="Desired authentication type ('smb' or 'http').")
    # Filters
    mode_scan_filters = mode_scan.add_argument_group("Filtering")
    mode_scan_filters.add_argument("--filter-method-name", default=[], action='append', type=str, help="")
    mode_scan_filters.add_argument("--filter-protocol-name", default=[], action='append', type=str, help="")
    mode_scan_filters.add_argument("--filter-pipe-name", default=[], action='append', type=str, help="")
    mode_scan_filters.add_argument("--filter-transport-name", default=["msrpc", "dcerpc"], choices=["msrpc", "dcerpc"], nargs='*', type=str, help="")
    # Credentials
    mode_scan_credentials = mode_scan.add_argument_group("Authentication & connection")
    mode_scan_credentials.add_argument("-u", "--username", dest="auth_username", default="", help="Username to authenticate to the remote machine.")
    mode_scan_credentials.add_argument("-p", "--password", dest="auth_password", default="", help="Password to authenticate to the remote machine. (if omitted, it will be asked unless -no-pass is specified)")
    mode_scan_credentials.add_argument("-d", "--domain", dest="auth_domain", default="", help="Windows domain name to authenticate to the machine.")
    mode_scan_credentials.add_argument("--hashes", dest="auth_hashes", action="store", metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    mode_scan_credentials.add_argument("--no-pass", action="store_true", help="Don't ask for password (useful for -k)")
    mode_scan_credentials.add_argument("--dc-ip", action="store", metavar="ip address", help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")
    # Kerberos
    mode_scan_credentials.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")
    mode_scan_credentials.add_argument("--aes-key", dest="auth_aeskey", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication (128 or 256 bits)")
    mode_scan_credentials.add_argument("--kdcHost", dest="kdcHost", action="store", metavar="FQDN KDC", help="FQDN of KDC for Kerberos.") 
    # Targets source
    mode_scan_targets_source = mode_scan.add_mutually_exclusive_group(required=True)
    mode_scan_targets_source.add_argument("-t", "--target-ip", default=None, help="IP address or hostname of the target machine")
    mode_scan_targets_source.add_argument("-f", "--targets-file", default=None, help="File containing a list of IP address or hostname of the target machines")
    # Listener
    mode_scan_targets_listener = mode_scan.add_mutually_exclusive_group(required=False)
    mode_scan_targets_listener.add_argument("-i", "--interface", default=None, help="Interface to listen on incoming authentications.")
    mode_scan_targets_listener.add_argument("-I", "--ip-address", default=None, help="IP address to listen on incoming authentications.")

    # Creating the "fuzz" subparser ==============================================================================================================
    mode_fuzz = argparse.ArgumentParser(add_help=False)
    mode_fuzz.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode (default: False)")
    mode_fuzz.add_argument("--debug", default=False, action="store_true", help="Debug mode (default: False)")
    # Advanced configuration
    mode_fuzz_advanced_config = mode_fuzz.add_argument_group("Advanced configuration")
    mode_fuzz_advanced_config.add_argument("--export-json", default=None, type=str, help="Export results to specified JSON file.")
    mode_fuzz_advanced_config.add_argument("--export-xlsx", default=None, type=str, help="Export results to specified XLSX file.")
    mode_fuzz_advanced_config.add_argument("--export-sqlite", default=None, type=str, help="Export results to specified SQLITE3 database file.")
    mode_fuzz_advanced_config.add_argument("--delay", default=None, type=int, help="Delay between attempts (in seconds)")
    mode_fuzz_advanced_config.add_argument("--min-http-port", default=64000, type=int, help="Verbose mode (default: False)")
    mode_fuzz_advanced_config.add_argument("--max-http-port", default=65000, type=int, help="Verbose mode (default: False)")
    mode_fuzz_advanced_config.add_argument("--smb-port", default=445, type=int, help="SMB port (default: 445)")
    mode_fuzz_advanced_config.add_argument("--dce-port", default=135, type=int, help="DCERPC port (default: 135)")
    mode_fuzz_advanced_config.add_argument("--dce-ports", default=[], nargs='+', type=int, help="DCERPC ports")
    mode_fuzz_advanced_config.add_argument("--auth-type", default=None, type=str, help="Desired authentication type ('smb' or 'http').")
    # Filters
    mode_fuzz_filters = mode_fuzz.add_argument_group("Filtering")
    mode_fuzz_filters.add_argument("--filter-method-name", default=[], action='append', type=str, help="")
    mode_fuzz_filters.add_argument("--filter-protocol-name", default=[], action='append', type=str, help="")
    mode_fuzz_filters.add_argument("--filter-pipe-name", default=[], action='append', type=str, help="")
    mode_fuzz_filters.add_argument("--filter-transport-name", default=["msrpc", "dcerpc"], choices=["msrpc", "dcerpc"], nargs='*', type=str, help="")
    # Credentials
    mode_fuzz_credentials = mode_fuzz.add_argument_group("Authentication & connection")
    mode_fuzz_credentials.add_argument("--only-known-exploit-paths", action="store_true", default=False, help="Only test known exploit paths for each functions")
    mode_fuzz_credentials.add_argument("-u", "--username", dest="auth_username", default="", help="Username to authenticate to the remote machine.")
    mode_fuzz_credentials.add_argument("-p", "--password", dest="auth_password", default="", help="Password to authenticate to the remote machine. (if omitted, it will be asked unless -no-pass is specified)")
    mode_fuzz_credentials.add_argument("-d", "--domain", dest="auth_domain", default="", help="Windows domain name to authenticate to the machine.")
    mode_fuzz_credentials.add_argument("--hashes", dest="auth_hashes", action="store", metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    mode_fuzz_credentials.add_argument("--no-pass", action="store_true", help="Don't ask for password (useful for -k)")
    mode_fuzz_credentials.add_argument("--dc-ip", action="store", metavar="ip address", help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")
    # Kerberos
    mode_fuzz_credentials.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")
    mode_fuzz_credentials.add_argument("--aes-key", dest="auth_aeskey", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication (128 or 256 bits)")
    mode_fuzz_credentials.add_argument("--kdcHost", dest="kdcHost", action="store", metavar="FQDN KDC", help="FQDN of KDC for Kerberos.") 
    # Targets source
    mode_fuzz_targets_source = mode_fuzz.add_mutually_exclusive_group(required=True)
    mode_fuzz_targets_source.add_argument("-t", "--target-ip", default=None, help="IP address or hostname of the target machine")
    mode_fuzz_targets_source.add_argument("-f", "--targets-file", default=None, help="File containing a list of IP address or hostname of the target machines")
    # Listener
    mode_fuzz_targets_listener = mode_fuzz.add_mutually_exclusive_group(required=False)
    mode_fuzz_targets_listener.add_argument("-i", "--interface", default=None, help="Interface to listen on incoming authentications.")
    mode_fuzz_targets_listener.add_argument("-I", "--ip-address", default=None, help="IP address to listen on incoming authentications.")

    # Creating the "coerce" subparser ==============================================================================================================
    mode_coerce = argparse.ArgumentParser(add_help=False)
    mode_coerce.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode (default: False)")
    mode_coerce.add_argument("--debug", default=False, action="store_true", help="Debug mode (default: False)")
    # Advanced configuration
    mode_coerce_advanced_config = mode_coerce.add_argument_group("Advanced configuration")
    mode_coerce_advanced_config.add_argument("--delay", default=None, type=int, help="Delay between attempts (in seconds)")
    mode_coerce_advanced_config.add_argument("--http-port", default=80, type=int, help="HTTP port (default: 80)")
    mode_coerce_advanced_config.add_argument("--smb-port", default=445, type=int, help="SMB port (default: 445)")
    mode_coerce_advanced_config.add_argument("--dce-port", default=135, type=int, help="DCERPC port (default: 135)")
    mode_coerce_advanced_config.add_argument("--dce-ports", default=[], nargs='+', type=int, help="DCERPC ports")
    mode_coerce_advanced_config.add_argument("--always-continue", default=False, action="store_true", help="Always continue to coerce")
    mode_coerce_advanced_config.add_argument("--auth-type", default=None, type=str, help="Desired authentication type ('smb' or 'http').")
    # Filters
    mode_coerce_filters = mode_coerce.add_argument_group("Filtering")
    mode_coerce_filters.add_argument("--filter-method-name", default=[], action='append', type=str, help="")
    mode_coerce_filters.add_argument("--filter-protocol-name", default=[], action='append', type=str, help="")
    mode_coerce_filters.add_argument("--filter-pipe-name", default=[], action='append', type=str, help="")
    mode_coerce_filters.add_argument("--filter-transport-name", default=["msrpc", "dcerpc"], choices=["msrpc", "dcerpc"], nargs='*', type=str, help="")
    # Credentials
    mode_coerce_credentials = mode_coerce.add_argument_group("Authentication & connection")
    mode_coerce_credentials.add_argument("-u", "--username", dest="auth_username", default="", help="Username to authenticate to the machine.")
    mode_coerce_credentials.add_argument("-p", "--password", dest="auth_password", default="", help="Password to authenticate to the machine. (if omitted, it will be asked unless -no-pass is specified)")
    mode_coerce_credentials.add_argument("-d", "--domain", dest="auth_domain", default="", help="Windows domain name to authenticate to the machine.")
    mode_coerce_credentials.add_argument("--hashes", dest="auth_hashes", action="store", metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    mode_coerce_credentials.add_argument("--no-pass", action="store_true", help="Don't ask for password (useful for -k)")
    mode_coerce_credentials.add_argument("--dc-ip", action="store", metavar="ip address", help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")
    # Kerberos
    mode_coerce_credentials.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")
    mode_coerce_credentials.add_argument("--aes-key", dest="auth_aeskey", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication (128 or 256 bits)")
    mode_coerce_credentials.add_argument("--kdcHost", dest="kdcHost", action="store", metavar="FQDN KDC", help="FQDN of KDC for Kerberos.") 
    # Targets source
    mode_coerce_targets_source = mode_coerce.add_mutually_exclusive_group(required=True)
    mode_coerce_targets_source.add_argument("-t", "--target-ip", default=None, help="IP address or hostname of the target machine")
    mode_coerce_targets_source.add_argument("-f", "--targets-file", default=None, help="File containing a list of IP address or hostname of the target machines")
    # Listener
    listener_group = mode_coerce.add_argument_group("Listener")
    listener_group.add_argument("-l", "--listener-ip", required=True, type=str, help="IP address or hostname of the listener machine")

    # Adding the subparsers to the base parser
    subparsers = parser.add_subparsers(help="Mode", dest="mode", required=True)
    mode_scan_parser = subparsers.add_parser("scan", parents=[mode_scan], help="Tests known methods with known working paths on all methods, and report when an authentication is received.")
    mode_coerce_parser = subparsers.add_parser("coerce", parents=[mode_coerce], help="Trigger authentications through all known methods with known working paths")
    mode_fuzz_parser = subparsers.add_parser("fuzz", parents=[mode_fuzz], help="Tests every method with a list of exploit paths, and report when an authentication is received.")

    options = parser.parse_args()

    if options.auth_password == '' and options.auth_username != '' and options.auth_hashes is None and options.no_pass is not True:
        from getpass import getpass
        options.auth_password = getpass("Password:")

    return options


def main():
    available_methods = find_and_load_coerce_methods()

    options = parseArgs()

    reporter = Reporter(verbose=options.verbose, options=options)

    # Parsing targets
    targets = []
    if options.target_ip is not None:
        targets = [options.target_ip]
    elif options.targets_file is not None:
        if os.path.exists(options.targets_file):
            f = open(options.targets_file, 'r')
            targets = sorted(list(set([line.strip() for line in f.readlines()])))
            f.close()
            reporter.print_verbose("Loaded %d targets." % len(targets))
        else:
            print("[!] Could not open targets file '%s'." % options.targets_file)
            sys.exit(0)

    # Sort uniq on targets list
    targets = sorted(list(set(targets)))

    final_targets = []
    # Parsing target to filter IP/DNS/CIDR
    for target in targets:
        if is_ipv4_cidr(target):
            final_targets += [ip for ip in expand_cidr(target)]
        elif is_ipv4_addr(target):
            final_targets.append(target)
        elif is_ipv6_addr(target):
            final_targets.append(target)
        elif is_fqdn(target):
            final_targets.append(target)
        elif target.startswith("http://") or target.startswith("https://"):
            import urllib.parse
            target = urllib.parse.urlparse(target).netloc
            final_targets.append(target)
        else:
            if options.debug:
                print("[debug] Target '%s' was not added." % target)
    
    # Sort 
    targets = sorted(list(set(final_targets)))

    credentials = Credentials(
        domain=options.auth_domain,
        username=options.auth_username,
        password=options.auth_password,
        hashes=options.auth_hashes,
        use_kerberos=options.use_kerberos,
        aesKey=options.auth_aeskey,
        kdcHost=options.kdcHost
    )

    # Processing actions
    if options.mode == "coerce":
        reporter.print_info("Starting coerce mode")
        if credentials.use_kerberos:
            reporter.print_info("Connecting with Kerberos, using ccache file: '%s'" % os.getenv("KRB5CCNAME"))
        elif credentials.is_anonymous():
            reporter.print_info("No credentials provided, trying to connect with a NULL session.")
        for target in targets:
            reporter.print_info("Scanning target %s" % target)
            # Checking credentials if any
            if not "msrpc" in options.filter_transport_name or try_login(credentials, target, verbose=options.verbose):
                # Starting action
                action_coerce(target, available_methods, options, credentials, reporter)

    elif options.mode == "scan":
        reporter.print_info("Starting scan mode")
        if credentials.use_kerberos:
            reporter.print_info("Connecting with Kerberos, using ccache file: '%s'" % os.getenv("KRB5CCNAME"))
        elif credentials.is_anonymous():
            reporter.print_info("No credentials provided, trying to connect with a NULL session.")
        if not can_listen_on_port("0.0.0.0", 445):
            reporter.print_warn("Cannot listen on port tcp/%d. Are you root or are other servers running?" % 445)
        else:
            for target in targets:
                reporter.print_info("Scanning target %s" % target)
                # Checking credentials if any
                if not "msrpc" in options.filter_transport_name or try_login(credentials, target, verbose=options.verbose):
                    # Starting action
                    action_scan(target, available_methods, options, credentials, reporter)

            # Reporting results
            if options.export_json is not None:
                reporter.exportJSON(options.export_json)
            if options.export_xlsx is not None:
                reporter.exportXLSX(options.export_xlsx)
            if options.export_sqlite is not None:
                reporter.exportSQLITE(options.export_sqlite)

    elif options.mode == "fuzz":
        reporter.print_info("Starting fuzz mode")
        if credentials.use_kerberos:
            reporter.print_info("Connecting with Kerberos, using ccache file: '%s'" % os.getenv("KRB5CCNAME"))
        elif credentials.is_anonymous():
            reporter.print_info("No credentials provided, trying to connect with a NULL session.")
        if not can_listen_on_port("0.0.0.0", 445):
            reporter.print_warn("Cannot listen on port tcp/%d. Are you root or are other servers running?" % 445)
        else:
            for target in targets:
                reporter.print_info("Fuzzing target %s" % target)
                # Checking credentials if any
                if not "msrpc" in options.filter_transport_name or try_login(credentials, target, verbose=options.verbose):
                    # Starting action
                    action_fuzz(target, available_methods, options, credentials, reporter)

            # Reporting results
            if options.export_json is not None:
                reporter.exportJSON(options.export_json)
            if options.export_xlsx is not None:
                reporter.exportXLSX(options.export_xlsx)
            if options.export_sqlite is not None:
                reporter.exportSQLITE(options.export_sqlite)

    print("[+] All done! Bye Bye!")

if __name__ == '__main__':
    main()
