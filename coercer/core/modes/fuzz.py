#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : fuzz.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 Sep 2022


from coercer.core.Filter import Filter
from coercer.core.Reporter import Reporter
from coercer.structures.Modes import Modes
from coercer.core.tasks.execute import execute_tasks
from coercer.core.tasks.prepare import prepare_tasks
from coercer.network.smb import list_remote_pipes
from coercer.network.utils import get_ip_addr_to_listen_on
from coercer.network.rpc import portmap_discover

from coercer.core.Reporter import reporter

def action_fuzz(target, available_methods, options, credentials):
    filter = Filter(
        filter_method_name=options.filter_method_name,
        filter_protocol_name=options.filter_protocol_name,
        filter_pipe_name=options.filter_pipe_name
    )

    # Preparing pipes ==============================================================================================================

    named_pipe_of_remote_machine = []
    ports = set()
    if "msrpc" in options.filter_transport_name:
        if credentials.is_anonymous():
            reporter.print_info("Cannot list SMB pipes with anonymous login, using list of known pipes")
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
                reporter.print_info("Using integrated list of %d SMB named pipes." % len(named_pipe_of_remote_machine))
        else:
            named_pipe_of_remote_machine = list_remote_pipes(target, credentials)
            reporter.print_info("Found %d SMB named pipes on the remote machine." % len(named_pipe_of_remote_machine), verbose=True)
        kept_pipes_after_filters = []
        for pipe in named_pipe_of_remote_machine:
            if filter.pipe_matches_filter(pipe):
                kept_pipes_after_filters.append(pipe)
        if len(kept_pipes_after_filters) == 0 and not credentials.is_anonymous():
            reporter.print_error("No SMB named pipes matching filter --filter-pipe-name %s were found on the remote machine." % options.filter_pipe_name)
            return None
        elif len(kept_pipes_after_filters) == 0 and credentials.is_anonymous():
            reporter.print_error("No SMB named pipes matching filter --filter-pipe-name %s were found in the list of known named pipes." % options.filter_pipe_name)
            return None
        else:
            named_pipe_of_remote_machine = kept_pipes_after_filters

    if "dcerpc" in options.filter_transport_name:
        portmap = portmap_discover(target, options.dce_port)
        for uuid in portmap.get("ncacn_ip_tcp",[]):
            for port in portmap["ncacn_ip_tcp"][uuid]:
                ports.add(port)

    # Preparing tasks ==============================================================================================================

    tasks = prepare_tasks(available_methods, options, filter, Modes.FUZZ)
    
    # Executing tasks =======================================================================================================================

    listening_ip = get_ip_addr_to_listen_on(target, options)
    reporter.print_info("Listening for authentications on '%s', SMB port %d" % (listening_ip, options.smb_port), debug=True)

    execute_tasks(tasks, options, target, credentials, Modes.FUZZ, listening_ip, ports, named_pipe_of_remote_machine)
