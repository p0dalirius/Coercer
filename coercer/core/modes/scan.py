#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : scan.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 Sep 2022


from coercer.core.Filter import Filter
from coercer.structures.Modes import Modes
from coercer.core.tasks.execute import execute_tasks
from coercer.core.tasks.prepare import prepare_tasks
from coercer.network.utils import get_ip_addr_to_listen_on
from coercer.network.rpc import portmap_discover

from coercer.core.Reporter import reporter

def action_scan(target, available_methods, options, credentials):
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

    tasks = prepare_tasks(available_methods, options, filter, Modes.SCAN, portmap)

    # Executing tasks =======================================================================================================================

    listening_ip = get_ip_addr_to_listen_on(target, options)
    reporter.print_info("Listening for authentications on '%s', SMB port %d" % (listening_ip, options.smb_port), verbose=True)

    execute_tasks(tasks, options, target, credentials, Modes.SCAN, listening_ip)