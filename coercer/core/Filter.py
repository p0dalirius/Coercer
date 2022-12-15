#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Filter.py
# Author             : Podalirius (@podalirius_)
# Date created       : 15 Sep 2022

class Filter(object):
    """
    Documentation for class Filter
    """

    def __init__(self, filter_method_name=None, filter_protocol_name=None, filter_pipe_name=None):
        super(Filter, self).__init__()
        self.filter_method_name = filter_method_name
        self.filter_protocol_name = filter_protocol_name
        self.filter_pipe_name = filter_pipe_name

    def method_matches_filter(self, instance):
        """
        Function method_matches_filter

        Parameters:
            ?:instance

        Return:
            bool:outcome
        """
        if len(self.filter_method_name) != 0 or len(self.filter_protocol_name) != 0:
            outcome = False
        else:
            outcome = True
        #
        for method in self.filter_method_name:
            if method in instance.function["name"]:
                outcome = True
        #
        for protocol in self.filter_protocol_name:
            if (protocol in instance.protocol["shortname"]) or (protocol in instance.protocol["longname"]):
                outcome = True
        return outcome

    def pipe_matches_filter(self, pipe_name):
        """
        Function pipe_matches_filter

        Parameters:
            ?:pipe_name

        Return:
            bool:outcome
        """
        if len(self.filter_pipe_name) != 0:
            outcome = False
        else:
            outcome = True
        #
        for pipe in self.filter_pipe_name:
            if pipe in pipe_name:
                outcome = True
        return outcome
