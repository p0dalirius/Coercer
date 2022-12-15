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
        outcome = True
        #
        if self.filter_method_name is not None:
            if self.filter_method_name in instance.function["name"]:
                outcome = outcome and True
            else:
                outcome = outcome and False
        #
        if self.filter_protocol_name is not None:
            if (self.filter_protocol_name in instance.protocol["shortname"]) or (self.filter_protocol_name in instance.protocol["longname"]):
                outcome = outcome and True
            else:
                outcome = outcome and False
        return outcome

    def pipe_matches_filter(self, pipe_name):
        """
        Function pipe_matches_filter

        Parameters:
            ?:pipe_name

        Return:
            bool:outcome
        """
        outcome = True
        #
        if self.filter_pipe_name is not None:
            if self.filter_pipe_name in pipe_name:
                outcome = outcome and True
            else:
                outcome = outcome and False
        return outcome
