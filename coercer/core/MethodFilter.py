#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : MethodFilter.py
# Author             : Podalirius (@podalirius_)
# Date created       : 15 Sep 2022

class MethodFilter(object):
    """
    Documentation for class MethodFilter
    """

    def __init__(self, filter_method_name=None, filter_protocol_name=None):
        super(MethodFilter, self).__init__()
        self.filter_method_name = filter_method_name
        self.filter_protocol_name = filter_protocol_name

    def matches_filter(self, instance):
        """
        Function matches_filter

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
    
