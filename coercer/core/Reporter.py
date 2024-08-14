#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Reporter.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 Jul 2022

import sqlite3
import os
import json
import xlsxwriter
import sys
from coercer.structures.ReportingLevel import ReportingLevel
from coercer.structures.TestResult import TestResult


CURSOR_UP_ONE = '\x1b[1A'
ERASE_LINE = '\x1b[2K'


class Reporter(object):
    """
    This class is responsible for reporting the results of tests and exploits performed on targets.
    It handles the storage and display of test results, including saving them to a database.
    The Reporter class is designed to be flexible and can be used in different modes, such as scan or fuzz mode.

    Attributes:
        options (dict): A dictionary containing options for the reporter, such as the mode of operation.
        verbose (bool): A boolean indicating whether verbose output is enabled.
        test_results (dict): A nested dictionary storing the results of tests and exploits, organized by target, uuid, version, function name, and named pipe.

    Methods:
        __init__(self, options, verbose=False): Initializes the Reporter object with the given options and verbosity level.
        print_testing(self, msprotocol_rpc_instance): Prints a message indicating that a test is being performed on a given msprotocol_rpc_instance.
        print_info(self, message): Prints an informational message to the console.
        print_warn(self, message): Prints a warning message to the console.
        print_verbose(self, message): Prints a verbose message to the console if verbose mode is enabled.
        report_test_result(self, target, uuid, version, namedpipe, msprotocol_rpc_instance, result, exploitpath): Reports the result of a test or exploit, storing it in the database and optionally printing it to the console.
    """

    def __init__(self, options, verbose=False):
        super(Reporter, self).__init__()
        self.options = options
        self.verbose = verbose
        self.test_results = {}

    def print_testing(self, msprotocol_rpc_instance):
        print("      [>] (\x1b[93m%s\x1b[0m) %s " % ("-testing-", str(msprotocol_rpc_instance)))
        sys.stdout.flush()

    def print_info(self, message):
        print("\x1b[1m[\x1b[92minfo\x1b[0m\x1b[1m]\x1b[0m %s" % message)
        sys.stdout.flush()

    def print_warn(self, message):
        print("\x1b[1m[\x1b[91mwarn\x1b[0m\x1b[1m]\x1b[0m %s" % message)
        sys.stdout.flush()

    def print_verbose(self, message):
        print("[debug]",message)

    def report_test_result(self, target, uuid, version, namedpipe, msprotocol_rpc_instance, result, exploitpath):
        """
        Reports the result of a test or exploit, storing it in the database and optionally printing it to the console.

        Parameters:
            target (str): The target of the test or exploit.
            uuid (str): The unique identifier of the test or exploit.
            version (str): The version of the target.
            namedpipe (str): The named pipe used for the test or exploit.
            msprotocol_rpc_instance (object): The instance of the MSProtocol RPC.
            result (TestResult): The result of the test or exploit.
            exploitpath (str): The path to the exploit used.

        This method stores the test or exploit result in the reporter's internal database, organized by target, uuid, version, function name, and named pipe. It also prints the result to the console based on the reporter's mode and verbosity level.
        """

        function_name = msprotocol_rpc_instance.function["name"]
        if target not in self.test_results.keys():
            self.test_results[target] = {}
        if uuid not in self.test_results[target].keys():
            self.test_results[target][uuid] = {}
        if version not in self.test_results[target][uuid].keys():
            self.test_results[target][uuid][version] = {}
        if function_name not in self.test_results[target][uuid][version].keys():
            self.test_results[target][uuid][version][function_name] = {}
        if namedpipe not in self.test_results[target][uuid][version][function_name].keys():
            self.test_results[target][uuid][version][function_name][namedpipe] = []

        # Save result to database
        self.test_results[target][uuid][version][function_name][namedpipe].append({
            "function": msprotocol_rpc_instance.function,
            "protocol": msprotocol_rpc_instance.protocol,
            "testresult": result.name,
            "exploitpath": exploitpath
        })

        sys.stdout.write(CURSOR_UP_ONE)
        sys.stdout.write(ERASE_LINE)
        if self.options.mode in ["scan", "fuzz"]:
            if result == TestResult.SMB_AUTH_RECEIVED:
                print("      [\x1b[1;92m+\x1b[0m] (\x1b[1;92m%s\x1b[0m) %s " % ("SMB  Auth", str(msprotocol_rpc_instance)))
                sys.stdout.flush()
            elif result == TestResult.HTTP_AUTH_RECEIVED:
                print("      [\x1b[1;92m+\x1b[0m] (\x1b[1;92m%s\x1b[0m) %s " % ("HTTP Auth", str(msprotocol_rpc_instance)))
                sys.stdout.flush()
            elif result == TestResult.NCA_S_UNK_IF:
                print("      [\x1b[1;95m-\x1b[0m] (\x1b[1;95m%s\x1b[0m) %s " % ("-No Func-", str(msprotocol_rpc_instance)))
                sys.stdout.flush()
            else:
                if self.verbose:
                    print("      [\x1b[1;91m!\x1b[0m] (\x1b[1;91m%s\x1b[0m) %s " % (result.name, str(msprotocol_rpc_instance)))
                    sys.stdout.flush()
        elif self.options.mode in ["coerce"]:
            if result == TestResult.ERROR_BAD_NETPATH:
                print("      [\x1b[1;92m+\x1b[0m] (\x1b[1;92m%s\x1b[0m) %s " % ("ERROR_BAD_NETPATH", str(msprotocol_rpc_instance)))
                sys.stdout.flush()
            else:
                if self.verbose:
                    print("      [\x1b[1;91m!\x1b[0m] (\x1b[1;91m%s\x1b[0m) %s " % (result.name, str(msprotocol_rpc_instance)))
                    sys.stdout.flush()

    def exportXLSX(self, filename):
        """
        Exports the test results to an XLSX file.

        This method exports the test results stored in the `self.test_results` dictionary to an XLSX file specified by the `filename` parameter. The file is created in the specified directory, and if the directory does not exist, it is created. The method also prints a message indicating the path where the results were exported.

        Parameters:
        - filename (str): The name of the file to which the results will be exported. This can include a directory path.

        Returns:
        - None
        """

        basepath = os.path.dirname(filename)
        filename = os.path.basename(filename)
        if basepath not in [".", ""]:
            if not os.path.exists(basepath):
                os.makedirs(basepath)
            path_to_file = basepath + os.path.sep + filename
        else:
            path_to_file = filename
        # export

        workbook = xlsxwriter.Workbook(path_to_file)
        worksheet = workbook.add_worksheet()

        header_format = workbook.add_format({'bold': 1})
        header_fields = ["Target", "Interface UUID", "Interface version", "SMB named pipe", "Protocol long name", "Protocol short name", "RPC function name", "Operation number", "Result", "Working path"]
        for k in range(len(header_fields)):
            worksheet.set_column(k, k + 1, len(header_fields[k]) + 3)
        worksheet.set_row(0, 60, header_format)
        worksheet.write_row(0, 0, header_fields)

        row_id = 1
        for target in self.test_results.keys():
            for uuid in self.test_results[target].keys():
                for version in self.test_results[target][uuid].keys():
                    for function_name in self.test_results[target][uuid][version].keys():
                        for namedpipe in self.test_results[target][uuid][version][function_name].keys():
                            for test_result in self.test_results[target][uuid][version][function_name][namedpipe]:
                                data = [target, uuid, version, namedpipe, test_result["protocol"]["longname"], test_result["protocol"]["shortname"], test_result["function"]["name"], test_result["function"]["opnum"], test_result["testresult"], test_result["exploitpath"]]
                                worksheet.write_row(row_id, 0, data)
                                row_id += 1
        worksheet.autofilter(0, 0, row_id, len(header_fields) - 1)
        workbook.close()
        self.print_info("Results exported to XLSX in '%s'" % path_to_file)

    def exportJSON(self, filename):
        """
        Exports the test results to a JSON file.

        This method exports the test results stored in the `self.test_results` dictionary to a JSON file specified by the `filename` parameter. The file is created in the specified directory, and if the directory does not exist, it is created. The method also prints a message indicating the path where the results were exported.

        Parameters:
        - filename (str): The name of the file to which the results will be exported. This can include a directory path.

        Returns:
        - None
        """

        basepath = os.path.dirname(filename)
        filename = os.path.basename(filename)
        if basepath not in [".", ""]:
            if not os.path.exists(basepath):
                os.makedirs(basepath)
            path_to_file = basepath + os.path.sep + filename
        else:
            path_to_file = filename
        # export
        f = open(path_to_file, "w")
        f.write(json.dumps(self.test_results, indent=4))
        f.close()
        self.print_info("Results exported to JSON in '%s'" % path_to_file)

    def exportSQLITE(self, filename):
        """
        Exports the test results to a SQLite database file.

        This method exports the test results stored in the `self.test_results` dictionary to a SQLite database file specified by the `filename` parameter. The file is created in the specified directory, and if the directory does not exist, it is created. The method also prints a message indicating the path where the results were exported.

        Parameters:
        - filename (str): The name of the file to which the results will be exported. This can include a directory path.

        Returns:
        - None
        """

        basepath = os.path.dirname(filename)
        filename = os.path.basename(filename)
        if basepath not in [".", ""]:
            if not os.path.exists(basepath):
                os.makedirs(basepath)
            path_to_file = basepath + os.path.sep + filename
        else:
            path_to_file = filename
        # Exporting results
        # Connecting to sqlite
        conn = sqlite3.connect(path_to_file)
        # Creating a cursor object using the cursor() method
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS results(target VARCHAR(255), uuid VARCHAR(255), version VARCHAR(255), named_pipe VARCHAR(255), protocol_shortname VARCHAR(255), protocol_longname VARCHAR(512), function_name VARCHAR(255), result VARCHAR(255), path VARCHAR(512));")
        cursor.execute("DELETE FROM results;")
        for target in self.test_results.keys():
            for uuid in self.test_results[target].keys():
                for version in self.test_results[target][uuid].keys():
                    for function_name in self.test_results[target][uuid][version].keys():
                        for named_pipe in self.test_results[target][uuid][version][function_name].keys():
                            for test_result in self.test_results[target][uuid][version][function_name][named_pipe]:
                                cursor.execute("INSERT INTO results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (
                                        target,
                                        uuid,
                                        version,
                                        named_pipe,
                                        test_result["protocol"]["shortname"],
                                        test_result["protocol"]["longname"],
                                        function_name,
                                        test_result["testresult"],
                                        str(bytes(test_result["exploitpath"], 'utf-8'))[2:-1].replace('\\\\', '\\')
                                    )
                                )
        # Commit your changes in the database
        conn.commit()
        # Closing the connection
        conn.close()
        self.print_info("Results exported to SQLITE3 db in '%s'" % path_to_file)
