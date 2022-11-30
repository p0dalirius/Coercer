### Scan mode

```
./Coercer.py scan -u 'Administrator' -p 'Admin123!' --target 192.168.1.46
```

Complete help of this mode:

```
# ./Coercer.py scan -h
       ______
      / ____/___  ___  _____________  _____
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      v2.1-blackhat-edition
    \____/\____/\___/_/   \___/\___/_/       by @podalirius_

usage: Coercer.py scan [-h] [-v] [--export-json EXPORT_JSON] [--export-xlsx EXPORT_XLSX] [--export-sqlite EXPORT_SQLITE] [--delay DELAY] [--min-http-port MIN_HTTP_PORT] [--max-http-port MAX_HTTP_PORT] [--smb-port SMB_PORT]
                       [--filter-method-name FILTER_METHOD_NAME] [--filter-protocol-name FILTER_PROTOCOL_NAME] [-u USERNAME] [-p PASSWORD] [-d DOMAIN] [--hashes [LMHASH]:NTHASH] [--no-pass] [--dc-ip ip address]
                       (-t TARGET_IP | -f TARGETS_FILE) [-i INTERFACE | -I IP_ADDRESS]

options:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose mode (default: False)
  -t TARGET_IP, --target-ip TARGET_IP
                        IP address or hostname of the target machine
  -f TARGETS_FILE, --targets-file TARGETS_FILE
                        File containing a list of IP address or hostname of the target machines
  -i INTERFACE, --interface INTERFACE
                        Interface to listen on incoming authentications.
  -I IP_ADDRESS, --ip-address IP_ADDRESS
                        IP address to listen on incoming authentications.

Advanced options:
  --export-json EXPORT_JSON
                        Export results to specified JSON file.
  --export-xlsx EXPORT_XLSX
                        Export results to specified XLSX file.
  --export-sqlite EXPORT_SQLITE
                        Export results to specified SQLITE3 database file.
  --delay DELAY         Delay between attempts (in seconds)
  --min-http-port MIN_HTTP_PORT
                        Verbose mode (default: False)
  --max-http-port MAX_HTTP_PORT
                        Verbose mode (default: False)
  --smb-port SMB_PORT   SMB port (default: 445)

Filtering methods:
  --filter-method-name FILTER_METHOD_NAME
  --filter-protocol-name FILTER_PROTOCOL_NAME

Credentials:
  -u USERNAME, --username USERNAME
                        Username to authenticate to the remote machine.
  -p PASSWORD, --password PASSWORD
                        Password to authenticate to the remote machine. (if omitted, it will be asked unless -no-pass is specified)
  -d DOMAIN, --domain DOMAIN
                        Windows domain name to authenticate to the machine.
  --hashes [LMHASH]:NTHASH
                        NT/LM hashes (LM hash can be empty)
  --no-pass             Don't ask for password (useful for -k)
  --dc-ip ip address    IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
```