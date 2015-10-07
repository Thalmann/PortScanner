import optparse
import nmap
import re
from socket import *

def is_ip(string):
    if re.match("[0-9]{1-3}'.'[0-9]{1-3}'.'[0-9]{1-3}'.'[0-9]{1-3}", string) != None:
        return True
    return False

def nmap_scan(tgt_host, tgt_port):
    nm_scan = nmap.PortScanner()
    nm_scan.scan(tgt_host, tgt_port)
    state = nm_scan[tgt_host]['tcp'][int(tgt_port)]['state']
    print ' [*] ' + tgt_host + ' tcp/' + tgt_port + ' ' + state

def main():
    parser = optparse.OptionParser('usage %prog -H ' + '<target host> -p <target port>')
    parser.add_option('-H', dest='tgt_host', type='string', help='specify target host')
    parser.add_option('-p', dest='tgt_port', type='string', help='specify target port[s] separated by comma')
    (options, args) = parser.parse_args()
    tgt_host = options.tgt_host
    tgt_ports = str(options.tgt_port).split(',')
    
    if tgt_host is None or tgt_ports[0] is None:
        print '[-] You must specify a target host and port[s].'
        exit(0)
    
    tgt_host = tgt_host if is_ip(tgt_host) else gethostbyname(tgt_host)
    
    for tgt_port in tgt_ports:
        nmap_scan(tgt_host, tgt_port)

if __name__ == '__main__':
    main()
