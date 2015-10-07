import optparse
from socket import *
from threading import *

screen_lock = Semaphore(value=1)
def connScan(tgt_host, tgt_port):
    try:
        conn_skt = socket(AF_INET, SOCK_STREAM)
        conn_skt.connect((tgt_host, tgt_port))
        conn_skt.send('Hello\r\n')
        results = conn_skt.recv(100)
        screen_lock.acquire()
        print '[+]%d/tcp open'% tgt_port
        print '[+] ' + str(results)
    except:
        screen_lock.acquire()
        print '[-]%d(tcp closed)'% tgt_port
    finally:
        screen_lock.release()
        conn_skt.close()

def portScan(tgt_host, tgt_ports):
    try:
        tgtIP = gethostbyname(tgt_host)
    except:
        print "[-] Cannot resolve '%s': Unknown host"%tgt_host
        return
    try:
        tgtName = gethostbyaddr(tgtIP)
        print '\n[+] Scan Results for: ' + tgtName[0]
    except:
        print '\n[+] Scan Results for: ' + tgtIP
    setdefaulttimeout(1)
    for tgt_port in tgt_ports:
        print 'Scanning port ' + tgt_port
        t = Thread(target=connScan, args=(tgt_host, int(tgt_port)))
        t.start()

def main():
    parser = optparse.OptionParser('usage %prog -H ' + '<target host> -p <target port>')
    parser.add_option('-H', dest='tgt_host', type='string', help='specify target host')
    parser.add_option('-p', dest='tgt_port', type='string', help='specify target port[s] separated by comma')
    (options, args) = parser.parse_args()
    tgt_host = options.tgt_host
    tgt_ports = str(options.tgt_port).split(',')
    print tgt_ports
    if tgt_host is None or tgt_ports[0] is None:
        print '[-] You must specify a target host and port[s].'
        exit(0)
    portScan(tgt_host, tgt_ports)

if __name__ == '__main__':
    main()
