#!/usr/bin/env python

#Bugs
# Filter by role no longer works

import struct, socket
import getopt, sys, os
import subprocess
import ast
import re
from netaddr import IPNetwork

progdir = '/root/bin/'
confdir = progdir + 'confs/'
ccds = progdir + 'ccds/'
ccdlocks = progdir + 'ccds.lock/'
clientconfs = progdir + 'clients/'
rsadir = progdir + 'rsa/'
networks = progdir + 'networks/'

def ip2int(ip):
    val = lambda ipstr: struct.unpack('!I', socket.inet_aton(ipstr))[0]
    return val(ip)

def int2ip(num):
    val = lambda n: socket.inet_ntoa(struct.pack('!I', n))
    return val(num)

def valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError: 
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False
    return True

def valid_patt(patt,item):
    match = patt.search(item)
    if match:
        return True
    else:
        return False
            

def checkip(seqip, iplist):
    for ip in iplist:
        if ip == seqip:
            return True
            
def valid_ipv4_netmask(netmask):
    if not valid_ipv4_address(netmask):
        try:
            int(netmask)
        except ValueError:
            return False
        if not 1 <= int(netmask) <= 32:
            return False
    return True


def incrementasset(role):
    assets = listclient('assets', role)

    if assets:
        assetlist = []
        for i in assets:
            assetlist.append(i.split('-')[2])
        assettag = int(max(assetlist)) + 1
    else:
        if role in 'SC':
            assettag = 100  #SC (Server Class) devices already exist in the 001 -006 space
        elif role in 'LH':
            assettag = '2500'  #LH (Lighthouse G1) devices already exist in the 002000 - 002300 space
        elif role in 'VLH':
            assettag = '5000'  #Virtualized Lighthouse ie. G2 physcial devices
        elif role in 'CSE':
            assettag = 10000  #Cloud Scan Engine
        elif role in 'PSE':
            assettag = 30000  #Physical Scan Engine ie. repurposed LH devices
        elif role in 'VSE':
            assettag = 40000  #Virtual Scan Engines
    return str(assettag).zfill(6) 
    
    
def incrementip(usernet):
    iplist = []
    startip = 50

    netparts = usernet.split('/')
    if not netparts:
        return False
    
    startipdec = ip2int(netparts[0])                        #decimal form of the network address
    maxclients = pow(2,(32 - int(netparts[1]))) - startip   #decimal form of the number of hosts with given mask
    
    minipdec = startipdec + startip                         #lowest ip in decimal format
    maxipdec = startipdec + maxclients + startip - 2        #highest ip in decimal format
    minip = int2ip(minipdec)                                #lowest ip in dotted notation
    maxip = int2ip(maxipdec)                                #highest ip in dotted notation
    
    itemlist = listclient('ips', None)
    for userip in itemlist:
        if userip:
            try:
                socket.inet_aton(userip)  #Makes sure the groups are in IPv4 network form for sorted below
                iplist.append(userip)
            except:
                pass
    
    for seqdec in range(minipdec, maxipdec):
        seqip = int2ip(seqdec)
        if checkip(seqip, iplist):
            pass
        else:
            newclientip = seqip
            break
    return newclientip
        
def listclient(option,role):
    #Get config information from CCD file
    clientlist = []
    clientdirlist = os.listdir(ccds)
    if not clientdirlist:
        return False
        
    for client in os.listdir(ccds):
        if option == 'all':
            if role:
                patt = re.compile(r'CFS-%s-[0-9]{6}' % role)
                match = patt.search(client)
                if not match:
                    continue
            expr = re.compile(r'ifconfig-push.*')
            filename = ccds + client 
            lines = grepfile(expr, filename)
            hostip = lines.split()[1]
            hostmask =  lines.split()[2]
            hostwithmask = hostip + "/" + hostmask
            cidrnet = str(IPNetwork(hostwithmask).cidr)
            netcidr = cidrnet.split('/')[0] 
            maskcidr = cidrnet.split('/')[1]
            
            netfilepath = networks + netcidr
            if os.path.isfile(netfilepath):
                netexpr = re.compile(r'%s' % netcidr)
                if grepfile(netexpr, netfilepath):
                    output = client + ","  + hostip + "," + cidrnet
                    clientlist.append(output)
            else:
                output = client + ","  + hostip + ",Missing Network Config"
                clientlist.append(output)            
            
        elif option == 'assets':
            if role:
                patt = re.compile(r'CFS-%s-[0-9]{6}' % role)
                match = patt.search(client)
                if match:
                    matchline = match.group()
                    clientlist.append(matchline)
            else:
                clientlist.append(client)
        elif option == 'networks':
            for config in os.listdir(networks):
                file = open(networks + config)
                for network in file:
                    clientlist.append(network.rstrip())  
                              
        elif option == 'ips':
            expr = re.compile(r'ifconfig-push.*')
            file = ccds + client 
            line = grepfile(expr, file)
            userip = line.split()[1]
            if userip:
                try:
                    socket.inet_aton(userip)  #Makes sure the groups are in IPv4 network form for sorted below
                    clientlist.append(userip)
                except:
                    pass
        else:
            pattasset = re.compile(r'CFS-(LH|VLH|SC|CSE|PSE|VSE)-[0-9]{6}') 
            if valid_patt(pattasset,option):
                userip = val1.get('conn_ip', None)
                if(str(userip) == "None"):
                    userip = "--"
                line = userip
                clientlist.append(line)
    
    s = set()
    clients = filter(lambda i: not i in s and not s.add(i), clientlist)
    if option == 'ips':
        return sorted(clients, key=lambda x:tuple(map(int, x.split('.'))))
    else:
        return sorted(clients)

def outputclient(assetname):
    vpnconf = []
        
    f = rsadir + 'keys/' + assetname + '.crt'
    if os.path.isfile(f):
        cmd = 'source ' + confdir + 'vpnpki.conf; openssl x509 -in ' + f + ' -serial -noout'
        p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        output, err = p.communicate()
        pem = output.split('=')[1].strip() + '.pem'
    else:
        return False
    
    fname = confdir + 'vpnclients.conf'
    if os.path.isfile(fname):
        f = open(fname,'r')
        for line in f:
            vpnconf.append(line.strip())
    else:
        return False
    
    vpnconf.append('<ca>')  
    fname = rsadir + 'keys/ca.crt'
    if os.path.isfile(fname):
        f = open(fname,'r')
        for line in f:
            vpnconf.append(line.strip())
        vpnconf.append('/ca')
    else:
        return False
    
    vpnconf.append('<cert>')
    fname = rsadir + 'keys/' + pem
    if os.path.isfile(fname):
        cmd = 'source ' + confdir + 'vpnpki.conf; openssl x509 -in ' + rsadir + 'keys/' + pem
        p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        output, err = p.communicate()
        for line in output.split('\n'):
            vpnconf.append(line.strip())
        vpnconf.append('</cert>')
    else:
        return False
    
    vpnconf.append('<key>')
    fname = rsadir + 'keys/' + assetname + '.key'
    if os.path.isfile(fname):
        f = open(fname,'r')
        for line in f:
            vpnconf.append(line.strip())
        vpnconf.append('</key>')
    else:
        return False
    
    vpnconf.append('key-direction 1')
    vpnconf.append('<tls-auth>')
    fname = rsadir + 'keys/ta.key'
    if os.path.isfile(fname):
        f = open(fname,'r')
        for line in f:
            vpnconf.append(line.strip())
        vpnconf.append('</tls-auth>')
    else:
        return False
     
    for line in vpnconf:
        print line
        
    return vpnconf

def moveclient(client, group):
    patt = re.compile(r'CFS-(LH|VLH|SC|CSE|PSE|VSE)-[0-9]{6}') 
    if valid_patt(patt,client):
        name = client
    
    grouplist = listgroup('verbose')
    if not searchlist(group, grouplist):
        print "Please enter a valid Group"
        sys.exit(2)
        
    clientip = incrementip(group)
    if not clientip:
        print "Error: Unable to increment IP"
        sys.exit(2)
    
    # Find CCD file and change IP.
    #cmd = '/usr/local/openvpn_as/scripts/sacli --user ' + name + ' --key conn_ip --value ' + clientip +' UserPropPut'
    #p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    #output, err = p.communicate()


def searchlist(item, itemlist):
    for i in itemlist:
        if item == i:
            return True
    return False
   
def grepfile(patt,filename):
    """ finds patt in file - patt is a compiled regex
        returns all lines that match patt """
    matchlines = []

    if os.path.isfile(filename):
        f = open(filename,'r')
        for line in f:
            match = patt.search(line)
            if match:
                matchline = match.group()
                matchlines.append(matchline)
            results = '\n '.join(matchlines)
            f.close()
            if results:
                return results
            else:
                return None
    else:
        return False
    sys.exit()
   
def greplist(patt,itemlist):
    """ finds patt in itemlist - patt is a compiled regex
        returns all lines that match patt """
    for i in itemlist:
        match = patt.search(i)
        if match:
            return True
    return False

def createclient(item, network, subnet, force):
    #Creates ASSET Tag, IP address, ccd file, client cert, client key and client config with embedded keys
    assetname = None
    pattasset = re.compile(r'CFS-(LH|VLH|SC|CSE|PSE|VSE)-[0-9]{6}') 
    pattrole = re.compile(r'^(LH|VLH|SC|CSE|PSE|VSE)$') 
    if valid_patt(pattasset,item):
        assetname = item
    elif valid_patt(pattrole,item):
        assetname = "CFS-%s-%s" % (item,incrementasset(item))
    else:
        print 'Enter either a role (CSE,LH) or an asset tag'
        sys.exit(2)
    
    for root, dirs, files in os.walk(networks):
        if not network in files:
            print "Please enter an existing network config"
            nets = listclient('networks',None)
            for net in nets:
                print net
            sys.exit(2)

    cidrnet = network + '/' + subnet
    netpath = networks + network

    expr = re.compile(r'.*%s.%s.*' % (network,subnet))
    if not grepfile(expr,netpath) :
        warning = assetname + ": Please enter an existing subnet"
        sys.stderr.write(warning + '\n')
        nets = listclient('networks',None)
        for net in nets:
            print net
        sys.exit(2)

    clientip = incrementip(cidrnet)
    if not clientip:
        print "Error: Unable to increment IP"
        sys.exit(2)

    #find available IP address
    ip = IPNetwork(cidrnet) 
    netmask = ip.netmask

    #create ccd file
    clientfile = ccds + assetname  
    if not os.path.exists(clientfile) or force:
        myfile = open(clientfile,'w')
        clientconfig = "ifconfig-push " + clientip + " "+ str(netmask) +"\n"
        myfile.write(clientconfig)
        myfile.close()

    #check to see if the cert already exists
    certindex = rsadir + "/keys/index.txt"
    expr = re.compile(r'^V.*CN=%s.*' % assetname)
    if grepfile(expr,certindex) and force:
        #get serial of certificate
        cmd = 'source ' + confdir + 'vpnpki.conf; openssl x509 -in ' + rsadir + 'keys/' + assetname + '.crt -serial -noout'
        p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        output, err = p.communicate()
        pem = output.split('=')[1].strip() + '.pem'

        #revoke certificate
        cmd = 'source ' + confdir + 'vpnpki.conf; openssl ca -revoke ' + rsadir + 'keys/' + pem
        p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        output, err = p.communicate()
            
    if not grepfile(expr,certindex):
        cmd = 'source ' + confdir + 'vpnpki.conf; openssl req -batch -nodes -newkey rsa:1024 -new -out ' + rsadir +'keys/' + assetname + '.req -keyout ' + rsadir + 'keys/' + assetname + '.key'
        p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        output, err = p.communicate()
        
        cmd = 'source ' + confdir + 'vpnpki.conf; openssl ca -batch -keyfile ' + rsadir + 'keys/ca.key -cert ' + rsadir + 'keys/ca.crt -in ' + rsadir + 'keys/' + assetname + '.req -out ' + rsadir + 'keys/' + assetname + '.crt'
        p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        output, err = p.communicate()

        return True  
    

def deleteclient(name):
    # Delete CCD file and revoke certificate
    return False

def lockclient(name):
    # Move CCD file to clientlockdir
    return False

def usage():
    progname =  os.path.basename(sys.argv[0])
    print ""
    print "%s arguments:" % progname
    print "-h, --help                                           Show this help message and exit"
    print "-l, --list all                                       List all client data in CSV format"
    print "-l, --list all -r <role>                             List all client data in CSV format in <role>"
    print "-l, --list ips                                       List client IP addresses"
    print "-l, --list ips -r <role>                             List client IP addresses in <role>"
    print "-l, --list assets                                    List assets"
    print "-l, --list assets -r <role>                          List assets in <role>"
    print "-l, --list networks                                  List network addresses"
    print "-c  --create <role name> -n <network> -s <subnet>    Create a config for a role with autogenerated asset tag"
    print "-c  --create <asset name> -n <network> -s <subnet>   Create a config for an existing asset"
    print "-c  --create <network name> -n <network> -s <subnet> Create a config for a network"
    print "-d, --delete <asset name>                            Delete an asset"
    print "-d, --delete <network name>                          Delete a network"   
    print "-o, --output <asset>                                 Outputs VPN config for <asset>" 
    print "-f, --force                                          Override interactivity"
    print ""
    print "Filters:"
    print "-r, --role <role name>                               Name of the asset role (eg. CSE, PSE, SC)"
    print ""
    print "Examples:"
    print "List all client asset names"
    print "     %s --list assets"  % progname
    print "List all client data in CSV format"
    print "     %s --list all"  % progname
    print "List clients filtering on CSE ROLE"
    print "     %s --list all -r CSE"  % progname
    print "Create a new client with auto-generated asset tag:"
    print "     %s -c CSE -n 10.0.50.0 -s 24" % progname
    print "Create a new client config for an existing asset:"
    print "     %s -c CFS-CSE-123456 -n 10.0.50.0 -s 24" % progname
    print "Delete an asset:"
    print "     %s -d CFS-CSE-123456" % progname
    print "Move a client to a new network:"
    print "     %s -m CFS-CSE-123456 -n 10.0.50.0 -s 24" % progname
    print "Output a client VPN configuration file with embedded certs"
    print "     %s -o CFS-CSE-123456"  % progname
    print ""

def main():
    subnet = None
    role = None
    asset = None
    network = None
    verbose = None
    group = None
    force = None
    global servernet 
    servernet = '192.168.1.'
    global serverips 
    serverips = [3,21,20,25,26]
    
    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:], "hl:c:s:n:d:r:o:f", ["help","list=","create=","subnet=","network=","delete=","role=","output=","force"])
        if not opts:
            usage()
            sys.exit(2)
    except getopt.GetoptError as err:
        print(err) # will print something like "option -a not recognized"
        usage()
        sys.exit(2)
    
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-l","--list"):
            option = arg
            operation = 'list'
        elif opt in ("-c","--create"):
            item = arg
            operation = 'create'
        elif opt in ("-s","--subnet"):
            subnet = arg
        elif opt in ("-n","--network"):
            network = arg
        elif opt in ("-r","--role"):
            role = arg
        elif opt in ("-o", "--output"):
            asset = arg
            operation = 'output'
        elif opt in ("-d","--delete"):
            item = arg
            operation = 'delete'
        elif opt in ("-f","--force"):
            force=True
        else:
            operation = 'usage'
            usage()
            sys.exit()
    
    if operation in 'list':
        if option in 'ips':
            itemlist = listclient('ips',role)
            for item in itemlist:
                print item
        elif option in 'networks':
             itemlist = listclient('networks',role)
             for item in itemlist:
                print item
        elif option in 'assets':
            itemlist = listclient('assets',role)
            if itemlist:
                for item in itemlist:
                    print item
        elif option in 'all':
            itemlist = listclient('all',role)
            for item in itemlist:
                print item
        else:
            print "Unknown Option - %s" % option
            sys.exit(2)
    elif operation in 'create':
        if item and network and subnet:
            createclient(item,network,subnet,force) 
        else:
            print "Please provide asset/role, network and subnet"
            sys.exit(2)
    
    elif operation in 'delete':
        deleteclient(option)
    elif operation in 'output':
        if asset:
            outputclient(asset)
        else:
            print "Please provide asset"
   

        
if __name__ == "__main__":
    main()
    
    
