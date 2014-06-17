#!/usr/bin/env python

#Bugs
#?

import struct, socket
import getopt, sys, os
import subprocess
import ast
import re

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
            
def checknetmask(netmask):
    if netmask >= 1 and netmask <= 32:
        return True
    else:
        return False

def incrementasset(platform):
    assets = listasset(platform)
    if assets:
        assetlist = []
        for i in assets:
            assetlist.append(i.split('-')[2].zfill(6))
        assettag = int(max(assetlist)) + 1
    else:
        if platform in 'SC':
            assettag = 100  #SC (Server Class G1) devices already exist in the 001 -006 space
        elif platform in 'LH':
            assettag = 2500  #LH (Lighthouse G1) devices already exist in the 002000 - 002300 space
        elif platform in 'VLH':
            assettag = 2500  #LH (Virtualized G2 Lighthouse hypervisor) 
        elif platform in 'BE':
            assettag = 10000  #G2 Base Engine (G2 Lighthouse unconfigured)
        elif platform in 'CE':
            assettag = 10000  #Cloud Engine (G1 Cloud device)
        elif platform in 'PE':
            assettag = 30000  #Physical Engine (G2 Lightouse)
        elif platform in 'VE':
            assettag = 40000  #Virtual Engines (G2 Virtual device on Xenserver, ESXi, Hyper-V)
    return str(assettag).zfill(6) 

def incrementclientip():
    netparts = []
    iplist = []
    startip = 2
    
    #p = subprocess.Popen(['/usr/local/openvpn_as/scripts/confdba', '-s'], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    #tmpdba, err = p.communicate()
    #confdba = ast.literal_eval(tmpdba)
    
    p = subprocess.Popen(['cat', '/root/bin/confdbas.txt'], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    tmpdba, err = p.communicate()
    confdba = ast.literal_eval(tmpdba)
    
    for key1,val1 in confdba.items():
        if key1 == 'Default':
            if isinstance(val1, dict):
                for key2,val2 in val1.items():
                    if key2 == 'vpn.server.static.0.network':
                        network = val1.get('vpn.server.static.0.network', None)
                        netmask = val1.get('vpn.server.static.0.netmask_bits', None)
                        
    startipdec = ip2int(network)                        #decimal form of the network address
    maxclients = pow(2,(32 - int(netmask))) - startip   #decimal form of the number of hosts with given mask
    print maxclients
    minipdec = startipdec + startip + 8192                        #lowest ip in decimal format
    maxipdec = startipdec + maxclients + startip - 2 + 8192      #highest ip in decimal format
    minip = int2ip(minipdec)                                #lowest ip in dotted notation
    maxip = int2ip(maxipdec)                                #highest ip in dotted notation

    #p = subprocess.Popen(['/usr/local/openvpn_as/scripts/confdba', '-us'], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    #tmpdba, err = p.communicate()
    #userdba = ast.literal_eval(tmpdba)

    p = subprocess.Popen(['cat', '/root/bin/confdbaus.txt'], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    tmpdba, err = p.communicate()
    userdba = ast.literal_eval(tmpdba)

    for key1,val1 in userdba.items():
        if isinstance(val1, dict):
            for key2,val2 in val1.items():
                usertype = val1.get(key2, val2)
                if usertype == 'user_connect' or usertype == 'user_compile':
                    userip = val1.get('conn_ip', None)
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
    
    print newclientip
    return newclientip

    
def incrementipgroup(group):
    p = subprocess.Popen(['/usr/local/openvpn_as/scripts/confdba', '-us'], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    confdba, err = p.communicate()
    userdba = ast.literal_eval(confdba)
	
    #p = subprocess.Popen(['cat', '/root/bin/confdbaus.txt'], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    #tmpdba, err = p.communicate()
    #userdba = ast.literal_eval(tmpdba)
    netparts = []
    iplist = []
    startip = 2
    
    # Assumes all subnets are assigned by group. Could foul it up if assigned to user.
    for key1,val1 in userdba.items():
        if key1 == group:
            if isinstance(val1, dict):
                for key2,val2 in val1.items():
                    usertype = val1.get(key2, val2)
                    if usertype == 'group':
                        usernet = val1.get('group_subnets.0', None)
                        netparts = usernet.split('/')
    if not netparts:
        return False
    
   
    startipdec = ip2int(netparts[0])                        #decimal form of the network address
    maxclients = pow(2,(32 - int(netparts[1]))) - startip   #decimal form of the number of hosts with given mask
    
    minipdec = startipdec + startip                         #lowest ip in decimal format
    maxipdec = startipdec + maxclients + startip - 2        #highest ip in decimal format
    minip = int2ip(minipdec)                                #lowest ip in dotted notation
    maxip = int2ip(maxipdec)                                #highest ip in dotted notation

    for key1,val1 in userdba.items():
        if isinstance(val1, dict):
            for key2,val2 in val1.items():
                usertype = val1.get(key2, val2)
                if usertype == 'user_connect' or usertype == 'user_compile':
                    userip = val1.get('conn_ip', None)
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
 
def listgroup(verbose):
    p = subprocess.Popen(['/usr/local/openvpn_as/scripts/confdba', '-us'], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    confdba, err = p.communicate()
    userdba = ast.literal_eval(confdba)
    itemlist = []
    netlist = []
    alllist = []
    for key1,val1 in userdba.items():
        if isinstance(val1, dict):
            groupname = key1
            if groupname is not 'Dev':
                for key2,val2 in val1.items():
                    usertype = val1.get(key2, val2)
                    if usertype == 'group':
                        usernet = val1.get('group_subnets.0', None)
                        try:
                            socket.inet_aton(groupname)  #Makes sure the groups are in IPv4 network form for sorted below
                            netlist.append(groupname)
                        except:
                            itemlist.append(groupname)
    alllist = sorted(netlist, key=lambda x:tuple(map(int, x.split('.')))) + sorted(itemlist)
    return alllist
 
        
def listclient(option, showitem):
    p = subprocess.Popen(['/usr/local/openvpn_as/scripts/confdba', '-us'], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    confdba, err = p.communicate()
    userdba = ast.literal_eval(confdba)
    clientlist = []
    for key1,val1 in userdba.items():
        if isinstance(val1, dict):
            username = key1
            #"group_subnets.0": "172.17.0.0/16", 
            for key2,val2 in val1.items():
                usertype = val1.get(key2, val2)
                if usertype == 'user_connect' or usertype == 'user_compile':
                    patt = re.compile(r'CFS-%s-[0-9]{5,6}' % showitem)
                    match = patt.search(username)
                    if option == 'all':
                        if showitem:
                            patt2 = re.compile(r'.*%s.*' % showitem)
                            match = patt2.search(username)
                            if match:
                                usergroup = val1.get('conn_group', None)
                                if(str(usergroup) == "None"):
                                    usergroup = "--"
                                userip = val1.get('conn_ip', None)
                                if(str(userip) == "None"):
                                    userip = "--"
                                usernet = val1.get('group_subnets.0', None)
                                if(str(usernet) == "None"):
                                    usernet = "--"
                                    for key3,val3 in userdba.items():
                                        if key3 == usergroup:
                                            usernet = val3.get('group_subnets.0', None)
                                            if(str(usernet) == "None"):
                                                usernet = "--"
                                superuser = val1.get('prop_superuser', None)
                                if not (str(superuser) == "true"):
                                    line = username + "," + usergroup + "," + usernet + "," + userip
                                    clientlist.append(line)
                        else:
                            usergroup = val1.get('conn_group', None)
                            if(str(usergroup) == "None"):
                                usergroup = "--"
                            userip = val1.get('conn_ip', None)
                            if(str(userip) == "None"):
                                userip = "--"
                            usernet = val1.get('group_subnets.0', None)
                            if(str(usernet) == "None"):
                                usernet = "--"
                                for key3,val3 in userdba.items():
                                    if key3 == usergroup:
                                        usernet = val3.get('group_subnets.0', None)
                                        if(str(usernet) == "None"):
                                            usernet = "--"
                            superuser = val1.get('prop_superuser', None)
                            if not (str(superuser) == "true"):
                                line = username + "," + usergroup + "," + usernet + "," + userip
                                clientlist.append(line)
                    elif option == 'name':
                        superuser = val1.get('prop_superuser', None)
                        if not (str(superuser) == "true"):
                            if showitem:
                                patt = re.compile(r'.*%s.*' % showitem)
                                match = patt.search(username)
                                if match:
                                    clientlist.append(username)
                            else:
                               clientlist.append(username)
                        
                    elif option == 'ips':
                        superuser = val1.get('prop_superuser', None)
                        if not (str(superuser) == "true"):
                            if showitem: 
                                patt = re.compile(r'.*%s.*' % showitem)
                                match = patt.search(username)
                                if match:
                                    userip = val1.get('conn_ip', None)
                                    if userip:
                                        try:
                                            socket.inet_aton(userip)  #Makes sure the groups are in IPv4 network form for sorted below
                                            clientlist.append(userip)
                                        except:
                                            pass
                            else:
                                userip = val1.get('conn_ip', None)
                                if userip:
                                    try:
                                        socket.inet_aton(userip)  #Makes sure the groups are in IPv4 network form for sorted below
                                        clientlist.append(userip)
                                    except:
                                        pass
                    elif option == 'groups':
                        if showitem: 
                            if username == showitem:
                                usergroup = val1.get('conn_group', None)
                                clientlist.append(usergroup)
                            else: 
                                pass
                        else:
                            userip = val1.get('conn_ip', None)
                            usergroup = val1.get('conn_group', None)
                            clientlist.append(usergroup)
                    elif option == 'networks':
                        if showitem: 
                                patt = re.compile(r'.*%s.*' % showitem)
                                match = patt.search(username)
                                if match:
                                    usergroup = val1.get('conn_group', None)
                                    usernet = val1.get('group_subnets.0', None)
                                    if(str(usernet) == "None"):
                                        for key3,val3 in userdba.items():
                                            if key3 == usergroup:
                                                usernet = val3.get('group_subnets.0', None)
                                    if usernet:
                                        clientlist.append(usernet)
                        else:
                            usergroup = val1.get('conn_group', None)
                            usernet = val1.get('group_subnets.0', None)
                            if(str(usernet) == "None"):
                                for key3,val3 in userdba.items():
                                    if key3 == usergroup:
                                        usernet = val3.get('group_subnets.0', None)
                            if usernet:
                                clientlist.append(usernet)
                            
                    elif match:
                        userip = val1.get('conn_ip', None)
                        if(str(userip) == "None"):
                            userip = "--"
                        line = userip
                        clientlist.append(line)
    
    if option == 'ips':
        return sorted(clientlist, key=lambda x:tuple(map(int, x.split('.'))))
    else:
        return sorted(set(clientlist))

def listasset(platform):
    users = listclient('name', platform)
    
    matchlist = []
    patt = re.compile(r'CFS-%s-[0-9]{5,6}' % platform)
    for user in users:
        match = patt.search(user)
        if match:
            matchline = match.group()
            matchlist.append(matchline)
    return sorted(matchlist)
    
def moveclient(client, group):
    patt = re.compile(r'CFS-(LH|VLH|SC|CE|PE|VE|BE)-[0-9]{5,6}') 
    if valid_patt(patt,client):
        name = client
    
    grouplist = listgroup('verbose')
    if not searchlist(group, grouplist):
        print "Please enter a valid Group"
        sys.exit(2)
        
    clientip = incrementipgroup(group)
    if not clientip:
        print "Error: Unable to increment IP"
        sys.exit(2)
    
    cmd = '/usr/local/openvpn_as/scripts/sacli --user ' + name + ' --key conn_group --value ' + group + ' UserPropPut'
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()
    
    cmd = '/usr/local/openvpn_as/scripts/sacli --user ' + name + ' --key conn_ip --value ' + clientip +' UserPropPut'
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()


def searchlist(item, itemlist):
    for i in itemlist:
        if item == i:
            return True
    return False
    
def greplist(patt,itemlist):
    """ finds patt in itemlist - patt is a compiled regex
        returns all lines that match patt """
    for i in itemlist:
        match = patt.search(i)
        if match:
            return True
    return False

def migrateclient(name, group):
    
    clientip = incrementipgroup(group)
    if not clientip:
        print "Error: Unable to increment IP"
        sys.exit(2)

    cmd = '/usr/local/openvpn_as/scripts/sacli --user ' + name + ' --key prop_autologin --value true UserPropPut'
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()
    
    cmd = '/usr/local/openvpn_as/scripts/sacli --user ' + name + ' --key conn_group --value ' + group +' UserPropPut'
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()
    
    cmd = '/usr/local/openvpn_as/scripts/sacli --user ' + name + ' --key pvt_password_digest --value 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 UserPropPut'
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()
    
    cmd = '/usr/local/openvpn_as/scripts/sacli --user ' + name + ' --key conn_ip --value ' + clientip +' UserPropPut'
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()
    
    cmd = '/usr/local/openvpn_as/scripts/sacli --user ' + name + ' --key access_from.0 --value' +'+ALL_S2C_SUBNETS'
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()
    
    return name
    

def createclient(name, group):
    patt = re.compile(r'CFS-(LH|VLH|SC|CE|PE|VE|BE)-[0-9]{5,6}') 
    if valid_patt(patt,name):
        name = name
    
    patt = re.compile(r'(LH|VLH|SC|CE|PE|VE|BE)') 
    if valid_patt(patt,name):
        name = "CFS-%s-%s" % (name,incrementasset(name))

    grouplist = listgroup('verbose')
    if not searchlist(group, grouplist):
        print "Please enter a valid Group"
        sys.exit(2)

    clientip = incrementipgroup(group)
    if not clientip:
        print "Error: Unable to increment IP"
        sys.exit(2)

    cmd = '/usr/local/openvpn_as/scripts/sacli --user ' + name + ' --key prop_autologin --value true UserPropPut'
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()

    cmd = '/usr/local/openvpn_as/scripts/sacli --user ' + name + ' --key conn_group --value ' + group +' UserPropPut'
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()
    
    cmd = '/usr/local/openvpn_as/scripts/sacli --user ' + name + ' --key pvt_password_digest --value 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 UserPropPut'
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()
    
    cmd = '/usr/local/openvpn_as/scripts/sacli --user ' + name + ' --key conn_ip --value ' + clientip +' UserPropPut'
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()
    
    
    return name
    
def creategroup(network,subnet):

    grouplist = listgroup('verbose')
    if searchlist(network, grouplist):
        print "Group %s already exists" % network
        sys.exit(2)

    if checknetmask(subnet):
        print "Please enter valid netmask"
        sys.exit(2)

    cmd = '/usr/local/openvpn_as/scripts/sacli --user %s --key group_declare --value true UserPropPut' % network
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()
    
    cmd = '/usr/local/openvpn_as/scripts/sacli --user %s --key c2s_dest_s --value false UserPropPut' % network
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()
    
    cmd = '/usr/local/openvpn_as/scripts/sacli --user %s --key c2s_dest_v --value false UserPropPut' % network
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()
    
    cmd = '/usr/local/openvpn_as/scripts/sacli --user %s --key prop_autologin --value true UserPropPut' % network    
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()
    
    cmd = '/usr/local/openvpn_as/scripts/sacli --user %s --key prop_deny --value false UserPropPut' % network    
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()
    
    cmd = '/usr/local/openvpn_as/scripts/sacli --user %s --key prop_superuser --value false UserPropPut' % network    
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()
 
    count = 0
    netstartip = ip2int(network)
    for hostip in serverips:
        sip = netstartip + hostip
        natip = int2ip(sip)
        srvip = str(servernet) + str(hostip)
        
        cmd = '/usr/local/openvpn_as/scripts/sacli --user %s --key access_to.%s --value "+SUBNET:%s(%s)" UserPropPut' % (network,count,srvip,natip)
        p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        output, err = p.communicate()
        
        #cmd = '/sbin/iptables -A PREROUTING -d %s/32 -p tcp -j DNAT --to-destination %s' % (natip,srvip)
        #p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        #output, err = p.communicate()
        
        count += 1

    cmd = '/usr/local/openvpn_as/scripts/sacli --user %s --key group_subnets.0 --value %s/%s UserPropPut' % (network,network,subnet)
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()
    

def deleteclient(name):
    cmd = '/usr/local/openvpn_as/scripts/sacli --user ' + name + ' UserPropDelAll'
    p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output, err = p.communicate()


def outputclient(client, attribute):
    if attribute in 'config': 
        cmd = '/usr/local/openvpn_as/scripts/sacli --user ' + client + ' GetAutoLogin'
        p = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        output, err = p.communicate()
        return output
    elif attribute in 'ip':
        tmpout = listclient('ips', client)
        return '\n'.join(map(str, tmpout))
    elif attribute in 'group':
        tmpout = listclient('groups', client)
        return '\n'.join(map(str, tmpout))
    elif attribute in 'network':
        tmpout = listclient('networks', client)
        return '\n'.join(map(str, tmpout))
    


def usage():
    progname =  os.path.basename(sys.argv[0])
    print ""
    print "%s arguments:" % progname
    print "-h, --help                                   Show this help message and exit"
    print "-l, --list clients                           List clients"
    print "-l, --list clients -p <platform>             List clients for <platform>"
    print "-l, --list groups                            List groups"
    print "-l, --list all                               List all client data in CSV format"
    print "-l, --list all -p <platform>                 List all client data in CSV format for <platform>"
    print "-l, --list ips                               List client IP addresses"
    print "-l, --list ips -p <platform>                 List client IP addresses for <platform>"
    print "-l, --list networks                          List network addresses"
    print "-l, --list networks -p <platform>            List network addresses for <platform>"
    print "-o, --output <client> -a <attribute>         Output client attribute - config, ip, group"
    print "-m, --migrate <client> -g <group>            Migreate client to OpenVPN AS"
    print "-c  --create client -n <name> -g <group>     Create new client"
    print "-c  --create client -p <platform> -g <group> Create new client with auto created name"
    print "-c  --create group -n <name> -s <subnet>     Create new group"
    print "-d, --delete <client|group> -n <name>        Delete client or group (--name required)"
    print ""
    print "Filters:"
    print "-s  --subnet <network/bits>                  Network address for client (eg. 24)"
    print "-n, --name <client|group>                    Name of client or group"
    print "-g, --group <group name>                     Name of group"
    print "-p, --platform <platform name>               Name of the client platform (eg. CE, PE, SC)"
    print ""
    print "Examples:"
    print "Create a new client:"
    print "     %s --create=client --platform=CE --group=10.0.50.0" % progname
    print "Create a new client (short format):"
    print "     %s -c client -p CE -g 10.0.50.0" % progname
    print "Create a new group:"
    print "     %s --create=group --name=10.0.50.0 --subnet=24" % progname
    print "Delete a client:"
    print "     %s --delete=CFS-CE-123456" % progname
    print "Delete a group:"
    print "     %s --delete=10.0.50.0" % progname
    print "Move a client:"
    print "     %s --move=CFS-CE-123456 --group=10.0.50.0" % progname
    print ""

def main():
    network = None
    platform = None
    name = None
    attribute = None
    verbose = False
    group = None
    global servernet 
    servernet = '192.168.1.'
    global serverips 
    serverips = [3,20,25,26]
    
    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:], "hl:c:s:n:g:d:p:o:m:a:", ["help","list=","create=","subnet=","name=","group=","delete=","platform=","output=","migrate=","attribute="])
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
        elif opt in ("-m", "--migrate"):
            client = arg
            operation = 'migrate'
        elif opt in ("-l","--list"):
            option = arg
            operation = 'list'
        elif opt in ("-c","--create"):
            client = arg
            operation = 'create'
        elif opt in ("-s","--subnet"):
            subnet = arg
        elif opt in ("-n","--name"):
            name = arg
        elif opt in ("-p","--platform"):
            platform = arg
        elif opt in ("-g","--group"):
            group = arg
        elif opt in ("-a","--attribute"):
            attribute = arg
        elif opt in ("-d","--delete"):
            option = arg
            operation = 'delete'
        elif opt in ("-o","--output"):
            option = arg
            operation = 'output'
        else:
            operation = 'usage'
            usage()
            sys.exit()
    
    if operation in 'list':
        if option in 'ips':
            if platform:
                itemlist = listclient('ips', platform)
            else:
                itemlist = listclient('ips', None)
            for item in itemlist:
                print item
        elif option in 'groups':
            itemlist = listgroup('verbose')
            for item in itemlist:
                print item
        elif option in 'networks':
             itemlist = listclient('networks', None)
             for item in itemlist:
                print item
        elif option in 'clients':
            if platform:
                itemlist = listclient('name', platform)
            else:
                itemlist = listclient('name', None)
            for item in itemlist:
                    print item
        elif option in 'all':
            if platform:
                itemlist = listclient('all', platform)
            else:
                itemlist = listclient('all', None)
            for item in itemlist:
                print item
        else:
            print "Unknown Option - %s" % option
            sys.exit(2)
    elif operation in 'create':
        if group:
            createclient(client, group)
        else:
            print "Please provide group"
            sys.exit(2)
    elif operation in 'delete':
        deleteclient(option)
    elif operation in 'migrate':
        if group:
            migrateclient(client, group)
        else:
            print "Please provide group"
    elif operation in 'output':
        if option:
            client = option 
            if attribute:
                output = outputclient(client,attribute)
                print output
            else:
                print "Please enter an attribute to output - config, ip or group"
                sys.exit(2)
        else:
            print "Please provide client"
            sys.exit(1)
   

        
if __name__ == "__main__":
    main()

