#Readme File#

***Overview***
vnak combines a number of attacks against multiple protocols in to one easy to use tool. Its aim is to be the one tool a user needs to attack multiple VoIP protocols.

vnak currently supports the following attacks:
Attack Number   Protocol        Attack Description
-------------   --------        ------------------
0               IAX             Authentication Downgrade
1               IAX             Known Authentication Challenge
2               IAX             Call Hangup
3               IAX             Call Hold/Quelch
4               IAX             Registration Reject
5               H.323           Registration Reject
6               SIP             Registration Reject
7               SIP             Call Reject
8               SIP             Known Authentication Challenge



***Requires***
Python 2.4 on Linux. vnak may work on Windows if the required libraries can be compiled, however it has only been tested on Linux. For Windows users, vnak can be easily run from a Linux LiveCD such as Backtrack.

vnak depends on the following libraries:
dpkt 1.6 -- Available at: http://dpkt.googlecode.com/files/dpkt-1.6.tar.gz
PyPcap 1.1 -- Available at: http://www.monkey.org/~dugsong/pypcap/pypcap-1.1.tar.gz


***Usage Example***

Sample usage targetting one client (192.168.132.1) connecting to the server (192.168.132.128)
--
bt voip # python vnak.py -a 8 192.168.132.1 192.168.132.128

vnak - VoIP Network Attack Kit
iSEC Partners, Copyright 2007 <c>
http://www.isecpartners.com
Written by Zane Lackey

Known Authentication Challenge attack completed succesfully against host 192.168.132.1.
Signal caught, exiting...

bt voip #
--

Sample usage targetting all clients connecting to the server (192.168.132.128)
--
bt voip # python vnak.py -e -a 8 192.168.132.128

vnak - VoIP Network Attack Kit
iSEC Partners, Copyright 2007 <c>
http://www.isecpartners.com
Written by Zane Lackey

Known Authentication Challenge attack completed succesfully against host 192.168.132.1.
Signal caught, exiting...

bt voip #


***Agreement***

The utility and all names, marks, brands, logos, and designs belong to iSEC Partners. The utility is proprietary to iSEC Partners and are protected by applicable intellectual property laws, including, but not limited to copyrights and trademarks. Accordingly, no modification, reverse engineering, derivative works, distribution, transmission, or selling of the utility without the express written consent of iSEC Partners.


****Questions/Comments***

Zane Lackey
zane@isecpartners.com