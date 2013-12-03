pktap_demo
==========
This program is a demonstration of PKTAP (Packet TAP) interface of Mac OSX (Darwin/XUN).

 * This program need "pktap.h" file. Please get from the site of XNU.
 * http://www.opensource.apple.com/source/xnu/xnu-2422.1.72/bsd/net/pktap.h

build & run
==========
 `$ curl -o pktap.h http://www.opensource.apple.com/source/xnu/xnu-2422.1.72/bsd/net/pktap.h`  
 `$ make`  
 `$ sudo ./pktap_demo [interface]...`  
 
license
==========
This software is released under the MIT License.  
Please refer http://opensource.org/licenses/mit-license.php for detail.
