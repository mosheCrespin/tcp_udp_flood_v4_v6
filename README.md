### *C Program which Generates TCP/IPv4 RST flood attack, UDP/IPv4 flood attack and UDPv6 flood attack*


_______________
*first U should notice that the running environment of this program is linux*

### How to Use:
- clone this project by `git clone https://github.com/mosheCrespin/tcp_udp_flood_v4_v6.git`
- open the terminal and run the following command: `make all`
  #### IPv4 flood -> the exec file named `flood`:  
  - run this following command: `sudo ./flood -t [target ip] -p [target port] -r[for switching to UDP flood]`
  
  *more details:*
  
  - The `target IP-address` for the flood attacks to be passed via command-line option `-t` whereas the default is `127.0.0.1`.
  
  - The `target port` to be passed via command-line option `–p` whereas the default is `443`.
  
  -	Command-line option `–r` to switch from the default sending of RST flood to the UDP flood attack.
  
   #### UDPv6 flood -> the exec file named `v6_flood`:  
   
  - run this following command: `sudo ./v6_flood -t [target ip] -p [target port] 
  
  *more details:*
  
  - The `target IP-address` for the flood attacks to be passed via command-line option `-t` whereas the default is `::1`.
  
  - The `target port` to be passed via command-line option `–p` whereas the default is `443`.
  
---------------------------
for any quastion please contact me at: `mosheCrespin@gmail.com`

