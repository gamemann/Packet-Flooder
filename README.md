# Packet Flooder/Generator
## Newer Packet Sequence Program (Faster)
I would recommend checking out my newer Packet Sequence program [here](https://github.com/gamemann/Packet-Sequence). This newer tool takes my Packet Flooding/Generator tool to the next level by making it so you can define sequences with more features such as sourcing out as specific IP/CIDR ranges. It is still under development, but I'm making great progress and hope to implement functionality that'll allow it to operate as a network monitoring tool.

This tool is also **a lot** more faster than this Packet Flooder tool because I've moved as much instructions outside of the while loop (for sending packets) as possible. With that said, I've added command line support for replacing values in the first sequence. The only thing it does not include is native IPIP support. Other than that, it is overall a better solution than this program.

## Description
This is a packet flooder/generator tool made in C that supports sending TCP, UDP, IPIP, and ICMP packets. This program also supports many features including randomizing each packet's characteristics such as its source IP, port, and more. This tool is also multithreaded by using `pthreads`. My goal is to achieve the highest packets per second rate with this tool while also being able to use neat features like randomizing payload, source IPs, and more.

**Note** - Please use this tool at your own risk. I am not responsible for any damage done and do not support using this tool for illegal operations such as targeted (D)DoS attacks. This tool was primarily made for pen-testing.

## Why Did I Make This?
I've been learning how to mitigate (D)DoS attacks against my Anycast network and wanted to do pen-testing using different characteristics in each packet. I figured I'd make a pen-testing tool I can use to test out my (D)DoS mitigation methods on firewalls I make in the future and present (including my [XDP Firewall](https://github.com/gamemann/XDP-Firewall)).

## Compiling
I use GCC to compile this program. You must add `-lpthread` at the end of the command when compiling via GCC.

Here's an example:

```
git clone https://github.com/gamemann/Packet-Flooder.git
cd Packet-Flooder
gcc -g src/flood.c -o flood -lpthread
```

## Usage
Here's output from the `--help` flag that goes over the program's command line usage:

```
./flood --help
Usage for: ./flood:
--dev -i => Interface name to bind to.
--src -s => Source address (0/unset = random/spoof).
--dst -d => Destination IP to send packets to.
--port -p => Destination port (0/unset = random port).
--sport => Source port (0/unset = random port).
--internal => When set, if no source IP is specified, it will randomize the source IP from the 10.0.0.0/8 range.
--interval => Interval between sending packets in micro seconds.
--threads -t => Amount of threads to spawn (default is host's CPU count).
--count -c => The maximum packet count allowed sent.
--time => Amount of time in seconds to run tool for.
--smac => Source MAC address in xx:xx:xx:xx:xx:xx format.
--dmac => Destination MAC address in xx:xx:xx:xx:xx:xx format.
--payload => The payload to send. Format is in hexadecimal. Example: FF FF FF FF 49.
--verbose -v => Print how much data we've sent each time.
--nostats => Do not track PPS and bandwidth. This may increase performance.
--urg => Set the URG flag for TCP packets.
--ack => Set the ACK flag for TCP packets.
--psh => Set the PSH flag for TCP packets.
--rst => Set the RST flag for TCP packets.
--syn => Set the SYN flag for TCP packets.
--fin => Set the FIN flag for TCP packets.
--min => Minimum payload length.
--max => Maximum payload length.
--tcp => Send TCP packets.
--icmp => Send ICMP packets.
--icmptype => The ICMP type to send when --icmp is specified.
--icmpcode => The ICMP code to send when --icmp is specified.
--ipip => Add outer IP header in IPIP format.
--ipipsrc => When IPIP is specified, use this as outer IP header's source address.
--ipipdst => When IPIP is specified, use this as outer IP header's destination address.
--nocsum => Do not calculate the IP header's checksum. Useful for checksum offloading on the hardware which'll result in better performance.
--nocsum4 => Do not calculate the layer 4's checksum (e.g. TCP/UDP). It will leave the checksum field as 0 in the headers.
--minttl => The minimum TTL (Time-To-Live) range for a packet.
--maxttl => The maximum TTL (Time-To-Live) range for a packet.
--tos => The TOS (Type Of Service) to set on each packet.
--help -h => Show help menu information.
```

Example:

```
./flood --dev ens18 --dst 10.50.0.4 --port 80 -t 1 --interval 100000 --tcp --min 1200 --max 1200 -v
```

## Credits
* [Christian Deacon](https://www.linkedin.com/in/christian-deacon-902042186/) - Created program.