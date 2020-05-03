# Packet Flooder
## Description
This is an improved version of my UDP Sender [program](https://github.com/gamemann/UDP-Sender). However, this program also supports TCP SYN floods. The source IP is completely randomized/spoofed each time a packet is sent. 

## Why Did I Make This?
I've been learning how to mitigate TCP-related attacks recently and decided to make a TCP SYN flood tool. Since I was planning to rewrite my UDP Sender program anyways, I decided to create a program that does both UDP and TCP (SYN) floods.

## Compiling
I used GCC to compile this program. You must add `-lpthread` at the end of the command when compiling via GCC.

Here's an example:

```
gcc -g src/flood.c -o src/flood -lpthread
```

## Usage
Here's output from the `--help` flag that goes over the program's command line usage:

```
./flood --help
Usage for: ./flood:
--dev -i => Interface name to bind to.
--src -s => Source address (none = random/spoof).
--dst -d => Destination IP to send packets to.
--port -p => Destination port (0 = random port).
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
--tcp => Send TCP packet with SYN flag set instead of UDP packet.
--help -h => Show help menu information.
```

Example:

```
./flood --dev ens18 --dst 10.50.0.4 --port 80 -t 1 --interval 100000 --tcp --min 1200 --max 1200 -v
```

## Credits
* [Christian Deacon](https://www.linkedin.com/in/christian-deacon-902042186/) - Created program.