My LS13 scripts
===============

These were used during the LS13 exercise to pretty much own the red team and their callbacks to home from vulnerable machines. Code is horrible - copypasted together in 5 minutes from other scripts I had laying around. But it worked for us for 16 hours. It might not work for you and it will most definitely not work in real life without serious modifications.

### incoming.rb / outgoing.rb

Used these to monitor all incoming and outgoing traffic and pick out connections that haven't been seen before. Outgoing based on src/dst/dstport tuple and incoming based on payload only (to get rid of all noise and scoring connections).

These enabled us to very quickly spot malicious downloads, callbacks to red team machines etc. Scripts were fed from SPAN destination that aggregated all ingress and egress traffic from all our machines.

For some technical reasons I ran these with external tcpdump but there is no reason why it shouldn't work with Pcap::Capture.open_live

Usage: tcpdump -U -i eth2 -nn -w - tcp or udp | ./outgoing.rb

NB! No IPv6 support (2013 - shame on me). I just used additional tcpdump to monitor all IPv6 traffic in case red team tries to use it between our machines, unfortunately they didn't.

### dns.rb

This is similar to previous but for monitoring all DNS lookups. I didn't have enough time to improve it during the exercise and it wasn't put into good use.

### exec-notify.c

I created this statically linked binary (for maximum compatibility) for easy process execution logging to syslog (which we immediately sent to trusted central collector)

### network/arpmac-to-ipsg-bindings.rb

For quickly creating IPSG static bindings into switches. Enables you to lock down your network against MAC and ARP spoofing in case red team gains access to any of your machines.

