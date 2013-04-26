#!/usr/bin/ruby
#
# MagicIDS 9.0RC1!!
#
# --- Friendly reminder for red team ---
# If you steal this, beware, this has been copypasted together in 20 minutes
# from several other scripts I had created before ;)

require 'pcap'

RE_HTTP = Regexp.new('^(GET|POST|PUT|OPTIONS|HEAD) .* HTTP/\d\.\d')
RE_SSH = Regexp.new('^SSH-')
RE_SMTP = Regexp.new('^220 .*SMTP.*\n$')

@tcpflows = {}
def tcpflow(pkt)
	fkey = [pkt.src.to_i, pkt.sport, pkt.dst.to_i, pkt.dport]
	rkey = [pkt.dst.to_i, pkt.dport, pkt.src.to_i, pkt.sport]
	
	if pkt.tcp_flags == 2
		@tcpflows[fkey] = pkt
		@tcpflows[rkey] = pkt
		return
	end

	return unless @tcpflows.include?(fkey)
	return unless pkt.tcp_data_len > 0

	#proto = if pkt.tcp_data.match(RE_HTTP) then :http
	#elsif pkt.tcp_data.match(RE_SSH) then :ssh
	#elsif pkt.tcp_data.match(RE_SMTP) then :smtp
	#end

	magic(:tcp, @tcpflows[fkey].src.to_s, @tcpflows[fkey].dst.to_s, @tcpflows[fkey].dport, nil, pkt.tcp_data)

	@tcpflows.delete(fkey)
	@tcpflows.delete(rkey)
end

@udpflows = {}
@last_cleanup = Time.now
def udpflow(pkt)
        ts = Time.now

        # clean up timeout'ed flows
        # we do this first because we are not using another thread for this
        # and this might lead to stale flows if there is no traffic for a while
        if ts - @last_cleanup > 15
                @last_cleanup = ts
                @udpflows.delete_if { |k,v| ts - v > 60 }
        end

        # UDP fragments don't have checksum field and no ports either
        # these can't start new flow so skip them
        return unless pkt.respond_to?("udp_sum")
        return unless pkt.udp_len > 0

        fkey = [pkt.src.to_i, pkt.sport, pkt.dst.to_i, pkt.dport]
        rkey = [pkt.dst.to_i, pkt.dport, pkt.src.to_i, pkt.sport]

        unless @udpflows.include?(fkey)
        magic(:udp,  pkt.src.to_s, pkt.dst.to_s, pkt.dport, nil, pkt.udp_data)
        end

        @udpflows[fkey] = ts
        @udpflows[rkey] = ts

end

def getcolor(fg = "default", bg = "default", effect = "none")
  fgcolors = {
    "black" => "30;",
    "red" => "31;",
    "green" => "32;",
    "yellow" => "33;",
    "blue" => "34;",
    "magenta" => "35;",
    "cyan" => "36;",
    "white" => "37;",
    "default" => "39;"
  }

  bgcolors = {
    "black" => "40",
    "red" => "41",
    "green" => "42",
    "yellow" => "43",
    "blue" => "44",
    "magenta" => "45",
    "cyan" => "46",
    "white" => "47",
    "default" => "49"
  }
  retval = ""
  retval << "\033["
  retval << "0;" if effect == "none"
  retval << "1;" if effect =~ /bright/
  retval << "4;" if effect =~ /underline/
  retval << "5;" if effect =~ /blink/
  retval << (fgcolors[fg] || fgcolors["default"])
  retval << (bgcolors[bg] || bgcolors["default"])
  retval << "m"
  retval
end

def paint(kw, color, bgcolor = "default")
	r = ""
	r << getcolor(color, bgcolor)
	r << kw
	r << getcolor
end

def ippaint(ip)
	color = case ip
	when /^10\.8\.(6|108)\./ then "yellow"
	when /^10\.8\.(7|109)\./ then "blue"
	when /^10\.8\.(3|104)\./ then "green"
	when /^10\./ then "red"
	else "magenta"
	end
	paint(ip, color)
end

def beenseen(proto, src, dst, dport)
	key = [proto, src, dst, dport]
	
	if @seen[key]
		@seen[key] += 1
	else
		@seen[key] = 1
	end
end

OURBC = /^10\.8\.(6|7|3|108|109|100)\.255$/
OUR = /^10\.8\.(6|7|3|108|109|104)\./
def magic(proto, src, dst, dport, dpi, data)

	@history.puts "%s %s %s %s %s %s" % [Time.now.to_s, proto, src, dst, dport, data ? data.gsub(/[^[:print:]]/, ".") : nil]

	if src =~ OUR && data && data.gsub(/[^[:print:]]/, ".") =~ /score\.html.*Wget/ && !@scoring.include?(dst)
		@scoring << dst
		puts "New scoring dst #{dst}"
	elsif @scoring.include?(dst)
		return
	end

	f = false
	f = true if proto == :udp && dst == "10.50.51.108" && dport == 514
	f = true if proto == :udp && (dst == "10.0.0.2" || dst == "10.8.3.2") && dport == 123 

	f = true if proto == :tcp && dst == "10.0.173.34" # scoring
	f = true if proto == :tcp && dst == "10.0.128.2" # scoring
	f = true if proto == :tcp && dst == "10.0.128.3" # scoring
	f = true if proto == :tcp && dst == "10.0.135.205" # scoring
	f = true if proto == :tcp && dst == "10.0.130.243" # scoring

	f = true if proto == :udp && src == "10.8.6.2" && dst == "10.0.0.2" && dport == 53 # root dns
	f = true if proto == :udp && src == "10.8.108.2" && dst == "10.0.0.2" && dport == 53 # root dns
	f = true if proto == :udp && (dst == "224.0.0.252" || dst == "224.0.0.251") && (dport == 53 || dport == 5355)  # wpad & shit
	f = true if proto == :udp && src =~ OUR && (dst == "10.8.6.2" || dst == "10.8.108.2" || dst == "10.8.3.2" || dst == "10.8.104.2") && dport == 53 # meie recursion
	f = true if proto == :tcp && src == "10.8.108.5" && dst == "10.8.108.4" && dport == 3306
	#f = true if proto == :udp && dst =~ OURBC && (dport == 137 || dport == 138)
	#f = true if proto == :udp && dst =~ OUR && src =~ OUR && dport == 53
	f = true if proto == :udp && (dport == 137 || dport == 138)
	#f = true if dst !~ OUR || src !~ OUR
	f = true if src !~ OUR
	#f = true if src

	#return if f

	#return if src =~ OUR and 
	return if src !~ OUR
	seen = beenseen(proto, src, dst, dport)
	return if seen > 15

	printf "%s %s %s %s %s %-140.140s\n", 
		(seen == 1 ? paint(seen.to_s.ljust(6), "default", "red") : seen.to_s.ljust(6)),
		proto.to_s.ljust(3),
		dport.to_s.ljust(5),
		ippaint(src.ljust(16)),
		ippaint(dst.ljust(16)),
		data ? data.gsub(/[^[:print:]]/, ".") : nil

end

@history = File.open("history.#{Time.now.to_i}", "w")

@trap = false
trap("SIGINT") do
	File.open("seen", "w") { |f| Marshal.dump(@seen, f) }
	@trap = true
end

@seen = {}
@seen = File.open("seen") { |f| Marshal.load(f) } if File.exists?("seen")

@scoring = []

cap = Pcap::Capture.open_offline("-")
cap.loop(0) do |pkt|
	break if @trap
	if pkt.tcp?
		tcpflow(pkt)
	elsif pkt.udp?
		udpflow(pkt)
	end
end
cap.close
@history.close
