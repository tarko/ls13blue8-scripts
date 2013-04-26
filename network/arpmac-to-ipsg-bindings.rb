#!/usr/bin/ruby
require "pp"

arp = {}

File.readlines("arptable").each do |a|
	next unless a =~ /^([\d\.]+)\s+ether\s+([\w:]+)\s+/
	ip = $1
	mac = $2
	arp[mac.gsub(/:/, "")] = ip
end

#pp arp

File.readlines("mactable").each do |m|
	next unless m =~ /^(\d+)\s+([\w\.]+)\s+\w+\s+\d+\s+(\w+)/
	vlan = $1
	mac = $2
	mac2 = mac.gsub(/\./, "")
	int = $3

	next unless ["1086", "1087", "1083", "1088", "1084"].include?(vlan)

	if arp[mac2]
		puts "ip source binding %s %s vlan %s interface %s" % [arp[mac2], mac, vlan, int]
	else
		$stderr.puts "unmatched mac: #{m}"
	end
end
