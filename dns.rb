#!/usr/bin/ruby

$stdout.sync = true

@trap = false
trap("SIGINT") do
  File.open("dnsseen", "w") { |f| Marshal.dump(@seen, f) }
  @trap = true
end

@seen = {}
@seen = File.open("dnsseen") { |f| Marshal.load(f) } if File.exists?("dnsseen")

$stdin.each do |l|
	break if @trap

	next unless l =~ /IP (\d+\.\d+\.\d+\.\d+)\.\d+ \> (\d+\.\d+\.\d+\.\d+)\.\d+.*(\w+\?) ([^\s]+)/
	src = $1
	dst = $2
	qtype = $3
	q = $4

	key = [src, dst, qtype, q]

	if @seen[key]
		@seen[key] += 1
	else
		@seen[key] = 1
	end

	cseen = @seen[key]

	printf "%-5.5s %s %s %s %s\n", cseen, src, dst, qtype, q if cseen < 5
end
