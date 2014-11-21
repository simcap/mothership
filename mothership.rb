#!/usr/bin/env ruby

begin
  require 'ffi/pcap'
rescue LoadError
  abort "! Cannot load require 'ffi/pcap'. Install it with 'gem install ffi-pcap --no-ri --no-rdoc'."
end
require 'resolv'
require 'pry'
require 'whois'
require 'yaml/store'

STORE_PATH = "#{ENV['HOME']}/.mothership.yml"

Mothership = Struct.new(:ip, :port, :hostname, :domain, :org)

pcap = FFI::PCap.open_live

interface = pcap.device
local_net = IPAddr.new(FFI::PCap.lookupnet(interface))

print "-> Listening on interface #{interface} (localnet: #{local_net}). "
pcap.set_filter('tcp')

HOSTS_INFO_QUERY = Hash.new do |hash, key|
  hostname = Resolv::DNS.new.getname(key).to_s
  main_domain = hostname.chomp('.').split('.').last(2).join('.') ## too basic
  who = Whois.whois(main_domain)
  contact = who.registrant_contact if who
  org = contact.organization if contact
  hash[key] = Mothership.new(key, nil, hostname, main_domain, org)
end

store = YAML::Store.new(STORE_PATH)
puts "Storing data at #{STORE_PATH}"

pcap.loop do |_, eth_frame|
  ip_payload = eth_frame.body.unpack('x14a*').first

  version_and_length = ip_payload.unpack('B8').first
  ip_version, ip_header_length = [version_and_length[0,4], version_and_length[4,7]].map { |i| i.to_i(2) }
  
  tcp_payload = ip_payload.unpack("x#{ip_header_length * 4}a*").first
  source_port, destination_port = tcp_payload.unpack('nn')

  source_ip, dest_ip = ip_payload.unpack('x12a4a4').map { |raw| IPAddr.new_ntoh(raw) }

  if local_net.include?(source_ip)
    mothership = HOSTS_INFO_QUERY[dest_ip.to_s]
    mothership.port = destination_port

    store.transaction do
      unless store.root? mothership.ip
        store[mothership.ip] = mothership.to_h
        puts "Storing mothership call to #{mothership.to_h}"
      end
    end
  end
end
