#!/usr/bin/perl -l
# thanks for Honeynor and k2jp
# see http://www.honeynor.no/tools/cc2asn/about.php
# see http://d.hatena.ne.jp/k2jp/20090627/1246102447
use strict;
use warnings;
use utf8;

my @multiplier = ( 16777216, 65536, 256 );
sub getIpAddressAsNumber {
	# $1: 192.0.2.1
	my $ipAddress = shift;
	my @octet = split /\./, $ipAddress;
	my $number = $octet[0] * $multiplier[0] + $octet[1] * $multiplier[1] + $octet[2] * $multiplier[2] + $octet[3];
	return $number;
}
sub getIpAddress {
	#$1: 3221225985 (192.0.2.1)
	my $ipAddressNumber = shift;
	my @ipAddress;
	$ipAddress[0] = int ($ipAddressNumber / $multiplier[0]);
	$ipAddress[1] = int (($ipAddressNumber - $ipAddress[0] * $multiplier[0]) / $multiplier[1]);
	$ipAddress[2] = int (($ipAddressNumber - $ipAddress[0] * $multiplier[0] - $ipAddress[1] * $multiplier[1]) / $multiplier[2]);
	$ipAddress[3] = $ipAddressNumber - $ipAddress[0] * $multiplier[0] - $ipAddress[1] * $multiplier[1] - $ipAddress[2] * $multiplier[2];
	my $ipAddressString = join '.', @ipAddress;
	return $ipAddressString;
}
sub getStartAndEndAddressAsNumber {
	#$1: 192.0.2.0/24
	my $ipAddress = shift;
	my ($startAddress,$cidr) = split /\//, $ipAddress;
	my $start = &getIpAddressAsNumber($startAddress);
	my $end = $start + 2**(32 - $cidr) - 1;
	return ($start, $end);
}

# Special IP Address Block
# https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.xhtml
# https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
# IP Address in CIDR,Network Name
# 192.0.2.0/24,RFC5737 Documentation (TEST-NET-1)
open my $special, '<:utf8', 'special.csv' or die $!;
open my $assetList, '>:utf8', 'special.tsv' or die $!;
while (my $line = <$special>) {
	chomp $line;
	my ($ipAddressCidr,$networkName) = split /,/, $line;
	my ($start, $end) = &getStartAndEndAddressAsNumber($ipAddressCidr);
	my ($startAddress,$cidr) = split /\//, $ipAddressCidr;
	my $endAddress = &getIpAddress($end);
	print $assetList "$ipAddressCidr\t$startAddress\t$endAddress\t$start\t$end\t\t$networkName";
}
close $special;
close $assetList;

# Whois list
# https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.xhtml
# 1.0.0.0/8,whois.apnic.net
my %rdapUri = (
	#'whois.apnic.net' => 'https://rdap.apnic.net/',
	#'whois.arin.net' => 'https://rdap.arin.net/registry/',
	#'whois.ripe.net' => 'https://rdap.db.ripe.net/',
	#'whois.lacnic.net' => 'https://rdap.lacnic.net/rdap/',
	#'whois.afrinic.net' => 'https://rdap.afrinic.net/rdap/',
	'whois.apnic.net' => 'http://rdap.apnic.net/',
	'whois.arin.net' => 'http://rdap.arin.net/registry/',
	'whois.ripe.net' => 'http://rdap.db.ripe.net/',
	'whois.lacnic.net' => 'http://rdap.lacnic.net/rdap/',
	'whois.afrinic.net' => 'http://rdap.afrinic.net/rdap/',
);
open my $whoisList, '<:utf8', 'whois.csv' or die $!;
open my $rdapList, '>:utf8', 'rdap.tsv' or die $!;
while (my $line = <$whoisList>) {
	chomp $line;
	my ($ipAddressCidr,$whoisServer) = split /,/, $line;
	my ($start, $end) = &getStartAndEndAddressAsNumber($ipAddressCidr);
	my ($startAddress,$cidr) = split /\//, $ipAddressCidr;
	my $endAddress = &getIpAddress($end);
	if (defined $rdapUri{$whoisServer} ){
		print $rdapList "$ipAddressCidr\t$startAddress\t$endAddress\t$start\t$end\t$rdapUri{$whoisServer}";
	} else {
		print $rdapList "$ipAddressCidr\t$startAddress\t$endAddress\t$start\t$end\t";
	}
}
close $whoisList;
close $rdapList;

exit 0;
