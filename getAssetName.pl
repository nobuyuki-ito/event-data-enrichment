#!/usr/bin/perl -l
# thanks for Honeynor and k2jp
# see http://www.honeynor.no/tools/cc2asn/about.php
# see http://d.hatena.ne.jp/k2jp/20090627/1246102447
use strict;
use warnings;
use utf8;
# rpm package on Fedora 29: perl-libwww-perl perl-LWP-Protocol-https
use LWP::UserAgent;
# rpm package on Fedora 29: perl-JSON
use JSON;
use IO::Socket;

my %file = (
	special => 'special.tsv',
	asset => 'assetInfo.tsv',
	rdap => 'rdap.tsv',
	hostname => 'hostname.csv',
);

my @multiplier = ( 16777216, 65536, 256 );
sub getIpAddressAsNumber {
	# $1: 192.0.2.1
	my $ipAddress = shift;
	my @octet = split /\./, $ipAddress;
	my $number = $octet[0] * $multiplier[0] + $octet[1] * $multiplier[1] + $octet[2] * $multiplier[2] + $octet[3];
	return $number;
}
sub getIpAddressCidr {
	#$1: 3221225984 (192.0.2.0)
	#$2: 3221226239 (192.0.2.255)
	my $start = shift;
	my $end = shift;
	my $numberOfAddress = $end - $start + 1;
	my $count = 0;
	while ($numberOfAddress > 1) {
		$numberOfAddress = $numberOfAddress / 2;
		$count++;
	}
	my $cidr = 32 - $count;
	return $cidr;
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
sub getStartAndEndAddress {
	#$1: 192.0.2.0/24
	my $ipAddress = shift;
	my ($startAddress,$cidr) = split /\//, $ipAddress;
	my $start = &getIpAddressAsNumber($startAddress);
	my $end = $start + 2**(32 - $cidr) - 1;
	my $endAddress = &getIpAddress($end);
	return ($startAddress, $endAddress, $start, $end);
}

sub getAssetInformation {
	#$1: 3221225985 (192.0.2.1)
	my $number = shift;
	my $file = shift;
	my ($countryCode, $assetName);
	if (-r $file) {
		open my $list, '<:utf8', $file or die $!;
		# IP Address\tStart Address\tEnd Address\tstart\tend\tCountry Code\tAsset Name
		# 192.0.2.0/24	192.0.2.0	192.0.2.255	3221225984	3221226239		RFC5737 Documentation (TEST-NET-1)
		while (my $line = <$list>) {
			chomp $line;
			$line =~ /^(#.*|\s*|)$/ and next;
			my @assetInfo = split /\t/, $line;
			if ($number >= $assetInfo[3] and $number <= $assetInfo[4]) {
				($countryCode, $assetName) = ($assetInfo[5], "$assetInfo[0] $assetInfo[6]");
			}
		}
		close $list;
	}
	return ($countryCode, $assetName);
}

my $ipAddress = shift;
$ipAddress =~ /^(\d{1,3}\.){3}\d{1,3}$/ or die "$0: FATAL: Malformed String; exit";
my $number = &getIpAddressAsNumber($ipAddress);
my ($countryCode, $assetName, $hostname);

# Special IP address
($countryCode, $assetName) = &getAssetInformation($number, $file{special});
if (defined $countryCode and defined $assetName) {
	print "$countryCode\t$assetName";
	exit 0;
}

my $ua = LWP::UserAgent->new;
# IE11 on Windows 10
$ua->agent('Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko');

# Already registerd assets
($countryCode, $assetName) = &getAssetInformation($number, $file{asset});
if (defined $countryCode and defined $assetName) {
	print "$countryCode\t$assetName";
} else {
	# RDAP
	my $rdapUri;
	# IP Address\tStart Address\tEnd Address\tstart\tend\tRDAP URI
	# 1.0.0.0/8	1.0.0.0	1.255.255.255	16777216	33554431	https://rdap.apnic.net/
	open my $rdapList, '<:utf8', $file{rdap} or die $!;
	while (my $line = <$rdapList>) {
		chomp $line;
		my @assetInfo = split /\t/, $line;
		if ($number >= $assetInfo[3] and $number <= $assetInfo[4]) {
			$rdapUri = $assetInfo[5];
			$rdapUri =~ m#/$# or $rdapUri .= '/';
			last;
		}
	}
	close $rdapList;
	my $uri = "${rdapUri}ip/$ipAddress";
	my $request = HTTP::Request->new('GET', $uri);
	my $response = $ua->request($request);
	unless ($response->is_success) {
		my $status = $response->code;
		print STDERR "$0: ERROR: RDAP lookup failed($status): $uri";
		$assetName = 'RDAP lookup failed';
		print "\t$assetName";
		exit 1;
	}
	my $answer = decode_json($response->content);
	my %asset = (
		ipAddressCidrBlock => '',
		startAddress => $$answer{startAddress},
		endAddress => $$answer{endAddress},
		start => 0,
		end => 0,
		countryCode => $$answer{country},
		networkName => $$answer{name},
	);
	# whois (JP only)
	defined $asset{countryCode} or $asset{countryCode} = '';
	unless ($asset{countryCode} eq 'JP') {
		($asset{start}, $asset{end}) = (&getIpAddressAsNumber($asset{startAddress}), &getIpAddressAsNumber($asset{endAddress}));
		my $cidr = &getIpAddressCidr($asset{start}, $asset{end});
		$asset{ipAddressCidrBlock} = "$asset{startAddress}/$cidr";
	} else {
		my $whoisServer = 'whois.nic.ad.jp';
		my $socket = IO::Socket::INET->new(
			PeerAddr =>$whoisServer,
			PeerPort => 43,
			Timeout => 60,
		);
		unless ($socket) {
			print STDERR "$0: ERROR: Connection failed: $whoisServer";
		} else {
			print $socket "$ipAddress/e\n";
			my @response = <$socket>;
			close $socket;
			scalar @response < 0 and print STDERR "$0: ERROR: No response: $whoisServer";
			foreach (@response) {
				m#Network Number.\s+((\d{1,3}\.){3}\d{1,3}/\d\d)# and $asset{ipAddressCidrBlock} = $1;
				/Network Name.\s+(.+)/ and $asset{networkName} = $1;
				/Organization.\s+(.+)/ and $asset{networkName} .= " $1";
			}
			($asset{startAddress}, $asset{endAddress}, $asset{start}, $asset{end}) = &getStartAndEndAddress($asset{ipAddressCidrBlock});
		}
	}
	($countryCode, $assetName) = ($asset{countryCode}, "$asset{ipAddressCidrBlock} $asset{networkName}");
	print "$countryCode\t$assetName";

	open my $whoisLookupResult, '>>:utf8', $file{asset} or die $!;
	print $whoisLookupResult "$asset{ipAddressCidrBlock}\t$asset{startAddress}\t$asset{endAddress}\t$asset{start}\t$asset{end}\t$asset{countryCode}\t$asset{networkName}";
	close $whoisLookupResult;
}

# Already registerd hostname
if (-r $file{hostname}) {
	open my $hostnameList, '<:utf8', $file{hostname} or die $!;
	# IP Address\tHostname
	# 192.0.2.1	www.example.com
	while (my $line = <$hostnameList>) {
		chomp $line;
		$line =~ /^(#.*|\s*|)$/ and next;
		my @assetInfo = split /\t/, $line;
		if ($assetInfo[0] eq $ipAddress) {
			$hostname = $assetInfo[1];
			print "$ipAddress\t$hostname";
			exit 0;
		}
	}
	close $hostnameList;
}

# DNS reverse lookup
my @octed = split /\./, $ipAddress;
my $queryName;
while (scalar @octed > 0) {
	$queryName .= pop @octed;
	$queryName .= '.';
}
$queryName .= 'in-addr.arpa';
my $dnsRequest = HTTP::Request->new('GET', "https://dns.google.com/resolve?name=$queryName&type=PTR");
my $dnsResponse = $ua->request($dnsRequest);
unless ($dnsResponse->is_success) {
	my $status = $dnsResponse->code;
	print STDERR "$0: ERROR: Google Public DNS lookup failed($status): $queryName";
	$hostname = $queryName;
	print "$ipAddress\t$hostname";
	exit 1;
}
my $dnsAnswer = decode_json($dnsResponse->content);
my $answer = shift @{$$dnsAnswer{Answer}};
$hostname = $$answer{data};
$hostname =~ s/\.$//;
print "$ipAddress\t$hostname";

open my $hostnameLookupResult, '>>:utf8', $file{hostname} or die $!;
print $hostnameLookupResult "$ipAddress\t$hostname";
close $hostnameLookupResult;

exit 0;
