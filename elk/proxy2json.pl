#!/usr/bin/perl -l
use warnings;
use strict;
use utf8;
use JSON;

my $logFileName = 'challenge1.txt';
# Client IP address
# Client Hostname?
# Timestamp
# Request method
# Request URI
# HTTP version
# Mime type
# Response code
# Request size?
# Response size
# User-Agent?
# Proxy server IP address?

my %monthInNumber = (
	Jan => 1,
	Feb => 2,
	Mar => 3,
	Apr => 4,
	May => 5, 
	Jun => 6,
	Jul => 7,
	Aug => 8,
	Sep => 9,
	Oct => 10,
	Nov => 11,
	Dec => 12
);
my %defaultPort = (
	HTTP => 80,
	HTTPS => 443,
	FTP => 21,
);

-f $logFileName or die "$0: FATAL: $logFileName is not found; exit";
open my $log, '<:utf8', $logFileName or die "$0: FATAL: $!";
while (my $line = <$log>) {
	my $event;
	unless ($line =~ m#^((\d{1,3}\.){3}\d{1,3})\s(\S+)\s\[([\w/:]+\s\S+)\]\s"(\w+)\s(\S+)\s(\S+)"\s(\S+)\s(\d+)\s(\d+)\s(\d+)\s(\S+)\s((\d{1,3}\.){3}\d{1,3})#) {
		print "$0: WARN: Unparsed: $line";
	} else {
		my ($clientHostName, $timestampString, $uri, $mime, $userAgent) = ($3, $4, $6, $8, $12);
		my $event = {
			sourceAddress => $1,
			#sourceHostName => $3,
			#deviceReceiptTime => $4,
			requestMethod => $5,
			requestUrl => $6,
			httpVersion => $7,
			#fileType => $8,
			deviceEventClassId => $9,
			bytesIn => $10,
			bytesOut => $11,
			#requestClientApplication => $12,
			destinationAddress => $13,
		};
		my $timestamp = '2019-03-20T00:00:00+09:00';
		my ($day, $month, $year, $time, $timezone);
		if ($timestampString =~ m#^(\d\d)/([a-zA-Z]{3})/(\d\d\d\d):(\d\d:\d\d:\d\d)\s([+-]\d\d\d\d)#) {
			($day, $month, $year, $time, $timezone) = ($1, $monthInNumber{$2}, $3, $4, $5);
			$timestamp = sprintf "%04d-%02d-%02dT$time$timezone", $year, $month, $day;
		}
		$event->{deviceReceiptTime} = $timestamp;

		my %request;
		if ($event->{requestMethod} eq 'CONNECT') {
			$event->{applicationProtocol} = 'HTTPS';
			($event->{destinationHostName}, $event->{destinationPort}) = split /:/, $event->{requestUrl};
		} elsif ($event->{requestUrl} =~ m#^(\w+)://(.+?)/(.*)#) {
			$event->{applicationProtocol} = uc $1;
			my ($host, $path) = ($2, $3);
			($event->{destinationHostName}, my $port) = split /:/, $host;
			if (defined $port and $port =~ /^\d+$/) {
				$event->{destinationPort} = $port;
			} else {
				$event->{destinationPort} = $defaultPort{"$event->{applicationProtocol}"};
			}
			unless (defined $path) {
				$event->{requestUrlFileName} = undef;
				$event->{requestUrlQuery} = undef;
			} else {
				if ($path eq '') {
					$event->{requestUrlFileName} = undef;
				} elsif ($path =~ /(.+?)\?(.*)/) {
					($event->{requestUrlFileName}, my $query) = ($1, $2);
					if (defined $query and $query ne '') {
						$event->{requestUrlQuery} = $query;
					} else {
						$event->{requestUrlQuery} = undef;
					}
				} else {
					$event->{requestUrlFileName} = $path;
					$event->{requestUrlQuery} = undef;
				}
			}
			if (defined $event->{requestUrlFileName} and $event->{requestUrlFileName} =~ /\.(\w+)$/) {
				$event->{requestUrlFileExtension} = $1;
			} else {
				$event->{requestUrlFileExtension} = undef;
			}
		}
		if ($event->{destinationHostName} =~ /\.(\w+)$/) {
			$event->{tld} = $1;
		} else {
			$event->{tld} = undef;
		}

		# undef if NULL or '-'
		defined $clientHostName and $clientHostName eq '-' and undef $clientHostName;
		$event->{sourceHostName} = $clientHostName;
		defined $mime and $mime eq '-' and undef $mime;
		$event->{fileType} = $mime;
		if (defined $userAgent) {
			if ($userAgent eq '-') {
					undef $userAgent;
			} else {
				$userAgent =~ s/^"//;
				$userAgent =~ s/"$//;
			}
		}
		$event->{requestClientApplication} = $userAgent;

		print to_json($event);
	}
}
close $log;
exit 0;
