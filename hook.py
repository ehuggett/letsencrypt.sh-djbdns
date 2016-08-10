#!/usr/bin/env python3

import argparse
import time
import sys
import subprocess
import dns.exception
import dns.resolver

def parse_args():
    # Create the first parser object and get just the first parameter
    parser = argparse.ArgumentParser('Argument format parser')
    parser.add_argument('arg_format', type=str, help='The first argument.' +
                        'It tells us what input to expect next.')
    args_ns, remaining = parser.parse_known_args()

    # Generate a new parser based on the first parameter
    parser = format_specific_parser(args_ns.arg_format)

    # There will always be at least one set of input (in this case at least)
    args_ns, remaining = parser.parse_known_args(args=remaining, namespace=args_ns)

    # Iterate over the remaining input, if any, adding to the namespace
    while remaining:
        args_ns, remaining = parser.parse_known_args(args=remaining,
                                                     namespace=args_ns)

    return args_ns

def format_specific_parser(arg_format):
    parser = argparse.ArgumentParser("Command line parser for %s" % arg_format)
    if (arg_format == "deploy_challenge"):
        args_deploy_challenge(parser)
    # elif (...):
        # other format function calls
    else:
        args_unknown(parser)
    return parser

def args_unknown(parser):
    parser.add_argument("extra", nargs = '*', default = '')

def args_deploy_challenge(parser):
    parser.add_argument('challenges', type=str, action='append', nargs=3) 

def get_host_authoritative_nameservers(host):
    auth_nameservers = []
    soa_answer = dns.resolver.query(host, dns.rdatatype.SOA, raise_on_no_answer = False)
    soa_response = soa_answer.response
    rrset = None

    # If we have an ANSWER, use that, otherwise use the AUTHORITY section (which
    # will be the nameservers for the parent host)
    if soa_answer.rrset:
        soa_rrset = soa_response.answer[0]
    else:
        soa_rrset = soa_response.authority[0]

    # Parent host is the one with NS records, which may not be the same as host
    parent_host = soa_rrset.name

    ns_answer = dns.resolver.query(parent_host, dns.rdatatype.NS)

    for ns_rrset in ns_answer.rrset:
        auth_nameservers.append(ns_rrset.to_text())

    return auth_nameservers

def get_host_ip_addresses(host):
    ip_addresses = []
    ip_answer = dns.resolver.query(host, dns.rdatatype.A)

    for ip_rrset in ip_answer.rrset:
        ip_addresses.append(ip_rrset.to_text())

    return ip_addresses

def verify_challenge(host, challenge, ns_ip_addresses):
    nameserver_count = len(ns_ip_addresses)
    record_match_count = 0

    # Check that every nameserver IP contains the challenge record
    for ns_ip in ns_ip_addresses:
        # Use the authoritative server as a resolver - this works since we
        # will only issue queries where the resolver is the authority (i.e.
        # recursive queries are not required)
        print("+++ Check auth resolver with IP: " + ns_ip)
        auth_resolver = dns.resolver.Resolver(configure = False)
        auth_resolver.nameservers = [ns_ip]

        print("+++ Query for " + host + " TXT record")
        dns_answer = auth_resolver.query(host, 'TXT')

        if dns_answer:
            for dns_rrset in dns_answer.rrset:
                dns_text = dns_rrset.to_text()

                # DNS library quotes returned strings - for comparisons we
                # need to remove them
                if dns_text.startswith('"') and dns_text.endswith('"'):
                    dns_text = dns_text[1:-1]

                print("++++ Challenge: " + challenge)
                print("++++ DNS response: " + dns_text)

                if dns_text == challenge:
                    record_match_count += 1
                    break

    return (record_match_count == nameserver_count and record_match_count >= 1)

LOOKUP_SLEEP_SECONDS = 60
MAX_DNS_ATTEMPTS = 10
DEFAULT_TTL = 120

# path to the file the tinydns records will be written to
outputfile = "/path/to/temp/file"

# path to the script that will do something with the tinydns config this script produces
# The script will be passed the value of outputfile as its first parameter
scriptfile = "/path/to/script.(sh|py|pl|etc)"

args = parse_args()
action = args.arg_format

if action == 'deploy_challenge':
    records = args.challenges

    tinydns = list()
    for domain, token, challenge in records:
        host = "_acme-challenge." + domain
        tinydns.append("'" + host + ":" + challenge + ":" + str(DEFAULT_TTL))

    print("++ Writing tinydns config to " + outputfile)
    with open(outputfile, mode='wt') as dnsconfig:
        dnsconfig.write('\n'.join(tinydns))

    if subprocess.call([scriptfile,outputfile]) != 0:
        print("++ FATAL ERROR: " + scriptfile + " exited with non-zero status")
        sys.exit(1)

    for domain, token, challenge in records:
        host = "_acme-challenge." + domain

        # Get the NS records for the domain, not the host, as the host record may
        # not exist yet
        print("++ Get NS IP addresses to query auth servers for " + domain)
        nameservers = get_host_authoritative_nameservers(domain)
        ns_ip_addresses = []

        for nameserver in nameservers:
            host_ip_addresses = get_host_ip_addresses(nameserver)
            for host_ip_address in host_ip_addresses:
                ns_ip_addresses.append(host_ip_address)

        print(ns_ip_addresses)

        for current_attempt in range(MAX_DNS_ATTEMPTS):
            print("++ Checking for DNS record, attempt: {}/{}".format(current_attempt+1, MAX_DNS_ATTEMPTS))

            try:
                if verify_challenge(host, challenge, ns_ip_addresses):
                    print("++ Challenge successful!")
                    break
            except dns.exception.Timeout:
                print("++ DNS timeout, quitting...")
                sys.exit(1)
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass

            time.sleep(LOOKUP_SLEEP_SECONDS)
        else:
            print("++ Failed to find record for: " + domain)
            sys.exit(1)
