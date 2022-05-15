
import argparse
from getpass import getpass
import base64
import sys

from impacket.examples.utils import parse_credentials, parse_target
from impacket.dcerpc.v5.dcomrt import DCOMConnection


from .wcce import ICertRequestD2, ICertRequestD, CLSID_CCertRequestD, IID_ICertRequestD2, IID_ICertRequestD, DCERPCSessionError
from .template import Template, EKUS_NAMES
from .certificate import generate_csr, generate_pfx, new_key, load_x509_certificate, is_alt_name_in_cert, cert_to_pem, cert_get_extended_key_usage, load_pfx, generate_pkcs7, csr_to_pem, csr_to_der, pkcs7_to_pem, pkcs7_to_der
from .sid import KNOWN_SIDS, name_from_sid
from .ldap import connect_ldap, get_base_dn, search_ldap, ldap_results, security_descriptor_control, SR_SECURITY_DESCRIPTOR, ACCESS_ALLOWED_OBJECT_ACE

def target_type(target):
    domain, username, password, address = parse_target(target)

    if username == "":
        raise argparse.ArgumentTypeError("Username must be specified")

    if domain == "":
        raise argparse.ArgumentTypeError(
            "Domain of user '{}' must be specified".format(username)
        )

    if address == "":
        raise argparse.ArgumentTypeError(
            "Target address (hostname or IP) must be specified"
        )

    return domain, username, password, address


def target_creds_type(target):
    (userdomain, username, password) = parse_credentials(target)

    if username == "":
        raise argparse.ArgumentTypeError("Username should be be specified")

    if userdomain == "":
        raise argparse.ArgumentTypeError(
            "Domain of user '{}' should be be specified".format(username)
        )

    return (userdomain, username, password or '', '')


def main_req(args,ca_host,ca_service,username,password,domain,lmhash,nthash,cert_pass):
    print("[ certi ] Service: {}".format(ca_service))
    print("[ certi ] Template: {}".format(args.template))
    print("[ certi ] Username: {}".format(username))
    #print(ca_host,username,password,domain,lmhash,nthash,args.aesKey,True,args.dc_ip)
    
    dcom = DCOMConnection(
        ca_host,
        username=username,
        password=password,
        domain=domain,
        lmhash='',
        nthash='',
        aesKey=args.aesKey,
        doKerberos=True,
        kdcHost=args.dc_ip,
        oxidResolver=True,
    )

    key = new_key()

    cn = username
    csr = generate_csr(
        key,
        cn=cn,
    )
    csr = csr_to_der(csr)

    try:
        attributes = {
            "CertificateTemplate": args.template,
        }
        
        resp = request_cert(dcom, ca_service, csr, attributes)
        print("[ certi ] Response: 0x{:X} {}".format(resp["Disposition"], resp["DispositionMessage"]))

        if resp["EncodedCert"]:
            pfx_bytes = process_cert(
                key,
                resp["EncodedCert"],
                cert_pass,
                f'{username}.pfx',
                cn,
            )
        else:
            print("[-] No certificate was returned")

        return pfx_bytes

    except DCERPCSessionError as ex:
        print("Error: {}".format(ex), file=sys.stderr)
        if ex.error_code == 0x80094011:
            print("Help: Try using Kerberos authentication with -k -n params", file=sys.stderr)
    finally:
        dcom.disconnect()


def request_cert(dcom, service, csr, attributes):
    iInterface = dcom.CoCreateInstanceEx(CLSID_CCertRequestD, IID_ICertRequestD)
    iCertRequestD = ICertRequestD(iInterface)
    return iCertRequestD.Request(service, csr, attributes=attributes)


def request2_cert(dcom, service, csr, attributes):
    iInterface = dcom.CoCreateInstanceEx(CLSID_CCertRequestD, IID_ICertRequestD2)
    iCertRequestD2 = ICertRequestD2(iInterface)
    return iCertRequestD2.Request2(service, csr, attributes=attributes)


def process_cert(key, encoded_cert, cert_pass, out_file, cn):
    cert = load_x509_certificate(encoded_cert, cert_format="der")

    print("[ certi ] Cert subject: {}".format(cert.subject.rfc4514_string()))
    print("[ certi ] Cert issuer: {}".format(cert.issuer.rfc4514_string()))
    print("[ certi ] Cert Serial: {:X}".format(cert.serial_number))

    # print(cert_to_pem(cert).decode())
    extended_usages = cert_get_extended_key_usage(cert)
    if extended_usages:
        print("[ certi ] Cert Extended Key Usage: {}".format(", ".join([
            EKUS_NAMES.get(oid, oid) for oid in extended_usages
        ])))

    pfx_filename = "{}.pfx".format(cn)

    if cert_pass:
        cert_password = cert_pass.encode()
    else:
        cert_password = b"admin"

    pfx_bytes = generate_pfx(key, cert, cert_password)

    if out_file:
        pfx_filename = out_file

    #with open(pfx_filename, "wb") as fo:
    #    fo.write(pfx_bytes)

    #print()
    #print("[*] Saving certificate in {} (password: {})".format(
    #    pfx_filename,
    #    cert_password.decode()
    #))
    return pfx_bytes


def main_list(args):

    ldap_conn = connect_ldap(
        domain=args.userdomain,
        user=args.username,
        password=args.password,
        lmhash=args.lmhash,
        nthash=args.nthash,
        aesKey=args.aes,
        dc_ip=args.dc_ip,
        kerberos=args.kerberos
    )

    sids_resolver = SidsResolver(ldap_conn)

    if "ca" in args.classes:
        print("[*] Root CAs\n")
        for cert in fetch_root_cas(ldap_conn, args.userdomain):
            print_cert(cert)
            print("")

            print("[*] Authority Information Access\n")
            for cert in fetch_aia_cas(ldap_conn, args.userdomain):
                print_cert(cert)
                print("")


    if "ntauth" in args.classes:
        print("[*] NtAuthCertificates - Certificates that enable authentication\n")
        for cert in fetch_ntauthcertificates(ldap_conn, args.userdomain):
            print_cert(cert)
            print("")


    enroll_services = None
    if "service" in args.classes:
        print("[*] Enrollment Services\n")
        enroll_services = list(fetch_enrollment_services(
            ldap_conn,
            args.userdomain
        ))
        for service in enroll_services:
            print_service(service)
            print("")


    if "template" in args.classes:
        templates = list(fetch_templates(
            ldap_conn,
            args.userdomain,
            temp_names=args.temp_name,
            ldap_filter=args.temp_filter,
        ))
        if not enroll_services:
            enroll_services = list(fetch_enrollment_services(
                ldap_conn,
                args.userdomain
            ))

        for template in templates:
            for service in enroll_services:
                if template.name in service.templates:
                    template.enroll_services.append(service.name)

        print("[*] Templates\n")
        for temp in templates:
            if args.enabled and not temp.is_enabled():
                continue

            if args.vuln and not temp.is_vulnerable():
                continue

            print_template(temp, sids_resolver)
            print("")



EX_RIGHT_CERTIFICATE_ENROLLMENT = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
EX_RIGHT_CERTIFICATE_AUTOENROLLMENT = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

def print_service(enroll_ca):
    print("Name: {}".format(enroll_ca.name))
    print("DNS name: {}".format(enroll_ca.dnsname))
    print("Templates: {}".format(", ".join(enroll_ca.templates)))
    if enroll_ca.web_services:
        print("Web services: {}".format(", ".join(enroll_ca.web_services)))
    print("Certificate:")
    print_cert(enroll_ca.cert, offset=2)


def print_template(temp, sids_resolver):
    print("Name: {}".format(temp.name))
    print("Schema Version: {}".format(temp.schema_version))

    if temp.enroll_services:
        print("Enroll Services: {}".format(", ".join(temp.enroll_services)))

    vulns = []

    if temp.is_vuln_to_san_impersonation():
        vulns.append("ESC1 - SAN Impersonation")

    if temp.is_vuln_to_any_purpose():
        vulns.append("ESC2 - Any Purpose")

    if temp.is_vuln_to_request_agent_certificate():
        vulns.append("ESC3.1 - Request Agent Certificate")

    if temp.is_vuln_to_request_with_agent_certificate():
        vulns.append("ESC3.2 - Use Agent Certificate")

    if vulns:
        print("Vulnerabilities: {}".format(", ".join(vulns)))

    print("msPKI-Certificate-Name-Flag: (0x{:x}) {}".format(
        temp.certificate_name_flags,
        ", ".join(temp.certificate_name_flags_names)
    ))
    print("msPKI-Enrollment-Flag: (0x{:x}) {}".format(
        temp.enrollment_flags,
        ", ".join(temp.enrollment_flags_names)
    ))

    if temp.ra_signature is not None:
        print("msPKI-RA-Signature: {}".format(temp.ra_signature))
    print("pKIExtendedKeyUsage: {}".format(", ".join([EKUS_NAMES.get(oid, oid) for oid in temp.ekus])))

    if temp.certificate_application_policies:
        print("msPKI-Certificate-Application-Policy: {}".format(", ".join([
            EKUS_NAMES.get(oid, oid) for oid in temp.certificate_application_policies
        ])))

    if temp.ra_application_policies:
        print("msPKI-RA-Application-Policy: {}".format(", ".join([
            EKUS_NAMES.get(oid, oid) for oid in temp.ra_application_policies
        ])))

    owner_sid = temp.owner_sid.formatCanonical()
    owner_domain, owner_name = sids_resolver.get_name_from_sid(owner_sid)
    print("SD Owner: {} {}\{}".format(temp.owner_sid.formatCanonical(), owner_domain, owner_name))

    enroll_sids = set()
    autoenroll_sids = set()
    write_owner_sids = set()
    write_dacl_sids = set()
    write_property_sids = set()
    for ace in temp.dacl.aces:
        if ace["TypeName"] == "ACCESS_ALLOWED_OBJECT_ACE":
            ace = ace["Ace"]
            mask = ace["Mask"]
            sid = ace["Sid"].formatCanonical()
            if ace.hasFlag(ace.ACE_OBJECT_TYPE_PRESENT):
                if guid_to_string(ace["ObjectType"]) == EX_RIGHT_CERTIFICATE_ENROLLMENT:
                    enroll_sids.add(sid)
                elif guid_to_string(ace["ObjectType"]) == EX_RIGHT_CERTIFICATE_AUTOENROLLMENT:
                    autoenroll_sids.add(sid)
        elif ace["TypeName"] == "ACCESS_ALLOWED_ACE":
            ace = ace["Ace"]
            mask = ace["Mask"]
            sid = ace["Sid"].formatCanonical()

        else:
            continue

        if mask.hasPriv(mask.GENERIC_WRITE) \
           or mask.hasPriv(mask.GENERIC_ALL) \
           or mask.hasPriv(ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP):
            write_property_sids.add(sid)

        if mask.hasPriv(mask.WRITE_DACL):
            write_dacl_sids.add(sid)

        if mask.hasPriv(mask.WRITE_OWNER):
            write_owner_sids.add(sid)

    print("Permissions")
    print("  Enrollment Permissions")
    print("    Enrollment Rights")
    print_sids(enroll_sids, sids_resolver, offset=6)

    if autoenroll_sids:
        print("    AutoEnrollment Rights")
        print_sids(autoenroll_sids, sids_resolver, offset=6)

    print("  Write Permissions")
    print("    Write Owner")
    print_sids(write_owner_sids, sids_resolver, offset=6)

    print("    Write DACL")
    print_sids(write_dacl_sids, sids_resolver, offset=6)

    print("    Write Property")
    print_sids(write_property_sids, sids_resolver, offset=6)


def print_sids(sids, sids_resolver, offset=0):
    blanks = " " * offset
    msg = []
    for sid in sids:
        domain, name = sids_resolver.get_name_from_sid(sid)
        msg.append("{} {}\{}".format(sid, domain, name))

    print("\n".join(["{}{}".format(blanks, line) for line in msg]))

def guid_to_string(guid):
    return "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(
        guid[3], guid[2], guid[1], guid[0],
        guid[5], guid[4],
        guid[7], guid[6],
        guid[8], guid[9],
        guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]
    )

def print_cert(cert, offset=0):
    blanks = " " * offset
    msg = [
            "Cert Subject: {}".format(cert.subject.rfc4514_string()),
            "Cert Serial: {:X}".format(cert.serial_number),
            "Cert Start: {}".format(cert.not_valid_before),
            "Cert End: {}".format(cert.not_valid_after),
            "Cert Issuer: {}".format(cert.issuer.rfc4514_string()),
        ]
    print("{}{}".format(blanks, "\n{}".format(blanks).join(msg)))

class EnrollmentService:

    def __init__(self):
        self.name = ""
        self.cert = None
        self.dnsname = ""
        self.templates = []
        self.web_services = []

def fetch_templates(ldap_conn, domain, temp_names=None, ldap_filter=""):
    temp_filter = "(objectClass=pKICertificateTemplate)"

    if temp_names:
        names_filter = "(|{})".format(
            "".join("(name={})".format(name) for name in temp_names)
        )

        temp_filter = "(&{}{})".format(temp_filter, names_filter)

    if ldap_filter:
        temp_filter = "(&{}{})".format(temp_filter, ldap_filter)


    conf_base = "CN=Configuration,{}".format(get_base_dn(domain))
    resp = search_ldap(
        ldap_conn,
        temp_filter,
        conf_base,
        controls = security_descriptor_control(sdflags=0x05) # Query owner and DACL
    )

    for item in ldap_results(resp):
        temp = Template()
        for attribute in item['attributes']:
            at_type = str(attribute['type'])
            if at_type == "name":
                temp.name = str(attribute['vals'][0])
            elif at_type == "msPKI-Certificate-Name-Flag":
                temp.certificate_name_flags = int(attribute['vals'][0])
            elif at_type == "msPKI-Enrollment-Flag":
                temp.enrollment_flags = int(attribute['vals'][0])
            elif at_type == "msPKI-RA-Signature":
                temp.ra_signature = int(attribute['vals'][0])
            elif at_type == "msPKI-Private-Key-Flag":
                temp.private_key_flags = int(attribute['vals'][0])
            elif at_type == "pKIExtendedKeyUsage":
                for val in attribute['vals']:
                    oid = str(val)
                    temp.ekus.append(oid)
            elif at_type == "nTSecurityDescriptor":
                sec_desc_bytes = attribute['vals'][0].asOctets()
                temp.security_descriptor.fromString(sec_desc_bytes)
            elif at_type == "msPKI-Template-Schema-Version":
                temp.schema_version = int(attribute['vals'][0])
            elif at_type == "msPKI-Certificate-Application-Policy":
                temp.certificate_application_policies = [
                    str(val) for val in attribute['vals']
                ]
            elif at_type == "msPKI-RA-Application-Policies":
                temp.ra_application_policies = [
                    str(val) for val in attribute['vals']
                ]

        yield temp


def fetch_enrollment_services(ldap_conn, domain):
    enroll_filter = "(objectCategory=pKIEnrollmentService)"
    conf_base = "CN=Configuration,{}".format(get_base_dn(domain))

    resp = search_ldap(ldap_conn, enroll_filter, conf_base)

    for item in ldap_results(resp):
        enr = EnrollmentService()
        for attribute in item['attributes']:
            at_type = str(attribute['type'])
            if at_type == "cACertificate":
                cert_bytes = attribute['vals'][0].asOctets()
                enr.cert = load_x509_certificate(cert_bytes, cert_format="der")
            elif at_type == "name":
                enr.name = str(attribute['vals'][0])
            elif at_type == "dNSHostName":
                enr.dnsname = str(attribute['vals'][0])
            elif at_type == "certificateTemplates":
                enr.templates = [str(v) for v in attribute['vals']]
            elif at_type == "msPKI-Enrollment-Servers":
                enr.web_services = [str(v).split("\n")[3] for v in attribute['vals']]
        yield enr


def fetch_aia_cas(ldap_conn, domain):
    cas_filter = "(objectClass=certificationAuthority)"
    ntauth_base = "CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,{}".format(get_base_dn(domain))
    resp = search_ldap(ldap_conn, cas_filter, ntauth_base)
    return get_certs_from_ldap_response(resp)


def fetch_ntauthcertificates(ldap_conn, domain):
    cas_filter = "(objectClass=certificationAuthority)"
    ntauth_base = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,{}".format(get_base_dn(domain))
    resp = search_ldap(ldap_conn, cas_filter, ntauth_base)

    return get_certs_from_ldap_response(resp)


def fetch_root_cas(ldap_conn, domain):
    cas_filter = "(objectClass=certificationAuthority)"

    cas_search_base = "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,{}".format(get_base_dn(domain))

    resp = search_ldap(ldap_conn, cas_filter, cas_search_base)

    return get_certs_from_ldap_response(resp)


def get_certs_from_ldap_response(resp):
    for item in ldap_results(resp):
        for attribute in item['attributes']:
            if str(attribute['type']) == "cACertificate":
                for val in attribute['vals']:
                    cert_bytes = val.asOctets()
                    cert = load_x509_certificate(cert_bytes, cert_format="der")
                    yield cert


def ldap_get_name_from_sid(ldap_conn, sid):
    if type(sid) is not str:
        sid = sid.formatCanonical()

    sid_filter = "(objectsid={})".format(sid)
    resp = search_ldap(ldap_conn, sid_filter)

    for item in ldap_results(resp):
        for attribute in item['attributes']:
            if str(attribute["type"]) == "sAMAccountName":
                name = str(attribute["vals"][0])
                return name

def ldap_get_domain_from_sid(ldap_conn, sid):
    if type(sid) is not str:
        sid = sid.formatCanonical()

    sid_filter = "(objectsid={})".format(sid)
    resp = search_ldap(ldap_conn, sid_filter)

    for item in ldap_results(resp):
        for attribute in item['attributes']:
            at_type = str(attribute["type"])
            if at_type == "name":
                return str(attribute["vals"][0])

                name = ".".join([x.lstrip("DC=") for x in value.split(",")])
                return name


class SidsResolver:

    def __init__(self, ldap_conn):
        self.ldap_conn = ldap_conn
        self.cached_sids = {}
        self.domain_sids = {}

    def get_name_from_sid(self, sid):
        if type(sid) is not str:
            sid = sid.formatCanonical()

        try:
            return ("BUILTIN", KNOWN_SIDS[sid])
        except KeyError:
            pass

        try:
            return self.cached_sids[sid]
        except KeyError:
            pass

        domain_sid = "-".join(sid.split("-")[:-1])
        domain = self.get_domain_from_sid(domain_sid)


        name = ldap_get_name_from_sid(self.ldap_conn, sid)
        self.cached_sids[sid] = (domain, name)

        return (domain, name)

    def get_domain_from_sid(self, sid):
        try:
            return self.domain_sids[sid]
        except KeyError:
            pass

        name = ldap_get_domain_from_sid(self.ldap_conn, sid)
        self.domain_sids[sid] = name
        return name
