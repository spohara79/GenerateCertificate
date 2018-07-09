from OpenSSL import crypto
import shutil

class GenerateCertificate(object):

    DIGEST = "sha256" # default digest
    KEYSIZE = 2048 # default keysize
    SERIAL_FILE = '/root/ca/serial' # serial file (get next serial number)
    SERIAL_OLD_FILE = '/root/ca/serial.old' # old serial file (last serial)
    INDEX_FILE = '/root/ca/index.txt' # CA Db file to write cert entries
    INDEX_OLD_FILE = '/root/ca/index.txt.old' # backup file
    CA_CRT = '/root/ca/intermediate/certs/intermediate.cert.pem' # signing cert (Intermediate)
    CA_KEY = '/root/ca/intermediate/private/intermediate.key.pem' # signing key
    CA_PASS = '' # passphrase for key

    def __init__(self, email):
        """ we just need an email address and we'll default everything else """
        self.serial = hex(self.serial_int)[2:]
        self.next_serial = hex(self.serial_int + 1)[2:]
        self.email = email
        self.pkey = self._gen_keypair()
        self.csr = self._gen_csr()
        self.cert = self._gen_cert()
        self._write_serial()
        self._write_index()

    def _write_serial(self):
        """write next available serial, and move old file"""
        # move current to old
        shutil.move(self.SERIAL_FILE, self.SERIAL_OLD_FILE)
        # write next
        with open(self.SERIAL_FILE, 'wb') as f:
            f.write(self.next_serial + '\n')

    def _write_index(self):
        """write to the CA Db
        tab delimited fields:
          1. cert status (V=valid, R=revoked, E=expired)
          2. cert expire date (YYMMDDHHMMSSZ format)
          3. cert revocation date (YYMMDDHHMMSSZ[,reason] format. Empty is not revoked
          4. cert serial - in hex
          5. cert filename or literal string 'unknown'
          6. cert DN
        """
        # copy to old
        shutil.copyfile(self.INDEX_FILE, self.INDEX_OLD_FILE)
        cert_exp = self.cert.get_notBefore()
        dn_dict = dict(self.cert.get_subject().get_components())
        cert_dn = '/C={0}/ST={1}/O={2}/OU={3}/CN={4}'.format(dn_dict['C'], dn_dict['ST'], dn_dict['O'], dn_dict['OU'], dn_dict['CN'])
        # write new entry
        with open(self.INDEX_FILE, 'a') as f:
            f.write('\t'.join(['V', cert_exp, '', str(self.serial), 'unknown', cert_dn]) + '\n')

    def _gen_keypair(self):
        """generate RSA 2048-bit key pair"""
        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, self.KEYSIZE)
        return pkey

    def _gen_csr(self):
        """generate CSR"""

        subject = {
            'C': 'XX', # country code
            'ST': 'XXXXX', # state or province (no abbreviation)
            'L': 'XXXXXX', # locality
            'O': 'XXXXX', #org
            'OU': 'XXXXX', #org unit
            'CN': 'XXXXX', # common name
            'emailAddress': 'XXXXX@XXXXX.XX', # email
        }
        
        req = crypto.X509Req()
        subj = req.get_subject()

        for key, value in subject.items():
            setattr(subj, key, value)

        req.set_pubkey(self.pkey)
        req.sign(self.pkey, self.DIGEST)
        return req

    def _gen_cert(self, ca_pass=CA_PASS):
        """generate a certificate from the csr"""

        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(self.CA_CRT, 'rb').read())
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(self.CA_KEY, 'rb').read(), passphrase=ca_pass)

        cert = crypto.X509()
        cert.set_serial_number(self.serial_int)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(60 * 60 * 24 * 365) # one year
        cert.set_issuer(ca_cert.get_subject())
        cert.set_subject(self.csr.get_subject())
        cert.add_extensions([
            crypto.X509Extension("basicConstraints", True,"CA:FALSE"),
            crypto.X509Extension("nsCertType", False, "client, email"),
            #crypto.X509Extension("keyUsage", True,"critical, nonRepudiation, digitalSignature, keyEncipherment"),
            crypto.X509Extension("extendedKeyUsage", False, "clientAuth, emailProtection"),
            crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=cert),
            crypto.X509Extension("authorityKeyIdentifier", False, "keyid:always",issuer=ca_cert)
        ])
        cert.set_pubkey(self.csr.get_pubkey())
        cert.sign(ca_key, self.DIGEST)
        return cert
   
   @property
   def serial_int(self):
        """read the next available serial number"""
        with open(self.SERIAL_FILE, 'rb') as f:
            serial = int(f.readline().strip(), 16)
        return serial

    @property
    def certificate(self):
        return crypto.dump_certificate(crypto.FILETYPE_PEM, self.cert)

    @property
    def private_key(self):
        return crypto.dump_privatekey(crypto.FILETYPE_PEM, self.pkey)
