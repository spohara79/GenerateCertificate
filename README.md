# GenerateCertificate
pyOpenSSL class to generate keys and csr, and generate certificate

Update the class variable `CA_PASS` for the signing cert passphrase

The function `_gen_csr` must be updated to how you want the subject built:
```python
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
```
