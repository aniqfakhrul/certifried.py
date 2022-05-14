
import unittest
from unicrypto import get_cipher_by_name
from unicrypto import symmetric

tdes_ecb = [
	('000102030405060708090A0B0C0D0E0F1011121314151617', '982662605553244D', '0011223344556677'),	
]

tdes_cbc = [
	('0123456789abcdeff1e0d3c2b5a49786fedcba9876543210','fedcba9876543210' , '37363534333231204E6F77206973207468652074696D6520666F722000000000', '3FE301C962AC01D02213763C1CBD4CDC799657C064ECF5D41C673812CFDE9675'),
]

class TDESTest:
	def ecb_enc(self, cipherobj:symmetric.symmetricBASE, vector):
		for i, res in enumerate(vector):
			key, plaintext, ciphertext = res
			plaintext = bytes.fromhex(plaintext)
			key = bytes.fromhex(key)
			ciphertext = bytes.fromhex(ciphertext)

			ctx = cipherobj(key)
			enc_data = ctx.encrypt(plaintext)
			if enc_data != ciphertext:
				raise Exception('Ciphertext doesnt match to vector! TDES %s Cipher: \r\n%s \r\nVector: \r\n%s' % (i, enc_data, ciphertext))
			
			ctx = cipherobj(key)
			dec_data = ctx.decrypt(enc_data)
			if dec_data != plaintext:
				raise Exception('Decrypted data doesnt match plaintext! TDES-ECB Cipher: \r\n%s \r\nPlaintext: \r\n%s' % (dec_data.hex(), plaintext.hex()))

		return True
	
	def cbc_enc(self, cipherobj:symmetric.symmetricBASE, vector):
		for i, res in enumerate(vector):
			key, iv, plaintext, ciphertext = res
			plaintext = bytes.fromhex(plaintext)
			key = bytes.fromhex(key)
			ciphertext = bytes.fromhex(ciphertext)
			iv = bytes.fromhex(iv)

			ctx = cipherobj(key, symmetric.MODE_CBC, iv)
			enc_data = ctx.encrypt(plaintext)
			if enc_data != ciphertext:
				raise Exception('Ciphertext doesnt match to vector! TDES %s Cipher: \r\n%s \r\nVector: \r\n%s' % (i, enc_data, ciphertext))

			ctx = cipherobj(key, symmetric.MODE_CBC, iv)
			dec_data = ctx.decrypt(enc_data)
			if dec_data != plaintext:
				raise Exception('Decrypted data doesnt match plaintext! TDES-CBC Cipher: \r\n%s \r\nPlaintext: \r\n%s' % (dec_data.hex(), plaintext.hex()))

		return True


class pureTDES(TDESTest, unittest.TestCase):
	def setUp(self):
		self.cipherobj = get_cipher_by_name('TDES', 'pure')
	
	def test_ecb(self):
		self.ecb_enc(self.cipherobj, tdes_ecb)
	
	def test_cbc(self):
		self.cbc_enc(self.cipherobj, tdes_cbc)

class CryptoTDES(TDESTest, unittest.TestCase):
	def setUp(self):
		self.cipherobj = get_cipher_by_name('TDES', 'crypto')
	
	def test_ecb(self):
		self.ecb_enc(self.cipherobj, tdes_ecb)
	
	def test_cbc(self):
		self.cbc_enc(self.cipherobj, tdes_cbc)

class pycryptodomeTDES(TDESTest, unittest.TestCase):
	def setUp(self):
		self.cipherobj = get_cipher_by_name('TDES', 'pycryptodome')
	
	def test_ecb(self):
		self.ecb_enc(self.cipherobj, tdes_ecb)
	
	def test_cbc(self):
		self.cbc_enc(self.cipherobj, tdes_cbc)

class cryptographyTDES(TDESTest, unittest.TestCase):
	def setUp(self):
		self.cipherobj = get_cipher_by_name('TDES', 'cryptography')
	
	def test_ecb(self):
		self.ecb_enc(self.cipherobj, tdes_ecb)
	
	def test_cbc(self):
		self.cbc_enc(self.cipherobj, tdes_cbc)

class MBEDTLSTDES(TDESTest, unittest.TestCase):
	def setUp(self):
		self.cipherobj = get_cipher_by_name('TDES', 'mbedtls')
	
	def test_ecb(self):
		self.ecb_enc(self.cipherobj, tdes_ecb)
	
	def test_cbc(self):
		self.cbc_enc(self.cipherobj, tdes_cbc)

if __name__ == '__main__':
	unittest.main()