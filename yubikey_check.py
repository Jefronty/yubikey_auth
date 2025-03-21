"""
Name: Yubikey Check
Description: an importable and executable module for verifying the touch of Yubikey

Author: Matthew Boyle
License: MIT
API credential source: https://upgrade.yubico.com/getapikey/

CLI usage:
python yubikey_check.py [-h][-Vvs] [-c API_CLIENT_ID] [-k API_SECRET_KEY] [-t] [TOKEN]
-h, --help: display help text
-v, --verbose: enable verbose output, show API response as dict
-V, --version: display version information
-s, --strict: olny validate known Yubikeys, ignored if none in config
-c ID, --client ID: API client ID value from yubico
-k KEY, --key KEY: API secret key value from yubico
-t TOKEN, --token TOKEN: output from touching yubikey
TOKEN: output from touching yubikey (same as using -t)

config file: yubi.py
  client_id: API client ID value from yubico used if none is provided at runtime
  key: API secret key value from yubico used if none is provided at runtime
  known_devices: tuple of specified yubikey prefixes to be used when doing strict validation
"""

__version__ = (1,0,7)

import sys
from yubico_client import Yubico
try:
	from inputimeout import inputimeout
	HAS_ITO = True
except:
	HAS_ITO = False

import yubi

class YubiCheck(object):
	"""class to verify Yubikey token"""
	__message = None
	def __init__(self, client_id=None, key=None):
		"""initialize API"""
		self.known_devices = yubi.known_devices
		self.__client_id = client_id or yubi.client_id
		self.__key = key or yubi.key
		try:
			self.client = Yubico(self.__client_id, self.__key)
		except:
			self.client = None

	def add_device(self, dev_str):
		"""add a device to the known_devices"""
		if dev_str in self.known_devices:
			return True
		if not isinstance(dev_str, str) or len(dev_str) < 12:
			self.__message = {'status': 'Error', 'description': 'invalid device string provided: must be a 12 character string'}
			return False
		_dev = dev_str[:12]
		if _dev not in self.known_devices:
			self.known_devices += (_dev,)
		return True

	@property
	def message(self):
		"""return content of __message attribute"""
		return self.__message

	def set_credentials(self, client_id=None, key=None):
		"""override credentials set in __init__"""
		if not client_id is None:
			 self.__client_id = client_id
		if not key is None:
			self.__key = key
		try:
			self.client = Yubico(self.__client_id, self.__key)
		except:
			return False
		return True

	def yubi_check(self, inp=None, strict=False):
		"""check yubikey token for validity

		Keyword arguments:
		inp -- str, Yubikey token value, if None will request user input
		strict -- flag to check whether yubikey is a known device, if known_devices is empty this is ignored
		"""
		if inp is None:
			if not HAS_ITO:
				# fallback to standard user input
				if sys.version_info[0] < 3:
					# python 2.x
					inp = raw_input('Touch Yubikey ')
				else:
					# python 3.x
					inp = input('Touch Yubikey ')
			else:
				try:
					inp = inputimeout('Touch Yubikey ', 30)
				except Exception as e:
					# no input provided
					self.__message = {'status': 'Failed', 'description': 'No token string provided', 'error': str(e)}
					return False
		try:
			inp = inp.lower().strip()
		except:
			self.__message = {'status': 'Failed', 'description': 'non-string token value provided'}
			return False
		if len(inp) != 44:
			# invalid input
			self.__message = {'status': 'Failed', 'description': 'invalid token string provided'}
			return False
		if strict and self.known_devices and inp[:12] not in self.known_devices:
			self.__message = {'status': 'Failed', 'description': 'unauthorized key used'}
			return False
		try:
			self.__message = self.client.verify(inp, return_response=True)
			return self.__message['status'] == 'OK'
		except Exception as e:
			self.__message = {'status': 'Failed', 'description': 'API Error', 'error': str(e)}
			return False

if __name__ == "__main__":
	import argparse
	desc = "Standalone script for verifying Yubikey touch\ncredentials can be gotten at https://upgrade.yubico.com/getapikey/\nand stored in yubi.py or passed as -c and -k values"
	parser = argparse.ArgumentParser(description=desc)
	parser.add_argument('token_str', nargs='?', help='output of Yubikey without flag')
	parser.add_argument('-c', '--client', metavar='CID', help='API client_id string')
	parser.add_argument('-k', '--key', help='API secret_key string')
	parser.add_argument('-t', '--token', metavar='STR', help='output of Yubikey')
	parser.add_argument('-s', '--strict', action='store_true', help='only validate known Yubikeys if any in known_devices')
	parser.add_argument('-v', '--verbose', action='store_true', help='display full response')
	parser.add_argument('-V', '--version', action='version', version='Yubikey check v%s' % '.'.join(map(str, list(__version__))))

	args = parser.parse_args()

	token = args.token or args.token_str

	yc = YubiCheck(args.client, args.key)
	print(str(yc.yubi_check(token, args.strict)))
	if args.verbose:
		print(yc.message)
