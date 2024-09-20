"""
Name: Yubikey Check
Description: an importable and executable module for verifying the touch of Yubikey

Author: Matthew Boyle
License: MIT
API credential source: https://upgrade.yubico.com/getapikey/

CLI usage:
python yubikey_check.py [-hVv] [-c API_CLIENT_ID] [-k API_SECRET_KEY] [-t] [TOKEN]
-h, --help: display help text
-V, --verbose: enable verbose output, show API response as dict
-v, --version: display version information
-c ID, --client ID: API client ID value from yubico
-k KEY, --key KEY: API secret key value from yubico
-t TOKEN, --token TOKEN: output from touching yubikey
TOKEN: output from touching yubikey (same as using -t)

config file: yubi.py
  client_id: API client ID value from yubico used if none is provided at runtime
  key: API secret key value from yubico used if none is provided at runtime
  known_devices: tuple of specified yubikey prefixes to be used when doing strict validation
"""

__version__ = (1,0,3)

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
	_response = None
	def __init__(self, client_id=None, key=None):
		"""initialize API"""
		self.known_devices = yubi.known_devices
		if not client_id:
			client_id = yubi.client_id
		self.client_id = client_id
		if not key:
			key = yubi.key
		self.key = key
		try:
			self.client = Yubico(self.client_id, self.key)
		except:
			self.client = None

	def response(self):
		"""return content of _response attribute"""
		return self._response

	def set_credentials(self, client_id=None, key=None):
		"""override credentials set in __init__"""
		if not client_id is None:
			 self.client_id = client_id
		if not key is None:
			self.key = key
		try:
			self.client = Yubico(self.client_id, self.key)
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
					self._response = {'status': 'Failed', 'description': 'No token string provided', 'error': e}
					return False
		try:
			inp = inp.lower().strip()
		except:
			self._response = {'status': 'Failed', 'description': 'non-string token value provided'}
			return False
		if len(inp) != 44:
			# invalid input
			self._response = {'status': 'Failed', 'description': 'invalid token string provided'}
			return False
		if strict and self.known_devices and inp[:12] not in self.known_devices:
			self._response = {'status': 'Failed', 'description': 'unauthorized key used'}
			return False
		try:
			self._response = self.client.verify(inp, return_response=True)
			return self._response['status'] == 'OK'
		except Exception as e:
			self._response = {'status': 'Failed', 'description': 'API Error', 'error': e}
			return False

if __name__ == "__main__":
	import argparse
	desc = "Standalone script for verifying Yubikey touch\ncredentials can be gotten at https://upgrade.yubico.com/getapikey/\nand stored in yubi.py or passed as -c and -k values"
	parser = argparse.ArgumentParser(description=desc)
	parser.add_argument('token_str', nargs='?', help='output of Yubikey without flag')
	parser.add_argument('-c', '--client', metavar='CID', help='API client_id string')
	parser.add_argument('-k', '--key', help='API secret_key string')
	parser.add_argument('-t', '--token', metavar='STR', help='output of Yubikey')
	parser.add_argument('-V', '--verbose', action='store_true', help='display full response')
	parser.add_argument('-v', '--version', action='version', version='Yubikey check v%s' % '.'.join(map(str, list(__version__))))

	args = parser.parse_args()

	token = args.token or args.token_str
	cid = args.client
	api_key = args.key

	yc = YubiCheck(cid, api_key)
	print(str(yc.yubi_check(token)))
	if args.verbose:
		print(yc.response())
