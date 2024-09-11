import yubi
import sys
from yubico_client import Yubico
try:
	from inputimeout import inputimeout
except:
	pass
if 'inputimeout' in locals():
	has_ito = True
else:
	has_ito = False

class YubiCheck():
	"""class to verify Yubikey token"""
	def __init__(self, client_id=None, key=None):
		"""initialize API"""
		self.known_devices = yubi.known_devices
		if not client_id:
			client_id = yubi.client_id
		if not key:
			key = yubi.key
		self.client = Yubico(client_id, key)

	def yubi_check(self, inp=None, strict=True):
		"""check yubikey token for validity

		Keyword arguments:
		inp -- str, Yubikey token value, if None will request user input
		strict -- flag to check whether yubikey is a known device, if no devices are listed this is ignored
		"""
		if inp is None:
			if not has_ito:
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
				except:
					# no input provided
					return False
		if len(inp.strip()) != 44:
			# ubvakud input
			return False
		if strict and len(self.known_devices) > 0 and inp[:12] not in self.known_devices:
			return False
		try:
			return self.client.verify(inp.strip())
		except:
			return False

if __name__ == "__main__":
	yc = YubiCheck()
	if len(sys.argv) > 1:
		print(str(yc.yubi_check(sys.argv[1])))
	else:
		print(str(yc.yubi_check()))
