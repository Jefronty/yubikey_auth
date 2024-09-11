# yubikey_auth
Python wrapper to validate Yubikey athentication

required package:
#yubico_client#: `pip install yubico-client`

optional package:
#inputimeout#: `pip install iniputimeout`

yubi.py is the config file with the API credentials from [Yubico API request](https://upgrade.yubico.com/getapikey/) and the `known_devices` tuple

Yubikeys generate 44 character strings with the first 12 being consistant and unique to each Yubikey.  To limit which Yubikeys can be validated put the 12 character prefix into the `known_devices` tuple as a string

`known_devices = ('cccccccc0123', 'cccccccclike')`
