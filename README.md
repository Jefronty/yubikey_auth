# yubikey_auth
Python wrapper to validate Yubico OTP athentication

## required package:
*[yubico_client](https://github.com/Kami/python-yubico-client)*: `pip install yubico-client`

## optional package:  
*[inputimeout](https://github.com/johejo/inputimeout)*: `pip install inputimeout`

yubi.py is the config file with the API credentials from [Yubico API request](https://upgrade.yubico.com/getapikey/) and the `known_devices` tuple

Yubikeys generate 44 character strings with the first 12 being consistant and unique to each Yubikey.  To limit which Yubikeys can be validated put the 12 character prefix into the `known_devices` tuple as a string

`known_devices = ('cccccccc0123', 'cccccccclike')`

This can be imported to other scripts or run independently with the ability to pass the Yubikey token string as an argument
