# netssh
Script for interrogating network devices via SSH very quickly (1000's of devices in minutes).

Key Features:
- Using a list of devices with associated commands, retrieve consolidated output
- Special feature allows for string searching across multiple devices
- Supports Cisco ASA, IOS, IOS-XE, IOS-XR, NX-OS; Netscaler and Linux
- Single thread or Multi-threaded mode
- Allows running multiple commands against different device groups
- Output into single file or multiple files per device. Zipped files supported
- Unauthenticated email of output supported via SMTP server
- Customizable script calls via CLI arguments and/or configuration file
- If using saved passwords (eg when used in conjunction with Crontab), they are stored encrypted.

Note: At this point in time, configuration commands are not supported. Only works on systems that use the "/" file seperator, i.e Windows not supported at this point in time.

## Installation
### Prequisites
- Relies on Python modules that can be installed via PIP (Netmiko being the main one). Python3 is required.
### Installing Program
Clone this GIT repo to a directory on the local machine. However when calling the script call it from a separate folder. Copy ouput, devices, commands and config files to the calling folder.
## Credits
Ruwan Samaranayake
## License
Refer to license file in repository
