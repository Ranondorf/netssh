# netssh
Script for interrogating network devices very quickly via SSH (1000's of devices in minutes).

Key Features:

- Using a list of devices with associated commands, retrieve consolidated output
- Special feature allows for string searching across multiple devices
- Supports Cisco ASA, IOS, IOS-XE, IOS-XR, NX-OS; Netscaler and Linux
- Single thread or Multi-threaded mode (with option to choose the number of threads running)
- Allows running multiple commands against different device groups
- Output into single file or multiple files per device. Zipped files supported
- Authenticated and authenticated email supported via SMTP server
- Customizable script calls via CLI arguments and/or configuration file
- If using saved passwords (eg when used in conjunction with Crontab), they are stored encrypted.
- At this point in time, read only commands are supported on Cisco and Citrix devices.

Sample use cases:

- Need to find out if a particular piece of configuration appears on certain devices? Run the query against 100s of devices in seconds
- Need to backup configuration for some devices? schedule a cronjob to run the program to grab the config files, zip them and email them on a regular basis.

Requirements:

- Runs on UNIX/LiNUX based systems only. Only works on systems that use the "/" file seperator, i.e Windows not supported at this point in time.
- Python 3

## Installation
### Prequisites

- Relies on Python modules that can be installed via PIP (Netmiko being the main one). Python3 is required.
### Installing Program
Clone this GIT repo to a directory on the local machine. However when calling the script call it from a separate folder. Copy ouput, devices, commands and config files to the calling folder.

For example, setup like this

/....some path....../netssh/

/..some other path.../workding_dir/

Copy devices, commands and config files to the working_dir folder from script_input_files. Then call netssh from that working_dir folder.

## Credits
Ruwan Samaranayake
## License
Refer to license file in repository
