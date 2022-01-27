# checkLogs
Python script to scan log files/system for unauthorized access around Linux systems
## Table of contents
* [General info](#general-info)
* [Getting started](#getting-started)
* [Usage](#usage)

## General info
The script will quickly scan over log files in /var/log to find any attempts of unauthorized access on system. Add custom flags or SecurityLog names to customize the script to your specific environment
## Getting started
To run this project, extract it to the /opt folder, allow executable permission then run it as sudo<br />
```
sudo chmod 755 checkLogs.py
```
Keep in mind that the script can be automated with crontab :)

## Usage
Simply just run the script checkLogs.py

```
sudo ./checkLogs.py
```

## Notes

I made this script as a class project in security python class as a blue team tool that can be used to help identify unauthorized access around the system.
