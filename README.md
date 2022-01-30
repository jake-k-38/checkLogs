# checkLogs
Python script to scan log files/system for unauthorized access around Linux systems
## Table of contents
* [General info](#general-info)
* [Getting started](#getting-started)
* [Usage](#usage)

## General info
The script will quickly scan over log files in /var/log to find any attempts of unauthorized access on system. Add custom strings to flags, SecurityLog, and SecurityLogFolder to customize the script to your specific environment. See example below:
```
def isSecurityLog(name): #Add any log files you want to check, make sure the keyword flag is set for specific log format
    if 'httpd-access.log' in name:
        return True
    --etc...
    elif 'access.log' in name:
        return True
    else:
        return False
```
```
def isSecurityLogFolder(name): #Add any log folders you want to check, make sure the keyword flag is set for specific log format
    if 'netstat' in name:
        return True
    elif 'apache2' in name: #you can scan access logs
        return True
    elif 'httpd' in name: #you can scan access logs
        return True
    else:
        return False
```
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
