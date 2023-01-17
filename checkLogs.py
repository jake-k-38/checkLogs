#!/usr/bin/python3
#!/usr/bin/python
import os
import re
import datetime

# keywords that can indicate unauthorized access around system
flags = ['Failed password for',                  # SSH failed login
         'incorrect password attempts',  # Sudo failed attempts
         'authentication failure',        # vsFTP failed attempt
         'Access denied for user',
         ]

# extension names for compressed log file to avoid
fileexts = ['.tar.gz', '.bz2', '.zip', '.gz']

#Max failed login attempts before script flags IP
maxFails = 15

#Show raw output of any suspicious log item found
rawOutput = False

logfile = []
logFolders = []
info = []
sudoFailed = []
rawLoginAttempts = []
attemptedLoginIPS = []

now = datetime.datetime.now()

def isSecurityLog(name): #Add any log files you want to check, make sure the keyword flag is set for specific log format
    if 'secure' in name:
        return True
    elif 'auth.log' in name:
        return True
    elif 'messages' in name:
        return True
    elif 'syslog' in name:
        return True
    elif 'faillog' in name:
        return True
    elif 'journal' in name:
        return True
    elif 'vsftpd.log' in name:
        return True
    elif 'mysql.log' in name:
        return True
    elif 'xferlog' in name:
        return True
    elif 'error.log' in name:
        return True
    else:
        return False

def check_extension(name): #Make sure the log files are not compressed
    for ext in fileexts:
        if name.endswith(ext):
            return False
    return True

def bordered(text):
    lines = text.splitlines()
    width = max(len(s) for s in lines)
    res = ['┌' + '─' * width + '┐']
    for s in lines:
        res.append('│' + (s + ' ' * width)[:width] + '│')
    res.append('└' + '─' * width + '┘')
    return '\n'.join(res)

def main():
  print('Starting scan @: ' + now.strftime('%Y-%m-%d %H:%M:%S'))
  print('')
  print('')
  print('')
  print('Scanning through these log files: ')
  print('')

  for file in os.listdir('/var/log'): #default log directory
      logfiledir = os.path.join('/var/log', file)
      if check_extension(logfiledir) and (not os.path.isdir(logfiledir)) and (not '-' in logfiledir): #filter out 'old' logs/dirs
          if isSecurityLog(logfiledir):
              logfile.append(logfiledir)
              print(logfiledir)

  print('')
  print('*******************************')
  print('')

  for logs in logfile: #loop through logfile list /var/log
      info = []
      print(bordered('Now Scanning.... ' + logs))
      print('')
      with open(logs) as x: #make a loop through all directories
          x = x.readlines()
          for line in x:  # find keywords in the var logs aka log file that can indicate attacks
              for key in flags:
                  if key in line:
                      info.append(line)  # store into an array for further analysis
                      break

      rawLoginAttempts = []
      attemptedLoginIPS = []
      sudoFailed = []
      findIP = ''
      # filter out logs example: sshd/sudo attempts
      for x in info:  # loop through the keywords found and filter out ips
          if 'sudo' in x:
              if x in sudoFailed:
                  continue
          sudoFailed.append(x)
          rawLoginAttempts.append(x)
          findIP = re.findall(r'[0-9]+(?:\.[0-9]+){3}', x)
          if findIP in attemptedLoginIPS or not (findIP):  # don't add two entries of ips
              continue
          attemptedLoginIPS.append(findIP)  # add ip into list

      if rawOutput:
        print('Raw data: ')
        print('')
        for x in rawLoginAttempts:
            print(x)
        print('')

      print('Total suspicious event(s): ', len(rawLoginAttempts))
      print('Attempted Login IPS: ', attemptedLoginIPS)
      print('')
      if len(rawLoginAttempts) > maxFails: #can be removed if using crontab to autorun
          print('Execute these iptables rules as sudo if under attack from the IP(s):\n')
          print('Run this to check current rules: iptables -L INPUT --line-numbers\n')
          for i in attemptedLoginIPS:
              print('sudo iptables -A INPUT -s', str(i)[2:-2], '-j DROP') #[2:-2] removes the brackets []
              #print('sudo ufw deny from', str(i)[2:-2]) #uncomment if using UFW
          print('')
  print('Finished @' + ' ' + now.strftime('%Y-%m-%d %H:%M:%S'))

if __name__ == "__main__":
  main()
