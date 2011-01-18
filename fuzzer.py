#!/usr/bin/env python
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.child import createChild
from ptrace.debugger import ProcessSignal
from signal import SIGABRT, SIGBUS, SIGCHLD, SIGFPE, SIGSEGV, SIGILL, SIGTERM, SIGQUIT, SIGUSR1, SIGUSR2, SIGIOT, SIGCLD
from ptrace.tools import locateProgram
from string import ascii_lowercase, ascii_uppercase
from sys import stderr, argv, exit
import socket
import re
from optparse import OptionParser
#Just learnt there's an option parser in Python, which will come in useful

#import string
supported = ['ftp'] #supported remote services

servicePorts = {'ftp':21}

#helps trying to determine where fault occurred
##Help from simple_dbg.py example that comes with python ptrace
#the libraries to import
def usage():
  bold = "\033[1m"
  reset = "\033[0;0m"
  print >>stderr, "usage: %s <options> <program to fuzz>" % argv[0]
  print >>stderr, "Note: the program specified needs to be the fully qualified address"
  print >>stderr, "e.g. /usr/bin/id"
  print >>stderr, "for more information %s -h" % argv[0]
  bold = "\033[1m"
  reset = "\033[0;0m"
  print bold + "The options are:" + reset
  print "-h\tprint help"
  print "-a, "
  print "Fuzz all program parameters a-z and A-Z, and the no flag option."
  print "-c, "
  print "Fuzz specific program arguments.\n\r\n\r"
  print bold + "The syntax for specifying arguments with -c is:" + reset
  print "The way to specify an argument with a single hyphen is with a single colon (:) and for an argument with 2 hyphens is with 2 colons (::). This allows for arguments with a hyphen in the flag. "
  print "An example is (using part of the man page for Nmap):"
  print "Nmap 5.00 ( http://nmap.org )"
  print "Usage: nmap [Scan Type(s)] [Options] {target specification}"
  print "TARGET SPECIFICATION:"
  print "  Can pass hostnames, IP addresses, networks, etc."
  print "  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254"
  print "  -iL <inputfilename>: Input from list of hosts/networks"
  print "  -iR <num hosts>: Choose random targets"
  print "  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks"
  print "  --excludefile <exclude_file>: Exclude list from file"
  print "..."
  print "  --dns-servers <serv1[,serv2],...>: Specify custom DNS servers\n\n"
  print "If you wanted to fuzz the parameters -iL, --exclude, --excludefile and --dns-servers, and the program Nmap is located at /usr/bin/nmap, then the command to fuzz would be "
  print bold + " %s -c :iL::exlude::excludefile::dns-servers /usr/bin/nmap" % argv[0]
  print reset
  print "If the no flag argument needs to be fuzzed (no options), for instance doing nmap fuzzedstring, then an  extra colon needs to be added to the end. So"
  print bold + "%s -c :iL::exlude::excludefile::dns-servers: /usr/bin/nmap" % argv[0]
  print reset
  exit(1)
  
def signal(signalVal, command):
  #print "SIGABRT:", SIGABRT, "SIGBUS:", SIGBUS, "SIGCHLD:", SIGCHLD, "SIGFPE:", SIGFPE, "SIGSEGV:", SIGSEGV
  if signalVal == SIGABRT:
    error =  "*****************************PROCESS WAS ABORTED*****************************\n"
    error+="Something went wrong, but unable to determine reasoning. Could be handled signal from program, or compiler of program may have stack-smashing protection. GCC3.4 and above have this (version can be determined by gcc -v)."
  elif signalVal == SIGIOT:
    error =  "*****************************PROCESS WAS ABORTED*****************************\n"
    error+="Something went wrong, but unable to determine reasoning. Could be handled signal from program, or compiler of program may have stack-smashing protection. GCC3.4 and above have this (version can be determined by gcc -v)."
  elif signalVal == SIGBUS:
    error = "*****************************PROCESS CREATED A BUS ERROR*****************************"
  elif signalVal == SIGCHLD:
    error = "*****************************CHILD PROCESS TERMINATED*****************************"
  elif signalVal == SIGCLD:
    error = "*****************************CHILD PROCESS TERMINATED*****************************"
  elif signalVal == SIGFPE:
    error =  "*****************************PROCESS DIVISION BY 0*****************************"
  elif signalVal == SIGSEGV:
    error =  "*****************************SEGMENTATION FAULT*****************************"
  elif signalVal == SIGILL:
    error =  "*****************************ILLEGAL INSTRUCTION*****************************"
  elif signalVal == SIGQUIT:
    error =  "*****************************PROGRAM QUIT (CORE DUMPED)*****************************"
  elif signalVal == SIGTERM:
    error = "*****************************PROGRAM TERMINATED*****************************"
  elif signalVal == SIGUSR1:
    error = "*****************************USER DEFINED SIGNAL CALLED*****************************"
  elif signalVal == SIGUSR2:
    error = "*****************************USER DEFINED SIGNAL CALLED*****************************"
  else:
    error =  "*********************** NO IDEA ******************************"
  vulnerableCommand = "Vulnerable command is: "
  for elem in command:
    vulnerableCommand = vulnerableCommand + elem + " "
  error = error + '\n' + vulnerableCommand + '\n'
  return error

def attack():
  #create fuzzed arguments
  #use list for amounts each different attack vector (upto 65535)
  #(saves time over incrementing)
  #if find anything, if want to take error, further will need to be done manually
  amount = [1,2,3	,4,5,10,25,50,75,100,250,500,750,1000,2000,3000,4000,5000,7500,10000,12500,15000,20000,25000]#,30000,50000,75000,10000,20000,30000,40000,50000,60000,65535]
  #effectively how many times each different element will be used to attack the program
  global attackChain
  attackChain = len(amount)

  #Need to test for buffer underflows + overflows, format string vulnerabilities, 
  #Heap overflows, integer under/overflow and directory traversal

  attacks = ['A', '%n', '%s']
  global fuzzString
  fuzzString = []
  for attackElement in attacks:
    for integer in amount:
      fuzzString.append(attackElement*integer)
  #so far buffer + heap under/overflows, and format string vulnerabilities covered
  for integer in range(attackChain):
    fuzzString.append('../'*integer+'etc/passwd')
  #directory traversal covered (as long as /etc/passwd is used)
  #very unlikely you would need to go back further than attackChain amount of directories
  #integerOverflow = [-65537, -65535, -1, 0, 100, 1000, 10000, 65535, 65536, 100000]
  #fuzz += integerOverflow
  #MAY NEED SEPARATE OPTION FOR NUMBERS, AS MAY BE INCOMPATIBLE!
  #checked still a list with isinstance(fuzz, list)
  #and 'not isinstance(fuzz, basestring)'

  return fuzzString
  
def fuzz(debugger, pid, is_attached, vulnerableCommand):
  #attach the recently created process to the debugger
  process = debugger.addProcess(pid, is_attached)
  #process.dumpRegs()
  process.cont()
  event = process.waitEvent()
  error = ''
  if (isinstance(event, ProcessSignal)):
    print "died with signal %i" % event.signum
    error = signal(event.signum, vulnerableCommand)
    print 'Register dump:'
    processDump = "%s" % process.dumpRegs()
    print processDump
    #process.dumpRegs()
    #error = error + processDump
  return error
  #else:
    #print vulnerableCommand
    #print event
    #fuzz(debugger, pid, is_attached, vulnerableCommand)
  #print "New process event: %s" % event
  #signal = process.waitSignals(SIGABRT)
  #print "New signal: %s:" % signal
  
  
def genFuzzOpts():
  #Create a list a-z and A-Z for looping through
  insensitiveAlphabet = []
  #Extra non-flag option needed
  insensitiveAlphabet.append("")
  for letter in ascii_lowercase:
    #Put a dash at the start of each option (for running the process)
    option = '-' + letter
    insensitiveAlphabet.append(option)
  #del(insensitiveAlphabet[3])
  for letter in ascii_uppercase:
    option = '-' + letter
    insensitiveAlphabet.append(option)
  return insensitiveAlphabet

def genFuzzOpts2(flags):
  optionsList = []
  #change from form :a:b:c::d to -a, -b, -c, --d etc
  #option used for better accuracy
  options = flags.split(':')
  print options
  #needs : at start, so make sure options[0] is blank
  if options[0]!='':
    usage()
    exit(1)
  #check for : at end (the no flag option)
  if options[len(options)-1] == '':
    optionsList.append('')
  #for going from options[1] upto the 2nd to last element
  argument = ''
  for optPart in range(1, len(options)-1):
    if options[optPart] == '':
      argument+='-'
    else:
      argument+='-' + options[optPart]
      optionsList.append(argument)
      argument = ''
  #if 1 option only
  if len(options)==2:
    if options[1]!='':#if it isn't just -c : but e.g. -c :a
      argument+= '-'+options[1]
      optionsList.append(argument)
  #print optionsList
  #exit(1)
  return optionsList

def procFork(arguments):
  #try:
  #copy environment variables
  env = None
  arguments[0] = locateProgram(arguments[0])
  #print 'child not created yet'
  #print arguments
  #to stop there being 2 arguments for the no argument case
  if arguments[1] == "":
    del(arguments[1])
  child = createChild(arguments, False, env)
  return child
  #except:
    #print 'problem creating child'

#Fuzz the program
def fuzzProg(arguments, program):
  is_attached = False
  #create the debugger

  dbg = PtraceDebugger()
  #create list to fuzz the argument
  fuzzed = attack()
  
  index = 0
  filename = 'ErrorsIn' + program
  file = open(filename, 'w')

  #for fuzzing each argument in turn
  for arg in arguments:
    for fuzzedArg in fuzzed:
      toFuzz = [program, arg, fuzzedArg]
      pid = procFork(toFuzz)
      #print 'PID is: ', pid
      is_attached = True
      #print toFuzz
      error = fuzz(dbg, pid, is_attached, toFuzz)
      #if there's an error, print it to file
      if error != '':
        print error
        file.write(error)
  #make sure to close file after fuzzed
  file.close()
  #Quit the debugger after fuzzing everything  
  dbg.quit()

def getHistory(cmd, index, fuzz): #fetches the last 10 
  history = [fuzz[index-1]]
  for num in range(2, 12):
    if index-num < 0:
      break
    history.append(cmd + fuzz[index-num])
  return history

def fuzzFTP(ip='127.0.0.1', port=21, username='ftpuser', password='ftpuser', connected=False):
  global fuzz
  fuzz = attack()
  fuzz.insert(0, ' ') #insert the blank argument at the start
  filename = 'ftpFuzzResultsFor'+ip
  file = open(filename, 'w')
  file.write('---------------------FTP fuzzing results for host ' + ip + '---------------------\r\n')
  commandList = ['ABOR', 'CWD', 'DELE', 'LIST', 'MDTM', 'MKD', 'NLST', 'PASS', 'PASV', 'PORT', 'PWD', 'QUIT', 'RETR', 'RMD', 'RNFR', 'RNTO', 'SITE', 'SIZE', 'STOR', 'TYPE', 'USER', 'APPE', 'CDUP', 'HELP', 'MODE', 'NOOP', 'STAT', 'STOU', 'STRU', 'SYST']
  
  #correctResponse = {
  
  #  'ABOR': , 'CWD': , 'DELE': , 'LIST': , 'MDTM': , 'MKD': , 
  #  'NLST': , 'PASS': , 'PASV': , 'PORT': , 'PWD': , 'QUIT': , 
  #  'RETR': , 'RMD': , 'RNFR': , 'RNTO': , 'SITE': , 'SIZE': , 
  #  'STOR': , 'TYPE': , 'USER': , 'APPE': ['150', '501'] , 'CDUP': , 'HELP': , 
  #  'MODE': , 'NOOP': , 'STAT': , 'STOU': , 'STRU': , 'SYST': 
  #}

  #peter@peter-desktop:~$ nc -nv 192.168.1.78 21
  #Connection to 192.168.1.78 21 port [tcp/*] succeeded!
  #220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------
  #220-You are user number 1 of 50 allowed.
  #220-Local time is now 17:51. Server port: 21.
  #220-This is a private system - No anonymous login
  #220-IPv6 connections are also welcome on this server.
  #220 You will be disconnected after 15 minutes of inactivity.
  #USER ftpuser
  #331 User ftpuser OK. Password required
  #PASS password
  #230-User ftpuser has group access to:  1001      
  #230 OK. Current directory is /
  #APPE
  #501 No file name
  #?
  #500 ?
  #HELP
  #214-The following SITE commands are recognized
  #ALIAS
  #CHMOD
  #IDLE
  #UTIME
  #214 Pure-FTPd - http://pureftpd.org/
  #ABOR
  #226 Since you see this ABOR must've succeeded
  #REIN
  #500 Unknown command
  #CWD
  #250 OK. Current directory is /
  #MDTM
  #501 Missing argument
  #MDTM passwd
  #213 20110112174746
  #NLST
  #425 No data connection
  #PWD
  #257 "/" is your current location
  #RETR
  #501 No file name
  #RETR passwd
  #425 No data connection
  #RMD
  #550 No directory name
  #RNFR
  #550 No file name
  #RNFR passwd
  #350 RNFR accepted - file exists, ready for destination
  #RNTO .
  #451 Rename/move failure: Device or resource busy
  #SITE
  #500 SITE: Missing argument
  #HELP
  #214-The following SITE commands are recognized
  #  ALIAS
  #  CHMOD
  #  IDLE
  #  UTIME
  #214 Pure-FTPd - http://pureftpd.org/
  #SITE ALIAS
  #214-The following aliases are available :
  #214  
  #SITE CHMOD
  #501 Missing argument
  #SITE CHMOD passwd
  #550 No file name
  #SITE IDLE
  #501 SITE IDLE: Missing argument
  #SITE IDLE passwd
  #501 Garbage found after value : passwd
  #SITE SIZE
  #500 SITE SIZE is an unknown extension
  #SITE UTIME
  #501 No file name
  #SITE UTIME passwd
  #501 Missing argument
  #SIZE
  #501 Missing argument
  #SIZE passwd
  #213 1758
  #STOR
  #501 No file name
  #STOR passwd
  #553 Can't open that file: Permission denied
  #TYPE
  #501-Missing argument
  #501-A(scii) I(mage) L(ocal)
  #501 TYPE is now ASCII
  #TYPE A
  #200 TYPE is now ASCII
  #TYPE I
  #200 TYPE is now 8-bit binary
  #TYPE L
  #200-Missing argument
  #200 TYPE is now 8-bit binary
  #TYPE AAAAAAAAA
  #200 TYPE is now ASCII
  #TYPE A
  #200 TYPE is now ASCII
  #USER
  #530 You're already logged in
  #APPE
  #501 No file name
  #APPE passwd
  #553 Can't open that file: Permission denied
  #CDUP 
  #250 OK. Current directory is /
  #MODE
  #501 Missing argument
  #HELP MODE
  #214-The following SITE commands are recognized
  #  ALIAS
  #  CHMOD
  #  IDLE
  #  UTIME
  #214 Pure-FTPd - http://pureftpd.org/
  #MODE HELP
  #504 Please use S(tream) mode
  #500 ?
  #S
  #500 Unknown command
  #MODE S
  #200 S OK
  #500 ?
  #LIST
  #425 No data connection
  #NOOP
  #200 Zzz...
  #STAT
  #211 http://www.pureftpd.org/
  #STOU
  #425-FILE: pureftpd.4d2deb2e.b2.0000
  #425 No data connection
  #STRU
  #501 Missing argument
  #STRU passwd 
  #504 Only F(ile) is supported
  #STRU F
  #200 F OK
  #SYST
  #215 UNIX Type: L8
  #EXIT
  #500 Unknown command
  #QUIT									     
  #221-Goodbye. You uploaded 0 and downloaded 0 kbytes.                      
  #221 Logout.								     
  #############################################################################################

  #fuzz authentication
  for string in fuzz:
    for num in range(1, 3): #2 different loops, for fuzzing username & password separately
      print "Fuzzing username & password with string:" + string
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      if sock==-1:
        print "Socket creation failure"
        exit(1)
      try:
        connection = sock.connect((ip, port))
      except socket.error:
        print 'Problem connecting to host. Make sure host alive & service running on specified port'
        exit(1)
      answer = sock.recv(1024)
      if answer[0:3]!='220':
        print "Something wrong, not connected!"
        print "Exiting..."
        exit(1)
      if num % 2 == 1: #need to fuzz username, and then use real username to fuzz password
        user = string
      else:
        user = username
      sock.send('USER ' + user + '\r\n') #fuzz username
      answer = sock.recv(1024)
      if num % 2 == 1: #just fuzzing USER + want to loop again instead of trying PASS
        continue
      sock.send('PASS ' + string + '\r\n') #Fuzz password
      answer = sock.recv(1024)
      if answer[0:3]=='230':
        print "Password accepted! This shouldn't happen unless the user specified has a password consisting of a series of A's or a number. This will be counted as an error."
      history = getHistory('PASS', fuzz.index(string), fuzz)
      file.write('Server crashed after:\r\n')
      for sentCommand in range(len(history)):
        file.write(history[sentCommand] + '\r\n')
      sock.close()

  sock2 = None #may be needed later
  #Need nested for loop in order to fuzz each command easily.
  for cmd in commandList:
    for string in fuzz:
      print "Fuzzing", cmd, "with string:" + string
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      if sock==-1:
        print "Socket creation failure"
        exit(1)
      try:
        try:
          connection = sock.connect((ip, port))
        except socket.error:
          print 'Problem connecting to host. Make sure host alive & service running on specified port'
          exit(1)
        answer = sock.recv(1024)
        if answer[0:3]!='220':
          print "Something wrong, not connected!"
          print "Exiting..."
          exit(1)
        sock.send('USER ' + username + '\r\n')
        sock.recv(1024)
        sock.send('PASS ' + password + '\r\n')
        answer = sock.recv(1024)
        temp = False #used for infinite loop in a few lines
        if answer[0:3]=='530':
          print 'User not accepted! Wrong username or password.'
          exit(1)
        while(True): #if returned code needs PASV or PORT
          sock.send(cmd + ' ' + string + '\r\n') #evil buffer
          answer = sock.recv(1024)
          if cmd=='HELP' and fuzz.index(string)==0: #HELP on its own shows the available SITE commands. These also need to be fuzzed.
            temp = answer.split('\r\n')[1:-2] #get the additional site commands 
            #enter the additional site commands into the array in form 'SITE <command>'
            index = fuzz.index[cmd]+1 #get the index to insert them in (next index)
            for command in temp:
              fuzz.insert(index, 'SITE ' + command) #each command is a SITE command
          connectionModeAttempts = 0
          for x in range(2): 
            if answer[0:3]=='425':#Needs to either change, or nothing open anyway
              if connectionModeAttempts==0:
                sock.send('PORT\r\n')
                connectionModeAttempts+=1
              elif connectionModeAttempts==1:
                connectionModeAttempts+=1
                sock.send('PASV\r\n')
                try:
                  sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                  answer = sock2.recv(1024)
                  if answer[0:3]=='227':#passive mode is allowed
                    match = re.search(r'(\,\d+)+', answer) #Obtaining the numbers to calculate the port
                    (temp1, temp2) = match.group().split(',')[-2:] 
                    port = int(temp1)*256 + int(temp2) #calculating the port to connect to
                    sock2.connect((ip, port))
                except sock2.error
                  print "Passive mode socket creation failure"
                  exit(1)
            if (sock2): #if using passive mode, check this channel too
              answer2 = sock2.recv(1024)
              sentCommand = cmd + ' ' + string
              if answer2[0:3] not in correctResponse[cmd]:
                writeError(file, sentCommand, 'There appears to be an error with', answer)
            if answer[0:3] not in correctResponse[cmd]: #not a correct response as per dictionary
              writeError(file, sentCommand, 'There appears to be an error with', answer)
          if connectionModeAttempts>=2:
            break
        sock.send('QUIT\r\n')
        sock.close()
      except sock.error:
        print 'Problem occurred. Service may be down.'
        history = getHistory(cmd, fuzz.index(string), fuzz)
        file.write('Server crashed after:\r\n')
        for sentCommand in range(len(history)):
          file.write(history[sentCommand] + '\r\n')
        sock.close()
  

def fuzzPOP(ip='127.0.0.1', port=21, username='ftpuser', password='ftpuser', connected=False):
  global fuzz
  fuzz = attack()
  filename = 'POP3fuzzResultsFor'+ip
  file = open(filename, 'w')
  fuzzedCommands = ['USER', 'PASS', 'LIST', 'STAT', 'RETR', 'DELE', 'NOOP', 'RSET', 'UPDATE', 'TOP', 'UIDL', 'APOP'] #more to follow
  #3 stages of fuzzing POP3 - fuzz username, password, and then every command while authenticated
  variableList = ['', '', ''] # for holding different fuzzes between username, password + a command to fuzz when authenticated
  try:
    for variableToFuzz in range(len(fuzzedCommands)):
      #first if is 1, since @ variablToFuzz==0, the USER command will be fuzzed
      if variableToFuzz == 1: #Need username in order to fuzz password
        variableList[0] = username
      elif variableToFuzz > 1:
        variableList[1] = password #variableList[0] already the correct username
    
      #for element in variableList:
      for fuzzElem in range(len(fuzz)):
        try:
          sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          sock.connect((ip, port)) #create socket & connect to pop3 server
        except:
          sock.error:
        if variableToFuzz[0]==username:
          sock.send('USER ' + username)
          answer = sock.recv(1024)
          if answer[:1]=='-':
            print 'Error with username ' + username
            exit(1)
        if variableToFuzz[1]==password:
          sock.send('PASS ' + password)
          answer = sock.recv(1024)
          if answer[:1]=='-':
            print 'Error with password ' + password
            exit(1)
        #Now need to do fuzzing
        sentCommand = fuzzedCommands(variableToFuzz) + ' ' + fuzz(fuzzElem)
        sock.send(sentCommand)
        answer = sock.recv(1024)
        if fuzzedCommands(variableToFuzz)=='RSET' or fuzzedCommands(variableToFuzz)=='NOOP':
          if answer[:1]=='-':
            writeError(file, sentCommand, 'There was an error')
        if answer[:1]=='+':
          writeError(file, sentCommand, 'There seems to be an error')
  except sock.error:
    print 'Problem occurred. Service may be down.'
    history = getHistory(cmd, fuzz.index(string), fuzz)
    file.write('Server crashed after:\r\n')
    for sentCommand in range(len(history)):
      file.write(history[sentCommand] + '\r\n')

  file.close()
  sock.close()

def writeError(file, command, Error='There was an error', wrongReturn=''):
  #this will write an error to stdout & a file
  file.write(Error + ' ' + command)
  print Error + ' ' + command
  if wrongReturn!='':
    file.write('The answer given was: ' + wrongReturn)
    print 'The answer given was: ' + wrongReturn

def main():
  params = len(argv)
  flags = None
  defaultUsage = 'usage: %prog [options] [program] [service (server fuzzer only)]\nSupported Remotes Services: '
  #-------------OPTIONS NEEDED-------------
  #user, password, file (with read/write access if possible), option for hanging until reset
  global supported
  for service in supported:
    defaultUsage+=service+' ' #for easier updating supported services, just need to update global list
  defaultUsage+="\nPlease ust full path for service, not starting script"
  parser = OptionParser(usage=defaultUsage)
  # parser.add_option("-h", action="callback", callback=usage)
  parser.add_option("-a", "--all", action="store_true", dest="all", help="Command line fuzzer, fuzzes all program parameters a-z and A-Z, and the no flag option.")
  parser.add_option("-p", "--port", type="int", dest="port", help="Port for server (if not default for service)")
  parser.add_option("-t", "--target", action="store", type="string", dest="ip", help="Target IP address")
  parser.add_option("-u", "--username", action="store", type="string", dest="username", help="Username for logging on server, enabling full fuzzing")
  parser.add_option("-w", "--password", action="store", type="string", dest="password", help="Password for logging onto server, enabling full fuzzing")
  parser.add_option("-c", action="store", type="string", dest="flags", help="Command line fuzzer, fuzzes specific program arguments.\n\r\n\rThe syntax for specifying arguments with -c is:\nThe way to specify an argument with a single hyphen is with a single colon (:) and for an argument with 2 hyphens is with 2 colons (::). This allows for arguments with a hyphen in the flag.\nAn example is (using part of the man page for Nmap):\nNmap 5.00 ( http://nmap.org )\nUsage: nmap [Scan Type(s)] [Options] {target specification}\nTARGET SPECIFICATION:\n  Can pass hostnames, IP addresses, networks, etc.\n  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254\n  -iL <inputfilename>: Input from list of hosts/networks\n  -iR <num hosts>: Choose random targets\n  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks\n  --excludefile <exclude_file>: Exclude list from file\n...\n  --dns-servers <serv1[,serv2],...>: Specify custom DNS servers\n\nIf you wanted to fuzz the parameters -iL, --exclude, --excludefile and --dns-servers, and the program Nmap is located at /usr/bin/nmap, then the command to fuzz would be \n%s -c :iL::exlude::excludefile::dns-servers /usr/bin/nmap\nIf the no flag argument needs to be fuzzed (no options), for instance doing nmap fuzzedstring, then an  extra colon needs to be added to the end. So %s -c :iL::exlude::excludefile::dns-servers: /usr/bin/nmap" % (argv[0], argv[0]))
  (options, args) = parser.parse_args()
  #try:
  if (options.all):
  #command line argument fuzzer with all simple arguments
    arguments = genFuzzOpts()
    fuzzProg(arguments, argv[params-1])
  #command line argument fuzzer with specific flags
  if (options.flags):
    arguments = genFuzzOpts2(options.flags)
    fuzzProg(arguments, argv[params-1])
  #remoteService = params-1  
  #if argv[params-1] not in supported:
  #    usage()
  #  if not (options.port):
  #    port = servicesPorts[argv[params-1]
  #      usage()
  #      exit(1)
  #    arguments = genFuzzOpts2(argv[2])
  #    fuzzProg(arguments, argv[params-1])	
  #else:
  #  usage()
  #  exit(1)
  #except:
  #invalid option
  #moreHelp()

if __name__=='__main__':
  main()

