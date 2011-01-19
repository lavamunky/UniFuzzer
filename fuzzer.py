#!/usr/bin/env python
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.child import createChild
from ptrace.debugger import ProcessSignal
from signal import SIGABRT, SIGBUS, SIGCHLD, SIGFPE, SIGSEGV, SIGILL, SIGTERM, SIGQUIT, SIGUSR1, SIGUSR2, SIGIOT, SIGCLD
from ptrace.tools import locateProgram
from string import ascii_lowercase, ascii_uppercase
from sys import stderr, argv, exit
from xml.etree import ElementTree
import socket
import types
import re
from optparse import OptionParser
#Just learnt there's an option parser in Python, which will come in useful

#import string
supported = ['ftp', 'pop3'] #supported remote services

servicePorts = {'ftp':21, 'pop3':110}

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
    error+="Something went wrong, but unable to determine reasoning. Could be handled signal from program, or compiler of program may have stack-smashing protection. GCC3.4 and above have this (version can be determined by gcc -v).\n"
  elif signalVal == SIGIOT:
    error =  "*****************************PROCESS WAS ABORTED*****************************\n"
    error+="Something went wrong, but unable to determine reasoning. Could be handled signal from program, or compiler of program may have stack-smashing protection. GCC3.4 and above have this (version can be determined by gcc -v).\n"
  elif signalVal == SIGBUS:
    error = "*****************************PROCESS CREATED A BUS ERROR*****************************\n"
  elif signalVal == SIGCHLD:
    error = "*****************************CHILD PROCESS TERMINATED*****************************\n"
    error += "This could be a serious error with the child. Further investigation with a fully featured debugger to determine problem with child process.\n"
  elif signalVal == SIGCLD:
    error = "*****************************CHILD PROCESS TERMINATED*****************************\n"
  elif signalVal == SIGFPE:
    error =  "*****************************PROCESS DIVISION BY 0*****************************\n"
    error += "This could possibly be a case where there was no argument given when expecting one, or possibly a integer underflow/overflow.\n"
  elif signalVal == SIGSEGV:
    error =  "*****************************SEGMENTATION FAULT*****************************\n"
    error += "A standard buffer overflow causes a segmentation fault. However, many other problems can also cause a segmentation fault, such as integer underflow/overflow, heap overflow and format string vulnerabilities.\n"
  elif signalVal == SIGILL:
    error =  "*****************************ILLEGAL INSTRUCTION*****************************\n"
    error += "This could mean that a buffer overflow is imminent and the Instruction Pointer (points to the next instruction in the program) has been overwritten or partially overwritten. This could also be caused by other vulnerabilities, such as a format string vulnerability.\n "
  elif signalVal == SIGQUIT:
    error =  "*****************************PROGRAM QUIT (CORE DUMPED)*****************************\n"
    error += "Not able to determine the error. Could be partly a operating system problem, or a partial instruction pointer overwrite lead the program to run other code which caused the core dump. Investigation of problem needed.\n"
  elif signalVal == SIGTERM:
    error = "*****************************PROGRAM TERMINATED*****************************\n"
    error += "The program terminated. This could be caused by many vulnerabilities. The program may have handled the exception and then quit. Further investigation into the problem needed.\n"
  elif signalVal == SIGUSR1:
    error = "*****************************USER DEFINED SIGNAL CALLED*****************************\n"
    error += "This is a user defined signal. Further investigation into problem needed.\n"
  elif signalVal == SIGUSR2:
    error = "*****************************USER DEFINED SIGNAL CALLED*****************************\n"
    error += "This is a user defined signal. Further investigation into problem needed.\n"
  else:
    error =  "*********************** ERROR CALLED BUT CANNOT DETERMINE ******************************\n"
    error += "This is a user defined signal. Further investigation into problem needed.\n"

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
  #amount = [2650]
  amount = range(0, 3000, 50) 
  #amount = [1,2,3,4,5,10,25,50,75,100,250,500,750,1000,2000,2500, 3000, 3500,4000, 4500,5000,5500,7500,10000,12500,15000,20000,25000]  #,30000,50000,75000,10000,20000,30000,40000,50000,60000,65535]
  #line above could be automated with a lot more values, but I think it runs out of memory with large values (possibly because of string manipulation calculations done later), meaning that I have to have balance between the amount of sizes and range of values
  #effectively how many times each different element will be used to attack the program
  global attackChain
  attackChain = len(amount)

  #Need to test for buffer underflows + overflows, format string vulnerabilities, 
  #Heap overflows, integer under/overflow and directory traversal

  attacks = ['X', '%n', '%s']
  global fuzzString
  fuzzString = []
  for attackElement in attacks:
    for integer in amount:
      fuzzString.append(attackElement*integer)
  #so far buffer + heap under/overflows, and format string vulnerabilities covered
  for integer in range(attackChain):
    for dirTraverse in ['../', '..\\']: #doesn't often matter, but just in case
      for file in ['etc/passwd', 'boot.ini', '']: #note boot.ini will not work on newer versions of windows
        #last '' for use with just changing directory.
        directory=dirTraverse*integer+file
        fuzzString.append(directory)
        fuzzString.append('/'+directory) #leading / has lead to directory traversals in the past
        fuzzString.append('\\'+directory)
  #directory traversal covered (as long as /etc/passwd is used)
  #very unlikely you would need to go back further than attackChain amount of directories
  #----------------------------MAKE SURE TO UNCOMMENT LINE AFTER!!!!---------------
  integerOverflow = [-65536, -1, 0, 1, 65536]
  #integerOverflow = range(-80000, 80000)
  #many integer overflows are specific numbers, not necessarily numbers I would pick if making it manually.
  #integers in arrays don't seem to have the same problem as strings in terms of length in arrays.
  #integerOverflow = [-65537, -65535, -1, 0, 100, 1000, 10000, 65535, 65536, 100000]
  #fuzzString+=integerOverflow
  for number in integerOverflow:
    fuzzString.append(str(number))
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
    print 'Register dump:\n'
    processInfo = "%s" % process.dumpRegs()
    error += processInfo
    print processInfo
    print 'Stack:\n'
    processInfo = "%s" % process.dumpStack() #display some memory words around the stack pointer
    error += processInfo
    print processInfo
    print 'Memory mappings:\n'
    processInfo = "%s" % process.dumpMaps()#display memory mappings
    error += processInfo
    print processInfo
    #process.dumpRegs()
    #error = error + processDump
  
  else:
    process.terminate(False)
    #print vulnerableCommand
    #print event
    #fuzz(debugger, pid, is_attached, vulnerableCommand)
  #print "New process event: %s" % event
  #signal = process.waitSignals(SIGABRT)
  #print "New signal: %s:" % signal
  return error
  
  
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
  #False shows stdout & stderr - could be changed, not sure if would affect program outputting memory dump etc
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
  fileProgName = program
  slashes = program.rfind('/') #if the user has put in the full program path
  if slashes!=-1:
    fileProgName = program[slashes+1:]
  filename = 'ErrorsIn' + fileProgName
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
    history.append(cmd + ' ' + fuzz[index-num])
  return history

def fuzzFTPmain(ip, port, username, password, toAttach, pid):
  is_attached = False
  if toAttach:
    if int(pid)>=0:
      #valid PID, so create debugger & attach it
      dbg=PtraceDebugger()
      process = dbg.addProcess(pid, is_attached)
      is_attached = True
      process.cont()
      event = process.waitEvent() #not sure about should use this considering calling another method, or whether should be here or not
      actualFTPfuzz(True, username, password, port, ip)
      actualFTPfuzz(False, username, password, port, ip)
      error = ''
      if (isinstance(event, ProcessSignal)):
        filename = 'ftpFuzzResultsFor'+ip
        file = open(filename, 'w')
        file.write('Error Found:\n')
        file.write(error)
        print "died with signal %i" % event.signum
        error = signal(event.signum, vulnerableCommand)
        print 'Next instruction:\n'
        processInfo = "%s" % process.dumpCore(filename) #display next instruction
        file.write('Next instruction:\n')
        file.write(processInfo)
        print processInfo
        print 'Register dump:\n'
        processInfo = "%s" % process.dumpRegs()
        file.write('Register dump:\n')
        file.write(processInfo)
        print processInfo
        print 'Stack:\n'
        processInfo = "%s" % process.dumpStack() #display some memory words around the stack pointer
        file.write('Stack:\n')
        file.write(processInfo)
        print processInfo
        print 'Memory mappings:\n'
        processInfo = "%s" % process.dumpMaps()#display memory mappings
        file.write('Memory Mappings:\n')
        file.write(processInfo)
        print processInfo
        file.close()
      return error
      #else:
        #print vulnerableCommand
        #print event
        #fuzz(debugger, pid, is_attached, vulnerableCommand)
    else:
      print 'If connecting a server, need a valid PID, otherwise set 4th arguments to False'
      exit(1)
  else: #not attaching
    actualFTPfuzz(True, username, password, port, ip)
    actualFTPfuzz(False, username, password, port, ip)

def actualFTPfuzz(justAuthentication, username, password, port, ip):
  global fuzz
  fuzz = attack()
  fuzz.insert(0, ' ') #insert the blank argument at the start
  filename = 'ftpFuzzResultsFor'+ip
  file = open(filename, 'w')
  file.write('---------------------FTP fuzzing results for host ' + ip + '---------------------\r\n')
  commandList = ['SITE EXEC', 'SITE INDEX', 'SITE UMASK', 'SITE IDLE', 'SITE CHMOD', 'SITE HELP', 'SITE NEWER', 'SITE MINFO', 'SITE GROUP', 'SITE GPASS', 'APPE', 'CWD', 'DELE', 'LIST', 'MDTM', 'NLST', 'PASV', 'PORT', 'PWD', 'RETR', 'RMD', 'RNFR', 'RNTO', 'SITE', 'SIZE', 'STOR', 'TYPE', 'CDUP', 'MODE', 'NOOP', 'STAT', 'STOU', 'STRU', 'SYST', 'ACCT', 'ADAT', 'ALLO', 'AUTH', 'CONF', 'LANG', 'MIC', 'MLSD', 'MLST', 'REIN', 'REST', 'RNTO', 'SMNT', 'MKD', 'HELP']
  
  correctResponse = {
  #Replies from the server we don't care about. From RFC959 (unless specified).
    'CWD': ['500', '501', '550'], 
    'DELE': ['450', '550'], 
    'LIST': ['125', '150', '226', '250', '450', '500', '501'], 
    'MDTM': ['550', '500', '501', '213'], #RFC3659
    'MKD': ['257', '500', '501', '550', '450'], 
    'NLST': ['125', '150', '226', '250', '425', '426', '451', '450', '500', '501'], 
    'PASS': ['530', '332'], 
    'PASV': ['227', '500', '501'], 
    'PORT': ['200', '500', '501'], 
    'PWD': ['500', '501', '502', '257'], 
    'RETR': ['226', '250', '425', '426', '451', '450', '550', '500', '501'], 
    'RMD': ['500', '501', '550'], 
    'RNFR': ['450', '550', '500', '501', '350'], 
    'RNTO': ['250', '532', '553', '500', '501'], 
    'SITE': ['200', '500', '501'], 
    'SIZE': ['550', '500', '501'], #RFC3659
    'STOR': ['425', '532', '450', '452', '553', '500', '501'], 
    'TYPE': ['200', '500', '501', '504'], 
    'USER': ['530', '331', '332'], 
    'APPE': ['150', '501', '550', '425'] , 
    'CDUP': ['200', '500', '501', '550', '250 CWD command successful. "/" is current directory'], 
    'HELP': ['211', '214', '500', '501', '502'], 
    'MODE': ['200', '500', '501', '504'], 
    'NOOP': ['200', '500'], 
    'STAT': ['211', '212', '213', '450', '500', '501'], 
    'STOU': ['425', '532', '450', '452', '553', '500', '501'], 
    'STRU': ['200', '500', '501', '504'], 
    'SYST': ['215', '500', '501'], 
    'ACCT': ['530', '500', '501'], 
    'ADAT': ['503', '501', '535'], #RFC2228 
    'ALLO': ['200', '500', '501', '504'], 
    'AUTH': ['500', '502', '504'], #RFC2228
    'CONF': ['502', '501', '503', '500', '537', '535', '533'], #RFC2228
    'LANG': ['500', '501', '502', '504'], #RFC2640
    'MIC': ['502', '501', '503', '500', '537', '535', '533'], #RFC2228
    'MLSD': ['500', '501', '550', '530', '553', '503', '504'], #RFC3659
    'MLST': ['500', '501', '550', '530', '553', '503', '504'], #RFC3659
    'REIN': ['500'], 
    'REST': ['500', '501', '350'], 
    'RNTO': ['250', '532', '553', '500', '501'], 
    'SMNT': ['500', '501', '550']
  }

  if justAuthentication==True:
    currentCMD = None
    currentOpts = None
    #fuzz authentication
    try:
      for string in fuzz:
        for num in range(1, 3): #2 different loops, for fuzzing username & password   separately
          print "Fuzzing username & password with string:" + string
          sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          if sock==-1:
            print "Socket creation failure"
            exit(1)
          try:
            connection = sock.connect((ip, port))
          except socket.error:
            print 'Problem connecting to host. Make sure host alive & service running on   specified port '
            exit(1)
          answer = sock.recv(1024)
          if answer[0:3]!='220':
            print "Something wrong, not connected!"
            print "Exiting..."
            exit(1)
          print answer
          if num % 2 == 1: #need to fuzz username, and then use real username to fuzz   password	
            user = string
            currentCMD='USER'
          else:
            user = username
            currentCMD='PASS'
          currentOpts=string
          sock.send('USER ' + user + '\r\n') #fuzz username
          answer = sock.recv(1024)
          print answer
          if num % 2 == 1: #just fuzzing USER + want to loop again instead of trying PASS
            #username is accepted without checking 99% of the time so no point doing any checks on this, will just give a lot of false positives.
            continue
          sock.send('PASS ' + string + '\r\n') #Fuzz password
          print answer
          answer = sock.recv(1024)
          #The only thing ever really that could be found with a username or password is some sort of memory corruption, which wouldn't be told to use by a return code so it's probably better just to not try and instead just save time since the fuzzer will now work quicker in this part.
          #if answer[0:3]=='230' or answer[0:3]=='220':
          #  passError = "Password accepted! This shouldn't happen unless the user specified has a  password consisting of a series of A's or a number. This will be counted as an error."
          #  print passError
          #  file.write(passError)
          #  history = getHistory('PASS', fuzz.index(string), fuzz)
          #  file.write('Server crashed after:\r\n')
          #  for sentCommand in range(len(history)):
          #    file.write(history[sentCommand] + '\r\n')
          #  print 'Answer is: ' + answer
          #  exit(1)
          sock.close()
    except Exception, Inst:
      print "Error: " + str(Inst)
      file.write("Error: "+str(Inst))
      history=getHistory(currentCMD, fuzz.index(currentOpts), fuzz)
      for sentCommand in range(len(history)):
        file.write(history[sentCommand] + '\r\n')
      
  else:
    try:
      sock2 = None #may be needed later
      #Need nested for loop in order to fuzz each command easily.
      for cmd in commandList:
        for string in fuzz:
          currentCMD=cmd
          currentOpts=string
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
            #print "here 4"
            for i in range(2): #if returned code needs PASV or PORT
              #print "here 5"
              sock.send(cmd + ' ' + string + '\r\n') #evil buffer
              #print "here 5a"
              answer = sock.recv(1024)
              while (answer[:3]=='230'):
                answer=sock.recv(1024)
              #print answer
              #print answer[0]
              if answer[0]=='5': #all these errors mean not implemented etc
                continue
              
              #print "here 7"
              connectionModeAttempts = 0
              #for x in range(2): #won't work without
              if answer[0:3]=='425':#Needs to either change, or nothing open anyway
                print "Trying PORT command"
                if connectionModeAttempts==0:
                  sock.send('PORT\r\n')
                  connectionModeAttempts+=1
                elif connectionModeAttempts==1:
                  print "Trying PASV commmand"
                  connectionModeAttempts+=1
                  sock.send('PASV\r\n')
                  try:
                    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    answer = sock2.recv(1024)
                    if answer[0:3]=='227':#passive mode is allowed
                      match = re.search(r'(\,\d+)+', answer) #Obtaining the numbers to calculate the port
                      (temp1, temp2) = match.group().split(',')[-2:] 
                      port = int(temp1)*256 + int(temp2) #calculating the port to connect to                     sock2.connect((ip, port))
                  except sock2.error:
                    print "Passive mode socket creation failure"
                    exit(1)
              else:
                print answer
              sentCommand = cmd + ' ' + string
              #print "here 8"
              if (sock2): #if using passive mode, check this channel too
                answer2 = sock2.recv(1024)  
                
                code = answer2[0:3]
              else:
                code = answer[0:3]
              if code!='202' and (code not in correctResponse[cmd]): 
                #not a correct response as per dictionary (code 202/502 for not implemented)
                writeError(file, sentCommand, 'There appears to be an error with', answer)
              #print "here 9"
              if connectionModeAttempts>=2:
                break
            sock.send('QUIT\r\n')
            sock.close()
            #print "here 10"
          except socket.error:
            print 'Problem occurred. Service may be down.'
            history = getHistory(cmd, fuzz.index(string), fuzz)
            file.write('Server crashed after:\r\n')
            for sentCommand in range(len(history)):
              file.write(history[sentCommand] + '\r\n')
            sock.close()


    except Exception, Inst:
      #print "here 11"
      print "Error: " + str(Inst)
      file.write("Error: "+str(Inst))
      history=getHistory(currentCMD, fuzz.index(currentOpts), fuzz)
      for sentCommand in range(len(history)):
        file.write(history[sentCommand] + '\r\n')  
      exit(1)

def fuzzPOPmain(ip, port, username, password, toAttach, pid):
  if toAttach: #local service, being attached
    if int(pid)<0:
      print 'Invalid PID. Make sure is correct if you want to attach a local service'
      exit(1)
    else:
      #valid PID, so create debugger & attach it
      dbg=PtraceDebugger()
      process = dbg.addProcess(pid, is_attached)
      is_attached = True
      process.cont()
      event = process.waitEvent() #not sure about should use this considering calling another method, or whether should be here or not
      actualPOPfuzz(ip, port, username, password)
      error = ''
      if (isinstance(event, ProcessSignal)):
        filename = 'POP3fuzzResultsFor'+ip
        file = open(filename, 'w')
        file.write('Error Found:\n')
        file.write(error)
        print "died with signal %i" % event.signum
        error = signal(event.signum, vulnerableCommand)
        print 'Next instruction:\n'
        processInfo = "%s" % process.dumpCore(filename) #display next instruction
        file.write('Next instruction:\n')
        file.write(processInfo)
        print processInfo
        print 'Register dump:\n'
        processInfo = "%s" % process.dumpRegs()
        file.write('Register dump:\n')
        file.write(processInfo)
        print processInfo
        print 'Stack:\n'
        processInfo = "%s" % process.dumpStack() #display some memory words around the stack pointer
        file.write('Stack:\n')
        file.write(processInfo)
        print processInfo
        print 'Memory mappings:\n'
        processInfo = "%s" % process.dumpMaps()#display memory mappings
        file.write('Memory Mappings:\n')
        file.write(processInfo)
        print processInfo
        file.close()
      return error
  else: #remote server, or local but not want debugger attached (because it would be quicker)
    actualPOPfuzz(ip, port, username, password)


def actualPOPfuzz(ip, port, username, password):
  global fuzz
  fuzz = attack()
  filename = 'POP3fuzzResultsFor'+ip
  file = open(filename, 'w')
  fuzzedCommands = ['USER', 'PASS', 'AUTH', 'LIST', 'STAT', 'RETR', 'DELE', 'NOOP', 'RSET', 'UPDATE', 'TOP', 'UIDL', 'APOP'] #more to follow
  #3 stages of fuzzing POP3 - fuzz username, password, and then every command while authenticated
  variableList = ['', '', ''] # for holding different fuzzes between username, password + a command to fuzz when authenticated
  try:
    for variableToFuzz in range(len(fuzzedCommands)):
      #variableToFuzz = str(variableToFuzz)
      #first if is 1, since @ variablToFuzz==0, the USER command will be fuzzed
      if variableToFuzz>1: #Need username in order to fuzz password
        variableList[0] = username
      if variableToFuzz > 1:
        variableList[1] = password #variableList[0] already the correct username
      #for element in variableList:
      for fuzzElem in range(len(fuzz)):
        try:
          sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          sock.connect((ip, port)) #create socket & connect to pop3 server
          answer = sock.recv(1024)
          print answer
        except socket.error:
          print 'Error creating the socket'
          exit(1)
        if variableList[0]==username:
          sock.send('USER ' + username + '\r\n')
          answer = sock.recv(1024)
          print answer
          if answer[:1]=='-':
            print 'Error with username ' + username
            exit(1)
        if variableList[1]==password:
          sock.send('PASS ' + password + '\r\n')
          answer = sock.recv(1024)
          print answer
          if answer[:1]=='-':
            print 'Error with password ' + password
            exit(1)
        #Now need to do fuzzing
        variableToFuzz=int(variableToFuzz)
        sentCommand = fuzzedCommands[variableToFuzz] + ' ' + fuzz[fuzzElem]
        print 'Fuzzing ' + fuzzedCommands[variableToFuzz] + ' with string: ' + fuzz[fuzzElem] + '\n'
        sock.send(sentCommand + '\r\n')
        answer = sock.recv(1024)
        print answer
        if fuzzedCommands[variableToFuzz] in ['RSET', 'NOOP', 'UIDL']:
          if answer[:1]=='-':
            writeError(file, sentCommand, 'There was an error', '\n')
        if answer[:1]=='+':
          writeError(file, sentCommand, 'There seems to be an error', '\n')
        sock.close()
  except socket.error:
    print 'Problem occurred. Service may be down.'
    history = getHistory(fuzzedCommands[variableToFuzz], fuzzElem, fuzz)
    file.write('Server crashed after:\r\n')
    for sentCommand in range(len(history)):
      file.write(history[sentCommand] + '\r\n')
    sock.close()
  file.close()

def fuzzOwnProtocol(file, address):
  boolDict = {'TRUE':True, 'FALSE':False}
  fuzz = attack()
  try:
    tree = ElementTree.parse(file)
  except Exception, inst:
    print "Unexpected error opening %s : %s" % (file, inst)
    exit(1)
  root = tree.getroot()
  userReply = None
  passReply = None
  connInit = []
  realCMDList = []
  realAuthCMDList = []
  firstIndex = 2 #index needs to change depending if there is special connection sequence and/or authorisation
  if len(root.getchildren())==5 and root.getchildren()[firstIndex]=='conn':
    firstIndex = firstIndex + 1
    #need certain commands to connect properly other than authorisation
    conn = root.getchildren()[2]
    for cmd in conn.getchildren():
      stdReps = []
      if len(cmd.getchildren)!=0: #then has replies or stdRep
        if cmd.getchildren()[0].tag=='reply':
          reply = boolDict[cmd.getchildren()[0].attrib['val']]
          if len(cmd.getchildren)>1: #has some standard replies
            for replies in cmd.getchildren[1:]:
              stdReps.append(replies)
        else:
          reply = False
      connInit.append([cmd.text, reply, stdReps])
          
  if root.getchildren()[firstIndex].tag != 'auth':
    #if no authorisation part, and list isn't length 3, then something is configured wrong.
    #Need at minimum the protocol to connect, the port & some commands to fuzz
    if len(root.getchildren())!=3:
      print 'Something wrong in the configuration file. Please see documentation for help.\n'
      exit(1)
    (protocol, port, commands) = root.getchildren()
  else:
    #depending on if authorisation needed within protocol
    (protocol, port, auth, commands) = root.getchildren()
    #the children of <auth>
    (unCMD, pwCMD) = auth.getchildren()
    userCMD = unCMD.text
    #getiterator gets the different occurrences of it used (in this case with the .text & with the value)
    #need correct username & password for fuzzing authenticated
    defaultUser = unCMD.getiterator()[1].attrib.values()[0]
    #if it says if there's a reply or not (since optional)
    #but could also be more if there are a number of 
    if len(unCMD.getiterator())>2 and unCMD.getiterator()[2].tag == 'reply' and protocol.text == 'TCP':
      userReply = unCMD.getiterator()[2].attrib.values()[0]
      if len(unCMD.getiterator())==4: #then know a std reply should get while fuzzing
        realAuthCMDList.append([userCMD, userReply, [unCMD.getiterator()[3].text], defaultUser])
      else:
        realAuthCMDList.append([userCMD, userReply, [], defaultUser])
    else:
      realAuthCMDList.append([userCMD, False, [], defaultUser])
    passwdCMD = pwCMD.text
    defaultPass = pwCMD.getiterator()[1].attrib.values()[0]
    if len(pwCMD.getiterator())>2 and unCMD.getiterator()[2].tag == 'reply' and protocol.text == 'TCP':
      passReply = pwCMD.getiterator()[2].attrib.values()[0]
      if len(pwCMD.getiterator())==4: #then know a std reply should get while fuzzing
        realAuthCMDList.append([passwdCMD, passReply, [pwCMD.getiterator()[3].text], defaultPass])
      else:
        realAuthCMDList.append([passwdCMD, passReply, [], defaultPass])
    else:
      realAuthCMDList.append([passwdCMD, False, [], defaultPass])
  proto = protocol.text  
  if proto != 'TCP' and proto != 'UDP':
    print 'Invalid protocol specified. Only TCP & UDP (case sensitive) possible to use'
    exit(1)
  #variable port not needed again, so can just be reused.
  port = port.text
  #the actual commands to fuzz (need to include userCMD & pwCMD)
  cmdList = commands.getchildren()
  for cmd in cmdList:
    if proto == 'TCP':
      reply = boolDict[cmd.getchildren()[0].attrib.values()[0]]
      stdReplies = []
      for stdReply in cmd.getchildren()[1:]:
        stdReplies.append(stdReply.text)
      cmdInfo = [cmd.text, reply, stdReplies]
      realCMDList.append(cmdInfo) 
    else: #UDP
      for cmd in cmdList:
        realCMDList.append([cmd.text, False, []])
  #now in form [['GET', ['203', '204']]] - array of arrays with the command & replies we should get from the result (if any reply)
  #now have the protocol being used, any authentication needed (with username & password which can be used for authenticating), any commands
  #and the replies I should get from the system usually (e.g. can't read ../../etc/passwd)
  if proto=='TCP':
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((address, port))
  elif proto=='UDP':
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  
  #this will effectively act as a pointer to a function, so that I can just call a single function, which will call different functions
  func_map = {'TCP' : sendTCP, 'UDP' : sendUDP}
  
  filename = 'UserSpecifiedProtocolResults'
  try:
    fileToWrite = open(filename, 'w')
  except IOError:
    print "Problem opening file"
    exit(1)
  try:
    #this type of fuzzer will just go through every permutation automatically without a whole lot of checking,
    #even if connection closed, will not restart it again, meaning that it cannot fuzz commands that will close a TCP connection
    introCMDList = connInit + realAuthCMDList
    for cmd in introCMDList:
      for fuzzElem in fuzz:
        fullCommand = cmd[0] + ' ' + fuzzElem
        info = [sock, address, port, cmd[1]] #TCP & UDP need different things, but this saves time over separately making separate functions for each
        reply = func_map[proto](info, fullCommand)
        #check if reply is 1 of the correct replies we should get, if not report it to the file.
        #The files will be very large if the standard reply was wrong, or if none were given. 
        for answer in cmd[2]: 
          #have to account for not exact answers
          #for example with FTP, reply is determined by a code, but the program can specify a sentence with this
          #so if the person who specified just put the code, this will check the for the code (which should always be at the start)
          if reply[:len(answer)] != answer:
            writeError(fileToWrite, fullCommand, '', reply)

    for cmd in realCMDList:
      info = [sock, address, port, cmd[1]]
      #do any special connection sequence
      for connCMD in connInit:
        fullCommand = connCMD[0]
      #try to login for each command fuzzed
      for authCMD in realAuthCMDList:
        fullCommand = authCMD[0] + " " + authCMD[-1] #authorise so can fuzz other commands
        reply = func_map[proto](info, fullCommand)
      for fuzzElem in fuzz:
        fullCommand = cmd[0] + " " + fuzzElem
        reply = func_map[proto](info, fullCommand) #fuzz commands
        for answer in cmd[2]:
          if reply[:len(answer)] != answer:
            writeError(fileToWrite, fullCommand, '', reply)
  except Exception, Inst:
    writeError(fileToWrite, fullCommand, '', Inst)
  if proto=='TCP':
    #need to close TCP connection after fuzzing
    sock.close()
  fileToWrite.close()


def sendTCP(info, message):
  #info is a list with the socket object, ip address, port, & whether it's expecting a reply
  sock = info[0]
  sock.send(message)
  answer = None
  if info[3] == 'TRUE':
    #expecting a reply
    answer = sock.recv(1024)
  return answer

def sendUDP(info, message):
  #info is a list with different things in depending on whether TCP  or UDP being used
  address = info[1]
  port = info[2]
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  sock.sendto(message, (address, port))
  return None

def writeError(file, command, Error, wrongReturn):
  if Error == '':
    Error='There was an error'
  #this will write an error to stdout & a file
  file.write(Error + ' ' + command)
  print Error + ' ' + command
  if wrongReturn!='':
    file.write('The answer given was: ' + wrongReturn)
    print 'The answer given was: ' + wrongReturn

def main():
  params = len(argv)
  flags = None
  port = None
  ip = None
  local = None
  attachRemote=False
  defaultUsage = 'usage: %prog [options] [program] [service (server fuzzer only)]\nSupported Remotes Services: '
  #-------------OPTIONS NEEDED-------------
  #user, password, file (with read/write access if possible), option for hanging until reset
  global supported
  for service in supported:
    defaultUsage+=service+' ' #for easier updating supported services, just need to update global list
  defaultUsage+="\nPlease use full path for service, not starting script"
  parser = OptionParser(usage=defaultUsage)
  # parser.add_option("-h", action="callback", callback=usage)
  parser.add_option("-a", "--all", action="store_true", dest="all", help="Fuzzes all simple options a-z and A-Z, and the no flag option for a command line program")
  parser.add_option("-p", "--port", type="int", dest="port", help="Port for server (if not default for service)")
  parser.add_option("-l", "--local", type="int", dest="local", help="Server PID for a remote server")
  parser.add_option("-t", "--target", action="store", type="string", dest="ip", help="Target IP address")
  parser.add_option("-u", "--username", action="store", type="string", dest="username", help="Username for logging on server, enabling full fuzzing", default="username")
  parser.add_option("-w", "--password", action="store", type="string", dest="password", help="Password for logging onto server, enabling full fuzzing", default="password")
  parser.add_option("-f", "--framework", action="store", type="string", dest="frameworkFile", help="File for specifying a user-specified protocol. See documentation for details.")
  parser.add_option("-c", action="store", type="string", dest="flags", help="Command line fuzzer, fuzzes specific program arguments.\n\r\n\rThe syntax for specifying arguments with -c is:\nThe way to specify an argument with a single hyphen is with a single colon (:) and for an argument with 2 hyphens is with 2 colons (::). This allows for arguments with a hyphen in the flag.\nAn example is (using part of the man page for Nmap):\nNmap 5.00 ( http://nmap.org )\nUsage: nmap [Scan Type(s)] [Options] {target specification}\nTARGET SPECIFICATION:\n  Can pass hostnames, IP addresses, networks, etc.\n  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254\n  -iL <inputfilename>: Input from list of hosts/networks\n  -iR <num hosts>: Choose random targets\n  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks\n  --excludefile <exclude_file>: Exclude list from file\n...\n  --dns-servers <serv1[,serv2],...>: Specify custom DNS servers\n\nIf you wanted to fuzz the parameters -iL, --exclude, --excludefile and --dns-servers, and the program Nmap is located at /usr/bin/nmap, then the command to fuzz would be \n%s -c :iL::exlude::excludefile::dns-servers /usr/bin/nmap\nIf the no flag argument needs to be fuzzed (no options), for instance doing nmap fuzzedstring, then an  extra colon needs to be added to the end. So %s -c :iL::exlude::excludefile::dns-servers: /usr/bin/nmap" % (argv[0], argv[0]))
  (options, args) = parser.parse_args()
  lastParam = argv[params-1]
  lastParam = lastParam.lower()
  #try:
  if (options.all):
  #command line argument fuzzer with all simple arguments
    arguments = genFuzzOpts()
    fuzzProg(arguments, lastParam)
    exit(1)
  #command line argument fuzzer with specific flags
  elif (options.flags):
    arguments = genFuzzOpts2(options.flags)
    fuzzProg(arguments, lastParam)
    exit(1)
  elif (options.frameworkFile):
    if not (options.target):
      print "A target needs to be specified for a user-specified protocol."
      exit(1)
    fuzzOwnProtocol(frameworkFile, ip)
    exit(1)
  elif not (options.port): #no port specified. Set port to standard for service
    if lastParam in supported: #if the last argument is a supported service
      port = servicePorts[lastParam]
    else:
      usage()
  ip = options.ip
  #so now if not command line fuzzer, & now have port
  if ip: #remote service fuzzer
    print "Fuzzing service at", ip
    #make sure is a valid IP address using regex
    match = re.search(r'([0-9]+\.)+[0-9]+', ip) 

    #Not 100% guaranteed to be valid IP, but will do in favour of having a long regular expression 
    if lastParam not in supported:
      print 'Need supported protocol'
      print defaultUsage
      exit(1)
    if not match:
      print 'Invalid IP address given'
      usage()
    local = options.local
    if local:
      if type(local) == types.IntType: #making sure the PID is a real number
        attachRemote = True #so need to attach debugger
      else:
        usage()
    #remote fuzzing
    #this part could possibly be done using a dictionary with the method associated with each protocol, but not sure if it would work
    #and it might not be even feasible because different protocols may need different parameters
    if not (options.username):
      print "You need at least a username!"
      exit(1)
    if lastParam == 'ftp':
      fuzzFTPmain(ip, port, options.username, options.password, attachRemote, local)
      exit(1)
    elif lastParam == 'pop3':
      fuzzPOPmain(ip, port, options.username, options.password, attachRemote, local)
      exit(1)
      

if __name__=='__main__':
  main()

