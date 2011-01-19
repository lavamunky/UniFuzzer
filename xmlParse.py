#!/usr/bin/python
from sys import exit
from xml.etree import ElementTree
import socket


def main():
  fuzz = ['A', 'AAAAAAAAAAAAAAA']
  file = 'FTPtest.xml'
  tree = ElementTree.parse(file)
  root = tree.getroot()
  userReply = None
  passReply = None
  realCMDList = []
  realAuthCMDList = []
  if root.getchildren()[2].tag != 'auth':
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
      reply = cmd.getchildren()[0].attrib.values()[0]
      if reply != 'TRUE' and reply != 'FALSE':
        print 'Each command must have a value for reply of either TRUE or FALSE as long as using TCP'
        exit(1)
      stdReplies = []
      for stdReply in cmd.getchildren()[1:]:
        stdReplies.append(stdReply.text)
      cmdInfo = [cmd.text, reply, stdReplies]
      realCMDList.append(cmdInfo) 
    else: #UDP
      for cmd in cmdList:
        realCMDList.append([cmd.text, False, []])
  print realCMDList #-----------TESTING PURPOSES ONLY-----------------
  print realAuthCMDList
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
  #this type of fuzzer will just go through every permutation automatically without a whole lot of checking,
  #even if connection closed, will not restart it again, meaning that it cannot fuzz commands that will close a TCP connection
  for cmd in realAuthCMDList:
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
    #try to login for each command fuzzed
    for authCMD in realAuthCMDList:
      fullCommand = authCMD[0] + " " + authCMD[-1]
      info = [sock, address, port, cmd[1]]
      reply = func_map[proto](info, fullCommand)
    for fuzzElem in fuzz:
      info = [sock, address, port, cmd[1]]
      fullCommand = cmd[0] + " " + fuzzElem
      reply = func_map[proto](info, fullCommand)
      for answer in cmd[2]:
        if reply[:len(answer)] != answer:
          writeError(fileToWrite, fullCommand, '', reply)

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

if __name__=='__main__':
  main()

