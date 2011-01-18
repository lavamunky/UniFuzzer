#!/usr/bin/python
from sys import exit
from xml.etree import ElementTree
#import socket

def main():
  file = 'FTPtest.xml'
  tree = ElementTree.parse(file)

  root = tree.getroot()
  (protocol, auth, commands) = root.getchildren()

  proto = protocol.attrib.values()[0]
  #the children of <auth>
  (unCMD, pwCMD) = auth.getchildren()

  userCMD = unCMD.text
  #getiterator gets the different occurrences of it used (in this case with the .text & with the value)
  #need correct username & password for fuzzing authenticated
  defaultUser = unCMD.getiterator()[1].attrib.values()[0]
  passwdCMD = pwCMD.text
  defaultPass = pwCMD.getiterator()[1].attrib.values()[0]

  #the actual commands to fuzz (need to include userCMD & pwCMD)
  cmdList = commands.getchildren()
  realCMDList = []
  for cmd in cmdList:
    if proto == 'TCP':
      reply = cmd.getchildren()[0].attrib.values()[0]
      if reply != 'TRUE' and reply != 'FALSE':
        print 'Each command must have a value for reply of either TRUE or FALSE as long as using TCP'
        exit(1)
      correctReplies = []
      for correctReply in cmd.getchildren()[1:]:
        correctReplies.append(correctReply.text)
      cmdInfo = [cmd.text, correctReplies]
      realCMDList.append(cmdInfo)
      
  print realCMDList
  #now in form [['GET', ['203', '204']]] - array of arrays with the command & replies we should get from the result (if any reply)
  #now have the protocol being used, any authentication needed (with username & password which can be used for authenticating), any commands
  #and the replies I should get from the system usually (e.g. can't read ../../etc/passwd)
  #def tcpStart()


  #sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  #sock.connect((ip, port)) #create socket & connect to pop3 server
  #sock.send('USER ' + username + '\r\n')
  #sock.recv(1024)

if __name__=='__main__':
  main()

