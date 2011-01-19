#!/usr/bin/python
from sys import exit
from xml.etree import ElementTree
import socket


def main(ip, file):
  boolDict = {'TRUE': True, 'FALSE': False}
  fuzz = ['A', 'AAAAAAAAAAAAAAA']
  file = 'FTPtest.xml'
  tree = ElementTree.parse(file)
  root = tree.getroot()
  fullSequence = []
  default = ''
  reply = ''
  protocol = None
  port = None
  baseParts = root.getchildren()
  cmdOrder = [] #for knowing how many loops to use
  for elem in baseParts:
    if elem.tag=='protocol':
      protocol=elem.text
      protocol = protocol.upper() #so that it isn't case sensitive
      if protocol != 'TCP' and protocol != 'UDP': #no point going any further if not tcp or udp
        print 'Invalid protocol specified. Only TCP & UDP (case sensitive) possible to use'
        exit(1)
    elif elem.tag=='port':
      port = int(elem.text)
    elif elem.tag=='seq':
      tempSeq=[]
      for command in elem.getchildren():
        seqCommand=command.getchildren()
        if len(seqCommand)==2: #then either default password & reply
          (default, reply) = seqCommand
          default = default.attrib.values()[0]
          reply = reply.attrib.values()[0]
        elif len(seqCommand)==1: #either have value for reply or default val
          if seqCommand[0].tag=='default':
            default= seqCommand[0].attrib.values()[0]
            reply = 'FALSE'
          elif seqCommand[0].tag=='reply':
            default = ''
            reply = seqCommand[0].attrib.values()[0]
          else:
            print "Problem parsing file. Please read docs for more info."
        else:
          default = ''
          reply = 'FALSE'
        tempSeq.append([command.text, default, reply]) #add the command, a default input & whether it needs a reply (only first mandatory)
      fullSequence.append(tempSeq)
      cmdOrder.append(1)
    elif elem.tag=='commands': #commands that don't have to go in a particular sequence
      for command in elem.getchildren():
        if len(command.getchildren())==1: #reply
          reply=command.getchildren()[0].attrib.values()[0]
        else:
          reply='FALSE'
        fullSequence.append([command.text, reply])
        cmdOrder.append(0)
    else:
      print "Something wrong parsing file. Please see docs for more info."

  #this will effectively act as a pointer to a function, so that I can just call a single function, which will call different functions
  func_map = {'TCP' : sendTCP, 'UDP' : sendUDP}

  #cmdOrder now something like [1, 0, 0, 0, 1] - number for each element in fullSequence
  #1 means it's a sequence, 0 meaning it's just on it's own
  for index in range(len(fullSequence)):
    if cmdOrder[index]==1: #sequence
      #print fullSequence[index]
      for commandIndex in range(len(fullSequence[index])): #looping through the sequence
        #for command in fullSequence[index]: #in a sequence so send bits before in the sequence before the command we're fuzzing
        #print fullSequence[index][commandIndex]
        for elem in fuzz:
          if protocol=='TCP':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((address, port))
          elif protocol=='UDP':
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

          command = fullSequence[index][commandIndex]
          sendSequence(index, fullSequence, commandIndex, protocol, sock, port, ip)
          info = [sock, command[0], elem, command[2], port, ip] #port & ip needed for UDP connection
          #what sendTCP or sendUDP is expecting. sockfd, the command, string sending with command & whether need a reply or not
          func_map[protocol](info)
          #print command[0] + " " + elem + "\nReply: " + command[2] + "\n\n"

    else:
      for elem in fuzz:
        if protocol=='TCP':
          sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          sock.connect((address, port))
          sock.recv(1024) #presumes that every TCP connection is initially sent something (as far as I know it is)
        elif protocol=='UDP':
          sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for commandIndex in range(index):
          if cmdOrder[commandIndex]==1: #if there is a sequence before this command, perform that sequence before, i.e. logging in  
            sendSequence(commandIndex, fullSequence, len(fullSequence[commandIndex]), protocol, sock, port, ip) #go through any sequence before this command can be done
        func_map[protocol]([sock, fullSequence[index][0], elem, fullSequence[index][1], port, ip])
        #print fullSequence[index][0] + " " + elem + "\nReply: " + fullSequence[index][1] + "\n\n" 
    if proto=='TCP':
    #need to close TCP connection after fuzzing
    sock.close()


def sendSequence(index, fullSequence, commandIndex, protocol, sock, port, ip):
  for prevCMDs in range(commandIndex): #loop through previous parts of sequence
    info = [sock] + fullSequence[index] + [port, ip]
    func_map[protocol](info)
    #print fullSequence[index][prevCMDs][0] + " " + fullSequence[index][prevCMDs][1] + "\nReply: " + fullSequence[index][prevCMDs][2]
    #loop through to get the start of the sequence correct
    #this is because you have a password you need a username, or you need an HELO first, then blah blah

def sendTCP(info):
  #info is a list with the socket object, ip address, port, & whether it's expecting a reply
  sock = info[0]
  message = info[1] + " " + info[2] + "\r\n"
  sock.send(message)
  answer = None
  if info[3] == 'TRUE':
    #expecting a reply
    answer = sock.recv(1024)


def sendUDP(info):
  #info is a list with different things in depending on whether TCP  or UDP being used
  sock = info[0]
  address = info[-1]
  port = info[-2]
  message = info[1] + " " + info[2] + "\r\n" #this presume that every ASCII based protocol has a line delimited of \r\n
  sock.sendto(message, (address, port))


if __name__=='__main__':
  main()

