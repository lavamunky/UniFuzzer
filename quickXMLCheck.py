import socket
from xml.etree import ElementTree
from sys import exit
import re

def main():
  boolDict = {'TRUE': True, 'FALSE': False}
  ip='192.168.1.4'
  file='FTPtest.xml'
  fuzz = ['A', 'AAA']
  tree = ElementTree.parse(file)
  root = tree.getroot()
  fullSequence = []
  default = ''
  eol = '\r\n'
  reply = ''
  protocol = None
  port = None
  baseParts = root.getchildren()
  cmdOrder = [] #for knowing how many loops to use
  for elem in baseParts:
    if elem.tag=='protocol':
      protocol=elem.text
      protocol = protocol.upper() #so that it isn't case sensitive

    elif elem.tag=='port':
      port = int(elem.text)
    elif elem.tag=='seq':
      tempSeq=[]
      for command in elem.getchildren():
        seqCommand=command.getchildren()
        if len(seqCommand)==3: #default string, reply & special end of line
          (default, reply, eol) = seqCommand
          eol = eol.decode('string_escape')
        if len(seqCommand)==2: #then either default string & reply
          default = ''
          reply = ''
          eol = ''
          for cmd in seqCommand:
            if cmd.tag=='reply':
              reply = cmd.attrib.values()[0]
            elif cmd.tag=='default':
              default = cmd.attrib.values()[0]
            elif cmd.tag=='EOL':
              eol = cmd.attrib.values()[0]
              eol = eol.decode('string_escape')
            else:
              print cmd.tag
              print "Something wrong parsing values.\nPlease see documentation for help"
              exit(1)
          if reply=='':
            reply=='FALSE'
          elif eol=='':
            eol=='\r\n'
        elif len(seqCommand)==1: #either have value for reply or default val
          if seqCommand[0].tag=='default':
            default= seqCommand[0].attrib.values()[0]
            eol = '\r\n'
            reply = 'FALSE'
          elif seqCommand[0].tag=='reply':
            default = ''
            reply = seqCommand[0].attrib.values()[0]
          elif seqCommand[0].tag=='EOL':
            eol = seqCommand[0].attrib.values()[0]
            eol = eol.decode('string_escape')
            reply = 'FALSE'
            default = ''
          else:
            print "Problem parsing file. Please read docs for more info."
        else:
          default = ''
          reply = 'FALSE'
          eol='\n'
        tempSeq.append([command.text, default, reply, eol]) #add the command, a default input & whether it needs a reply (only first mandatory)
      fullSequence.append(tempSeq)
      cmdOrder.append(1)
    elif elem.tag=='commands': #commands that don't have to go in a particular sequence
      for command in elem.getchildren():
        if len(command.getchildren())==2: #reply & end of line symbol
          reply=command.getchildren()[0].attrib.values()[0]
          eol=command.getchildren()[1].attrib.values()[0]          
          eol = eol.decode('string_escape')
        elif len(command.getchildren())==1: #reply or end of line symbol
          if command.getchildren()[0].tag=='reply':
            reply=command.getchildren()[0].attrib.values()[0]
            eol='\r\n'
          elif command.getchildren()[0].tag=='EOL':
            reply='FALSE'
            eol=command.getchildren()[0].attrib.values()[0]
            eol = eol.decode('string_escape')
          else:
            print 'Problem found with tag '+ command.getchildren()[0].tag
            exit(1)
        else:
          reply='FALSE'
          eol='\r\n'
        
        fullSequence.append([command.text, reply, eol])
        cmdOrder.append(0)
    else:
      print "Something wrong parsing file. Please see docs for more info."

  if protocol != 'TCP' and protocol != 'UDP': #no point going any further if not tcp or udp
    print 'Invalid protocol specified. Only TCP & UDP (case sensitive) possible to use'
    exit(1)
  elif port=='':
    print "No port specified, or specified incorrectly. Please see documentation for help."
    exit(1)

  #cmdOrder now something like [1, 0, 0, 0, 1] - number for each element in fullSequence
  #1 means it's a sequence, 0 meaning it's just on it's own
  for index in range(len(fullSequence)):
    if cmdOrder[index]==1: #sequence
      #print fullSequence[index]
      for commandIndex in range(len(fullSequence[index])): #looping through the sequence
        command=fullSequence[index][commandIndex]
        print command[0] + " " + command[1] + command[3] +"\nReply: " + command[2] +  "\r\n"
    else:
      print fullSequence[index][0] + " " + fullSequence[index][1] + fullSequence[index][2]

def sendSequence(index, fullSequence, commandIndex):
  for prevCMDs in range(commandIndex): #loop through previous parts of sequence
    print fullSequence[index][prevCMDs][0] + " " + fullSequence[index][prevCMDs][1] + fullSequence[index][prevCMDs][3]+"\nReply: " + fullSequence[index][prevCMDs][2] + "\r\n"

if __name__=='__main__':
  main()
