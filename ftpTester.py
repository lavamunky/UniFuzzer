import socket

def attack():
  #create fuzzed arguments
  #use list for amounts each different attack vector (upto 65535)
  #(saves time over incrementing)
  #if find anything, if want to take error, further will need to be done manually
  amount =[1,2,3	,4,5,10,25,50,75,100,250,500,750,1000,2000,3000,4000,5000,7500,10000,12500,15000,20000,25000]#,30000,50000,75000,10000,20000,30000,40000,50000,60000,65535]
  #effectively how many times each different element will be used to attack the program
  global attackChain
  attackChain = len(amount)

  #Need to test for buffer underflows + overflows, format string vulnerabilities, 
  #Heap overflows, integer under/overflow and directory traversal

  attacks = ['A', '%n', '%s']
  fuzz = []
  for attackElement in attacks:
    for integer in amount:
      fuzz.append(attackElement*integer)
  #so far buffer + heap under/overflows, and format string vulnerabilities covered
  for integer in range(attackChain):
    fuzz.append('../'*integer+'etc/passwd')
  #directory traversal covered (as long as /etc/passwd is used)
  #very unlikely you would need to go back further than attackChain amount of directories
  #integerOverflow = [-65537, -65535, -1, 0, 100, 1000, 10000, 65535, 65536, 100000]
  #fuzz += integerOverflow
  #MAY NEED SEPARATE OPTION FOR NUMBERS, AS MAY BE INCOMPATIBLE!
  #checked still a list with isinstance(fuzz, list)
  #and 'not isinstance(fuzz, basestring)'
  print 'Fuzz = \r\n'
  print fuzz[:10]
  exit(1)
  return fuzz

def getHistory(cmd, index, fuzz): #fetches the last 10 
  history = [fuzz[index-1]]
  for num in range(2, 12):
    if index-num < 0:
      break
    history.append(cmd + fuzz[index-num])
    history
    exit(1)
  return history

def main():
  #fuzz = attack()
  fuzz = ['whatever']
  port=21
  ip='192.168.1.78'
  username='ftpuser'
  password='ftpuser'
  filename = 'ftpFuzzResultsFor'+ip
#  file = open(filename, 'w')
#  file.write('---------------------FTP fuzzing results for host ' + ip + '---------------------\r\n')
  commandList = ['ABOR', 'CWD', 'DELE', 'LIST', 'MDTM', 'MKD', 'NLST', 'PASS', 'PASV', 'PORT', 'PWD', 'QUIT', 'RETR', 'RMD', 'RNFR', 'RNTO', 'SITE', 'SIZE', 'STOR', 'TYPE', 'USER', 'APPE', 'CDUP', 'HELP', 'MODE', 'NOOP', 'STAT', 'STOU', 'STRU', 'SYST']
  
#  #fuzz authentication
#  for string in fuzz:
#    for num in range(1, 3): #2 different loops, for fuzzing username & password separately
#      #print "Fuzzing username & password with string:" + string
#      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#      if sock==-1:
#        print "Socket creation failure"
#        exit(1)
#      try:
#        connection = sock.connect((ip, port))
#      except socket.error:
#        print 'Problem connecting to host. Make sure host alive & service running on specified port'
#        exit(1)
#      answer = sock.recv(1024)
#      if answer[0:3]!='220':
#        print "Something wrong, not connected!"
#        print "Exiting..."
#        exit(1)
#      if num % 2 == 1: #need to fuzz username, and then use real username to fuzz password
#        user = string
#      else:
#        user = username
#      sock.send('USER ' + user + '\r\n') #fuzz username
#      answer = sock.recv(1024)
#      if num % 2 == 1: #just fuzzing USER + want to loop again instead of trying PASS
#        continue
#      sock.send('PASS ' + string + '\r\n') #Fuzz password
#      answer = sock.recv(1024)
#      if answer[0:3]=='230':
#        print "Password accepted! This shouldn't happen unless the user specified has a password consisting of a series of A's or a number. This will be counted as an error."
#        history = getHistory('PASS', fuzz.index(string), fuzz)
#        file.write('Server crashed after:\r\n')
#        for sentCommand in range(len(history)):
#          file.write(history[sentCommand] + '\r\n')
#      sock.close()

  
  #Need nested for loop in order to fuzz each command easily.
  for cmd in commandList:
    for string in fuzz:
      print "Fuzzing", cmd, "with string:" + string
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

      if sock==-1:
        print "Socket creation failure"
        exit(1)
      #try:
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
      #connection = sock.connect((ip, port))
      #answer = sock.recv(1024)
      sock.send('USER ' + username + '\r\n')
      answer = sock.recv(1024)
      sock.send('PASS ' + password + '\r\n')
      answer = sock.recv(1024)
      if answer[0:3]=='530':
        print 'User not accepted! Wrong username or password.'
        exit(1)
      sock.send('HELP\r\n') #evil buffer
      answer = sock.recv(1024)
      print 'received:\r\n'
      print answer
      temp = answer.split('\r\n')[1:-2]
      #print temp[1:-2]
      for command in temp:
        fuzz.insert(1, 'SITE ' + command)
      print 'Fuzz = \r\n'
      print fuzz
      
      sock.send('QUIT\r\n')
      sock.close()
      exit(1)
      #except socket.error:
      #  print 'Problem occurred. Service may be down.'
      #  history = getHistory(cmd, fuzz.index(string), fuzz)
      #  #file.write('Server crashed after:\r\n')
      #  #for sentCommand in range(len(history)):
      #  #  file.write(history[sentCommand] + '\r\n')
      sock.close()
      exit(1)
if __name__=='__main__':
  main()

