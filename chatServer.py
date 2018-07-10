import sys
import argparse
import socket
import json
import hashlib
import base64
import gcm
import rsa
import time
from ChatParent import ChatParent


ASSOCIATED_DATA = 'TEST'
SERVER_DATABASE = 'server.database'
DELIMETER = "||"
CONNECTION_INFORMATION = 'con.info'
global ac_map
ac_map = {}
class ChatServer(ChatParent):
	def start(self):
		global addr
		global ListofUser
		global current_user
		ListofUser=[] #This list contains the important information about users such as username,IP,Port
		global parsed_msg
		parsed_msg = ""
		SRPA = ""
		K_s = ""
		current_user = ""

		self.check_arguments()
		self.open_socket()
		

		while 1:
			#try:
			msg,addr = sock.recvfrom(65565)
			parsed_msg = json.loads(msg)
	
			if parsed_msg['encrypted'] == 0:
				#Message is not encrypted
				#Checking the message type
				if parsed_msg['type'] == "PING":
					self.sendMsg({"type":"up"}, addr[0], addr[1])

				if parsed_msg['type'] == "SIGNIN":
					current_user = parsed_msg['username']
					if current_user in (i for j in ListofUser for i in j):
						self.sendMsg({"type":"DUPLICATE_USER"}, addr[0], addr[1])
						print "User already exist!"
					else:
						self.init_SRP_parameter()
						SRPA = parsed_msg['SRP']
						b, SRPB, verifier = self.prepare_SRP_msg2(parsed_msg['SRP'], parsed_msg['username'])
						if SRPB=='' and verifier=='':
							continue
						K_s = self.calculateSessionKey(parsed_msg['SRP'],SRPB, verifier, b)
				if parsed_msg['type'] == "CLIENT_AUTHENTICATION":
					print "client autentication received!"
					M1 =parsed_msg["hash"]
					if M1 == self.H(SRPA,SRPB,K_s):
						#Delaying response to client in order to slow down in case brute forcing
						time.sleep(1)
						self.prepare_SRP_msg4(SRPA, M1, K_s)
						self.add_user_to_list(current_user, K_s)	
					else:
						print "Client Authentication Failed!"
						self.sendNotification(addr, 0, 1)	
			else:
				#message is encrypted
				try:
					#Decrypting the message
					whole_msg = parsed_msg
					the_K_s = self.findSessionKey(parsed_msg['username'])				
					dec_msg = self.symdecrypt(parsed_msg['enc_msg'], ASSOCIATED_DATA, the_K_s, DELIMETER)
					parsed_msg = json.loads(dec_msg)
				except:
					print "Error Occured!  decrypting the encrypted received msg"
					continue

				if parsed_msg['type'] == "LIST": #Check if the message is LIST type
					try:
						strlistuser = str(', '.join([i[0] for i in ListofUser]))
						enc = self.symencrypt(strlistuser, ASSOCIATED_DATA, the_K_s, DELIMETER)
						self.sendMsg({"type":"LIST_REP","enc_msg":enc,"encrypted":1,"username":whole_msg['username']}, addr[0], addr[1])
					except:
						print "Error Occured!  while loading the recv LIST message"
				elif parsed_msg['type'] == "MESSAGE":
					target_user= parsed_msg['target_user']
					N1 = parsed_msg['N1']
					AC = self.randomGenerator(64)
					# Find the information of the user among the list of user
					user_exist=0
					des_port=0
					for info in ListofUser:
						if info[0] == target_user:
							des_port = info[1][1]
							user_exist=1
							break

					if user_exist == 1:
						#User exists. sending a message to the client regarding this error.
						try:		
							msg = '{"USER":"' + target_user + '","IP":"' + info[1][0] + '","PORT":' + str(des_port) + ',"EXIST":' + str(user_exist) + ',"N1-1":' + str(int(N1)-1) + ',"AC":"' + str(AC) + '"}'
							enc = self.symencrypt(str(msg), ASSOCIATED_DATA, the_K_s, DELIMETER)
							self.sendMsg({"type":"MESSAGE_REP","enc_msg":enc,"encrypted":1,"username":whole_msg['username']}, addr[0], addr[1])					
							self.storeAC(AC, whole_msg['username'],  target_user)
						except:
							print "Error Occured while sendinf MESSAGE_REP"
					else:
						try:
							self.sendNotification(addr, 1, self.symencrypt(str(2), ASSOCIATED_DATA, the_K_s, DELIMETER) )
						except:
							print "Error Occured while sendng notification regarding MESSAGE_REP"

				#Receiving a ticket from client. needs to be decrypted with private key.			
				elif parsed_msg['type'] == "AUTH_ALICE_TO_BOB":
					try:
						pr = rsa.loadPrivatekey('privatekey.pem')
						dec_serverticket = rsa.rsade(base64.b64decode(whole_msg["server_ticket"]), pr)
						parsed_serverticket = json.loads(dec_serverticket)
						dec = self.symdecrypt(whole_msg['enc_msg'], ASSOCIATED_DATA ,the_K_s, DELIMETER)
						N3 = json.loads(dec)['N3']
						if self.verifyAC(parsed_serverticket['AC'], parsed_serverticket['from'], parsed_serverticket['to']):
							if parsed_serverticket['to']== whole_msg['username']: # check if B is valid or not?
								try:
									key = parsed_serverticket['from'] + "_" + parsed_serverticket['to']
									del ac_map[key]
									N2 = parsed_serverticket["N2"]
									N4 = self.randomGenerator(64)
									alice_ticket_plain = '{"type":"AUTH_BOB_TO_ALICE","N4":' + str(N4) + ',"N2-1":' + str(int(N2)-1) + '}'
									loading = json.loads(alice_ticket_plain)
									#Should be encrytped with the key shared between Alice and Server
									alice_ticket_cipher = self.symencrypt(str(alice_ticket_plain), ASSOCIATED_DATA, self.findSessionKey(parsed_serverticket['from']), DELIMETER)
									tobe_enc = '{"type":"AUTH_SERVER_TO_BOB","alice_ticket":"' + str(alice_ticket_cipher) + '","N3-1":' + str(int(N3)-1) + ',"N4":' + str(N4) + ',"A":"' + str(parsed_serverticket['from']) + '"}'
									#Should be encrypted with the key shared between Bob and Server
									enc = self.symencrypt(str(tobe_enc), ASSOCIATED_DATA, self.findSessionKey(parsed_serverticket['to']), DELIMETER)
									jsonMsg = self.sendMsg({'enc_msg':enc,'type':'AUTH_SERVER_TO_BOB'}, addr[0], addr[1])	
								except:
									print "Error Occured while while sending AUTH_SERVER_TO_BOB"
							else:
								#B validity checking is not valid
								print "B validity checking is not valid"
					except:
						print "Error Occured while processing received serverticket"
				elif parsed_msg['type'] == "LOGOUT":
					logoutuser= whole_msg['username']
					for L in ListofUser:
						#hi
						try:
							if logoutuser in (L):
								del L[:] 
							if len(L) == 0:
								ListofUser.remove(L)
						except ValueError:
							pass
					print "logout!"



	def getCurrentTime(self):
		return int(time.time())/30

	def verifyAC(self, AC, From, To):
		key = From + "_" + To
		ms = self.getCurrentTime()
		if (int(ac_map[key].split(DELIMETER)[1]) == self.getCurrentTime() or int(ac_map[key].split(DELIMETER)[1])+1 == self.getCurrentTime()):
			if ac_map[key].split(DELIMETER)[0] == str(AC):
				return True
			else:
				print "ac is not valid"
				return False
		else:
			print "AC is expired"
			return False

	def storeAC(self, AC, From, To):
		key = From + "_" + To
		ac_map[key] = str(AC) + DELIMETER + str(self.getCurrentTime())

	def findSessionKey(self,username):
		for info in ListofUser:
			if info[0] == username:
				K_s =info[2]
				break
		return K_s

	def add_user_to_list(self, username, K_s):
		ListofUser.append([current_user,[addr[0],addr[1]],str(K_s)])
		print ListofUser

	def prepare_SRP_msg4(self,SRPA, M1, K_s):
		M22 = self.H(SRPA,M1,K_s)
		jsonMsg = json.dumps({"type":"SERVER_AUTHENTICATION","hash":M22})
		sock.sendto(jsonMsg, addr)
		jsonMsg=""	
		return M22

	def calculateSessionKey(self, SRPA, SRPB, verifier, b):
		u2 = self.H(SRPA,SRPB)  # Random scrambling parameter
		S_s = pow(SRPA * pow(verifier, u2, NN2), b, NN2)
		K_s = self.H(S_s)
		K_s = hashlib.md5(str(K_s)).hexdigest()
		return K_s		

	def init_SRP_parameter(self):
		global NN2
		global k2
		global g2
		NN2 = '00:c0:37:c3:75:88:b4:32:98:87:e6:1c:2d:a3:32:4b:1b:a4:b8:1a:63:f9:74:8f:ed:2d:8a:41:0c:2f:c2:1b:12:32:f0:d3:bf:a0:24:27:6c:fd:88:44:81:97:aa:e4:86:a6:3b:fc:a7:b8:bf:77:54:df:b3:27:c7:20:1f:6f:d1:7f:d7:fd:74:15:8b:d3:1c:e7:72:c9:f5:f8:ab:58:45:48:a9:9a:75:9b:5a:2c:05:32:16:2b:7b:62:18:e8:f1:42:bc:e2:c3:0d:77:84:68:9a:48:3e:09:5e:70:16:18:43:79:13:a8:c3:9c:3d:d0:d4:ca:3c:50:0b:88:5f:e3'
		NN2 = int(''.join(NN2.split()).replace(':', ''), 16)
		g2 = 2 # A generator modulo N
		k2 = self.H(NN2, g2)  # Multiplier parameter (k=3 in legacy SRP-6)

	def prepare_SRP_msg2(self, SRPA2, user):
		b2 = self.cryptrand(NN2, 64)
		SRPB2= ''
		verifier2=''
		u2 = self.retreiveUser(user)
		if u2:
			verifier2= u2['verifier']
			salt = u2['salt']
			SRPB2 = (k2*verifier2+pow(g2, b2, NN2)) % NN2
			self.sendMsg({"type":"SRP_RES","EXIST_USERNAME":0,"salt":str(salt),"SRP":SRPB2}, addr[0], addr[1])
		else:
			self.sendNotification(addr, 0, 1)		

		return b2, SRPB2, verifier2

	def H(self, *args):  # a one-way hash function
		a = ':'.join(str(a) for a in args)
		return int(hashlib.sha256(a.encode('utf-8')).hexdigest(), 16)

	def retreiveUser(self, username):
		db = self.readfile(SERVER_DATABASE)
		for user in db:
			if user['username'] == username:
				return user

	# Checking the arguments
	def check_arguments(self):
		global server_port
		if(len(sys.argv) < 1) :
			print "python ChatServer.py"
			sys.exit()

	def sendMsg(self, msg, ip, port):
		jsonmsg = json.dumps(msg)
		sock.sendto(jsonmsg, (ip, port))	

	def open_socket(self):
		global sock
		try :
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		except socket.error, err_msg :
			print 'Failed to create socket'
			sys.exit()
		#Binding a port
		try :
			ip, server_port = self.loadConnectionInformation(CONNECTION_INFORMATION)
			# print "port ", port
			sock.bind(("", int(server_port)))
			print "Server started! on port ", server_port
		except :
			print 'Bind failed '
			sys.exit()

server = ChatServer()
server.start()
