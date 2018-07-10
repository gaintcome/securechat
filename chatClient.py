import argparse
import hashlib
import sys
import json
import socket
import select
import gcm
import hmac
import rsa
import base64
# import random
import getpass
import time
from ChatParent import ChatParent

# Declaring Constant Values 
PUBLIC_KEY_FILE = 'pubkey.pub'
ASSOCIATED_DATA = 'TEST'
DELIMETER = "||"	
CONNECTION_INFORMATION = 'con.info.client'

#Declaration of global variables
global client_addr
global msg_tobesent
global command_username
global sessionkeys

class ChatClient(ChatParent):

	def start(self):
		self.check_arguments()
		self.open_socket()
		self.ping()
		self.signin()
		client_addr = {}
		command_username = ""
		sessionkeys = {}
		M1 = ""
		while(1) :
			socket_list = [sys.stdin, s]
			# Get the list of sockets
			read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])
			# The client does either listen to incoming messages or check the user input 
			for sock in read_sockets:
				if sock == s:
					# This part print the recieved messages from the other users
					recv_msg,addr = sock.recvfrom(65565)
					parsed_msg = json.loads(recv_msg)
						
					if parsed_msg['type'] == "SRP_RES":						
						self.calcualteSessionKey(SRPA, parsed_msg['SRP'], parsed_msg['salt'], user, password)
						M1 = self.prepare_SRP_msg3(SRPA, parsed_msg['SRP'])
					elif parsed_msg['type'] == "SERVER_AUTHENTICATION":
						M2 =parsed_msg['hash']
						if (M2 == self.H(SRPA,M1,K_c)):
							sys.stdout.write('+> '); sys.stdout.flush()
							pass # Mutual Athentication is completed in this step
						else:
							print "Server Authentication Failed!"
							sys.exit()

					#Response of List message request is received
					elif parsed_msg['type'] == "LIST_REP":
						sys.stdout.write('-< '); sys.stdout.flush()
						print "Signed users:", self.symdecrypt(parsed_msg['enc_msg'], ASSOCIATED_DATA,K_c,DELIMETER)
						sys.stdout.write('+> '); sys.stdout.flush()

					#Response of Client Info, such as IP and Port
					elif parsed_msg['type'] == "MESSAGE_REP":
						try:
							msg = self.symdecrypt(parsed_msg['enc_msg'], ASSOCIATED_DATA,K_c,DELIMETER)
							parsed_msg = json.loads(msg)
							if self.verifyNonce(N1,int(parsed_msg['N1-1'] + 1)):
								del N1
								N2 = self.randomGenerator(64)
								# Building Server Ticket and ecnrypt it with Server's public key
								msg6 = '{"N2":' + str(N2) + ',"AC":' + str(parsed_msg['AC']) + ',"from":"' + user + '","to":"' + parsed_msg['USER'] + '"}'
								pk = rsa.loadPublickey(PUBLIC_KEY_FILE)
								enc = rsa.rsaen(str(msg6), pk)	
								enc_msg6 = base64.b64encode(enc)
								client_addr = {}
								client_addr[0] = parsed_msg['IP']
								client_addr[1] = int(parsed_msg['PORT'])
								#Sending msg to Bob
								self.sendMsg({"type":"SERVERTICKET","server_ticket":enc_msg6 }, str(client_addr[0]), int(client_addr[1]))	
							else:
								#N-1 is not correct stop the program
								print "N1-1 recievde from server is not correct"
								sys.stdout.write('+> '); sys.stdout.flush()
						except:
							print "Error Occured in MESSAGE_REP"	
							sys.stdout.write('+> '); sys.stdout.flush()
					elif parsed_msg["type"].lower() == "serverticket":
						#Client is received a message named 'serverticket'. It indicates that someones want to have a chat with him securely.
						#He needs to send the received ticket, which is encrypted with the server's publc key, to the server.
						global N3
						client_addr = addr
						try:
							N3 = self.randomGenerator(64)
							server_ticket = parsed_msg["server_ticket"]
							enc_final = '{"type":"AUTH_ALICE_TO_BOB","N3":' + str(N3) + '}'
							iv, enc_final, tag = gcm.aes_encrypt(K_c, str(enc_final), ASSOCIATED_DATA)
							enc_final = base64.b64encode(enc_final + DELIMETER + iv + DELIMETER + tag);
							self.sendMsg({"type":"SERVERTICKET_DELIVER","server_ticket":server_ticket, "enc_msg": enc_final, "encrypted":1, "username":user},server_IP, server_port)
						except:
							print "Error Occured while receiving server_ticket from client!"
							sys.stdout.write('+> '); sys.stdout.flush()
					elif parsed_msg["type"] == "AUTH_SERVER_TO_BOB":
						# This is the reponse to the message that the client had previusly sent the message named 'serverticket'. 
						# Server generates N3-1, N4 and a ticket that can be read only by the sender
						try:
							msg = self.symdecrypt(parsed_msg["enc_msg"], ASSOCIATED_DATA, K_c, DELIMETER)
							msg = json.loads(msg)
							global a
							global N4
							N4 = 0
							a = 0
							if self.verifyNonce(N3, int(msg["N3-1"] + 1)):
								del N3
								alice_ticket = msg["alice_ticket"]
								a = self.randomGenerator(64)
								myDH = self.generateDH(a)
								N4 = msg["N4"]
								#Generating Message Authentication Code to prove authentication
								authentication_code =  hmac.generateMAC(str(myDH), str(N4))
								self.sendMsg({"type":"KE_REQ","alice_ticket":alice_ticket,"DH":myDH,"MAC":authentication_code}, client_addr[0], client_addr[1])
							else:
								print "N3 not valid"
								sys.stdout.write('+> '); sys.stdout.flush()
						except:
							print "Error Occured while sending the Key exchange Request!"
							sys.stdout.write('+> '); sys.stdout.flush()
					elif parsed_msg["type"] == "KE_REQ":
						#Start of Diffie-Hellman Key Exchange 
						#The First DE contribution is received by the sender client.
						try:
							msg = self.symdecrypt(parsed_msg["alice_ticket"], ASSOCIATED_DATA, K_c, DELIMETER)
							msg = json.loads(msg)


							if self.verifyNonce(N2,int(msg["N2-1"]+1)):
								del N2
								N4 = msg["N4"]
								DH_a = parsed_msg['DH']
								#Verifying MAC to ensure the authenticity of the message and DH contribution
								if parsed_msg["MAC"] == hmac.generateMAC(str(DH_a), str(N4)):
									b = self.randomGenerator(64)
									DH_b = self.generateDH(b)

									sessionkey = self.DH_sessionkey(DH_a, b)
									if command_username != "":
										sessionkeys[str(command_username)] = sessionkey + DELIMETER + str(client_addr[0]) + DELIMETER + str(client_addr[1])
										authentication_code = hmac.generateMAC(str(DH_b), str(N4))
										self.sendMsg({"type":"KE_RES","username":str(user),"enc_msg":"encrypted","DH":DH_b,"N4-1":str(int(N4-1)),"MAC":authentication_code}, addr[0], addr[1])
										time.sleep(0.05)
										self.sendSecureMsg(str(user) + DELIMETER + msg_tobesent, sessionkey, client_addr[0], client_addr[1])
										msg_tobesent = ""
									else:
										print "An Error Occured while saving client's session key in memory!"
										sys.stdout.write('+> '); sys.stdout.flush()
								else:
									print self.getError(3)
									sys.stdout.write('+> '); sys.stdout.flush()
									self.sendNotification(client_addr, 0, 3)
								
								del b, DH_a
								del DH_b
							else:
								print "N2 is not valid"
								sys.stdout.write('+> '); sys.stdout.flush()
						except:
							print "Error Occured while sending Second Key Exchange!"
							sys.stdout.write('+> '); sys.stdout.flush()
					elif parsed_msg["type"] == "KE_RES":
						#The client sends his own DH contribution
						if self.verifyNonce(N4,int(parsed_msg["N4-1"])+1):
							del N4
							DH_b = parsed_msg['DH']
							#Checking the generated MAC to ensure the authenticity of the sender
							if parsed_msg["MAC"] == hmac.generateMAC(str(DH_b), str(int(parsed_msg["N4-1"])+1)):
								sessionkey = self.DH_sessionkey(DH_b, a)
								sessionkeys[parsed_msg['username']] = sessionkey + DELIMETER + str(client_addr[0]) + DELIMETER + str(client_addr[1])
								del DH_b, a
							else:
								print self.getError(3)
								sys.stdout.write('+> '); sys.stdout.flush()
								try:
									self.sendNotification(client_addr, 0, 3)
								except:
									print "Error Occured while receving DH contribution of sending client!"
									sys.stdout.write('+> '); sys.stdout.flush() 
						else:
							print "N4 is not valid"

					elif parsed_msg['type'] == "SECURE_MESSAGE":
						#After DH Key Exchange, Messages are sent with the message type named 'Secure_Message' that is encrypted using the session key
						try:
							sys.stdout.write('\n-< '); sys.stdout.flush()
							self.recvSecureMsg(parsed_msg['enc_msg'], addr, sessionkeys[str(parsed_msg['username'])].split(DELIMETER)[0])
							sys.stdout.write('+> '); sys.stdout.flush()
						except:
							print "Error Occured while sending SECURE_MESSAGE"
							sys.stdout.write('+> '); sys.stdout.flush()
					elif parsed_msg['type'] == "DUPLICATE_USER":
						print "Duplicate user! Please use another user"
						sys.exit()
					elif parsed_msg['type'] == "NOTIFICATION":
						self.handleError(parsed_msg)
					elif parsed_msg['type'] == "up":
						continue	
					else:
						print "program crashed! Start over! " 
						sys.stdout.write('+> '); sys.stdout.flush()
				else :
					#Commands are entered by the client
					msg = sys.stdin.readline()
					if len(msg.split())>0:
						getCommand = msg.split()[0] # Extract command from command line

						if getCommand == "list":
							try:
								enc = self.symencrypt('{"type":"LIST"}', ASSOCIATED_DATA, K_c, DELIMETER)
								self.sendMsg({"enc_msg":enc,"encrypted":1,"username":user}, server_IP, server_port)
							except:
								print "Something is wrong! `list` is not working"
								sys.stdout.write('+> '); sys.stdout.flush()
						# "Send" command send a message to a specific user
						elif getCommand == "send":
							if len(msg.split()) == 1:
								print "Select one user from the output of `list` command"
								sys.stdout.write('+> '); sys.stdout.flush()
								continue
							elif len(msg.split()) == 2:
								print "Please enter your message!"
								sys.stdout.write('+> '); sys.stdout.flush()
								continue

							command_username = msg.split(" ")[1]
							msg_tobesent = msg.split(" ")[2:]
							msg_tobesent = " ".join(msg_tobesent)

							if user == command_username:
								sys.stdout.write('-< '); sys.stdout.flush()
								print "<From Myself:" + command_username + ">: " + msg_tobesent
								sys.stdout.write('+> '); sys.stdout.flush()
								continue

							#truncating too long msg
							msg_tobesent = msg_tobesent[0:4000]
							if not command_username in sessionkeys.keys():
								#Sesison key is not alreadt setup. So SRP needs to be done between server and client
								try:
									N1 = self.randomGenerator(64)
									# We need to ask from server what is the IP address and port of the user
									enc = self.symencrypt('{"type":"MESSAGE","target_user":"'+command_username+'","N1":'+str(N1)+'}', ASSOCIATED_DATA, K_c, DELIMETER)
									self.sendMsg({"enc_msg":enc,"encrypted":1,"username":user}, server_IP, server_port)
									sys.stdout.write('+> '); sys.stdout.flush()
								except:
									print "Error Occured while getting the client into from Server!"
									sys.stdout.write('+> '); sys.stdout.flush()
							else:
								if command_username != "":
									try:
										command_username = str(command_username)
										self.sendSecureMsg(str(user) + DELIMETER + msg_tobesent, sessionkeys[command_username].split(DELIMETER)[0], sessionkeys[command_username].split(DELIMETER)[1], sessionkeys[command_username].split(DELIMETER)[2])
										sys.stdout.write('+> '); sys.stdout.flush()
									except:
										print "Error Occured while sending secure message directly to client!"
										sys.stdout.write('+> '); sys.stdout.flush()
								else:
									print "Your Command Should be send<SPACE>recipient<SPACE>msg"
									sys.stdout.write('+> '); sys.stdout.flush()
							
						elif getCommand == "exit":
							try:
								enc = self.symencrypt('{"type":"LOGOUT"}', ASSOCIATED_DATA, K_c, DELIMETER)
								self.sendMsg({"enc_msg":enc,"encrypted":1,"username":user}, server_IP, server_port)
								sys.stdout.write('+> '); sys.stdout.flush()
							except:
								print "error on exit"		
								sys.stdout.write('+> '); sys.stdout.flush()					
							exit =1
							sys.exit()
						else:
							print "Command Does not Exist!"
							sys.stdout.write('+> '); sys.stdout.flush()
					else:
						continue
					
	
	#Command-name: SIGN-IN
	#Once the command is entered by the client, command for signin will be send to the server.	
	def signin(self):
		#SIGN-IN protocol format
		self.init_SRP_parameter()
		# SRP paramter initialising
		self.prepare_SRP_msg1()

##################################################################################################
##################################################################################################
##################################################################################################
	def sendSecureMsg(self, msg, sessionkey, ip, port):
		enc_msg = self.symencrypt(str(msg), ASSOCIATED_DATA, sessionkey, DELIMETER)
		self.sendDirectMsg({"type":"SECURE_MESSAGE","enc_msg":enc_msg,"username":str(user)}, ip, int(port))

	def recvSecureMsg(self, enc_msg, addr, sessionkey):
		decrypted_msg = self.symdecrypt(enc_msg,ASSOCIATED_DATA,sessionkey, DELIMETER)
		print "<From "+str(addr[0])+":"+str(addr[1])+":" + decrypted_msg.split(DELIMETER)[0] + ">: " + str(decrypted_msg.split(DELIMETER)[1])


	def handleError(self, parsed_msg):
		msg = ""
		if parsed_msg['encrypted'] == 1:
			msg = self.symdecrypt(parsed_msg['enc_msg'], ASSOCIATED_DATA,K_c,DELIMETER)	
		elif parsed_msg['encrypted'] == 0:
			msg = parsed_msg['msg']
		else:
			print "Unexpected Value for 'ecnrypted' value: ", parsed_msg['ecnrypted']
			sys.stdout.write('+> '); sys.stdout.flush()

		if int(msg) == 1:
			print self.getError(int(msg))
			sys.exit(1)	
		elif int(msg) == 2:
			print self.getError(int(msg))
			sys.stdout.write('+> '); sys.stdout.flush()
		elif int(msg) == 3:
			print self.getError(int(msg))
			sys.stdout.write('+> '); sys.stdout.flush()

	def verifyNonce(self, nonce, recievedNonce):
		if nonce == recievedNonce:
			return True
		else:
			return False

	def displayMsg(self, theList):
		msg = ""
		for x in theList:
			print "x ", x
			msg = msg + x + " "
		return msg


	def ping(self):
		try:
			pmsg = {"type":"PING","encrypted":0}
			jsonmsg = json.dumps(pmsg)
			s.sendto(jsonmsg, (server_IP, server_port))
		except (IOError,OverflowError):
			print "Server is not accessible! Are you sure server IP and PORT are correct?"
			sys.exit()
		try:
			s.settimeout(2)
			recv_msg,addr = s.recvfrom(65565)
			parsed_msg = json.loads(recv_msg)
			if parsed_msg['type'] == "up":
				return # server is up
		except:
			print "server is down!"
			sys.exit()

	def open_socket(self):
		try:
			global s
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		except:
			print 'Failed to create socket'
			sys.exit()

	def calcualteSessionKey(self, SRPA, SRPB, salt, user, password):
		global K_c
		u = self.H(SRPA,SRPB)  # Random scrambling parameter
		x = self.H(salt, user, password)
		S_c = pow(SRPB - k * pow(self.getG(), x, self.getN()), a + u * x, self.getN())
		K_c = self.H(S_c)
		K_c = hashlib.md5(str(K_c)).hexdigest()	


	def prepare_SRP_msg1(self):
		global SRPA
		global a
		a = self.cryptrand(self.getN(), 64)
		SRPA = pow(self.getG(), a, self.getN())
		self.sendMsg({"type":"SIGNIN","encrypted":0,"username":user,"SRP":SRPA}, server_IP, server_port)

	def prepare_SRP_msg3(self, SRPA, SRPB):
		M1=self.H(SRPA,SRPB,K_c)
		self.sendMsg({"type":"CLIENT_AUTHENTICATION","hash":M1,"encrypted":0}, server_IP, server_port)
		return M1

	def init_SRP_parameter(self):
		global k
		k = self.H(self.getN(), int(self.getG()))  # Multiplier parameter (k=3 in legacy SRP-6)

	def sendMsg(self, msg, ip, port):
		self.ping()
		jsonmsg = json.dumps(msg)
		s.sendto(jsonmsg, (ip, port))

	def sendDirectMsg(self, msg, ip, port):
		jsonmsg = json.dumps(msg)
		s.sendto(jsonmsg, (ip, port))		

	def check_arguments(self):
		global user
		global server_IP
		global server_port
		global password

		
		user = raw_input('username: ')
		password = getpass.getpass("password: ")
		server_IP, server_port = self.loadConnectionInformation(CONNECTION_INFORMATION)	

#Calling Sign-in function to sign the user in.
c = ChatClient()
c.start()

# http://www.saltycrane.com/blog/2008/01/saving-python-dict-to-file-using-pickle/
# http://www.bogotobogo.com/python/python_network_programming_tcp_server_client_chat_server_chat_client_select.php
