import socket
import pickle
import sys
import random
import json
import gcm
import rsa
import base64
import md5
import hashlib
class ChatParent:
	"""This is Parent class that accomodates the common functions in order to reduce the redundancies in client and server application"""
        global p
        global g
        global N
        global error_msg
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF 
        g = 2
        N = '00:c0:37:c3:75:88:b4:32:98:87:e6:1c:2d:a3:32:4b:1b:a4:b8:1a:63:f9:74:8f:ed:2d:8a:41:0c:2f:c2:1b:12:32:f0:d3:bf:a0:24:27:6c:fd:88:44:81:97:aa:e4:86:a6:3b:fc:a7:b8:bf:77:54:df:b3:27:c7:20:1f:6f:d1:7f:d7:fd:74:15:8b:d3:1c:e7:72:c9:f5:f8:ab:58:45:48:a9:9a:75:9b:5a:2c:05:32:16:2b:7b:62:18:e8:f1:42:bc:e2:c3:0d:77:84:68:9a:48:3e:09:5e:70:16:18:43:79:13:a8:c3:9c:3d:d0:d4:ca:3c:50:0b:88:5f:e3'
        N = int(''.join(N.split()).replace(':', ''), 16)        
	

        error_msg = ["Duplicate User!", "Authentication Failed!", "User does not Exist!", "Client to Client Authentication Failed!"]

        def getK(self):
                self.H(N, g)  # Multiplier parameter (k=3 in legacy SRP-6)

        def getN(self):
                return N        

        def getG(self):
                return int(g)

        def getP(self):
                return int(p)

        def H(self, *args):  # a one-way hash function
                a = ':'.join(str(a) for a in args)
                return int(hashlib.sha256(a.encode('utf-8')).hexdigest(), 16)

        def sendNotification(self, addr, encrypted, msg):
                if encrypted == 1:
                        self.sendMsg({"type":"NOTIFICATION","enc_msg":msg,"encrypted":1}, addr[0], addr[1])
                else:
                        self.sendMsg({"type":"NOTIFICATION","msg":msg,"encrypted":0}, addr[0], addr[1])

	#This function receives a filename and read the content and return them to the caller 
	def readfile(self, tmpFilename):
                try:
                        with open(tmpFilename, 'rb') as handle:
                                handle.seek(0)
                                first_char = handle.read(1)
                                if first_char:
                                        handle.seek(0)
                                        content = pickle.load(handle)
                                        return content
                                else:
                                        return []
                except (IOError, EOFError) as e:
                        print "Error occured while opening file! " + tmpFilename
                        sys.exit(0)

	#To write into a given filename
	def appendfile(self, msg, tmpFilename):
                try:
                        with open(tmpFilename, 'wb') as handle:
                                pickle.dump(msg, handle, protocol=pickle.HIGHEST_PROTOCOL)
                except (IOError, EOFError) as e:
                        print "Error occured while adding user into the file"
                        sys.exit(0)

        def cryptrand(self, N, n=1024):
                return random.SystemRandom().getrandbits(n) % N

        def randomGenerator(self, n):
                bb = random.SystemRandom().getrandbits(n)
                return bb

        def symencrypt(self, msg, ASSOCIATED_DATA, K_c, DELIMETER):
                iv, enc_msg, tag = gcm.aes_encrypt(K_c, msg, ASSOCIATED_DATA)
                enc_final = base64.b64encode(enc_msg + DELIMETER + iv + DELIMETER + tag)
                return enc_final

        def symdecrypt(self, msg, ASSOCIATED_DATA, K_c, DELIMETER):
                testbase = base64.b64decode(msg)
                listbase = testbase.split(DELIMETER)
                dec = gcm.aes_decrypt(K_c, ASSOCIATED_DATA, listbase[1], listbase[0],listbase[2])       
                return dec

        def generateDH(self, a):
                return (g^a) % p

        def DH_sessionkey(self, A,b):
                return md5.new(str(A^b)).digest()

        def getError(self, error_code):
                return error_msg[error_code]
                
        def loadConnectionInformation(self, conn_file):
                port = ""
                ip = ""
                coninfo = self.readfile(conn_file)
                if 'IP' in coninfo.keys():
                        ip = coninfo["IP"]

                if 'PORT' in coninfo.keys():
                        port = coninfo['PORT']

                return ip, int(port)

        