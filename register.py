import os
import random
import hashlib
import pickle
import argparse
import sys

N = '''00:c0:37:c3:75:88:b4:32:98:87:e6:1c:2d:a3:32:4b:1b:a4:b8:1a:63:f9:74:8f:ed:2d:8a:41:0c:2f:c2:1b:12:32:f0:d3:bf:a0:24:27:6c:fd:88:44:81:97:aa:e4:86:a6:3b:fc:a7:b8:bf:77:54:df:b3:27:c7:20:1f:6f:d1:7f:d7:fd:74:15:8b:d3:1c:e7:72:c9:f5:f8:ab:58:45:48:a9:9a:75:9b:5a:2c:05:32:16:2b:7b:62:18:e8:f1:42:bc:e2:c3:0d:77:84:68:9a:48:3e:09:5e:70:16:18:43:79:13:a8:c3:9c:3d:d0:d4:ca:3c:50:0b:88:5f:e3'''
N = int(''.join(N.split()).replace(':', ''), 16)
g = 2

DATABASE = 'server.database'
def cryptrand(n=1024):
	return random.SystemRandom().getrandbits(n) % N

def readfile(tmpFilename):
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



def appendfile(msg, tmpFilename):
	try:
		with open (tmpFilename, "wb") as handle:
			pickle.dump(msg, handle, protocol=pickle.HIGHEST_PROTOCOL)
	except (IOError, EOFError) as e:
		print "error occured"

def H(*args):
	a = ':'.join(str(a) for a in args)
	return int(hashlib.sha256(a.encode('utf-8')).hexdigest(), 16)

def retreiveUser(username):
	db = readfile(DATABASE)
	for user in db:
		print "testing " + user["username"]
		if user['username'] == username:
			return user


#receiving the arguments entered in comand line
parser = argparse.ArgumentParser()
parser.add_argument('-u', '--username', type=str)
parser.add_argument('-p', '--password', type=str)
args = parser.parse_args()

print str(args.username + "" + args.password)


k = H(N,g)
I = args.username
p = args.password
s = cryptrand(64)
x = H(s, I, p)
v = pow(g,x,N)

# user_data = [{'username': 'I', 'salt': 's', 'verifier': 'v'}]
# appendfile(user_data, DATABASE)
db = readfile(DATABASE)
print "database ", db
db.append({'username': I, 'salt': s, 'verifier': v})
print "database", db
appendfile(db, DATABASE)
print "database", db

retuser = retreiveUser('carol')
print retuser



