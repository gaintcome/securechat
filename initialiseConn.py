from ChatParent import ChatParent
import argparse
class initialiseConnectionFile(ChatParent):
	def initialise_client_conn(self, filename, ip, port):
		conn = {'IP':ip,'PORT':str(port)}
		self.appendfile(conn, filename)
		db = self.readfile(filename)
		print db


#receiving the arguments entered in comand line
parser = argparse.ArgumentParser()
parser.add_argument('-f', '--filename', type=str)
parser.add_argument('-sip', '--ip', type=str)
parser.add_argument('-sp', '--port', type=str)
args = parser.parse_args()


print "filename ", args.filename
print "ip ", args.ip
print "port ", args.port
conn = initialiseConnectionFile()
conn.initialise_client_conn(args.filename, args.ip, args.port)


# USAGE
# python initialiseConn.py -f con.info -sip localhost -sp 8080