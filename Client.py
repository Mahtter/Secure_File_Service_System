import socket
from Communication import UserToken, send_msg, recv_msg, client_handshake  # T3 / T5

# Structure for Communication between Servers
class DistributedClient:
    def __init__(self):
        self.g_sock = None   # becomes a SecureSession after connectGroup (T3/T5)
        self.f_sock = None   # becomes a SecureSession after connectFile  (T3/T5)
        self.token  = None

    # Group Server Methods
    def connectGroup(self, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        # T3 / T5: perform ephemeral X25519 handshake; g_sock is now a SecureSession
        self.g_sock = client_handshake(sock)
        return True

    def disconnectGroup(self):
        self.g_sock.close()

    def getToken(self, userName, password):
        # T1: password is sent inside the AES-GCM encrypted channel — never plaintext
        send_msg(self.g_sock, {"func": "getToken", "params": {"userName": userName, "password": password}})
        self.token = recv_msg(self.g_sock)
        if self.token:
            print(f"DEBUG: Token received for {self.token.userName}. Authorized Groups: {self.token.groups}")
        else:
            print("DEBUG: Failed to receive token from Group Server.")
        return self.token

    def createUser(self, userName, password="changeme"):
        send_msg(self.g_sock, {"func": "createUser", "params": {"userName": userName, "password": password, "userToken": self.token}})
        return recv_msg(self.g_sock)

    def createGroup(self, groupName):
        send_msg(self.g_sock, {"func": "createGroup", "params": {"groupName": groupName, "userToken": self.token}})
        return recv_msg(self.g_sock)

    def addUserToGroup(self, userName, groupName):
        send_msg(self.g_sock, {"func": "addUserToGroup", "params": {"userName": userName, "groupName": groupName, "userToken": self.token}})
        return recv_msg(self.g_sock)

    def listMembers(self, groupName):
        send_msg(self.g_sock, {"func": "listMembers", "params": {"groupName": groupName, "userToken": self.token}})
        return recv_msg(self.g_sock)

    # File Server Methods
    def connectFile(self, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        # T3 / T5: independent ECDHE handshake — completely separate session key from GS
        self.f_sock = client_handshake(sock)
        return True

    def disconnectFile(self):
        self.f_sock.close()

    def listFiles(self):
        send_msg(self.f_sock, {"func": "listFiles", "token": self.token, "params": {}})
        return recv_msg(self.f_sock)

    def upload(self, source, dest, group):
        try:
            with open(source, "rb") as f:
                file_bytes = f.read()
        except FileNotFoundError:
            print(f"Error: Local file '{source}' not found.")
            return False
        send_msg(self.f_sock, {
            "func": "upload",
            "token": self.token,
            "params": {"sourceFile": source, "destFile": dest, "groupName": group, "fileData": file_bytes}
        })
        return recv_msg(self.f_sock)

    def download(self, source, dest):
        send_msg(self.f_sock, {"func": "download", "token": self.token, "params": {"sourceFile": source, "destFile": dest}})
        res = recv_msg(self.f_sock)
        if res and isinstance(res, dict) and res.get("ok"):
            try:
                with open(dest, "wb") as f:
                    f.write(res.get("fileData"))
                return True
            except Exception as e:
                print(f"Write Error: {e}")
                return False
        return False


# Function that prints formatted list of commands
def commLst():
    print("-General-")
    print("\t-help- Shows list of Commands")
    print("\t-exit- Disconnect and end session")
    print("-Group Server-")
    print("\t-connectGroup- Connects to Group Server")
    print("\t-createUser ARG1 ARG2- Creates user ARG1 with password ARG2")
    print("\t-createGroup ARG1- Creates a Group named ARG1")
    print("\t-addToGroup ARG1 ARG2- Adds user ARG1 to group ARG2")
    print("\t-listMembers ARG1- Lists members of group ARG1")
    print("-File Server-")
    print("\t-connectFile- Connects to File Server")
    print("\t-upload ARG1 ARG2 ARG3- upload document with source ARG1 to destination ARG2 within group ARG3")
    print("\t-download ARG1 ARG2- download document with source ARG1 to destination ARG2")
    print("\t-listFiles- Shows list of uploaded files in current group")

# Function to perform login for users on startup
def login():
    un = input("Welcome to ClientConnect v2.0\nUsername: ")
    pw = input("Password: ")
    return un, pw

def FuncList(arglist, usr, pwd):
    if arglist[0] == "help":
        print("List of Commands:")
        commLst()
        return
    elif arglist[0] == "connectGroup":
        print("Connecting to Group Server...")
        print(f"Server Response: {c.connectGroup('localhost', 2004)}")
        print("Getting token...")
        c.getToken(usr, pwd)  # T1: credentials sent inside encrypted channel
        return
    elif arglist[0] == "connectFile":
        print("Connecting to File Server...")
        print(f"Server Response: {c.connectFile('localhost', 2005)}")
        return
    elif arglist[0] == "createUser":
        if len(arglist) < 3:
            print("Usage: createUser USERNAME PASSWORD")
            return
        print(f"Creating user {arglist[1]}...")
        print(f"Server Response: {c.createUser(arglist[1], arglist[2])}")
        return
    elif arglist[0] == "createGroup":
        print(f"Creating group {arglist[1]}...")
        print(f"Server Response: {c.createGroup(arglist[1])}")
        return
    elif arglist[0] == "addToGroup":
        print(f"Adding {arglist[1]} to group {arglist[2]}...")
        print(f"Server Response: {c.addUserToGroup(arglist[1], arglist[2])}")
        return
    elif arglist[0] == "listMembers":
        print(f"Members of group {arglist[1]}:")
        print(f"{c.listMembers(arglist[1])}")
        return
    elif arglist[0] == "upload":
        print(f"Uploading file {arglist[1]}...")
        print(f"Server Response: {c.upload(arglist[1], arglist[2], arglist[3])}")
        return
    elif arglist[0] == "download":
        print(f"Downloading file {arglist[1]}...")
        print(f"Server Response: {c.download(arglist[1], arglist[2])}")
        return
    elif arglist[0] == "listFiles":
        print("Files on server:")
        print(f"{c.listFiles()}")
        return
    else:
        print("Invalid Command")

# Main Code
if __name__ == "__main__":
    c = DistributedClient()
    usr, pwd = login()

    print(f"Welcome {usr}! Use command 'help' for list of commands.")
    y = True
    while y == True:
        x       = input(f"{usr}~$")
        arglist = x.split()
        if not arglist:
            continue
        FuncList(arglist, usr, pwd)
        if arglist[0] == "exit":
            y = False
            print("Disconnecting and ending session...")
