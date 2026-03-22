from openreward.environments import Server

from enigma import EnigmaDecrypt

if __name__ == "__main__":
    server = Server([EnigmaDecrypt])
    server.run()
