import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import time
from optparse import OptionParser

# pycryptodome for bcrypt implementtaion
from base64 import b64encode
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import bcrypt


# scrypt --> cryptography
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Argon2i --> pynacl
import nacl.pwhash

import psutil

class KDFTuning:
    algo = ''
    password = ''
    running_time = 1
    threshold = running_time + 0.2

    def argon2i(self):
        parallelization = psutil.cpu_count() * 2
        iteration = 9
        max_mem_usage_percent =  psutil.virtual_memory().percent +  12.5 

        memory_factor = 13 # for each of incrementing in factor of 2, starting with minimum 8192


        start_time = time.time()

        while True:
            print('--- %s seconds ---' % (time.time() - start_time), "cpu/memory cost factor" , memory_factor, "Memory Utilization percent" , psutil.virtual_memory().percent)
            if((time.time() - start_time) < self.running_time) and psutil.virtual_memory().percent < max_mem_usage_percent:
                start_time = time.time()
                kdf = nacl.pwhash.argon2id.str(str.encode(self.password), opslimit=iteration, memlimit=2**memory_factor)
            else:
                if((time.time() - start_time) > self.threshold): # Check if its way more than acceptable
                    print('--- %s seconds ---' % (time.time() - start_time), "cpu/memory cost factor" , memory_factor-1, "Memory Utilization percent" , psutil.virtual_memory().percent)
                else:
                    print('--- %s seconds ---' % (time.time() - start_time), "cpu/memory cost factor" , memory_factor, "Memory Utilization percent" , psutil.virtual_memory().percent)
                break
            memory_factor = memory_factor + 1

    def scrypt(self):

        cost = 14

        backend = default_backend()
        salt = os.urandom(16)

        start_time = time.time()

        while True:
            print('--- %s seconds ---' % (time.time() - start_time), "cpu/memory cost factor" , cost)
            if((time.time() - start_time) < self.running_time):
                start_time = time.time()
                kdf = Scrypt(salt=salt,length=32, n=2**cost,r=8,p=1,backend=backend)
                key = kdf.derive(str.encode(self.password))
            else:
                if((time.time() - start_time) > self.threshold): # Check if its way more than acceptable
                    print('--- %s seconds ---' % (time.time() - start_time), "cpu/memory cost factor" , cost-1)
                else:        
                    print('--- %s seconds ---' % (time.time() - start_time), "cpu/memory cost factor" , cost)
                break
            cost = cost + 1


    def pbkdf2(self):
        iterations = 100000
        backend = default_backend()
        salt = os.urandom(16)

        start_time = time.time()

        while True:
            print("--- %s seconds ---" % (time.time() - start_time) , " Iterations " , iterations)
            if((time.time() - start_time) < self.running_time):
                start_time = time.time()
                kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=iterations,backend=backend)
                key = kdf.derive(str.encode(self.password))
            else:
                if((time.time() - start_time) > self.threshold): # Check if its way more than acceptable
                    print("--- %s seconds ---" % (time.time() - start_time) , " Iterations " , iterations-5000)
                else:
                    print("--- %s seconds ---" % (time.time() - start_time) , " Iterations " , iterations)
                break
            iterations = iterations + 5000

    def bcrypt(self):
        cost = 12

        # only accepts passwords up to 72 byte long. 
        # If you want to hash passwords with no restrictions on their length, it is common practice to apply a cryptographic hash and then BASE64-encode 
        b64pwd = b64encode(SHA256.new(str.encode(self.password)).digest())

        start_time = time.time()

        while True:
            print("--- %s seconds ---" % (time.time() - start_time) , " Cost " , cost)
            if((time.time() - start_time) < self.running_time):
                start_time = time.time()
                bcrypt(b64pwd, cost)
            else:
                if((time.time() - start_time) > self.threshold): # Check if its way more than acceptable
                    print("--- %s seconds ---" % (time.time() - start_time) , " Cost " , cost-1)
                else:
                    print("--- %s seconds ---" % (time.time() - start_time) , " Cost " , cost)
                break
            cost = cost + 1

    def parse_command_line(self):
        parser = OptionParser()

        parser.add_option("--algo" , "-a" , action="store" , type="string" , dest="algo" , help = "algo to tune")
        parser.add_option("--password" , "-p" , action="store" , type="string" , dest="password" , help = "password to test")
        parser.add_option("--running_time" , "-t" , action="store" , type="int" , dest="running_time" , help = "acceptable running time in sec")

        (options, args) = parser.parse_args()

        if options.algo is None:
            print("Please specify algo")
        else:    
            self.algo = options.algo

        if options.password is None:
            print("Please specify password")
        else:
            self.password = options.password

        self.running_time = options.running_time    



    def main(self):
        self.parse_command_line()

        if 'pbkdf2' in self.algo:
            self.pbkdf2()
        elif 'bcrypt' in self.algo:
            self.bcrypt()
        elif 'scrypt' in self.algo:
            self.scrypt()
        elif 'argon2i' in self.algo:
            self.argon2i()


if __name__ == "__main__":
    KDFTuning().main()
