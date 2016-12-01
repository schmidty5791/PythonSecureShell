import os, cmd, sys
import hashlib, binascii
from datetime import datetime
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto import Random
import Crypto.Random
import re
import fileinput
import getpass
import logging

# set default values for logging purposes
username = 'no name'
password = 'no pass'
admin = False


############################################# EVALUATE ARGUMENTS #############################################
def evalArgs():
    logging.debug('Evaluating Arguments')
    global username
    global password
    for arg in sys.argv:
        if '--user' in arg:
            username = arg.split('=')[1]
        elif '--password' in arg:
            password = arg.split('=')[1]
        elif '--home' in arg: #check if home folder exists
            if os.path.exists(arg.split('=')[1]):
                os.chdir(arg.split('=')[1])
            else:
                yn = input('Directory does not exist, would you like to create one now? Y/N ')
                if yn == 'Y':
                    print('Making directory: {0}'.format(arg.split('=')[1]))
                    os.mkdir(arg.split('=')[1])
                else:
                    logging.error('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(), 'FAILURE', 'Directory not created'))
                    sys.exit()

    logging.basicConfig(filename='secureShell.log', filemode='w', level=logging.DEBUG) #startup log


############################################# SYSTEM INITIALIZATION #############################################
def sysInit():
    global username
    global password
    global admin

    #if user directory exists - continue
    if os.path.exists('{0}/{1}'.format(os.getcwd(), 'users.txt')):
        users = open('users.txt', 'r')
        if users.readline() == '': #if users empty setup admin account
            username = 'admin'
            password = getpass.getpass('Please input admin password: ')
            password2 = getpass.getpass('Please confirm the password: ')
            if password2 != password:
                logging.error('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(), 'FAILURE', 'Passwords dont match'))
                sysInit()
            else:
                users = open('users.txt', 'w')
                logging.debug('Writing user file')
                admin = True
                users.close()
        elif users.readline() != '': #if users file is initialized: prompt for password
            if username == 'no name':
                username = input('Please enter a valid username: ')
                password = getpass.getpass('Please input admin password: ')
                password2 = getpass.getpass('Please confirm the password: ')
                if password2 != password:
                    logging.error('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(),
                                                                 'FAILURE', 'Passwords dont match'))
                    sysInit()
        #authenticate username and password given from the command line
        authentic = authenticate(username, password)
        if authentic == False:
            logging.error('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(), 'FAILURE', 'Authentication failed'))
            sys.exit()
        if username == 'admin':
            admin = True
            logging.info('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(), 'SUCCESS', 'Admin authenticated'))
        else:
            logging.info('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(), 'SUCCESS', 'User authenticated'))
        SecureShell().cmdloop()

    #if users directory doesnt exist - setup admin account
    else:
        username = 'admin'
        os.system("stty -echo")
        password = input('Please input admin password: ')
        password2 = input('Please confirm the password: ')
        if password2 != password:
            logging.error('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(), 'FAILURE', 'Passwords do not match'))
            sysInit()
        else:
            os.system("stty echo")
            users = open('users.txt', 'w')
            print('Writing user file')
            x = passHash(password)
            users.write('{0}:${1}${2}${3}:{4}'.format(username, x[0], x[1], x[2], datetime.utcnow()))
            logging.info('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(), 'SUCCESS', 'Admin added to users'))
            admin = True
            users.close()


############################################# PASSWORD HASHING #############################################
def passHash(password, salt = Crypto.Random.get_random_bytes(16)):
    encodeNum = 5
    bytePass = salt + bytes(password, 'utf-8')
    hp = hashlib.sha256()
    for i in range(10000): #10000 iterations of hashing
        hp.update(bytePass)
    return (encodeNum, str(b64encode(salt), 'utf-8'), str(b64encode(hp.digest()), 'utf-8'))



############################################# AUTHENTICATE #############################################
def authenticate(username, password):
    logging.debug('Authenticating')
    users = open('users.txt', 'r')
    hp = hashlib.sha256()
    auth = False
    for line in users:
        uname = line.split(':')[0]
        securePass = line.split(':')[1]
        if username == uname:
            salt = b64decode(bytes(securePass.split('$')[2], 'utf-8'))
            hp = hashlib.sha256()
            bytePass = salt + bytes(password, 'utf-8')
            for i in range(10000):
                hp.update(bytePass)
            if str(b64encode(hp.digest()), 'utf-8') == securePass.split('$')[3]:
                auth = True
    return auth


############################################# SECURE SHELL #############################################
class SecureShell(cmd.Cmd):
    global username
    print(os.getcwd())
    intro = 'Type help or ? to list commands. \n '
    prompt = '>'
    # Basic commands
    def do_adduser(self, s):
        'Causes a user to be added to the system. Each username must be unique in the system. \nadduser username password'
        if admin == True:
            a = s.split()
            if len(a) != 2:
                print('Invalid format. Try adduser username password')
                return
            elif len(a) == 2:
                x = passHash(a[1])
                users = open('users.txt', 'r')
                for line in users: #Check if username already in users
                    if a[0] == line.split(':')[0]:
                        logging.error('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(),
                                                               'FAILURE', 'User already exists'))
                        return
                users.close()
                users = open('users.txt', 'a')
                users.write('\n{0}:${1}${2}${3}:{4}'.format(a[0], x[0], x[1], x[2], datetime.utcnow()))
                users.close()
        else:
            logging.error('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(), 'UNAUTHORIZED', 'Cannot add user'))

    def do_setpassword(self, s):
        'Allows the current user to change his/her password. \nsetpassword password'
        a = s.split()
        userExists = False
        count = -1
        x = passHash(a[0])
        users = open('users.txt', 'r+')
        for line in users:
            count += 1
            if username in line:
                userExists = True
                break
        users = open('users.txt', 'r+')
        content = users.readlines()  # reads line by line and out puts a list of each line

        content[count] = '{0}${1}${2}${3}${4}\n'.format(username, x[0], x[1], x[2], datetime.utcnow())
        users.close()
        users = open('users.txt', 'w')  # clears content of file.
        users.close()
        users = open('users.txt', 'r+')
        for item in content:  # rewrites file content from list
            print(item)
            users.write(item)
        users.close()
        if userExists == True:
            logging.info('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(), 'SUCCESS', 'User Changed Password'))
            print('SUCCESS')
        else:
            logging.error('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(),
                                                   'FAILURE', 'User failed to changer pass'))
            print('FAILURE')

    #Exit Command
    def do_exit(self, s):
        'Exits the system'
        return True

    def do_encrypt(self, s):
        'Encrypts and integrity protects a file'
        fileName = s.split()[0]
        password = s.split()[1]
        hashObj = passHash(password)
        hashedPass = hashObj[2]
        salt = hashObj[1]

        key = b64decode(bytes(hashedPass, 'utf-8'))
        digest = hashlib.sha256()
        iv = b'\x00' * 16

        #checking to make sure the files db exists and there isnt a file with the same name archived
        if os.path.exists('files.txt'):
            filedb = open('files.txt', 'r')

            #check if file name in files manifest
            for lines in filedb:
                if fileName == lines.split(':')[0]:
                    logging.error('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(),
                                                           'FAILURE', 'File already exists'))
                    filedb.close()
                    return
            filedb.close()

        filedb = open('files.txt', 'a')
        # check that file and destination dir exists
        if os.path.exists(fileName):
            if not os.path.exists('data'):
                os.mkdir(os.getcwd()+'/data')

            file = open(fileName, 'rb')  #open file to encrypt as binary
            e_file = open('{0}\data\{1}.enc'.format(os.getcwd(), fileName.split('.')[0]), 'wb') #create encrypted file in data
            encryptor = AES.new(key, AES.MODE_CBC, iv)

            while True:
                chunk = file.read(16)
                digest.update(chunk)
                if len(chunk) == 0:
                    break
                elif len(chunk)%16 != 0: #if it is not of block size, pad
                    x = 16 - len(chunk)
                    chunk += bytes([x])*x #add padding
                e_file.write(encryptor.encrypt(chunk)) #write encrypted chunk to encrypted file
            file.close()
            e_file.close()

            filedb.write('\n{0}:{1}:{2}:{3}:'.format(fileName, str(b64encode(digest.digest()), 'utf-8'),
                                                      salt, username))
            filedb.close()
        else:
            logging.error('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(),
                                                         'FAILURE', 'File does not exist'))

    def do_decrypt(self, s):
        'Checks that the user is authorized to decrypt the file and, if so, decrypts the file.'
        fileExists = False
        e_file = s.split()[0]
        file = s.split()[1]
        password = s.split()[2]
        digest = hashlib.sha256()

        #check that encrypted files manifest exists
        if os.path.exists('files.txt'):
            secureFiles = open('files.txt', 'r')
            #check the files manifest for the encrypted file
            for lines in secureFiles:
                if lines.split(':')[0] == e_file:
                    logging.debug('File found in manifest')
                    fileExists = True
                    salt = b64decode(bytes(lines.split(':')[2], 'utf-8'))
                    integrityField = lines.split(':')[1]
                    owner = lines.split(':')[3]
                    authUsers = lines.split(':')[4].split(',')
                    break

            if fileExists == False:
                #log error
                logging.error('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(),
                                                       'FAILURE', 'File not in manifest'))
                return

            #check if user is authorized
            if username == owner or username in authUsers:
                infile = open(os.getcwd() + '/data/' + e_file.split('.')[0] + '.enc', 'rb')
                outfile = open(file, 'wb')
                iv = b'\x00' * 16
                hashObj = passHash(password, salt)
                hashedPass = hashObj[2]
                key = b64decode(bytes(hashedPass, 'utf-8'))
                rawText = b''
                decryptor = AES.new(key, AES.MODE_CBC, iv) #initiate decryptor
                while True: #start decryption
                    chunk = infile.read(16)
                    if len(chunk) == 0: # check for end of file
                        #unpad
                        break
                    rawText += decryptor.decrypt(chunk)

                rawText = rawText[:len(rawText) - rawText[len(rawText) - 1]] #remove padding
                outfile.write(rawText)

                digest.update(rawText)

                if str(b64encode(digest.digest()), 'utf-8') == integrityField:
                    print('Success.')
                outfile.close()
                infile.close()


            else:
                logging.error('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(),
                                                       'UNAUTHORIZED', 'User not authorized to decrypt'))




    def do_authorize(self, s):
        'Allows a user to access a protected file. Only the owner of the file can successfully authorize other users.'
        newAuthUser = s.split()[0]
        e_file = s.split()[1]
        newManifest = ''
        secureFiles = open('files.txt', 'r')
        fileExists = False

        # check the files manifest for the encrypted file
        for lines in secureFiles:
            if lines.split(':')[0] == e_file:
                logging.debug('File found in manifest')
                fileExists = True
                fileName = lines.split(':')[0]
                integrityVal = lines.split(':')[1]
                codeSalt = lines.split(':')[2]
                owner = lines.split(':')[3]
                users = lines.split(':')[4].split(',')

                #check if user already authorized
                for user in users:
                    if user == newAuthUser:
                        logging.error('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(),
                                                   'FAILURE', 'User already authorized'))
                        return
                if newAuthUser == owner:
                    logging.error('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(),
                                                                 'FAILURE', 'User already authorized'))
                    return
                lines = '{0}:{1}:{2}:{3}:'.format(fileName, integrityVal, codeSalt, owner)
                users.append(newAuthUser)
                for user in users:
                    if user == ' ':
                        users.remove(' ')
                    if user == '':
                        users.remove('')

                for user in users:
                    if user != ' ':
                        lines = lines.rstrip('\n') + '{0},\n'.format(user)
            newManifest += lines
        secureFiles.close()
        print(newManifest)
        if fileExists == False:  # if file
            logging.error('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(),
                                                   'FAILURE', 'File not in manifest'))
            return
        elif owner != username:
            logging.error('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(),
                                                   'UNAUTHORIZED', 'User not authorized to authorize file'))
            return
        else:
            secureFiles = open('files.txt', 'w')
            secureFiles.write(newManifest)
            secureFiles.close()
            print('SUCCESS')
            return



    def do_deauthorize(self, s):
        'Removes access to a protected file. Only the owner of the file can successful deauthorize users.'
        remAuthUser = s.split()[0]
        e_file = s.split()[1]
        newManifest = ''
        secureFiles = open('files.txt', 'r')
        fileExists = False
        # check the files manifest for the encrypted file
        for lines in secureFiles:
            if lines.split(':')[0] == e_file:
                logging.debug('File found in manifest')
                fileExists = True
                fileName = lines.split(':')[0]
                integrityVal = lines.split(':')[1]
                codeSalt = lines.split(':')[2]
                owner = lines.split(':')[3]
                users = lines.split(':')[4].split(',')

                #check if user to add is among auth users
                if remAuthUser in users:
                    users.remove(remAuthUser)
                else:
                    logging.error('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(),
                                                   'FAILURE', 'User not found'))
                lines = '{0}:{1}:{2}:{3}:'.format(fileName, integrityVal, codeSalt, owner)
                for user in users:
                    lines += '{0}, '.format(user)
            newManifest += lines
        secureFiles.close()
        print(newManifest)
        if fileExists == False:  # if file
            logging.error('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(),
                                                   'FAILURE', 'File not in manifest'))
            return
        elif owner != username:
            logging.error('{0} $ {1} $ {2} $ {3}'.format(username, datetime.utcnow(),
                                                   'UNAUTHORIZED', 'User not authorized to authorize file'))
            return
        else:
            secureFiles = open('files.txt', 'w')
            secureFiles.write(newManifest)
            secureFiles.close()
            print('SUCCESS')
            return
if __name__ == '__main__':
    evalArgs()
    sysInit()

