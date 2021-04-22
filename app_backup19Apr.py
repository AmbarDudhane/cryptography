import struct

from Crypto.Cipher import AES
from flask import Flask, render_template, jsonify, make_response, request
import os
import random

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from werkzeug.utils import secure_filename

app = Flask(__name__)
# firstKey = bytes(32)
# secondKey = bytes(32)
firstKey = ""
secondKey = ""
iv = bytes(16)
# ct = bytes()
app.config['UPLOAD_FOLDER'] = "temp"


@app.route('/')
def hello_world():
    return 'Hello World!'


@app.route('/login')
def login():
    return render_template('Login.html')


@app.route('/register')
def register():
    return render_template('register.html')


@app.route('/admin')
def getadmin():
    return render_template('Admin.html')


@app.route('/index')
def index():
    return render_template('Index.html')


@app.route('/generatekey', methods=["GET"])
def generatekey():
    print("in generate key function")
    # firstKey = os.urandom(32)
    global firstKey
    # firstKey = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    firstKey = os.urandom(32)
    print('key', [x for x in firstKey])
    print("generate key:", firstKey)
    res = make_response(jsonify({"key": str(firstKey)}), 200)
    return res


@app.route('/encryptAES', methods=["POST"])
def encryptAES():
    fileobj = request.files['file']

    filename = secure_filename(fileobj.filename.lower())
    fileobj.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    # after saving, encrypt file
    encryptSingleKey(filename)
    return "AES Encryption Successful"


def encryptSingleKey(filename):
    # infile = open("temp//" + filename, "r")

    # iv = ''.join([chr(random.randint(0, 0xFF)) for i in range(16)])
    global iv
    iv = os.urandom(16)
    print("len of iv:", len(iv))
    aes = AES.new(firstKey, AES.MODE_CBC, iv)
    fsz = os.path.getsize("temp//" + filename)
    print("fsz:", fsz)
    fout = open("encrypted//enc_" + filename, 'w')
    # with open("encrypted//enc_" + filename, 'w') as fout:
    fout.write(str(fsz)+"\n")
    fout.write(str(iv) + "\n")
    sz = 2048

    with open("temp//" + filename) as fin:
        while True:
            data = fin.read(sz)
            n = len(data)
            if n == 0:
                break
            elif n % 16 != 0:
                data += '0' * (16 - n % 16)  # <- padded with spaces
            encd = aes.encrypt(data)
            fout.write(str(encd))



@app.route('/decryptAES', methods=["POST"])
def decryptAES():
    fileobj = request.files['defile']

    filename = secure_filename(fileobj.filename.lower())
    fileobj.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    # after saving, decrypt file
    decryptSingleKey(filename)
    return "AES Decryption Successful"


def decryptSingleKey(filename):
    f = open("temp//" + filename, "r")
    lineList = f.readlines()
    fsz = lineList[0]   # original file size
    # iv = lineList[1]    # iv
    encrypted_content = lineList[2]
    encrypted_content = encrypted_content.replace("b", "")
    encrypted_content = encrypted_content.replace("'", "")
    print("Enc content:", encrypted_content)
    global firstKey, iv
    aes = AES.new(firstKey, AES.MODE_CBC, iv)
    decd = aes.decrypt(encrypted_content)
    print("Decrypted Content:", str(decd), "**********")


if __name__ == '__main__':
    app.run()
