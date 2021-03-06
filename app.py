"""
Reference: https://www.thepythoncode.com/article/encrypt-decrypt-files-symmetric-python
RSA reference: https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/
"""
from cryptography.hazmat.backends import default_backend
from flask import Flask, render_template, jsonify, make_response, request, send_file, url_for, redirect
import os
from flask_mysqldb import MySQL
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from HashGenerate import HashGenerator

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = "temp"
# app.config['MYSQL_HOST'] = '127.0.0.1'
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PASSWORD'] = 'mysql123'
# app.config['MYSQL_DB'] = 'assignment3'

app.config['MYSQL_HOST'] = 'us-cdbr-east-03.cleardb.com'
app.config['MYSQL_USER'] = 'b4d5ecf0dad370'
app.config['MYSQL_PASSWORD'] = '42506877'
app.config['MYSQL_DB'] = 'heroku_3e5380c16d35e48'

mysql = MySQL(app)


@app.route('/')
def hello_world():
    return render_template('Login.html')


@app.route('/login')
def login():
    return render_template('Login.html')


@app.route('/checklogin', methods=['POST'])
def checklogin():
    if request.method == 'POST':
        result = request.form

        temp = (result["login"], result["password"])

        cur = mysql.connection.cursor()
        cur.execute("SELECT email, password FROM tbluser")
        rv = cur.fetchall()

        cur.close()

        if result["login"] == "Admin" and result["password"] == "admin":
            return redirect(url_for('getadmin'))
        elif temp in rv:
            return render_template("Index.html", username=temp[0])
        else:
            return "Login unsuccessful"

    return ""


@app.route('/showregister')
def showregister():
    return render_template('register.html')


@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        firstname = request.form['first_name']
        lastname = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO tbluser (email, first_name, last_name, password) VALUES (%s, %s, %s, %s)",
                    (email, firstname, lastname, password))
        mysql.connection.commit()
        cur.close()
        # flash('Record was successfully added')
        print(request.form['first_name'], " Record added successfully")
    return render_template('success_register.html')


@app.route('/admin')
def getadmin():
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, email, first_name, last_name from tbluser")
    userdatarv = cur.fetchall()
    cur.close()
    return render_template("Admin.html", userdata=userdatarv)


@app.route('/getadduser')
def getadduser():
    return render_template("AdminAddUser.html")


@app.route('/addnewuser', methods=['POST'])
def addnewuser():
    email = request.form['email']
    firstname = request.form['fname']
    lastname = request.form['lname']
    password = request.form['password']
    cur = mysql.connection.cursor()
    cur.execute("SELECT email FROM tbluser")
    rv = cur.fetchall()
    print("add new user:", rv)
    for t in rv:
        if email == t[0]:
            return "Email Already exists. Enter another email."

    cur.execute("INSERT INTO tbluser (email, first_name, last_name, password) VALUES (%s, %s, %s, %s)",
                (email, firstname, lastname, password))
    mysql.connection.commit()
    cur.close()
    return "New user added successfully. <a href='admin'>Go To Admin Page</a>"


@app.route('/edituser')
def edituser():
    id = request.args.get("id")
    print("Edit user id:", id)
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM tbluser where id=" + id)
    rv = cur.fetchall()
    print("rv:", rv)
    cur.close()
    return render_template("AdminEditUser.html", userdata=rv)


@app.route('/deleteuser')
def deleteuser():
    id = request.args.get("id")
    cur = mysql.connection.cursor()
    deleteQuery = "DELETE FROM tbluser where id=" + id
    cur.execute(deleteQuery)
    mysql.connection.commit()
    cur.close()
    return "User record deleted. <a href='admin'>Go To Admin Page</a>"


@app.route('/updateuser', methods=['POST'])
def updateuser():
    id = request.args.get("id")
    print("update user record id:", id)
    email = request.form['email']
    firstname = request.form['fname']
    lastname = request.form['lname']
    password = request.form['password']
    print("email:" + email + ", firstname:" + firstname + ", lastname:" + lastname + ", password:" + password)
    updateQuery = "UPDATE tbluser SET email='" + email + "', first_name='" + firstname + "', last_name='" + lastname + "', password='" + password + "' where id=" + id
    cur = mysql.connection.cursor()
    cur.execute(updateQuery)
    mysql.connection.commit()
    cur.close()
    print(id, " user record updated")
    return "User record updated. <a href='admin'>Go To Admin Page</a>"


@app.route('/gethash')
def gethash():
    username = request.args.get("username")
    return render_template('Hash.html', username=username)


@app.route('/downloadfile')
def download():
    filename = request.args.get('filename')
    enc = request.args.get("enc")
    print(filename + ", enc:" + enc)
    if enc == 'true':  # return file from encrypted folder
        return send_file(r'./encrypted/' + filename, as_attachment=True)
    elif enc == 'false':  # return file from decrypted folder
        return send_file(r'./decrypted/' + filename, as_attachment=True)
    return ""


@app.route('/getAES')
def getAES():
    print("in getAES")
    username = request.args.get("username")
    return render_template('AES_Encryption.html', username=username)


@app.route('/getRSA')
def getRSA():
    print("in getRSA")
    username = request.args.get("username")
    return render_template('RSA_Encryption.html', username=username)


@app.route('/generateRSAPrivateKey')
def generateRSAPrivateKey():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open('RSA keys//private_key.pem', 'wb') as f:
        f.write(pem)
    res = make_response(jsonify({"Private Key Status": "Generated"}), 200)
    return res


@app.route('/generateRSAPublicKey')
def generateRSAPublicKey():
    with open("RSA keys//private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open('RSA keys//public_key.pem', 'wb') as f:
            f.write(pem)

    res = make_response(jsonify({"Public Key Status": "Generated"}), 200)
    return res


@app.route('/downloadkey')
def downloadkey():
    keytype = request.args.get("keytype")
    print("keytype:", keytype)

    try:
        if keytype == 'private':
            return send_file(r'./RSA keys/private_key.pem', as_attachment=True)
        elif keytype == 'public':
            return send_file(r'./RSA keys/public_key.pem', as_attachment=True)
    except Exception as e:
        return str(e)

    return ""


@app.route('/encryptRSA', methods=["POST"])
def encryptRSA():
    fileobj = request.files['file']

    filename = secure_filename(fileobj.filename.lower())
    fileobj.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    # after saving, encrypt file
    with open("temp//" + filename, "rb") as file:
        # read all file data
        file_data = file.read()

    with open("RSA keys//public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    encrypted = public_key.encrypt(
        file_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # write the encrypted file
    with open("encrypted//enc_" + filename, "wb") as file:
        file.write(encrypted)
    return "RSA Encryption Successful. You can <a href='downloadfile?filename=enc_" + filename + "&enc=true'>download the file here</a>"


@app.route('/decryptRSA', methods=["POST"])
def decryptRSA():
    fileobj = request.files['defile']

    filename = secure_filename(fileobj.filename.lower())
    fileobj.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    # after saving, decrypt file
    with open("temp//" + filename, "rb") as file:
        # read all file data
        file_data = file.read()

    with open("RSA keys//private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    original_message = private_key.decrypt(
        file_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # write the decrypted file
    with open("decrypted//dec_" + filename, "wb") as file:
        file.write(original_message)

    return "RSA Decryption Successful. You can <a href='downloadfile?filename=dec_" + filename + "&enc=false'>download the file here</a>"


@app.route('/savenewpassword', methods=["POST"])
def savenewpassword():
    req = request.get_json()
    print("new password:", req)

    cur = mysql.connection.cursor()
    update_query = "UPDATE tbluser SET password = '" + req['password'] + "' WHERE email='" + req['username'] + "'"
    print("update query:", update_query)
    cur.execute(update_query)
    mysql.connection.commit()
    cur.close()
    res = make_response(jsonify({"Password Status": "Saved"}), 200)
    return res


def write_key(key):
    with open("key.key", "wb") as key_file:
        key_file.write(key)


def load_key():
    return open("key.key", "rb").read()


@app.route('/generatekey', methods=["GET"])
def generatekey():
    print("in generate key function")
    key = Fernet.generate_key()
    write_key(key)  # save key locally
    res = make_response(jsonify({"key": str(key)}), 200)
    return res


@app.route('/encryptAES', methods=["POST"])
def encryptAES():
    fileobj = request.files['file']

    filename = secure_filename(fileobj.filename.lower())
    fileobj.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    # after saving, encrypt file
    msg = encryptSingleKey(filename)
    return msg


def encryptSingleKey(filename):
    key = load_key()
    f = Fernet(key)

    with open("temp//" + filename, "rb") as file:
        # read all file data
        file_data = file.read()

    # encrypt data
    encrypted_data = f.encrypt(file_data)

    # write the encrypted file
    with open("encrypted//enc_" + filename, "wb") as file:
        file.write(encrypted_data)
    print("AES Encryption successful")
    return "AES Encryption Successful. You can <a href='downloadfile?filename=enc_" + filename + "&enc=true'>download the file here</a>"


@app.route('/decryptAES', methods=["POST"])
def decryptAES():
    fileobj = request.files['defile']

    filename = secure_filename(fileobj.filename.lower())
    fileobj.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    # after saving, decrypt file
    msg = decryptSingleKey(filename)
    return msg


def decryptSingleKey(filename):
    key = load_key()
    f = Fernet(key)
    with open("temp//" + filename, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    decrypted_data = f.decrypt(encrypted_data)
    # make new file and write decrypted content
    with open("decrypted//dec_" + filename, "wb") as file:
        file.write(decrypted_data)
    print("AES decryption successful")
    return "AES Decryption Successful. You can <a href='downloadfile?filename=dec_" + filename + "&enc=false'>download the file here</a>"


@app.route('/generateHash', methods=["POST"])
def generateHash():
    fileobj = request.files['file']

    filename = secure_filename(fileobj.filename.lower())
    fileobj.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    hg = HashGenerator()
    hash = hg.hashfile("temp//" + filename)
    print("Hash is", str(hash))
    return "The generated hash is " + str(hash)


if __name__ == '__main__':
    app.run()
