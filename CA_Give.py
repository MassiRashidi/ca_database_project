from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_pymysql import MySQL
import hashlib
from OpenSSL import crypto # Importation de la bibliothèque de cryptographie
import os
from io import BytesIO

app = Flask(__name__)

# --- Configuration ---
app.config['MYSQL_HOST'] = 'db'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'test'
app.config['MYSQL_DB'] = 'imovies'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor' 
app.config['SECRET_KEY'] = 'une-super-cle-secrete-pour-le-projet'

mysql = MySQL(app)

# --- Fonctions de la CA (pour l'instant, on utilise une CA auto-signée pour les tests) ---

def load_ca():
    """Charge la clé et le certificat de la CA. S'ils n'existent pas, les crée."""
    if not os.path.exists('ca_key.pem'):
        # Créer une clé pour la CA
        ca_key = crypto.PKey()
        ca_key.generate_key(crypto.TYPE_RSA, 2048)
        
        # Créer un certificat pour la CA
        ca_cert = crypto.X509()
        ca_cert.get_subject().CN = "iMovies Internal CA"
        ca_cert.set_serial_number(1)
        ca_cert.gmtime_adj_notBefore(0)
        ca_cert.gmtime_adj_notAfter(10*365*24*60*60) # Valide 10 ans
        ca_cert.set_issuer(ca_cert.get_subject())
        ca_cert.set_pubkey(ca_key)
        ca_cert.sign(ca_key, 'sha256')

        # Sauvegarder les fichiers
        with open('ca_key.pem', 'wb') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))
        with open('ca_cert.pem', 'wb') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
    
    # Charger les fichiers existants
    with open('ca_key.pem', 'rb') as f:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
    with open('ca_cert.pem', 'rb') as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
        
    return ca_key, ca_cert

# On charge notre CA au démarrage du serveur
ca_key, ca_cert = load_ca()


@app.route('/login', methods=['GET', 'POST'])
def login():
    # ... (le code de login reste identique) ...
    if request.method == 'POST':
        userDetails = request.form
        username = userDetails['username']
        password = userDetails['password']
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE uid = %s AND pwd = %s", (username, hashed_password))
        user = cur.fetchone()
        cur.close()
        if user:
            session['user_id'] = user['uid']
            return redirect(url_for('dashboard'))
        else:
            flash("Échec de la connexion. Vérifiez votre ID ou mot de passe.")
            return redirect(url_for('login'))
    return render_template('visu.html')

@app.route('/dashboard')
def dashboard():
    # ... (le code du dashboard reste identique) ...
    if 'user_id' in session:
        user_id = session['user_id']
        cur = mysql.connection.cursor()
        cur.execute("SELECT uid, firstname, lastname, email FROM users WHERE uid = %s", (user_id,))
        user_data = cur.fetchone()
        cur.close()
        return render_template('dashboard.html', user=user_data)
    return redirect(url_for('login'))

# --- NOUVELLE ROUTE POUR LA GÉNÉRATION DE CERTIFICAT ---
@app.route('/generate_certificate', methods=['POST'])
def generate_certificate():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    cur = mysql.connection.cursor()
    cur.execute("SELECT firstname, lastname, email FROM users WHERE uid = %s", (user_id,))
    user_data = cur.fetchone()
    cur.close()

    # 1. Créer une nouvelle clé privée pour l'utilisateur
    user_key = crypto.PKey()
    user_key.generate_key(crypto.TYPE_RSA, 2048)

    # 2. Créer le certificat de l'utilisateur
    user_cert = crypto.X509()
    user_cert.get_subject().CN = f"{user_data['firstname']} {user_data['lastname']}"
    user_cert.get_subject().emailAddress = user_data['email']
    user_cert.set_serial_number(os.urandom(4).hex()) # Numéro de série aléatoire
    user_cert.gmtime_adj_notBefore(0)
    user_cert.gmtime_adj_notAfter(365*24*60*60) # Valide 1 an
    user_cert.set_issuer(ca_cert.get_subject()) # L'émetteur est notre CA
    user_cert.set_pubkey(user_key)

    # 3. Signer le certificat avec la clé de notre CA
    user_cert.sign(ca_key, 'sha256')

    # 4. Créer le fichier PKCS#12 (certificat + clé privée)
    p12 = crypto.PKCS12()
    p12.set_certificate(user_cert)
    p12.set_privatekey(user_key)
    p12_data = p12.export()

    # Envoyer le fichier au navigateur pour téléchargement
    return send_file(
        BytesIO(p12_data),
        download_name=f'{user_id}_certificate.p12',
        mimetype='application/x-pkcs12'
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)