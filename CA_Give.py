from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_pymysql import MySQL
import hashlib
from OpenSSL import crypto
import os
from io import BytesIO
import datetime

app = Flask(__name__)

# --- Configuration ---
app.config['MYSQL_HOST'] = 'db'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'test'
app.config['MYSQL_DB'] = 'imovies'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

app.config['SECRET_KEY'] = 'a-super-secret-key-for-the-project'

mysql = MySQL(app)

# --- CA Functions ---

def load_ca():
    """Loads the CA key and certificate from a dedicated folder.
    If they do not exist, creates them."""


    ca_dir = 'ca_secrets'
    key_path = os.path.join(ca_dir, 'ca_key.pem')
    cert_path = os.path.join(ca_dir, 'ca_cert.pem')


    if not os.path.exists(ca_dir):
        os.makedirs(ca_dir) 
        

    if not os.path.exists(key_path):
        # Create a key for the CA
        ca_key = crypto.PKey()
        ca_key.generate_key(crypto.TYPE_RSA, 2048)

        # Create a certificate for the CA
        ca_cert = crypto.X509()
        ca_cert.get_subject().CN = "iMovies Internal CA"
        ca_cert.set_serial_number(1)
        ca_cert.gmtime_adj_notBefore(0)
        ca_cert.gmtime_adj_notAfter(10*365*24*60*60) # Valid for 10 years
        ca_cert.set_issuer(ca_cert.get_subject())
        ca_cert.set_pubkey(ca_key)
        ca_cert.sign(ca_key, 'sha256')


        with open(key_path, 'wb') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))
        with open(cert_path, 'wb') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))


    with open(key_path, 'rb') as f:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
    with open(cert_path, 'rb') as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

    return ca_key, ca_cert


ca_key, ca_cert = load_ca()



# --- CRL Generation Function ---
def generate_crl(ca_key, ca_cert):
    """Generates a CRL file based on revoked certs in the database."""
    ca_dir = 'ca_secrets'
    crl_file_path = os.path.join(ca_dir, 'crl.pem')
    crl = crypto.CRL()

    try:
        cur = mysql.connection.cursor()
        # Select only certificates that have a revoked_date
        cur.execute("SELECT serial_number, revoked_date FROM certificates WHERE revoked_date IS NOT NULL")
        revoked_certs = cur.fetchall()
        cur.close()
    except Exception as e:
        if 'cur' in locals() and cur:
             cur.close()
        print(f"Database error fetching revoked certs: {e}")
        revoked_certs = []

    # Add revoked certificates to the CRL object
    for cert in revoked_certs:
        serial_hex = cert['serial_number']
        rev_date = cert['revoked_date']
        rev_date_str = rev_date.strftime('%Y%m%d%H%M%SZ')

        revoked = crypto.Revoked()
        revoked.set_serial(serial_hex.encode('ascii'))
        revoked.set_rev_date(rev_date_str.encode('ascii'))
        crl.add_revoked(revoked)

    # Sign the CRL with the CA key

    crl_pem = crl.export(ca_cert, ca_key, crypto.FILETYPE_PEM, days=1, digest=b"sha256")

    try:
        with open(crl_file_path, 'wb') as f:
            f.write(crl_pem)
        print("CRL generated successfully from database.")
    except IOError as e:
        print(f"Error writing CRL file: {e}")


# Generate CRL on startup
if 'ca_key' in locals() and 'ca_cert' in locals():
    generate_crl(ca_key, ca_cert)
else:
    print("Error: CA key/cert not loaded, cannot generate initial CRL.")


@app.route('/login', methods=['GET', 'POST'])
def login():
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
            flash("Login failed. Check your ID or password.")
            return redirect(url_for('login'))
    # Assuming visu.html is your login page template
    return render_template('visu.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']
        cur = mysql.connection.cursor()
        cur.execute("SELECT uid, firstname, lastname, email FROM users WHERE uid = %s", (user_id,))
        user_data = cur.fetchone()
        cur.close()

        return render_template('dashboard.html', user=user_data)
    return redirect(url_for('login'))

@app.route('/update_info', methods=['POST'])
def update_info():

    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']


    new_firstname = request.form.get('firstname')
    new_lastname = request.form.get('lastname')
    new_email = request.form.get('email')


    if not new_firstname or not new_lastname or not new_email:
        flash("All fields are required.")
        return redirect(url_for('dashboard'))

    # Update the database
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE users
            SET firstname = %s, lastname = %s, email = %s
            WHERE uid = %s
        """, (new_firstname, new_lastname, new_email, user_id))
        mysql.connection.commit()
        cur.close()
        flash("Information updated successfully!")
    except Exception as e:
        mysql.connection.rollback()
        cur.close()
        print(f"Database error on user update: {e}")
        flash("Error updating information.")


    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():

    session.pop('user_id', None)
    flash("You have been logged out.")
    return redirect(url_for('login'))


@app.route('/generate_certificate', methods=['POST'])
def generate_certificate():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    cur = mysql.connection.cursor()
    cur.execute("SELECT firstname, lastname, email FROM users WHERE uid = %s", (user_id,))
    user_data = cur.fetchone()
    cur.close() 
    
    if not user_data:
        flash("User data not found.")
        return redirect(url_for('dashboard'))



    user_key = crypto.PKey()
    user_key.generate_key(crypto.TYPE_RSA, 2048)


    user_cert = crypto.X509()
    user_cert.get_subject().CN = f"{user_data['firstname']} {user_data['lastname']}"
    user_cert.get_subject().emailAddress = user_data['email']

    # Generate serial number
    serial_number_int = int.from_bytes(os.urandom(8), 'big')
    serial_number_hex = f"{serial_number_int:X}"
    user_cert.set_serial_number(serial_number_int)

    issued_date = datetime.datetime.utcnow()
    expiry_date = issued_date + datetime.timedelta(days=365)

    user_cert.gmtime_adj_notBefore(0)
    user_cert.gmtime_adj_notAfter(int((expiry_date - issued_date).total_seconds()))
    user_cert.set_issuer(ca_cert.get_subject())
    user_cert.set_pubkey(user_key)

    # Sign the user certificate with the CA key
    user_cert.sign(ca_key, 'sha256')


    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO certificates
            (serial_number, user_uid, common_name, email, issued_date, expiry_date)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            serial_number_hex,
            user_id,
            user_cert.get_subject().CN,
            user_data['email'],
            issued_date,
            expiry_date
        ))
        mysql.connection.commit() # Save changes to DB
        cur.close()
    except Exception as e:
        mysql.connection.rollback()
        if 'cur' in locals() and cur:
            cur.close()
        print(f"Database error on cert insert: {e}")
        flash("Error saving certificate details to database.")
        return redirect(url_for('dashboard'))




    p12 = crypto.PKCS12()
    p12.set_certificate(user_cert)
    p12.set_privatekey(user_key)
    p12_data = p12.export(passphrase=b'imovies')

    generate_crl(ca_key, ca_cert)


    return send_file(
        BytesIO(p12_data),
        download_name=f'{user_id}_certificate.p12',
        mimetype='application/x-pkcs12'
    )



@app.route('/cert_login_handler')
def cert_login_handler():

    client_dn = request.headers.get('X-Client-DN')

    if not client_dn:
        flash("Configuration error: Certificate information missing.")
        return redirect(url_for('login'))


    client_email = None
    try:
        
        parts = client_dn.split(',')
        for part in parts:

            part_stripped = part.strip()
            if part_stripped.startswith('emailAddress='):
                client_email = part_stripped.split('=', 1)[1]
                break
    except Exception as e:
        print(f"Error parsing DN: {client_dn}. Error: {e}")
        flash("Error reading certificate.")
        return redirect(url_for('login'))

    if not client_email:
        flash("Could not extract email from certificate.")
        return redirect(url_for('login'))


    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", (client_email,))
    user = cur.fetchone()
    cur.close()

    if user:
        session['user_id'] = user['uid']
        return redirect(url_for('dashboard'))
    else:
        flash("Certificate valid, but not recognized in our database.")
        return redirect(url_for('login'))

# --- Routes for Revocation (Using Database) ---

@app.route('/revoke', methods=['GET', 'POST'])
def revoke_page():

    if 'user_id' in session:
        user_id = session['user_id']
        user_certs = []
        try:
            cur = mysql.connection.cursor()

            cur.execute("""
                SELECT serial_number, common_name, expiry_date
                FROM certificates
                WHERE user_uid = %s AND revoked_date IS NULL
                ORDER BY issued_date DESC
            """, (user_id,))
            certs_from_db = cur.fetchall()
            cur.close()
            for cert in certs_from_db:
                 user_certs.append({
                     'serial': cert['serial_number'],
                     'cn': cert['common_name'],
                     'expiry': cert['expiry_date'].strftime('%Y-%m-%d')
                 })
        except Exception as e:
            if 'cur' in locals() and cur:
                cur.close()
            print(f"Database error fetching user certs: {e}")
            flash("Error retrieving your certificates.")

        return render_template('revoke.html', user_certs=user_certs)

    if request.method == 'POST':
         username = request.form['username']
         password = request.form['password']
         hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
         cur = mysql.connection.cursor()
         cur.execute("SELECT * FROM users WHERE uid = %s AND pwd = %s", (username, hashed_password))
         user = cur.fetchone()
         cur.close()
         if user:
             session['user_id'] = user['uid']
             return redirect(url_for('revoke_page'))
         else:
             flash("Authentication failed.")
             return render_template('revoke_login.html')

    return render_template('revoke_login.html')

@app.route('/perform_revoke', methods=['POST'])
def perform_revoke():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    serial_to_revoke = request.form.get('serial')
    if not serial_to_revoke:
        flash("No certificate selected for revocation.")
        return redirect(url_for('revoke_page'))

    user_id = session['user_id']
    revocation_date = datetime.datetime.utcnow()


    try:
        cur = mysql.connection.cursor()
        
        rows_affected = cur.execute("""
            UPDATE certificates
            SET revoked_date = %s
            WHERE serial_number = %s AND user_uid = %s AND revoked_date IS NULL
        """, (revocation_date, serial_to_revoke, user_id))
        mysql.connection.commit()
        cur.close()

        if rows_affected > 0:

             generate_crl(ca_key, ca_cert)
             flash(f"Certificate {serial_to_revoke} has been revoked.")
        else:
             
             flash("Revocation failed. Certificate may not exist, belong to you, or is already revoked.")

    except Exception as e:
        mysql.connection.rollback()
        if 'cur' in locals() and cur:
            cur.close()
        print(f"Database error on revoke: {e}")
        flash("An error occurred during revocation.")


    return redirect(url_for('revoke_page'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)