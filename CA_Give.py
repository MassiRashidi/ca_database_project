# Installer les bibliothèques nécessaires avec : pip install -r requirements.txt

from flask import Flask, render_template, request
from flask_pymysql import MySQL
import hashlib

app = Flask(__name__)

# --- Configuration de la base de données MySQL ---
app.config['MYSQL_HOST'] = 'db'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'test'
app.config['MYSQL_DB'] = 'imovies'
# Ajout pratique pour manipuler les résultats plus tard
app.config['MYSQL_CURSORCLASS'] = 'DictCursor' 

mysql = MySQL(app)

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
            return "Connexion réussie ! Bienvenue."
        else:
            return "Échec de la connexion. Vérifiez votre ID ou mot de passe."

    return render_template('visu.html') # Assure-toi que le nom du fichier est correct

if __name__ == '__main__':
    # --- LA MODIFICATION CRUCIALE EST ICI ---
    # On dit à Flask d'écouter sur toutes les adresses (0.0.0.0)
    # et d'utiliser le port 5000 à l'intérieur du conteneur.
    app.run(host='0.0.0.0', port=5000, debug=True)