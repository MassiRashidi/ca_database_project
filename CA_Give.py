# Installer les bibliothèques nécessaires avec : pip install Flask Flask-MySQLdb

from flask import Flask, render_template, request, redirect, url_for
from flask_mysqldb import MySQL
import hashlib # Pour le hachage SHA256

app = Flask(__name__)

# --- Configuration de la base de données MySQL ---
# Ces informations devront être adaptées à votre configuration Docker.
app.config['MYSQL_HOST'] = 'localhost' # Ou l'adresse IP de votre conteneur MySQL
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'votre_mot_de_passe_secret'
app.config['MYSQL_DB'] = 'imovies'

mysql = MySQL(app)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Gère la page de connexion. Affiche le formulaire (GET)
    et traite les données soumises (POST).
    """
    if request.method == 'POST':
        # --- Étape 2 : Vérification des identifiants ---
        userDetails = request.form
        username = userDetails['username']
        password = userDetails['password']

        # Hachage du mot de passe fourni en SHA256
        # Note : l'encodage en UTF-8 est important pour avoir un résultat cohérent.
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

        # Création d'un curseur pour interagir avec la DB
        cur = mysql.connection.cursor()
        
        # Requête pour trouver l'utilisateur et vérifier le mot de passe haché
        cur.execute("SELECT * FROM users WHERE uid = %s AND pwd = %s", (username, hashed_password))
        user = cur.fetchone() # Récupère le premier résultat
        cur.close()

        if user:
            # Si l'utilisateur est trouvé, rediriger vers le tableau de bord (à créer)
            return "Connexion réussie ! Bienvenue."
        else:
            # Sinon, afficher une erreur
            return "Échec de la connexion. Vérifiez votre ID ou mot de passe."

    # --- Étape 1 : Afficher le formulaire de connexion ---
    # Pour que cela fonctionne, il faut un fichier "login.html" dans un dossier "templates".
    return render_template('login.html')

if __name__ == '__main__':
    # Lance le serveur en mode débogage pour voir les erreurs facilement.
    app.run(debug=True)