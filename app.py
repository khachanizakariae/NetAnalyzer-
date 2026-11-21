
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
from analyzer import analyze_pcap

import os
import sqlite3
import json
from datetime import datetime


app = Flask(__name__)

# Configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024

DATABASE = os.path.join(BASE_DIR, 'netanalyzer.db')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# Creation de la base de donnees
def init_db():

    conn = sqlite3.connect(DATABASE)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            analysis_date TEXT,
            total_packets INTEGER,
            total_bytes INTEGER,
            source_ips TEXT,
            destination_ips TEXT,
            protocols TEXT,
            anomalies TEXT
        )
    """)

    conn.commit()
    conn.close()


# Sauvegarde des resultats
def save_analysis(filename, results):

    conn = sqlite3.connect(DATABASE)

    conn.execute("""
        INSERT INTO analyses (
            filename,
            analysis_date,
            total_packets,
            total_bytes,
            source_ips,
            destination_ips,
            protocols,
            anomalies
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        filename,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        results['total_packets'],
        results['total_bytes'],
        json.dumps(results['source_ips']),
        json.dumps(results['destination_ips']),
        json.dumps(results['protocols']),
        json.dumps(results['anomalies'])
    ))

    conn.commit()
    conn.close()


# Initialisation de la base
init_db()


@app.route('/')
def home():

    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload():

    if 'pcap_file' not in request.files:

        return render_template(
            'index.html',
            message="Aucun fichier sélectionné"
        )

    file = request.files['pcap_file']

    if file.filename == '':

        return render_template(
            'index.html',
            message="Aucun fichier sélectionné"
        )

    filename = secure_filename(file.filename)

    if not filename.lower().endswith(('.pcap', '.pcapng')):

        return render_template(
            'index.html',
            message="Format invalide"
        )

    filepath = os.path.join(
        app.config['UPLOAD_FOLDER'],
        filename
    )

    file.save(filepath)

    try:

        # Analyse du fichier PCAP
        results = analyze_pcap(filepath)

        # Sauvegarde dans SQLite
        save_analysis(filename, results)

        return render_template(
            'index.html',
            results=results,
            message="Analyse terminée avec succès !"
        )

    except Exception as e:

        return render_template(
            'index.html',
            message=f"Erreur pendant l'analyse : {str(e)}"
        )
    
@app.route('/history')
def history():

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    analyses = conn.execute("""
        SELECT * FROM analyses
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return render_template(
        'history.html',
        analyses=analyses
    )



if __name__ == '__main__':

    app.run(debug=True)
