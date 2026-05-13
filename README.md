# 🛡️ Network/TLS Posture Analyzer

**Module :** Sécurité Mobile / Sécurité Web  
**Année Universitaire :** 2023-2024  
**Réalisé par :** Yassir KADOUARI \& Marouane ISMAILI  

---

## 📖 Description du Projet
Ce projet est un **outil d'audit défensif du transport** spécialement conçu pour analyser la posture de sécurité des applications mobiles. Plutôt que de se focaliser sur des méthodes de contournement (offensives), notre outil propose une approche Blue Team complète :
1. **Analyse Statique (APK) :** Extraction du fichier `network_security_config.xml` pour détecter si le trafic en clair est autorisé (`cleartextTrafficPermitted`) et si le *Certificate Pinning* est appliqué.
2. **Analyse Dynamique (Proxy Logs) :** Extraction automatique d'Endpoints (URLs, domaines) depuis des fichiers logs bruts (Burp Suite, Wireshark).
3. **Moteur d'Analyse Heuristique (IA) :** Classification des flux réseau découverts (Production, Serveurs de Test oubliés, Outils de télémétrie/Analytics, Domaines Suspects) et proposition de recommandations de remédiation.
4. **Audit Cryptographique (SSLyze) :** Scan automatisé en temps réel des serveurs backend identifiés pour évaluer la configuration de leurs certificats, la présence de protocoles obsolètes (SSLv3, TLS 1.0) et la mise en place du `HSTS`.

---

## ⚙️ Architecture Technique
L'application repose sur une architecture découplée (Frontend/Backend) :
*   **Backend (Python / FastAPI) :** Gère l'analyse lourde des APK (via `pyaxmlparser`), des logs, le moteur de classification et les scans réseau (`sslyze`).
*   **Frontend (React / Vite) :** Interface utilisateur moderne (Design System *Glassmorphism* & *Dark Mode*) avec support du Drag & Drop et génération de rapports PDF (`html2pdf.js`).

---

## 🚀 Instructions d'Installation et Lancement

L'application nécessite l'exécution simultanée du Backend et du Frontend.

### Étape 1 : Démarrer l'API (Backend)
Ouvrez un premier terminal à la racine du projet :
```bash
# 1. Créer un environnement virtuel (recommandé)
python3 -m venv venv

# 2. L'activer
# Sous Linux/MacOS :
source venv/bin/activate
# Sous Windows :
# .\venv\Scripts\activate

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Lancer le serveur (FastAPI)
cd backend
uvicorn main:app --reload
```
*L'API sera disponible sur `http://127.0.0.1:8000`.*

### Étape 2 : Démarrer l'Interface Web (Frontend)
Ouvrez un second terminal à la racine du projet :
```bash
cd frontend

# 1. Installer les dépendances Node
npm install

# 2. Lancer le serveur de développement
npm run dev
```
*L'interface utilisateur sera accessible via votre navigateur sur `http://localhost:5173` (ou le port affiché dans le terminal).*

---

## 🧪 Fichiers de Test Fournis
Pour évaluer l'outil rapidement, nous avons inclus un fichier nommé `sample_proxy_logs.txt` à la racine du projet. 
Il simule une capture de trafic (contenant des API de production, des trackers, des serveurs de staging oubliés et des IPs brutes suspectes) afin de démontrer la pertinence de l'analyse heuristique (IA) lors de votre évaluation. 

Vous pouvez uploader ce fichier directement dans la zone **"Uploader Logs Proxy"** de l'interface.
