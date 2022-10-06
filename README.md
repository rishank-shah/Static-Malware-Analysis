# Static Malware Analysis

### Features
- [x] Virustotal API result
- [x] String Analysis
- [x] MalAPI.io integration
- [x] PE analysis
- [x] PDF/HTML Report

### Steps to run this project
```bash
git clone https://github.com/rishank-shah/Static-Malware-Analysis.git
cd Static-Malware-Analysis
pip install virtualenv
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```

### wkhtmltopdf setup
```bash
wget https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.4/wkhtmltox-0.12.4_linux-generic-amd64.tar.xz
sudo tar -xvf wkhtmltox-0.12.4_linux-generic-amd64.tar.xz
sudo cp wkhtmltox/bin/wkhtmltopdf /usr/bin/
```

### Create a folder ```malware-folder``` inside ```Static-Malware-Analysis``` directory and place malware samples inside it.

### Run main.py
```bash
python main.py 
```

### Reports will be generated and saved inside ```saved-analysis``` folder.