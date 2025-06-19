import json
import os
import pandas as pd
import pytz
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import csv
import time
import re
import feedparser
import dateparser

# === Chemins relatifs ===
BASE_DIR = "data_pour_TD_final"

PATH_AVIS = "data_pour_TD_final/Avis"
PATH_ALERTES = "data_pour_TD_final/alertes"
PATH_MITRE = "data_pour_TD_final/mitre"
PATH_FIRST = "data_pour_TD_final/first"


def nettoyer_description(description):
    """Nettoie le texte HTML en conservant seulement le texte utile"""
    if not description:
        return "Non disponible"

    # Supprimer les balises HTML mais garder le texte
    soup = BeautifulSoup(description, "html.parser")
    texte = soup.get_text(separator=" ", strip=True)

    # Remplacer les espaces multiples et sauts de ligne
    texte = ' '.join(texte.split())

    # Échapper les caractères problématiques pour CSV
    texte = texte.replace('"', "'").replace('\n', ' ').replace('\r', '')

    return texte[:1000]  # Limiter la longueur si nécessaire



def extraire_info_anssi(fichier_path, type_bulletin):
    try:
        with open(fichier_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        titre = data.get("title", "N/A")
        links = data.get('links', [])
        lien = links[0].get('url', 'Non disponible') if links else 'Non disponible'
        cve_refs = [cve.get("name") for cve in data.get("cves", []) if cve.get("name")]
        return titre, type_bulletin, lien, cve_refs
    except Exception as e:
        print(f"Erreur lecture {fichier_path}: {e}")
        return None


def extraire_info_cve(cve_id):
    # Essayer d'abord avec les fichiers locaux
    fichier_path = f'{PATH_MITRE}/{cve_id}'
    data = None

    # Vérifier si le fichier local existe
    if os.path.exists(fichier_path):
        try:
            with open(fichier_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            print(f"Erreur lecture fichier local CVE {cve_id}: {e}")

    # Si pas trouvé localement, essayer avec l'API
    if data is None:
        print(f"Tentative de récupération via API pour {cve_id}")
        data = get_cve_from_api(cve_id)
        if data is None:
            print(f"Échec de récupération pour {cve_id} via API")
            return None
        else:
            print('data found')
    result = {
        "CVE": cve_id,
        "Description": "Non disponible",
        "CVSS_Score": "Non disponible",
        "Severite": None,
        "CWE": "Non disponible",
        "CWE_Description": "Non disponible",
        "Affected_Products": [],
        "Date": None
    }

    try:
        # Structure différente selon si c'est de l'API ou du local
        if "vulnerabilities" in data:  # Format API
            descriptions = data["vulnerabilities"][0]["containers"]["cna"]["descriptions"]
            result["Description"] = nettoyer_description(descriptions[0]["value"])
            result["Date"] = data["vulnerabilities"][0]["cveMetadata"]["datePublished"]
            metrics = data["vulnerabilities"][0]["containers"]["cna"]["metrics"]
            affected = data["vulnerabilities"][0]["containers"]["cna"]["affected"]
            problemtype = data["vulnerabilities"][0]["containers"]["cna"].get("problemTypes", [{}])[0]
        else:  # Format local
            descriptions = data["containers"]["cna"]["descriptions"]
            result["Description"] = nettoyer_description(descriptions[0]["value"])
            result["Date"] = data["cveMetadata"]["datePublished"]
            metrics = data["containers"]["cna"]["metrics"]
            affected = data["containers"]["cna"]["affected"]
            problemtype = data["containers"]["cna"].get("problemTypes", [{}])[0]

        # Récupération des métriques CVSS
        for metric in metrics:
            for key in metric.keys():
                if key.lower().startswith("cvss"):
                    result["CVSS_Score"] = metric[key]["baseScore"]
                    result['Severite'] = metric[key]["baseSeverity"]
                    break

        # Récupération des informations CWE
        descriptions = problemtype.get("descriptions", [{}])
        if descriptions:
            result["CWE"] = descriptions[0].get("cweId", "Non disponible")
            result["CWE_Description"] = descriptions[0].get("description", "Non disponible")

        # Récupération des produits affectés
        for product in affected:
            vendor = product.get("vendor", "Inconnu")
            product_name = product.get("product", "Inconnu")
            versions = [v["version"] for v in product.get("versions", []) if v.get("status") == "affected"]
            result["Affected_Products"].append({
                "Vendor": vendor,
                "Product": product_name,
                "Versions": versions
            })

    except Exception as e:
        print(f"Erreur traitement données CVE {cve_id}: {e}")

    return result

def extraire_info_first(cve_id):
    fichier_path = f'{PATH_FIRST}/{cve_id}'
    try:
        with open(fichier_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return float(data['data'][0]["epss"])
    except:
        return None


def fill_csv():
    rows = []

    for bulletin_type, path in [("Alerte", PATH_ALERTES), ("Avis", PATH_AVIS)]:
        for fichier in os.listdir(path):
            fichier_path = f'{path}/{fichier}'

            info = extraire_info_anssi(fichier_path, bulletin_type)
            if not info:
                continue

            titre, type_bulletin, lien, cves = info

            for cve_id in cves:
                info_cve = extraire_info_cve(cve_id)
                if not info_cve:
                    continue
                epss = extraire_info_first(cve_id)
                rows.append({
                    "ID du bulletin": fichier,
                    "Titre du bulletin": titre,
                    "Type de bulletin": type_bulletin,
                    "Date de publication": info_cve['Date'],
                    "Identifiant CVE": cve_id,
                    "Score CVSS": info_cve['CVSS_Score'],
                    "Base Severity": info_cve['Severite'],
                    "Type CWE": info_cve['CWE'],
                    "Score EPSS": epss,
                    "Lien du bulletin": lien,
                    "Description": info_cve['Description'],  # Description nettoyée
                    "Produit": info_cve['Affected_Products']
                })

    # Création du DataFrame avec gestion des guillemets
    df = pd.DataFrame(rows)
    output_path = "data_pour_TD_final/donnees_consolidees.csv"

    # Sauvegarde avec quoting pour gérer les textes contenant des virgules
    df.to_csv(output_path, index=False, encoding='utf-8-sig',
              quoting=csv.QUOTE_NONNUMERIC, escapechar='\\')

    print(f"Fichier généré avec succès : {output_path}")
    return df


def fill_csv_debug():
    stats = {
        "bulletins_total": 0,
        "bulletins_ok": 0,
        "bulletins_no_cve": 0,
        "cve_total_refs": 0,
        "cve_mitre_missing": 0,
        "rows_kept": 0,
    }

    for bulletin_type, path in [("Alerte", PATH_ALERTES), ("Avis", PATH_AVIS)]:
        for fichier in os.listdir(path):
            stats["bulletins_total"] += 1
            info = extraire_info_anssi(f'{path}/{fichier}', bulletin_type)
            if not info:
                continue
            stats["bulletins_ok"] += 1
            _, _, _, cves = info
            if not cves:
                stats["bulletins_no_cve"] += 1
                continue
            for cve_id in cves:
                stats["cve_total_refs"] += 1
                if not extraire_info_cve(cve_id):
                    stats["cve_mitre_missing"] += 1
                    continue
                stats["rows_kept"] += 1
    print(json.dumps(stats, indent=2, ensure_ascii=False))


def get_existing_ids(csv_path="data_pour_TD_final/donnees_consolidees.csv"):
    if not os.path.exists(csv_path):
        return set()
    df = pd.read_csv(csv_path)
    return set(df["ID du bulletin"].unique())


def get_items_from_rss(url):
    feed = feedparser.parse(url)
    return feed.entries


def extraire_id_depuis_url(url):
    match = re.search(r'/((CERTFR|certfr)-\d{4}-(ALE|AVI)-\d+)/', url, re.IGNORECASE)
    return match.group(1) if match else None


def telecharger_et_sauver_bulletin(url):
    try:
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        title = soup.find("h1").text.strip()
        description = soup.find("div", class_="content").text.strip()
        cves = list(set(re.findall(r'CVE-\d{4}-\d+', soup.text)))
        return {
            "title": title,
            "description": description,
            "links": [{"url": url}],
            "cves": [{"name": cve} for cve in cves]
        }
    except Exception as e:
        print(f"Erreur lors du téléchargement de {url} : {e}")
        return None


def get_epss_from_api(cve_id):
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return float(data['data'][0]['epss'])
    except Exception as e:
        print(f"Erreur EPSS {cve_id}: {e}")
    return None



def get_epss_from_api(cve_id):
    """
    Récupère les données de vulnérabilité depuis l'API MITRE CVE 5.0.
    """
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print(f"Erreur CVE API {cve_id}: {e}")
    return None


def get_cve_from_api(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print(f"Erreur CVE API {cve_id}: {e}")
    return None

def extraire_info_cve_api(cve_id):
    data = get_cve_from_api(cve_id)
    if not data:
        return None

    result = {
        "CVE": cve_id,
        "Description": "Non disponible",
        "CVSS_Score": "Non disponible",
        "Severite": None,
        "CWE": "Non disponible",
        "CWE_Description": "Non disponible",
        "Affected_Products": [],
        "Date": None
    }

    try:
        result["Description"] = nettoyer_description(
            data["vulnerabilities"][0]["containers"]["cna"]["descriptions"][0]["value"]
        )
    except:
        pass
    try:
        result["Date"] = data["vulnerabilities"][0]["cveMetadata"]["datePublished"]
    except:
        pass
    try:
        metrics = data["vulnerabilities"][0]["containers"]["cna"]["metrics"]
        for metric in metrics:
            for key in metric.keys():
                if key.lower().startswith("cvss"):
                    result["CVSS_Score"] = metric[key]["baseScore"]
                    result['Severite'] = metric[key]["baseSeverity"]
                    break
    except:
        pass
    try:
        problemtype = data["vulnerabilities"][0]["containers"]["cna"].get("problemTypes", [{}])[0]
        descriptions = problemtype.get("descriptions", [{}])
        if descriptions:
            result["CWE"] = descriptions[0].get("cweId", "Non disponible")
            result["CWE_Description"] = descriptions[0].get("description", "Non disponible")
    except:
        pass
    try:
        affected = data["vulnerabilities"][0]["containers"]["cna"]["affected"]
        for product in affected:
            vendor = product.get("vendor", "Inconnu")
            product_name = product.get("product", "Inconnu")
            versions = [v["version"] for v in product.get("versions", []) if v.get("status") == "affected"]
            result["Affected_Products"].append({
                "Vendor": vendor,
                "Product": product_name,
                "Versions": versions
            })
    except:
        pass

    return result


def update_csv():
    existing_ids = get_existing_ids()
    rows = []

    for bulletin_type, path in [("Alerte", PATH_ALERTES), ("Avis", PATH_AVIS)]:
        print(len(os.listdir(path)))
        for fichier in os.listdir(path):
            print(fichier, fichier in existing_ids)
            if fichier in existing_ids:
                continue  # Ignorer les bulletins déjà traités

            fichier_path = f'{path}/{fichier}'
            info = extraire_info_anssi(fichier_path, bulletin_type)
            if not info:
                continue

            titre, type_bulletin, lien, cves = info
            print(cves)
            if not cves:
                continue

            for cve_id in cves:
                info_cve = extraire_info_cve(cve_id)
                if not info_cve:
                    continue
                epss = extraire_info_first(cve_id)
                rows.append({
                    "ID du bulletin": fichier,
                    "Titre du bulletin": titre,
                    "Type de bulletin": type_bulletin,
                    "Date de publication": info_cve['Date'],
                    "Identifiant CVE": cve_id,
                    "Score CVSS": info_cve['CVSS_Score'],
                    "Base Severity": info_cve['Severite'],
                    "Type CWE": info_cve['CWE'],
                    "Score EPSS": epss,
                    "Lien du bulletin": lien,
                    "Description": info_cve['Description'],
                    "Produit": info_cve['Affected_Products']
                })

    if not rows:
        print("Aucun nouveau bulletin à ajouter.")
        return

    output_path = "data_pour_TD_final/donnees_consolidees.csv"
    df_nouveau = pd.DataFrame(rows)

    if os.path.exists(output_path):
        df_existant = pd.read_csv(output_path)
        df_final = pd.concat([df_existant, df_nouveau], ignore_index=True)
    else:
        df_final = df_nouveau

    df_final.to_csv(output_path, index=False, encoding='utf-8-sig',
                    quoting=csv.QUOTE_NONNUMERIC, escapechar='\\')

    print(f"Mise à jour réussie : {len(rows)} lignes ajoutées.")
#fill_csv()
update_csv()