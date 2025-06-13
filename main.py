import json
#acceder à un avis via un fichier : à la place de response = requests.get(url) et data = response.json()
avis_id="CERTFR-2024-AVI-0012"
with open(r"avis/"+avis_id, 'r') as f:
    data=json.load(f)

#acceder à une alerte
alerte_id="CERTFR-2024-ALE-011"
with open(r"alertes/"+alerte_id, 'r') as f:
    data=json.load(f)

#acceder aux info mitre d'un cve
cve_id = "CVE-2023-46805"
with open(r"mitre/"+cve_id, 'r') as f:
    data=json.load(f)

#acceder aux info first d'un cve (epss)
cve_id = "CVE-2023-46805"
with open(r"first/"+cve_id, 'r') as f:
    data=json.load(f)
