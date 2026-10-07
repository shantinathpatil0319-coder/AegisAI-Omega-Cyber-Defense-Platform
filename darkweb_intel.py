import requests

def fetch_darkweb():
    try:
        r = requests.get(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query":"get_iocs"}
        )
        data = r.json()
        res = []
        for i in data.get("data",[])[:5]:
            res.append({
                "ioc": i["ioc"],
                "malware": i["malware"]
            })
        return res
    except:
        return [{"ioc":"offline","malware":"unknown"}]