import vt
from config import *
from ratelimit import limits, RateLimitException, sleep_and_retry

def escape_html(html):
    return html.replace("&","&amp;").replace("<","&lt;").replace('"',"&quot;").replace("'","&#39;")

ONE_MINUTE = 60
MAX_CALLS_PER_MINUTE = 4

@sleep_and_retry
@limits(calls=MAX_CALLS_PER_MINUTE, period=ONE_MINUTE)
def virustotal_api(malware_hash):
    try:
        results = {}
        client = vt.Client(config['virustotal_api_key'])
        vt_malware_file = client.get_object(f"/files/{malware_hash}")

        print("Fetched Virustotal results")
        
        results['magic_header'] = vt_malware_file.get("magic","-")
        results['times_submitted'] = vt_malware_file.get("times_submitted",0)

        if vt_malware_file.get('crowdsourced_yara_results',None) != None and len(vt_malware_file.get('crowdsourced_yara_results',None)) > 0:
            results['yara_rules'] = vt_malware_file.crowdsourced_yara_results
        
        if vt_malware_file.get("packers",None) != None:
            results['packers'] = vt_malware_file.packers

        if vt_malware_file.get("name",None) != None and len(vt_malware_file.get("name",None)) > 0:
            results['names'] = vt_malware_file.names

        if vt_malware_file.get("signature_info",None) != None :
            results['signature_info'] = vt_malware_file.signature_info
        
        if vt_malware_file.get("popular_threat_classification",None) != None:
            results['threat_classification'] = vt_malware_file.popular_threat_classification

        return results
    
    except Exception as e:
        print("Virus Total API Error")
        print(e)
        return None