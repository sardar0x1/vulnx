import subprocess
import json
from app import celery, create_app, db
from app.models import Scan, Vulnerability
from app.ai_engine import get_ai_analysis

app = create_app()
app.app_context().push()

def run_command(command):
    """
    Runs a command. For Windows, it should be prefixed with WSL.
    Example: ['wsl', 'subfinder', '-d', target_domain]
    For simplicity, we assume tools are in PATH. Add 'wsl' if needed.
    """
    # Uncomment the line below if you are running this from Windows and tools are in WSL
    # command.insert(0, 'wsl')
    
    print(f"Running command: {' '.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print(f"Error running command: {result.stderr}")
    return result.stdout.strip().splitlines()

@celery.task
def run_full_scan(target_domain, scan_id):
    scan = Scan.query.get(scan_id)
    if not scan:
        return

    scan.status = 'RUNNING'
    db.session.commit()

    try:
        # 1. Subfinder
        subdomains = run_command(['subfinder', '-d', target_domain, '-silent'])
        if not subdomains:
            raise ValueError("Subfinder found no subdomains.")

        # 2. Httpx (Piping subdomains to httpx)
        httpx_process = subprocess.Popen(['httpx', '-silent', '-json'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        httpx_output, _ = httpx_process.communicate(input='\n'.join(subdomains))
        live_hosts = [json.loads(line)['url'] for line in httpx_output.strip().splitlines()]
        
        if not live_hosts:
            raise ValueError("Httpx found no live hosts.")

        # 3. Nuclei (Piping live hosts to nuclei)
        nuclei_process = subprocess.Popen(['nuclei', '-json', '-severity', 'medium,high,critical', '-silent'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        nuclei_output, _ = nuclei_process.communicate(input='\n'.join(live_hosts))
        
        # 4. Parse Nuclei results and use AI
        for line in nuclei_output.strip().splitlines():
            result = json.loads(line)
            vuln_name = result.get('info', {}).get('name')
            vuln_url = result.get('matched-at')
            severity = result.get('info', {}).get('severity')

            # Get AI analysis
            ai_summary, ai_mitigation = get_ai_analysis(vuln_name, vuln_url)
            
            vuln = Vulnerability(
                scan_id=scan_id,
                name=vuln_name,
                severity=severity,
                url=vuln_url,
                ai_summary=ai_summary,
                ai_mitigation=ai_mitigation
            )
            db.session.add(vuln)
        
        scan.status = 'COMPLETED'
        db.session.commit()

    except Exception as e:
        print(f"Scan failed for {target_domain}: {e}")
        scan.status = 'FAILED'
        db.session.commit()