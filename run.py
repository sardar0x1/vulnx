from app import create_app, db
from app.models import User, Asset, Scan, Vulnerability

app = create_app()

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'Asset': Asset, 'Scan': Scan, 'Vulnerability': Vulnerability}