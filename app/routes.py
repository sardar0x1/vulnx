from flask import Blueprint, request, jsonify
from app import db
from app.models import User, Asset, Scan, Vulnerability
from app.tasks import run_full_scan
from flask_login import login_user, logout_user, current_user, login_required

bp = Blueprint('main', __name__)

@bp.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    if 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Missing username or password'}), 400
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    user = User()
    user.username = data['username']
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    user = User.query.filter_by(username=data['username']).first()
    if user is None or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid username or password'}), 401
    
    login_user(user, remember=True)
    return jsonify({'message': 'Login successful', 'user_id': user.id}), 200

@bp.route('/logout')
def logout():
    logout_user()
    return jsonify({'message': 'Logout successful'})

@bp.route('/assets', methods=['POST'])
@login_required
def add_asset():
    data = request.get_json() or {}
    if 'domain' not in data:
        return jsonify({'error': 'Domain is required'}), 400
    
    domain = data['domain']
    asset = Asset(domain=domain, owner=current_user)
    db.session.add(asset)
    db.session.commit()

    scan = Scan(asset_id=asset.id, status='PENDING')
    db.session.add(scan)
    db.session.commit()

    # Start the background scan
    run_full_scan.delay(domain, scan.id)

    return jsonify({'message': 'Scan started', 'scan_id': scan.id}), 202

@bp.route('/scans/<int:scan_id>', methods=['GET'])
@login_required
def get_scan_results(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    # Make sure the user can only see their own scans
    if scan.asset.owner.id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    vulns = []
    for v in scan.vulnerabilities:
        vulns.append({
            'name': v.name,
            'severity': v.severity,
            'url': v.url,
            'ai_summary': v.ai_summary,
            'ai_mitigation': v.ai_mitigation
        })

    return jsonify({
        'scan_id': scan.id,
        'domain': scan.asset.domain,
        'status': scan.status,
        'vulnerabilities': vulns
    })
