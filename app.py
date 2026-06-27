from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import secrets
import os
import base64
from datetime import datetime
from functools import wraps

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///horrorlauncher.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

db = SQLAlchemy(app)

# ─── MODELS ───────────────────────────────────────────────────────────────────

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    uuid = db.Column(db.String(36), unique=True, nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    skin_base64 = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Series(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text, nullable=True)
    author = db.Column(db.String(32), nullable=False)
    mc_version = db.Column(db.String(16), nullable=False)
    modloader = db.Column(db.String(32), nullable=False)  # forge / fabric / quilt / neoforge
    modloader_version = db.Column(db.String(32), nullable=False)
    thumbnail_base64 = db.Column(db.Text, nullable=True)
    manifest_url = db.Column(db.String(512), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    downloads = db.Column(db.Integer, default=0)

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-HL-Token')
        if not token:
            return jsonify({'error': 'Token requis'}), 401
        user = User.query.filter_by(token=token).first()
        if not user:
            return jsonify({'error': 'Token invalide'}), 401
        return f(user, *args, **kwargs)
    return decorated

# ─── AUTH ─────────────────────────────────────────────────────────────────────

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Pseudo et mot de passe requis'}), 400
    if len(username) < 3 or len(username) > 16:
        return jsonify({'error': 'Pseudo entre 3 et 16 caractères'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Mot de passe trop court (min 6)'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Pseudo déjà utilisé'}), 409

    user_uuid = str(uuid.uuid4())
    user_token = secrets.token_hex(32)

    user = User(
        username=username,
        password_hash=generate_password_hash(password),
        uuid=user_uuid,
        token=user_token
    )
    db.session.add(user)
    db.session.commit()

    return jsonify({
        'success': True,
        'username': username,
        'uuid': user_uuid,
        'token': user_token
    }), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Identifiants incorrects'}), 401

    # Renouvelle le token à chaque login
    user.token = secrets.token_hex(32)
    db.session.commit()

    return jsonify({
        'success': True,
        'username': user.username,
        'uuid': user.uuid,
        'token': user.token,
        'has_skin': user.skin_base64 is not None
    })


@app.route('/api/me', methods=['GET'])
@require_token
def me(user):
    return jsonify({
        'username': user.username,
        'uuid': user.uuid,
        'token': user.token,
        'has_skin': user.skin_base64 is not None,
        'created_at': user.created_at.isoformat()
    })


@app.route('/api/skin', methods=['POST'])
@require_token
def upload_skin(user):
    data = request.get_json()
    skin_b64 = data.get('skin_base64', '')
    if not skin_b64:
        return jsonify({'error': 'Skin manquant'}), 400
    # Vérifie taille (max ~1MB en base64)
    if len(skin_b64) > 1_400_000:
        return jsonify({'error': 'Skin trop volumineux (max 1MB)'}), 400
    user.skin_base64 = skin_b64
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/skin/<user_uuid>', methods=['GET'])
def get_skin(user_uuid):
    user = User.query.filter_by(uuid=user_uuid).first()
    if not user or not user.skin_base64:
        return jsonify({'error': 'Pas de skin'}), 404
    return jsonify({'skin_base64': user.skin_base64})


# ─── SERIES ───────────────────────────────────────────────────────────────────

@app.route('/api/series', methods=['GET'])
def get_series():
    all_series = Series.query.order_by(Series.created_at.desc()).all()
    return jsonify([{
        'id': s.id,
        'name': s.name,
        'description': s.description,
        'author': s.author,
        'mc_version': s.mc_version,
        'modloader': s.modloader,
        'modloader_version': s.modloader_version,
        'has_thumbnail': s.thumbnail_base64 is not None,
        'manifest_url': s.manifest_url,
        'downloads': s.downloads,
        'created_at': s.created_at.isoformat()
    } for s in all_series])


@app.route('/api/series/<int:series_id>', methods=['GET'])
def get_series_detail(series_id):
    s = Series.query.get_or_404(series_id)
    return jsonify({
        'id': s.id,
        'name': s.name,
        'description': s.description,
        'author': s.author,
        'mc_version': s.mc_version,
        'modloader': s.modloader,
        'modloader_version': s.modloader_version,
        'thumbnail_base64': s.thumbnail_base64,
        'manifest_url': s.manifest_url,
        'downloads': s.downloads,
        'created_at': s.created_at.isoformat()
    })


@app.route('/api/series/<int:series_id>/thumbnail', methods=['GET'])
def get_thumbnail(series_id):
    s = Series.query.get_or_404(series_id)
    if not s.thumbnail_base64:
        return jsonify({'error': 'Pas de thumbnail'}), 404
    return jsonify({'thumbnail_base64': s.thumbnail_base64})


@app.route('/api/series', methods=['POST'])
@require_token
def create_series(user):
    data = request.get_json()
    required = ['name', 'mc_version', 'modloader', 'modloader_version', 'manifest_url']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f'Champ requis: {field}'}), 400

    valid_loaders = ['forge', 'fabric', 'quilt', 'neoforge', 'vanilla']
    if data['modloader'].lower() not in valid_loaders:
        return jsonify({'error': f'Modloader invalide. Choix: {valid_loaders}'}), 400

    thumbnail = data.get('thumbnail_base64')
    if thumbnail and len(thumbnail) > 2_000_000:
        return jsonify({'error': 'Thumbnail trop volumineux (max ~1.5MB)'}), 400

    series = Series(
        name=data['name'],
        description=data.get('description', ''),
        author=user.username,
        mc_version=data['mc_version'],
        modloader=data['modloader'].lower(),
        modloader_version=data['modloader_version'],
        thumbnail_base64=thumbnail,
        manifest_url=data['manifest_url']
    )
    db.session.add(series)
    db.session.commit()
    return jsonify({'success': True, 'id': series.id}), 201


@app.route('/api/series/<int:series_id>/download', methods=['POST'])
def count_download(series_id):
    s = Series.query.get_or_404(series_id)
    s.downloads += 1
    db.session.commit()
    return jsonify({'success': True})


# ─── VALIDATE TOKEN (pour le launcher) ───────────────────────────────────────

@app.route('/api/validate', methods=['POST'])
def validate_token():
    data = request.get_json()
    token = data.get('token')
    user_uuid = data.get('uuid')
    if not token or not user_uuid:
        return jsonify({'valid': False}), 400
    user = User.query.filter_by(token=token, uuid=user_uuid).first()
    if not user:
        return jsonify({'valid': False}), 200
    return jsonify({
        'valid': True,
        'username': user.username,
        'uuid': user.uuid,
        'token': user.token
    })


# ─── HEALTH ───────────────────────────────────────────────────────────────────

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'HorrorLauncher API'})


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
