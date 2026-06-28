from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid, secrets, os, base64, json
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
    id           = db.Column(db.Integer, primary_key=True)
    username     = db.Column(db.String(32), unique=True, nullable=False)
    password_hash= db.Column(db.String(256), nullable=False)
    uuid         = db.Column(db.String(36), unique=True, nullable=False)
    token        = db.Column(db.String(64), unique=True, nullable=False)
    skin_base64  = db.Column(db.Text, nullable=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    # Statut en ligne
    status       = db.Column(db.String(32), default='offline')   # offline/online/ingame
    current_series_id = db.Column(db.Integer, nullable=True)
    last_seen    = db.Column(db.DateTime, default=datetime.utcnow)

class Series(db.Model):
    id               = db.Column(db.Integer, primary_key=True)
    name             = db.Column(db.String(64), nullable=False)
    description      = db.Column(db.Text, nullable=True)
    author           = db.Column(db.String(32), nullable=False)
    mc_version       = db.Column(db.String(16), nullable=False)
    modloader        = db.Column(db.String(32), nullable=False)
    modloader_version= db.Column(db.String(32), nullable=False)
    thumbnail_base64 = db.Column(db.Text, nullable=True)
    manifest_url     = db.Column(db.String(512), nullable=False)
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)
    downloads        = db.Column(db.Integer, default=0)

class Friendship(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status     = db.Column(db.String(16), default='pending')  # pending/accepted
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    sender_id   = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content     = db.Column(db.String(512), nullable=False)
    read        = db.Column(db.Boolean, default=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

class Party(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    host_id     = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    series_id   = db.Column(db.Integer, db.ForeignKey('series.id'), nullable=True)
    lan_ip      = db.Column(db.String(64), nullable=True)
    lan_port    = db.Column(db.Integer, nullable=True)
    invite_code = db.Column(db.String(8), unique=True, nullable=False)
    active      = db.Column(db.Boolean, default=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

class PartyMember(db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    party_id = db.Column(db.Integer, db.ForeignKey('party.id'), nullable=False)
    user_id  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joined_at= db.Column(db.DateTime, default=datetime.utcnow)

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-HL-Token', '').strip()
        if not token:
            return jsonify({'error': 'Token manquant'}), 401
        user = User.query.filter_by(token=token).first()
        if not user:
            return jsonify({'error': 'Token invalide ou expire — reconnecte-toi'}), 401
        return f(user, *args, **kwargs)
    return decorated

def user_to_dict(user, include_status=True):
    d = {
        'id':       user.id,
        'username': user.username,
        'uuid':     user.uuid,
        'has_skin': user.skin_base64 is not None,
    }
    if include_status:
        d['status']   = user.status
        d['last_seen']= user.last_seen.isoformat() if user.last_seen else None
        if user.status == 'ingame' and user.current_series_id:
            s = Series.query.get(user.current_series_id)
            if s:
                d['current_series'] = {
                    'id': s.id, 'name': s.name,
                    'mc_version': s.mc_version,
                    'modloader': s.modloader,
                }
    return d

# ─── AUTH ─────────────────────────────────────────────────────────────────────

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'error': 'Pseudo et mot de passe requis'}), 400
    if len(username) < 3 or len(username) > 16:
        return jsonify({'error': 'Pseudo entre 3 et 16 caracteres'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Mot de passe trop court (min 6)'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Pseudo deja utilise'}), 409
    user = User(
        username=username,
        password_hash=generate_password_hash(password),
        uuid=str(uuid.uuid4()),
        token=secrets.token_hex(32),
        status='offline'
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({'success': True, 'username': user.username,
                    'uuid': user.uuid, 'token': user.token}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json(force=True, silent=True) or {}
    user = User.query.filter_by(username=data.get('username','').strip()).first()
    if not user or not check_password_hash(user.password_hash, data.get('password','')):
        return jsonify({'error': 'Identifiants incorrects'}), 401
    user.token    = secrets.token_hex(32)
    user.status   = 'online'
    user.last_seen= datetime.utcnow()
    db.session.commit()
    return jsonify({'success': True, 'username': user.username,
                    'uuid': user.uuid, 'token': user.token, 'has_skin': user.skin_base64 is not None})

@app.route('/api/logout', methods=['POST'])
@require_token
def logout(user):
    user.status = 'offline'
    user.last_seen = datetime.utcnow()
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/me', methods=['GET'])
@require_token
def me(user):
    return jsonify(user_to_dict(user))

@app.route('/api/validate', methods=['POST'])
def validate_token():
    data = request.get_json(force=True, silent=True) or {}
    user = User.query.filter_by(token=data.get('token'), uuid=data.get('uuid')).first()
    if not user:
        return jsonify({'valid': False})
    return jsonify({'valid': True, 'username': user.username,
                    'uuid': user.uuid, 'token': user.token})

# ─── SKIN ─────────────────────────────────────────────────────────────────────

@app.route('/api/skin', methods=['POST'])
@require_token
def upload_skin(user):
    data = request.get_json(force=True, silent=True) or {}
    b64 = data.get('skin_base64', '')
    if not b64:
        return jsonify({'error': 'Skin manquant'}), 400
    if len(b64) > 1_400_000:
        return jsonify({'error': 'Skin trop volumineux (max 1MB)'}), 400
    user.skin_base64 = b64
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/skin/<user_uuid>', methods=['GET'])
def get_skin(user_uuid):
    user = User.query.filter_by(uuid=user_uuid).first()
    if not user or not user.skin_base64:
        return jsonify({'error': 'Pas de skin'}), 404
    return jsonify({'skin_base64': user.skin_base64})

@app.route('/api/skin/<user_uuid>/raw', methods=['GET'])
def get_skin_raw(user_uuid):
    user = User.query.filter_by(uuid=user_uuid).first()
    if not user or not user.skin_base64:
        return jsonify({'error': 'Pas de skin'}), 404
    return Response(base64.b64decode(user.skin_base64), mimetype='image/png',
                    headers={'Cache-Control': 'no-cache'})

@app.route('/csl/<username>.json', methods=['GET'])
def csl_profile(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({}), 404
    result = {'username': user.username}
    if user.skin_base64:
        result['skin']  = f"https://horrorlauncher-api-1.onrender.com/csl/skin/{username}.png"
        result['model'] = 'default'
    return jsonify(result)

@app.route('/csl/skin/<username>.png', methods=['GET'])
def csl_skin_png(username):
    user = User.query.filter_by(username=username).first()
    if not user or not user.skin_base64:
        return jsonify({'error': 'Pas de skin'}), 404
    return Response(base64.b64decode(user.skin_base64), mimetype='image/png',
                    headers={'Cache-Control': 'no-cache'})

# ─── SERIES ───────────────────────────────────────────────────────────────────

@app.route('/api/series', methods=['GET'])
def get_series():
    all_s = Series.query.order_by(Series.created_at.desc()).all()
    return jsonify([{
        'id': s.id, 'name': s.name, 'description': s.description,
        'author': s.author, 'mc_version': s.mc_version,
        'modloader': s.modloader, 'modloader_version': s.modloader_version,
        'has_thumbnail': s.thumbnail_base64 is not None,
        'manifest_url': s.manifest_url, 'downloads': s.downloads,
        'created_at': s.created_at.isoformat()
    } for s in all_s])

@app.route('/api/series/<int:sid>', methods=['GET'])
def get_series_detail(sid):
    s = Series.query.get_or_404(sid)
    return jsonify({
        'id': s.id, 'name': s.name, 'description': s.description,
        'author': s.author, 'mc_version': s.mc_version,
        'modloader': s.modloader, 'modloader_version': s.modloader_version,
        'thumbnail_base64': s.thumbnail_base64,
        'manifest_url': s.manifest_url, 'downloads': s.downloads,
    })

@app.route('/api/series/<int:sid>/thumbnail', methods=['GET'])
def get_thumbnail(sid):
    s = Series.query.get_or_404(sid)
    if not s.thumbnail_base64:
        return jsonify({'error': 'Pas de thumbnail'}), 404
    return Response(base64.b64decode(s.thumbnail_base64), mimetype='image/png')

@app.route('/api/series', methods=['POST'])
@require_token
def create_series(user):
    data = request.get_json(force=True, silent=True) or {}
    for field in ['name', 'mc_version', 'modloader', 'manifest_url']:
        if not data.get(field, '').strip():
            return jsonify({'error': f'Champ requis : {field}'}), 400
    modloader = data['modloader'].strip().lower()
    if modloader not in ['forge','fabric','quilt','neoforge','vanilla']:
        return jsonify({'error': 'Modloader invalide'}), 400
    ml_version = data.get('modloader_version','').strip()
    if modloader != 'vanilla' and not ml_version:
        return jsonify({'error': 'modloader_version requis'}), 400
    thumbnail = data.get('thumbnail_base64')
    if thumbnail and len(thumbnail) > 2_000_000:
        return jsonify({'error': 'Thumbnail trop volumineux'}), 400
    s = Series(
        name=data['name'].strip(), description=data.get('description','').strip(),
        author=user.username, mc_version=data['mc_version'].strip(),
        modloader=modloader, modloader_version=ml_version,
        thumbnail_base64=thumbnail, manifest_url=data['manifest_url'].strip()
    )
    db.session.add(s)
    db.session.commit()
    return jsonify({'success': True, 'id': s.id}), 201

@app.route('/api/series/<int:sid>/download', methods=['POST'])
def count_download(sid):
    s = Series.query.get_or_404(sid)
    s.downloads += 1
    db.session.commit()
    return jsonify({'success': True})

# ─── STATUS ───────────────────────────────────────────────────────────────────

@app.route('/api/status', methods=['POST'])
@require_token
def update_status(user):
    data = request.get_json(force=True, silent=True) or {}
    status = data.get('status', 'online')
    if status not in ['online', 'offline', 'ingame']:
        return jsonify({'error': 'Status invalide'}), 400
    user.status    = status
    user.last_seen = datetime.utcnow()
    user.current_series_id = data.get('series_id')
    db.session.commit()
    return jsonify({'success': True})

# ─── AMIS ─────────────────────────────────────────────────────────────────────

@app.route('/api/friends', methods=['GET'])
@require_token
def get_friends(user):
    # Amitiés acceptées
    friendships = Friendship.query.filter(
        ((Friendship.user_id == user.id) | (Friendship.friend_id == user.id)),
        Friendship.status == 'accepted'
    ).all()
    friends = []
    for f in friendships:
        fid = f.friend_id if f.user_id == user.id else f.user_id
        friend = User.query.get(fid)
        if friend:
            friends.append(user_to_dict(friend))
    return jsonify(friends)

@app.route('/api/friends/requests', methods=['GET'])
@require_token
def get_friend_requests(user):
    reqs = Friendship.query.filter_by(friend_id=user.id, status='pending').all()
    result = []
    for r in reqs:
        u = User.query.get(r.user_id)
        if u:
            result.append({'request_id': r.id, **user_to_dict(u, include_status=False)})
    return jsonify(result)

@app.route('/api/friends/add', methods=['POST'])
@require_token
def add_friend(user):
    data = request.get_json(force=True, silent=True) or {}
    username = data.get('username', '').strip()
    target = User.query.filter_by(username=username).first()
    if not target:
        return jsonify({'error': 'Joueur introuvable'}), 404
    if target.id == user.id:
        return jsonify({'error': 'Tu ne peux pas t ajouter toi-meme'}), 400
    existing = Friendship.query.filter(
        ((Friendship.user_id==user.id) & (Friendship.friend_id==target.id)) |
        ((Friendship.user_id==target.id) & (Friendship.friend_id==user.id))
    ).first()
    if existing:
        return jsonify({'error': 'Demande deja envoyee ou deja amis'}), 409
    f = Friendship(user_id=user.id, friend_id=target.id, status='pending')
    db.session.add(f)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/friends/accept/<int:req_id>', methods=['POST'])
@require_token
def accept_friend(user, req_id):
    f = Friendship.query.get_or_404(req_id)
    if f.friend_id != user.id:
        return jsonify({'error': 'Non autorise'}), 403
    f.status = 'accepted'
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/friends/decline/<int:req_id>', methods=['POST'])
@require_token
def decline_friend(user, req_id):
    f = Friendship.query.get_or_404(req_id)
    if f.friend_id != user.id:
        return jsonify({'error': 'Non autorise'}), 403
    db.session.delete(f)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/friends/remove', methods=['POST'])
@require_token
def remove_friend(user):
    data = request.get_json(force=True, silent=True) or {}
    target = User.query.filter_by(username=data.get('username','')).first()
    if not target:
        return jsonify({'error': 'Introuvable'}), 404
    f = Friendship.query.filter(
        ((Friendship.user_id==user.id) & (Friendship.friend_id==target.id)) |
        ((Friendship.user_id==target.id) & (Friendship.friend_id==user.id)),
        Friendship.status=='accepted'
    ).first()
    if not f:
        return jsonify({'error': 'Pas amis'}), 404
    db.session.delete(f)
    db.session.commit()
    return jsonify({'success': True})

# ─── MESSAGES ─────────────────────────────────────────────────────────────────

@app.route('/api/messages/<username>', methods=['GET'])
@require_token
def get_messages(user, username):
    other = User.query.filter_by(username=username).first()
    if not other:
        return jsonify({'error': 'Utilisateur introuvable'}), 404
    msgs = Message.query.filter(
        ((Message.sender_id==user.id) & (Message.receiver_id==other.id)) |
        ((Message.sender_id==other.id) & (Message.receiver_id==user.id))
    ).order_by(Message.created_at.asc()).all()
    # Marque comme lus
    for m in msgs:
        if m.receiver_id == user.id and not m.read:
            m.read = True
    db.session.commit()
    return jsonify([{
        'id': m.id,
        'from': User.query.get(m.sender_id).username,
        'content': m.content,
        'read': m.read,
        'created_at': m.created_at.isoformat()
    } for m in msgs])

@app.route('/api/messages/<username>', methods=['POST'])
@require_token
def send_message(user, username):
    other = User.query.filter_by(username=username).first()
    if not other:
        return jsonify({'error': 'Destinataire introuvable'}), 404
    data = request.get_json(force=True, silent=True) or {}
    content = data.get('content', '').strip()
    if not content or len(content) > 500:
        return jsonify({'error': 'Message vide ou trop long (max 500)'}), 400
    m = Message(sender_id=user.id, receiver_id=other.id, content=content)
    db.session.add(m)
    db.session.commit()
    return jsonify({'success': True, 'id': m.id}), 201

@app.route('/api/messages/unread', methods=['GET'])
@require_token
def unread_count(user):
    count = Message.query.filter_by(receiver_id=user.id, read=False).count()
    return jsonify({'unread': count})

# ─── PARTY ────────────────────────────────────────────────────────────────────

@app.route('/api/party/create', methods=['POST'])
@require_token
def create_party(user):
    data = request.get_json(force=True, silent=True) or {}
    # Ferme les partys précédentes de cet hôte
    old = Party.query.filter_by(host_id=user.id, active=True).all()
    for o in old:
        o.active = False
    code = secrets.token_hex(4).upper()
    party = Party(
        host_id=user.id,
        series_id=data.get('series_id'),
        lan_ip=data.get('lan_ip'),
        lan_port=data.get('lan_port'),
        invite_code=code,
        active=True
    )
    db.session.add(party)
    db.session.flush()
    member = PartyMember(party_id=party.id, user_id=user.id)
    db.session.add(member)
    db.session.commit()
    return jsonify({'success': True, 'party_id': party.id, 'invite_code': code})

@app.route('/api/party/join', methods=['POST'])
@require_token
def join_party(user):
    data = request.get_json(force=True, silent=True) or {}
    code = data.get('invite_code', '').strip().upper()
    party = Party.query.filter_by(invite_code=code, active=True).first()
    if not party:
        return jsonify({'error': 'Code invalide ou party terminee'}), 404
    existing = PartyMember.query.filter_by(party_id=party.id, user_id=user.id).first()
    if not existing:
        m = PartyMember(party_id=party.id, user_id=user.id)
        db.session.add(m)
        db.session.commit()
    s = Series.query.get(party.series_id) if party.series_id else None
    return jsonify({
        'success': True,
        'party_id': party.id,
        'lan_ip':   party.lan_ip,
        'lan_port': party.lan_port,
        'series':   {'id': s.id, 'name': s.name, 'mc_version': s.mc_version,
                     'modloader': s.modloader, 'modloader_version': s.modloader_version,
                     'manifest_url': s.manifest_url} if s else None
    })

@app.route('/api/party/<int:party_id>', methods=['GET'])
@require_token
def get_party(user, party_id):
    party = Party.query.get_or_404(party_id)
    members = PartyMember.query.filter_by(party_id=party.id).all()
    member_list = []
    for m in members:
        u = User.query.get(m.user_id)
        if u:
            member_list.append(user_to_dict(u, include_status=False))
    s = Series.query.get(party.series_id) if party.series_id else None
    return jsonify({
        'id': party.id,
        'host': User.query.get(party.host_id).username,
        'invite_code': party.invite_code,
        'lan_ip': party.lan_ip,
        'lan_port': party.lan_port,
        'active': party.active,
        'members': member_list,
        'series': {'id': s.id, 'name': s.name} if s else None
    })

@app.route('/api/party/<int:party_id>/update_lan', methods=['POST'])
@require_token
def update_lan(user, party_id):
    party = Party.query.get_or_404(party_id)
    if party.host_id != user.id:
        return jsonify({'error': 'Seul le host peut mettre a jour'}), 403
    data = request.get_json(force=True, silent=True) or {}
    party.lan_ip   = data.get('lan_ip', party.lan_ip)
    party.lan_port = data.get('lan_port', party.lan_port)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/party/<int:party_id>/close', methods=['POST'])
@require_token
def close_party(user, party_id):
    party = Party.query.get_or_404(party_id)
    if party.host_id != user.id:
        return jsonify({'error': 'Seul le host peut fermer'}), 403
    party.active = False
    db.session.commit()
    return jsonify({'success': True})

# ─── SESSION MINECRAFT ────────────────────────────────────────────────────────

@app.route('/session/minecraft/profile/<user_uuid>', methods=['GET'])
def mc_profile(user_uuid):
    user = User.query.filter_by(uuid=user_uuid).first()
    if not user:
        return jsonify({'error': 'Profile not found'}), 404
    textures = {'textures': {}}
    if user.skin_base64:
        textures['textures']['SKIN'] = {
            'url': f"https://horrorlauncher-api-1.onrender.com/api/skin/{user_uuid}/raw"
        }
    textures_b64 = base64.b64encode(json.dumps(textures).encode()).decode()
    return jsonify({'id': user_uuid.replace('-',''), 'name': user.username,
                    'properties': [{'name': 'textures', 'value': textures_b64}]})

@app.route('/session/minecraft/hasJoined', methods=['GET'])
def has_joined():
    user = User.query.filter_by(username=request.args.get('username','')).first()
    if not user:
        return '', 204
    textures = {'textures': {}}
    if user.skin_base64:
        textures['textures']['SKIN'] = {
            'url': f"https://horrorlauncher-api-1.onrender.com/api/skin/{user.uuid}/raw"
        }
    textures_b64 = base64.b64encode(json.dumps(textures).encode()).decode()
    return jsonify({'id': user.uuid.replace('-',''), 'name': user.username,
                    'properties': [{'name': 'textures', 'value': textures_b64}]})

@app.route('/session/minecraft/join', methods=['POST'])
def join_server():
    return '', 204

# ─── HEALTH ───────────────────────────────────────────────────────────────────

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'HorrorLauncher API v2'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
