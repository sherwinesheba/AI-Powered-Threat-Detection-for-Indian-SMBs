from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from elasticsearch import Elasticsearch
import openai
import smtplib
from email.mime.text import MIMEText
import threading
import time
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import numpy as np
import tensorflow as tf
from datetime import datetime
import queue
import logging
import json

app = Flask(__name__)
app.config.from_object('config.Config')
db = SQLAlchemy(app)
es = Elasticsearch([app.config['ELASTICSEARCH_URL']])
openai.api_key = app.config['OPENAI_API_KEY']

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    company_name = db.Column(db.String(255))
    subscriptions = db.relationship('Subscription', backref='user', lazy=True)
    alerts = db.relationship('Alert', backref='user', lazy=True)

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    plan_type = db.Column(db.String(50), default='basic')
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    end_date = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='active')

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    threat_type = db.Column(db.String(100))
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    resolved = db.Column(db.Boolean, default=False)

with app.app_context():
    db.create_all()

# TensorFlow Anomaly Detection Model (Autoencoder for network traffic)
class AnomalyDetector:
    def __init__(self):
        self.model = self.build_model()
        # Load pre-trained weights or train on normal data
        # For demo, assume trained on normal traffic features

    def build_model(self):
        input_dim = 5  # packet_size, flow_duration, packet_rate, byte_rate, tcp_flags
        encoding_dim = 32

        input_layer = tf.keras.layers.Input(shape=(input_dim,))
        encoded = tf.keras.layers.Dense(encoding_dim, activation='relu')(input_layer)
        decoded = tf.keras.layers.Dense(input_dim, activation='sigmoid')(encoded)

        autoencoder = tf.keras.models.Model(input_layer, decoded)
        autoencoder.compile(optimizer='adam', loss='mse')
        return autoencoder

    def detect(self, features):
        features = np.array([features])
        reconstruction_error = np.mean(np.square(features - self.model.predict(features)), axis=1)
        threshold = 0.1  # Tuned for <5s detection
        return reconstruction_error[0] > threshold, reconstruction_error[0]

detector = AnomalyDetector()

# Packet Capture and Analysis (Adapted for real-time <5s detection)
class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()

    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    def start_capture(self, interface="eth0"):
        def capture_thread():
            sniff(iface=interface, prn=self.packet_callback, store=0, stop_filter=lambda _: self.stop_capture.is_set())
        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()

class TrafficAnalyzer:
    def __init__(self):
        self.flow_stats = defaultdict(lambda: {'packet_count': 0, 'byte_count': 0, 'start_time': None, 'last_time': None})

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            flow_key = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time
            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time
            return self.extract_features(packet, stats)
        return None

    def extract_features(self, packet, stats):
        duration = stats['last_time'] - stats['start_time'] if stats['start_time'] else 0
        return {
            'packet_size': len(packet),
            'flow_duration': duration,
            'packet_rate': stats['packet_count'] / duration if duration > 0 else 0,
            'byte_rate': stats['byte_count'] / duration if duration > 0 else 0,
            'tcp_flags': packet[TCP].flags
        }

analyzer = TrafficAnalyzer()
capture = PacketCapture()

# Detection Engine (Anomaly + Signatures, <5s)
class DetectionEngine:
    def __init__(self):
        self.signature_rules = {
            'syn_flood': lambda f: f['tcp_flags'] == 2 and f['packet_rate'] > 100,
            'port_scan': lambda f: f['packet_size'] < 100 and f['packet_rate'] > 50,
            'phishing_email': lambda content: 'urgent' in content.lower() and 'click here' in content.lower(),  # Simple email check
            'ransomware': lambda file_change: len(file_change) > 1000 and 'encrypted' in file_change  # Mock file monitor
        }

    def detect_threats(self, features_or_content, is_packet=True):
        threats = []
        if is_packet:
            is_anomaly, score = detector.detect([features_or_content['packet_size'], features_or_content['flow_duration'],
                                                features_or_content['packet_rate'], features_or_content['byte_rate'],
                                                features_or_content['tcp_flags']])
            if is_anomaly:
                threats.append({'type': 'anomaly', 'score': score, 'confidence': min(1.0, score), 'severity': 'high'})
            for rule, condition in self.signature_rules.items():
                if rule in ['syn_flood', 'port_scan'] and condition(features_or_content):
                    threats.append({'type': 'signature', 'rule': rule, 'confidence': 1.0, 'severity': 'medium'})
        else:  # For email/malware
            for rule, condition in self.signature_rules.items():
                if rule in ['phishing_email', 'ransomware'] and condition(features_or_content):
                    threats.append({'type': 'signature', 'rule': rule, 'confidence': 0.9, 'severity': 'high'})
        return threats

engine = DetectionEngine()

# Alert System (<10s response)
class AlertSystem:
    def __init__(self):
        self.logger = logging.getLogger('cyber_alerts')
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler('alerts.log')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def generate_alert(self, threat, user_id, packet_info=None, content=None):
        alert_data = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'details': threat,
            'user_id': user_id,
            'severity': threat.get('severity', 'low')
        }
        self.logger.warning(json.dumps(alert_data))
        # Log to Elasticsearch
        es.index(index='cyber-logs', body=alert_data)
        # Save to DB
        alert = Alert(user_id=user_id, threat_type=threat['type'], description=str(threat), severity=threat.get('severity'))
        db.session.add(alert)
        db.session.commit()
        # Email alert
        user = User.query.get(user_id)
        if user:
            msg = MIMEText(f"Threat detected: {threat['type']} - {threat.get('rule', threat.get('score'))}")
            msg['Subject'] = 'Cyber Threat Alert'
            msg['From'] = app.config['MAIL_USERNAME']
            msg['To'] = user.email
            with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
                server.starttls()
                server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
                server.send_message(msg)
        # Automated response: e.g., block IP (mock)
        if threat['confidence'] > 0.8:
            print(f"Automated response: Block {packet_info.get('source_ip', 'unknown')}")  # Integrate with firewall

alert_system = AlertSystem()

# Real-time Monitoring Thread (<5s detection, <10s response)
def monitoring_thread():
    capture.start_capture()
    while True:
        try:
            packet = capture.packet_queue.get(timeout=1)
            features = analyzer.analyze_packet(packet)
            if features:
                threats = engine.detect_threats(features)
                for threat in threats:
                    packet_info = {'source_ip': packet[IP].src, 'destination_ip': packet[IP].dst}
                    # Assume user_id from session or config; for demo, use 1
                    alert_system.generate_alert(threat, 1, packet_info)
        except queue.Empty:
            continue

# For malware/phishing: Mock functions (integrate file/email watchers)
def analyze_malware(file_path):
    # Mock: Read file, extract API calls or patterns
    with open(file_path, 'r') as f:
        content = f.read()
    threats = engine.detect_threats(content, is_packet=False)
    return threats

def analyze_email(email_content, user_id):
    threats = engine.detect_threats(email_content, is_packet=False)
    for threat in threats:
        alert_system.generate_alert(threat, user_id)

# OpenAI Integration for Reports and Recommendations
def generate_report(threats):
    prompt = f"Generate a security report and policy recommendations for threats: {threats}. Focus on SMBs in India."
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content

def vulnerability_assessment(network_range):
    # Basic nmap-like scan (use python-nmap if installed)
    vulns = []  # Mock: Scan ports
    report = generate_report(f"Vulnerabilities in {network_range}: {vulns}")
    return report

# Routes
@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password_hash, password):
        session['user_id'] = user.id
        return redirect(url_for('dashboard'))
    return 'Invalid credentials'

@app.route('/register', methods=['POST'])
def register():
    email = request.form['email']
    password = request.form['password']
    company = request.form['company']
    hashed = generate_password_hash(password)
    user = User(email=email, password_hash=hashed, company_name=company)
    db.session.add(user)
    db.session.commit()
    # Create basic subscription
    sub = Subscription(user_id=user.id)
    db.session.add(sub)
    db.session.commit()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    alerts = Alert.query.filter_by(user_id=user_id).order_by(Alert.timestamp.desc()).limit(10).all()
    # Compliance report
    recent_threats = [a.description for a in alerts if not a.resolved]
    report = generate_report(recent_threats) if recent_threats else "No recent threats."
    return render_template('dashboard.html', alerts=alerts, report=report)

@app.route('/api/scan_vuln', methods=['POST'])
def scan_vuln():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    range_ = request.json['range']
    report = vulnerability_assessment(range_)
    return jsonify({'report': report})

@app.route('/api/analyze_email', methods=['POST'])
def api_analyze_email():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    content = request.json['content']
    user_id = session['user_id']
    analyze_email(content, user_id)
    return jsonify({'status': 'Analyzed'})

# Start monitoring on app start
if __name__ == '__main__':
    threading.Thread(target=monitoring_thread, daemon=True).start()
    app.run(debug=True)
