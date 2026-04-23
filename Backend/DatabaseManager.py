# DatabaseManager.py
import sqlite3
import json
from datetime import datetime, timedelta
import os
import threading

class DatabaseManager:
    def __init__(self, db_path='threat_detection.db'):
        self.db_path = db_path
        self._local = threading.local()
        self._force_recreate_tables()
    
    def get_connection(self):
        """Get thread-local database connection"""
        if not hasattr(self._local, 'conn'):
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn
    
    def get_cursor(self):
        """Get thread-local database cursor"""
        conn = self.get_connection()
        if not hasattr(self._local, 'cursor'):
            self._local.cursor = conn.cursor()
        return self._local.cursor

    def _force_recreate_tables(self):
        """Completely drop and recreate tables to ensure correct schema"""
        try:
            cursor = self.get_cursor()
            
            # Drop all existing tables
            cursor.execute("DROP TABLE IF EXISTS threats")
            cursor.execute("DROP TABLE IF EXISTS analysis_results")
            cursor.execute("DROP TABLE IF EXISTS users")
            cursor.execute("DROP TABLE IF EXISTS system_logs")
            
            # Create analysis_results table with EXACT column names
            cursor.execute('''
                CREATE TABLE analysis_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    log_data TEXT NOT NULL,
                    analysis_mode TEXT NOT NULL DEFAULT "standard",
                    prediction INTEGER NOT NULL,
                    confidence REAL NOT NULL,
                    threat_level TEXT NOT NULL,
                    source_ip TEXT,
                    features_used INTEGER DEFAULT 0,
                    behavioral_score REAL DEFAULT 0.0,
                    combined_confidence REAL DEFAULT 0.0,
                    encrypted_data TEXT,
                    timestamp TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            ''')
            
            # Create threats table
            cursor.execute('''
                CREATE TABLE threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER,
                    threat_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    source_ip TEXT,
                    confidence REAL,
                    timestamp TEXT NOT NULL,
                    status TEXT DEFAULT 'active',
                    FOREIGN KEY (analysis_id) REFERENCES analysis_results (id)
                )
            ''')
            
            # Create users table
            cursor.execute('''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE,
                    password_hash TEXT,
                    role TEXT DEFAULT 'user',
                    created_at TEXT NOT NULL,
                    last_login TEXT
                )
            ''')
            
            # Create system_logs table
            cursor.execute('''
                CREATE TABLE system_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    source TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
            ''')
            
            self.get_connection().commit()
            print("✅ Database tables recreated successfully")
            
            # Verify the table structure
            self._verify_table_structure()
            
        except Exception as e:
            print(f"❌ Error recreating tables: {e}")

    def _verify_table_structure(self):
        """Verify that all required columns exist"""
        try:
            cursor = self.get_cursor()
            
            cursor.execute("PRAGMA table_info(analysis_results)")
            columns = [col[1] for col in cursor.fetchall()]
            
            required_columns = [
                'user_id', 'log_data', 'analysis_mode', 'prediction', 
                'confidence', 'threat_level', 'source_ip', 'features_used',
                'behavioral_score', 'combined_confidence', 'encrypted_data',
                'timestamp', 'created_at'
            ]
            
            missing_columns = [col for col in required_columns if col not in columns]
            
            if missing_columns:
                print(f"❌ Missing columns in analysis_results: {missing_columns}")
                print(f"📋 Current columns: {columns}")
                return False
            else:
                print("✅ analysis_results table has all required columns")
                print(f"📋 Available columns: {columns}")
                return True
                
        except Exception as e:
            print(f"❌ Error verifying table structure: {e}")
            return False

    def save_enhanced_analysis_result(self, result_data):
        """Save enhanced analysis result to database"""
        try:
            # First verify table structure
            if not self._verify_table_structure():
                print("❌ Table structure invalid, cannot save data")
                return None

            cursor = self.get_cursor()
            
            # Use a simpler query with only essential fields to ensure it works
            query = '''
                INSERT INTO analysis_results (
                    user_id, log_data, analysis_mode, prediction, confidence,
                    threat_level, source_ip, timestamp, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            '''
            
            values = (
                result_data.get('user_id', 'anonymous'),
                result_data.get('log_data', ''),
                result_data.get('analysis_mode', 'standard'),
                result_data.get('prediction', 0),
                result_data.get('confidence', 0.0),
                result_data.get('threat_level', 'LOW'),
                result_data.get('source_ip', ''),
                datetime.now().isoformat(),
                datetime.now().isoformat()
            )
            
            print(f"💾 Saving analysis result for user: {values[0]}")
            
            cursor.execute(query, values)
            self.get_connection().commit()
            
            # Get the inserted ID
            result_id = cursor.lastrowid
            
            # If threat detected, save to threats table
            if result_data.get('prediction') == 1:
                self.save_threat_detection(result_id, result_data)
            
            print(f"✅ Analysis result saved with ID: {result_id}")
            return result_id
            
        except Exception as e:
            print(f"❌ Error saving analysis result: {e}")
            print("💡 Try deleting the database file and restarting the application")
            return None

    def save_threat_detection(self, analysis_id, result_data):
        """Save threat detection to threats table"""
        try:
            cursor = self.get_cursor()
            query = '''
                INSERT INTO threats (
                    analysis_id, threat_type, severity, description,
                    source_ip, confidence, timestamp, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            '''
            
            values = (
                analysis_id,
                result_data.get('threat_type', 'Suspicious Activity'),
                result_data.get('threat_level', 'MEDIUM'),
                result_data.get('description', 'Potential security threat detected'),
                result_data.get('source_ip', ''),
                result_data.get('combined_confidence', 0.0),
                datetime.now().isoformat(),
                'active'
            )
            
            cursor.execute(query, values)
            self.get_connection().commit()
            print(f"✅ Threat detection saved for analysis ID: {analysis_id}")
            
        except Exception as e:
            print(f"❌ Error saving threat detection: {e}")

    def get_enhanced_statistics(self):
        """Get enhanced statistics for dashboard"""
        try:
            cursor = self.get_cursor()
            stats = {}
            
            # Total threats
            cursor.execute('SELECT COUNT(*) FROM analysis_results WHERE prediction = 1')
            stats['total_threats'] = cursor.fetchone()[0]
            
            # Recent threats (last 24 hours)
            yesterday = (datetime.now() - timedelta(days=1)).isoformat()
            cursor.execute('''
                SELECT COUNT(*) FROM analysis_results 
                WHERE prediction = 1 AND timestamp > ?
            ''', (yesterday,))
            stats['recent_threats'] = cursor.fetchone()[0]
            
            # Total analysis count
            cursor.execute('SELECT COUNT(*) FROM analysis_results')
            stats['total_analysis'] = cursor.fetchone()[0]
            
            # Today's analysis count
            today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
            cursor.execute('SELECT COUNT(*) FROM analysis_results WHERE timestamp > ?', (today_start,))
            stats['today_analysis'] = cursor.fetchone()[0]
            
            # Success rate (percentage of analyses that detected threats)
            if stats['total_analysis'] > 0:
                stats['success_rate'] = stats['total_threats'] / stats['total_analysis']
            else:
                stats['success_rate'] = 0
            
            return stats
            
        except Exception as e:
            print(f"❌ Error getting statistics: {e}")
            return {
                'total_threats': 0,
                'recent_threats': 0,
                'total_analysis': 0,
                'today_analysis': 0,
                'success_rate': 0
            }

    def get_recent_threats(self, limit=10):
        """Get recent threats for dashboard"""
        try:
            cursor = self.get_cursor()
            cursor.execute('''
                SELECT t.threat_type, t.severity, t.description, t.source_ip, 
                       t.confidence, t.timestamp, a.user_id
                FROM threats t
                JOIN analysis_results a ON t.analysis_id = a.id
                ORDER BY t.timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            threats = []
            for row in cursor.fetchall():
                threats.append({
                    'type': row[0],
                    'severity': row[1],
                    'description': row[2],
                    'source_ip': row[3],
                    'confidence': row[4],
                    'timestamp': row[5],
                    'user_id': row[6]
                })
            
            return threats
            
        except Exception as e:
            print(f"❌ Error getting recent threats: {e}")
            return []

    def get_threat_distribution(self):
        """Get threat distribution by severity"""
        try:
            cursor = self.get_cursor()
            cursor.execute('''
                SELECT severity, COUNT(*) 
                FROM threats 
                WHERE status = 'active'
                GROUP BY severity
            ''')
            
            distribution = {}
            for row in cursor.fetchall():
                distribution[row[0]] = row[1]
            
            return distribution
            
        except Exception as e:
            print(f"❌ Error getting threat distribution: {e}")
            return {}

    def get_analysis_for_report(self, analysis_id):
        """Get analysis data for report generation"""
        try:
            cursor = self.get_cursor()
            cursor.execute('SELECT * FROM analysis_results WHERE id = ?', (analysis_id,))
            
            row = cursor.fetchone()
            if row:
                return {
                    'id': row[0],
                    'user_id': row[1],
                    'log_data': row[2],
                    'analysis_mode': row[3],
                    'prediction': row[4],
                    'confidence': row[5],
                    'threat_level': row[6],
                    'source_ip': row[7],
                    'features_used': row[8],
                    'behavioral_score': row[9],
                    'combined_confidence': row[10],
                    'encrypted_data': row[11],
                    'timestamp': row[12]
                }
            return None
            
        except Exception as e:
            print(f"❌ Error getting analysis for report: {e}")
            return None

    def get_recent_analysis_data(self, limit=50):
        """Get recent analysis data for reports"""
        try:
            cursor = self.get_cursor()
            cursor.execute('''
                SELECT * FROM analysis_results 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            analyses = []
            for row in cursor.fetchall():
                analyses.append({
                    'id': row[0],
                    'user_id': row[1],
                    'log_data': row[2],
                    'analysis_mode': row[3],
                    'prediction': row[4],
                    'confidence': row[5],
                    'threat_level': row[6],
                    'source_ip': row[7],
                    'features_used': row[8],
                    'behavioral_score': row[9],
                    'combined_confidence': row[10],
                    'encrypted_data': row[11],
                    'timestamp': row[12]
                })
            
            return analyses
            
        except Exception as e:
            print(f"❌ Error getting recent analysis data: {e}")
            return []

    def get_user_by_email(self, email):
        """Get user by email (for authentication)"""
        try:
            cursor = self.get_cursor()
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            row = cursor.fetchone()
            
            if row:
                return {
                    'id': row[0],
                    'username': row[1],
                    'email': row[2],
                    'password_hash': row[3],
                    'role': row[4],
                    'created_at': row[5],
                    'last_login': row[6]
                }
            return None
            
        except Exception as e:
            print(f"❌ Error getting user by email: {e}")
            return None

    def create_user(self, user_data):
        """Create a new user"""
        try:
            cursor = self.get_cursor()
            query = '''
                INSERT INTO users (username, email, password_hash, role, created_at)
                VALUES (?, ?, ?, ?, ?)
            '''
            
            values = (
                user_data.get('username', user_data.get('email').split('@')[0]),
                user_data.get('email'),
                user_data.get('password_hash', ''),
                user_data.get('role', 'user'),
                datetime.now().isoformat()
            )
            
            cursor.execute(query, values)
            self.get_connection().commit()
            
            return {
                'id': cursor.lastrowid,
                'username': values[0],
                'email': values[1],
                'role': values[3]
            }
            
        except Exception as e:
            print(f"❌ Error creating user: {e}")
            raise e

    def log_system_event(self, level, message, source='system'):
        """Log system event"""
        try:
            cursor = self.get_cursor()
            query = '''
                INSERT INTO system_logs (level, message, source, timestamp)
                VALUES (?, ?, ?, ?)
            '''
            
            values = (
                level,
                message,
                source,
                datetime.now().isoformat()
            )
            
            cursor.execute(query, values)
            self.get_connection().commit()
            
        except Exception as e:
            print(f"❌ Error logging system event: {e}")

    def close_connection(self):
        """Close thread-local connection"""
        if hasattr(self._local, 'conn'):
            self._local.conn.close()
            del self._local.conn
        if hasattr(self._local, 'cursor'):
            del self._local.cursor