import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import os
from dotenv import load_dotenv

load_dotenv()

def setup_database():
    """Setup PostgreSQL database and user"""
    try:
        # Connect to default postgres database
        conn = psycopg2.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            port=os.getenv('DB_PORT', '5432'),
            user='postgres',
            password=os.getenv('DB_PASSWORD', 'password'),
            database='postgres'
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        # Create database if it doesn't exist
        cursor.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = 'threat_detection'")
        exists = cursor.fetchone()
        
        if not exists:
            cursor.execute('CREATE DATABASE threat_detection')
            print("✅ Database 'threat_detection' created")
        else:
            print("✅ Database 'threat_detection' already exists")
        
        # Close connection to postgres database
        cursor.close()
        conn.close()
        
        # Now connect to our database and create tables
        conn = psycopg2.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            port=os.getenv('DB_PORT', '5432'),
            user='postgres',
            password=os.getenv('DB_PASSWORD', 'password'),
            database='threat_detection'
        )
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_results (
                id SERIAL PRIMARY KEY,
                user_id TEXT NOT NULL,
                log_data TEXT NOT NULL,
                analysis_mode TEXT NOT NULL,
                prediction INTEGER NOT NULL,
                confidence REAL NOT NULL,
                threat_level TEXT NOT NULL,
                source_ip TEXT,
                features_used INTEGER,
                behavioral_score REAL,
                combined_confidence REAL,
                encrypted_data TEXT,
                timestamp TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id SERIAL PRIMARY KEY,
                analysis_id INTEGER REFERENCES analysis_results(id),
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                source_ip TEXT,
                confidence REAL,
                timestamp TEXT NOT NULL,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                password_hash TEXT,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_analysis_timestamp ON analysis_results(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_analysis_prediction ON analysis_results(prediction)')
        
        conn.commit()
        print("✅ Tables created successfully")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"❌ Database setup error: {e}")

if __name__ == '__main__':
    setup_database()