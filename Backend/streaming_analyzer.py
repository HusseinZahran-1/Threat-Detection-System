import asyncio
import websockets
import json
from datetime import datetime
from collections import deque
import threading
import time

class StreamingAnalyzer:
    def __init__(self):
        self.connected_clients = set()
        self.recent_logs = deque(maxlen=1000)
        self.analysis_queue = asyncio.Queue()
        self.is_running = False
        self.background_thread = None
        
    async def start_monitoring(self):
        """Start the streaming analysis system"""
        self.is_running = True
        print("🚀 Starting streaming analyzer...")
        
        # Start background processing
        self.background_thread = threading.Thread(target=self.start_background_loop)
        self.background_thread.daemon = True
        self.background_thread.start()
        
        # Start WebSocket server
        await self.start_websocket_server()
    
    def start_background_loop(self):
        """Start background event loop for processing"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.process_analysis_queue())
    
    async def start_websocket_server(self):
        """Start WebSocket server for real-time communication"""
        try:
            server = await websockets.serve(
                self.handle_client,
                "localhost",
                8765
            )
            print("🌐 WebSocket server started on ws://localhost:8765")
            await server.wait_closed()
        except Exception as e:
            print(f"❌ WebSocket server error: {e}")
    
    async def handle_client(self, websocket, path):
        """Handle new WebSocket client connections"""
        self.connected_clients.add(websocket)
        print(f"✅ New client connected. Total clients: {len(self.connected_clients)}")
        
        try:
            # Send welcome message
            welcome_msg = {
                'type': 'connection_established',
                'message': 'Connected to threat detection stream',
                'timestamp': datetime.now().isoformat()
            }
            await websocket.send(json.dumps(welcome_msg))
            
            # Keep connection alive
            async for message in websocket:
                try:
                    data = json.loads(message)
                    await self.handle_client_message(websocket, data)
                except json.JSONDecodeError:
                    print("❌ Invalid JSON received from client")
                    
        except websockets.exceptions.ConnectionClosed:
            print("📡 Client disconnected")
        finally:
            self.connected_clients.remove(websocket)
            print(f"📡 Client disconnected. Total clients: {len(self.connected_clients)}")
    
    async def handle_client_message(self, websocket, data):
        """Handle messages from clients"""
        message_type = data.get('type')
        
        if message_type == 'subscribe_alerts':
            # Client wants to receive threat alerts
            await self.send_confirmation(websocket, 'subscribed_alerts')
            
        elif message_type == 'unsubscribe_alerts':
            # Client wants to stop receiving alerts
            await self.send_confirmation(websocket, 'unsubscribed_alerts')
            
        elif message_type == 'ping':
            # Respond to ping
            await self.send_pong(websocket)
            
        elif message_type == 'submit_log':
            # Client submitted a log for analysis
            await self.analyze_log_data(data.get('log_data'))
    
    async def analyze_log_data(self, log_data):
        """Analyze incoming log data in real-time"""
        if not log_data:
            return
        
        # Add to recent logs
        self.recent_logs.append({
            'timestamp': datetime.now().isoformat(),
            'data': log_data
        })
        
        # Perform quick analysis
        threat_score = await self.quick_analysis(log_data)
        
        if threat_score > 0.7:
            # High threat detected, send immediate alert
            alert = {
                'type': 'threat_alert',
                'threat': {
                    'threat_type': self.determine_threat_type(log_data),
                    'confidence': threat_score,
                    'timestamp': datetime.now().isoformat(),
                    'description': 'Real-time threat detected',
                    'severity': 'high' if threat_score > 0.8 else 'medium'
                }
            }
            await self.broadcast_to_clients(alert)
    
    async def quick_analysis(self, log_data):
        """Perform quick real-time threat analysis"""
        threat_indicators = 0
        
        if isinstance(log_data, str):
            log_data = log_data.lower()
            
            # Check for SQL injection patterns
            sql_patterns = ['union select', 'or 1=1', 'drop table', 'insert into', '--']
            if any(pattern in log_data for pattern in sql_patterns):
                threat_indicators += 0.3
            
            # Check for XSS patterns
            xss_patterns = ['<script>', 'javascript:', 'onerror=', 'alert(']
            if any(pattern in log_data for pattern in xss_patterns):
                threat_indicators += 0.3
            
            # Check for command injection
            cmd_patterns = [';', '|', '&', '`', '$(']
            if any(pattern in log_data for pattern in cmd_patterns):
                threat_indicators += 0.2
            
            # Check for path traversal
            path_patterns = ['../', '..\\', '/etc/passwd']
            if any(pattern in log_data for pattern in path_patterns):
                threat_indicators += 0.2
        
        return min(threat_indicators, 1.0)
    
    def determine_threat_type(self, log_data):
        """Determine the type of threat based on patterns"""
        if not isinstance(log_data, str):
            return 'Suspicious Activity'
        
        log_data = log_data.lower()
        
        if any(pattern in log_data for pattern in ['union', 'select', 'drop', 'insert']):
            return 'SQL Injection'
        elif any(pattern in log_data for pattern in ['<script>', 'javascript:', 'alert(']):
            return 'XSS Attack'
        elif any(pattern in log_data for pattern in ['../', '..\\', '/etc/']):
            return 'Path Traversal'
        elif any(pattern in log_data for pattern in [';', '|', '&', '`']):
            return 'Command Injection'
        else:
            return 'Suspicious Activity'
    
    async def process_analysis_queue(self):
        """Process analysis tasks from the queue"""
        while self.is_running:
            try:
                # Process any queued analysis tasks
                await asyncio.sleep(1)
                
                # Send periodic system updates
                await self.send_system_updates()
                
            except Exception as e:
                print(f"❌ Error in analysis queue processing: {e}")
                await asyncio.sleep(5)
    
    async def send_system_updates(self):
        """Send periodic system status updates to clients"""
        if not self.connected_clients:
            return
        
        system_status = {
            'type': 'system_metrics',
            'metrics': {
                'connected_clients': len(self.connected_clients),
                'recent_logs_count': len(self.recent_logs),
                'system_health': 95,
                'timestamp': datetime.now().isoformat()
            }
        }
        
        await self.broadcast_to_clients(system_status)
    
    async def broadcast_to_clients(self, message):
        """Broadcast message to all connected clients"""
        if not self.connected_clients:
            return
        
        disconnected_clients = set()
        
        for client in self.connected_clients:
            try:
                await client.send(json.dumps(message))
            except websockets.exceptions.ConnectionClosed:
                disconnected_clients.add(client)
            except Exception as e:
                print(f"❌ Error sending to client: {e}")
                disconnected_clients.add(client)
        
        # Remove disconnected clients
        self.connected_clients -= disconnected_clients
    
    async def send_confirmation(self, websocket, confirmation_type):
        """Send confirmation message to client"""
        confirmation = {
            'type': confirmation_type,
            'timestamp': datetime.now().isoformat()
        }
        try:
            await websocket.send(json.dumps(confirmation))
        except websockets.exceptions.ConnectionClosed:
            pass
    
    async def send_pong(self, websocket):
        """Respond to ping with pong"""
        pong = {
            'type': 'pong',
            'timestamp': datetime.now().isoformat()
        }
        try:
            await websocket.send(json.dumps(pong))
        except websockets.exceptions.ConnectionClosed:
            pass
    
    def submit_log_for_analysis(self, log_data):
        """Submit log data for analysis (thread-safe)"""
        asyncio.run_coroutine_threadsafe(
            self.analyze_log_data(log_data),
            asyncio.get_event_loop()
        )
    
    async def stop_monitoring(self):
        """Stop the streaming analysis system"""
        self.is_running = False
        print("🛑 Stopping streaming analyzer...")
        
        # Close all client connections
        for client in self.connected_clients.copy():
            await client.close()
        
        self.connected_clients.clear()

# Singleton instance
streaming_analyzer = StreamingAnalyzer()

async def start_streaming_analysis():
    """Start the streaming analysis system"""
    await streaming_analyzer.start_monitoring()

if __name__ == "__main__":
    # Test the streaming analyzer
    asyncio.run(start_streaming_analysis())