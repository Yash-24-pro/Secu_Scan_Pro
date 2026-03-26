import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import Scanner from './components/Scanner';
import Reports from './components/Reports';
import Settings from './components/Settings';
import RealTimeMonitor from './components/RealTimeMonitor';
import './styles/main.css';

function App() {
  const [activeScan, setActiveScan] = useState(null);
  const [wsConnection, setWsConnection] = useState(null);
  
  useEffect(() => {
    // Initialize WebSocket connection
    const ws = new WebSocket('ws://localhost:8000/ws');
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'scan_progress') {
        setActiveScan(data);
      }
    };
    setWsConnection(ws);
    
    return () => ws.close();
  }, []);
  
  return (
    <Router>
      <div className="app">
        <nav className="navbar">
          <div className="nav-container">
            <div className="logo">
              <h1>VulnScanner Pro</h1>
              <span className="badge">Enterprise Edition</span>
            </div>
            <ul className="nav-menu">
              <li><Link to="/">Dashboard</Link></li>
              <li><Link to="/scanner">Scanner</Link></li>
              <li><Link to="/reports">Reports</Link></li>
              <li><Link to="/monitor">Live Monitor</Link></li>
              <li><Link to="/settings">Settings</Link></li>
            </ul>
            <div className="status-indicator">
              <span className="status-dot"></span>
              System Active
            </div>
          </div>
        </nav>
        
        <div className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard activeScan={activeScan} />} />
            <Route path="/scanner" element={<Scanner ws={wsConnection} />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/monitor" element={<RealTimeMonitor ws={wsConnection} />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </div>
      </div>
    </Router>
  );
}

export default App;