import React, { useState, useEffect } from 'react';
import VulnerabilityChart from './VulnerabilityChart';
import axios from 'axios';

const Dashboard = ({ activeScan }) => {
  const [stats, setStats] = useState({
    totalScans: 0,
    vulnerabilities: 0,
    criticalVulns: 0,
    highVulns: 0,
    mediumVulns: 0,
    lowVulns: 0,
    averageScore: 0
  });
  
  const [recentScans, setRecentScans] = useState([]);
  
  useEffect(() => {
    fetchStats();
    fetchRecentScans();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(() => {
      fetchStats();
      fetchRecentScans();
    }, 30000);
    
    return () => clearInterval(interval);
  }, []);
  
  const fetchStats = async () => {
    try {
      const response = await axios.get('/api/stats');
      setStats(response.data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  };
  
  const fetchRecentScans = async () => {
    try {
      const response = await axios.get('/api/scans?limit=5');
      setRecentScans(response.data);
    } catch (error) {
      console.error('Error fetching recent scans:', error);
    }
  };
  
  return (
    <div className="dashboard">
      <div className="stats-grid">
        <div className="stat-card">
          <h3>Total Scans</h3>
          <div className="stat-value">{stats.totalScans}</div>
          <div className="stat-trend">+12% this week</div>
        </div>
        
        <div className="stat-card">
          <h3>Vulnerabilities Found</h3>
          <div className="stat-value">{stats.vulnerabilities}</div>
          <div className="stat-trend">Critical: {stats.criticalVulns}</div>
        </div>
        
        <div className="stat-card">
          <h3>Security Score</h3>
          <div className="stat-value">{stats.averageScore}/100</div>
          <div className="stat-trend">-5% from last scan</div>
        </div>
        
        <div className="stat-card">
          <h3>Active Scans</h3>
          <div className="stat-value">{activeScan ? 1 : 0}</div>
          <div className="stat-trend">
            {activeScan && `Scanning: ${activeScan.url}`}
          </div>
        </div>
      </div>
      
      <div className="charts-container">
        <div className="chart-card">
          <h3>Vulnerability Distribution</h3>
          <VulnerabilityChart stats={stats} />
        </div>
        
        <div className="recent-scans-card">
          <h3>Recent Scans</h3>
          <table className="scans-table">
            <thead>
              <tr>
                <th>URL</th>
                <th>Date</th>
                <th>Vulnerabilities</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {recentScans.map(scan => (
                <tr key={scan.id}>
                  <td>{scan.url}</td>
                  <td>{new Date(scan.created_at).toLocaleString()}</td>
                  <td>
                    <span className="badge critical">{scan.critical_count}</span>
                    <span className="badge high">{scan.high_count}</span>
                    <span className="badge medium">{scan.medium_count}</span>
                    <span className="badge low">{scan.low_count}</span>
                  </td>
                  <td>
                    <span className={`status-badge ${scan.status}`}>
                      {scan.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;