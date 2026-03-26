import React, { useState } from 'react';
import axios from 'axios';

const Scanner = ({ ws }) => {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentModule, setCurrentModule] = useState('');
  const [results, setResults] = useState(null);
  const [email, setEmail] = useState('');
  const [scheduleScan, setScheduleScan] = useState(false);
  const [scheduleTime, setScheduleTime] = useState('');
  
  const startScan = async () => {
    if (!url) {
      alert('Please enter a URL to scan');
      return;
    }
    
    setScanning(true);
    setProgress(0);
    setResults(null);
    
    try {
      // Start scan
      const response = await axios.post('/api/scan', {
        url,
        email: email || null,
        scheduled: scheduleScan,
        schedule_time: scheduleTime
      });
      
      const scanId = response.data.scan_id;
      
      // Listen for progress updates via WebSocket
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.scan_id === scanId) {
          setProgress(data.progress);
          setCurrentModule(data.current_module);
          
          if (data.completed) {
            setScanning(false);
            fetchResults(scanId);
          }
        }
      };
      
    } catch (error) {
      console.error('Error starting scan:', error);
      setScanning(false);
      alert('Failed to start scan: ' + error.message);
    }
  };
  
  const fetchResults = async (scanId) => {
    try {
      const response = await axios.get(`/api/scan/${scanId}/results`);
      setResults(response.data);
    } catch (error) {
      console.error('Error fetching results:', error);
    }
  };
  
  const downloadReport = async (format) => {
    try {
      const response = await axios.get(`/api/scan/${results.scan_id}/report/${format}`, {
        responseType: 'blob'
      });
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `scan_report_${results.scan_id}.${format}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      
    } catch (error) {
      console.error('Error downloading report:', error);
    }
  };
  
  return (
    <div className="scanner-container">
      <div className="scanner-form">
        <h2>Security Scanner</h2>
        
        <div className="form-group">
          <label>Target URL</label>
          <input
            type="url"
            placeholder="https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={scanning}
          />
        </div>
        
        <div className="form-group">
          <label>Email for Report (Optional)</label>
          <input
            type="email"
            placeholder="reports@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            disabled={scanning}
          />
        </div>
        
        <div className="form-group checkbox">
          <label>
            <input
              type="checkbox"
              checked={scheduleScan}
              onChange={(e) => setScheduleScan(e.target.checked)}
              disabled={scanning}
            />
            Schedule recurring scan
          </label>
        </div>
        
        {scheduleScan && (
          <div className="form-group">
            <label>Schedule Time</label>
            <input
              type="datetime-local"
              value={scheduleTime}
              onChange={(e) => setScheduleTime(e.target.value)}
              disabled={scanning}
            />
          </div>
        )}
        
        <button
          className="scan-button"
          onClick={startScan}
          disabled={scanning}
        >
          {scanning ? 'Scanning...' : 'Start Scan'}
        </button>
        
        {scanning && (
          <div className="progress-container">
            <div className="progress-bar">
              <div
                className="progress-fill"
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="progress-text">
              {progress}% - {currentModule}
            </div>
          </div>
        )}
      </div>
      
      {results && (
        <div className="results-container">
          <h3>Scan Results</h3>
          
          <div className="severity-summary">
            <div className="severity-card critical">
              <div className="severity-count">{results.severity_summary.critical}</div>
              <div className="severity-label">Critical</div>
            </div>
            <div className="severity-card high">
              <div className="severity-count">{results.severity_summary.high}</div>
              <div className="severity-label">High</div>
            </div>
            <div className="severity-card medium">
              <div className="severity-count">{results.severity_summary.medium}</div>
              <div className="severity-label">Medium</div>
            </div>
            <div className="severity-card low">
              <div className="severity-count">{results.severity_summary.low}</div>
              <div className="severity-label">Low</div>
            </div>
          </div>
          
          <div className="vulnerabilities-list">
            <h4>Detected Vulnerabilities</h4>
            {results.vulnerabilities && results.vulnerabilities.map((vuln, index) => (
              <div key={index} className={`vulnerability-item ${vuln.severity}`}>
                <div className="vuln-header">
                  <span className="vuln-type">{vuln.type}</span>
                  <span className="vuln-severity">{vuln.severity.toUpperCase()}</span>
                </div>
                <div className="vuln-description">{vuln.description}</div>
                <div className="vuln-location">{vuln.location}</div>
                <div className="vuln-remediation">
                  <strong>Remediation:</strong> {vuln.remediation}
                </div>
              </div>
            ))}
          </div>
          
          <div className="report-actions">
            <button onClick={() => downloadReport('pdf')}>
              Download PDF Report
            </button>
            <button onClick={() => downloadReport('html')}>
              Download HTML Report
            </button>
            <button onClick={() => downloadReport('json')}>
              Download JSON Report
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default Scanner;