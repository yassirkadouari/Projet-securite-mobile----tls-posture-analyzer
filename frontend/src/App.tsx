import React, { useState, useRef } from 'react';
import html2pdf from 'html2pdf.js';
import { 
  Shield, ShieldAlert, CheckCircle, XCircle, Download, Loader2, 
  FileBox, FileText, BrainCircuit, Activity, Lock, AlertTriangle
} from 'lucide-react';
import './App.css';

// --- Interfaces ---
interface AndroidConfig {
  cleartextTrafficPermitted: string;
  minSdkVersion: string;
  certificatePinning: boolean;
  pins: string[];
}

interface AIAnalysis {
  grouping: Record<string, string[]>;
  summary: string;
  recommendations: string[];
}

interface ScanData {
  hostname: string;
  port: number;
  certificate: any;
  protocols: Record<string, boolean>;
  vulnerabilities: Record<string, boolean>;
  security_headers: Record<string, boolean>;
  advanced_security: Record<string, boolean>;
}

function App() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const [androidConfig, setAndroidConfig] = useState<AndroidConfig | null>(null);
  const [endpoints, setEndpoints] = useState<string[]>([]);
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysis | null>(null);
  const [tlsScans, setTlsScans] = useState<Record<string, ScanData>>({});
  const [scanningTls, setScanningTls] = useState<Record<string, boolean>>({});

  const apkInputRef = useRef<HTMLInputElement>(null);
  const logsInputRef = useRef<HTMLInputElement>(null);

  // --- Handlers ---
  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>, type: 'apk' | 'logs') => {
    const file = event.target.files?.[0];
    if (!file) return;

    setLoading(true);
    setError(null);
    
    const formData = new FormData();
    formData.append('file', file);

    try {
      const endpoint = type === 'apk' ? '/api/upload-apk' : '/api/upload-logs';
      const response = await fetch(`http://127.0.0.1:8000${endpoint}`, {
        method: 'POST',
        body: formData,
      });
      const data = await response.json();
      
      if (!response.ok) throw new Error(data.detail || 'Erreur lors du traitement du fichier.');
      
      if (type === 'apk') {
        setAndroidConfig(data.security_config);
        mergeEndpoints(data.discovered_endpoints);
      } else {
        mergeEndpoints(data.endpoints);
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
      if (event.target) event.target.value = '';
    }
  };

  const mergeEndpoints = (newEndpoints: string[]) => {
    setEndpoints(prev => Array.from(new Set([...prev, ...newEndpoints])));
  };

  const handleAIAnalysis = async () => {
    if (endpoints.length === 0) return;
    setLoading(true);
    try {
      const response = await fetch('http://127.0.0.1:8000/api/ai-analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(endpoints),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail);
      setAiAnalysis(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleTLSScan = async (hostname: string) => {
    setScanningTls(prev => ({ ...prev, [hostname]: true }));
    try {
      const response = await fetch(`http://127.0.0.1:8000/api/scan?hostname=${hostname}&port=443`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail);
      setTlsScans(prev => ({ ...prev, [hostname]: data.data }));
    } catch (err: any) {
      alert(`Erreur scan ${hostname}: ${err.message}`);
    } finally {
      setScanningTls(prev => ({ ...prev, [hostname]: false }));
    }
  };

  const handleDownloadPDF = () => {
    const element = document.getElementById('report-content');
    if (!element) return;
    
    html2pdf().set({
      margin: 10, filename: `Audit_Defensif_Mobile.pdf`,
      image: { type: 'jpeg', quality: 0.98 },
      html2canvas: { scale: 2, useCORS: true, logging: false },
      jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
    }).from(element).save();
  };

  return (
    <div className="min-h-screen app-container">
      <div className="background-gradient"></div>
      
      <main className="main-content">
        <header className="header">
          <div className="logo-container">
            <Shield className="logo-icon" size={40} />
            <h1 className="logo-text">Audit Défensif <span className="highlight">Mobile / TLS</span></h1>
          </div>
          <p className="subtitle">Analyse APK, Endpoints Proxy et Posture de Sécurité Transport</p>
        </header>

        {error && (
          <div className="error-message">
            <ShieldAlert size={20} /> {error}
          </div>
        )}

        {/* UPLOAD SECTION */}
        <section className="upload-section glass-panel">
          <div className="upload-card" onClick={() => apkInputRef.current?.click()}>
            <FileBox size={40} className="upload-icon" />
            <h3>Uploader APK</h3>
            <p>Analyse de network_security_config.xml</p>
            <input type="file" ref={apkInputRef} accept=".apk" hidden onChange={(e) => handleFileUpload(e, 'apk')} />
          </div>

          <div className="upload-card" onClick={() => logsInputRef.current?.click()}>
            <FileText size={40} className="upload-icon" />
            <h3>Uploader Logs Proxy</h3>
            <p>Fichier texte brut (Burp/Wireshark)</p>
            <input type="file" ref={logsInputRef} accept=".txt,.log,.json" hidden onChange={(e) => handleFileUpload(e, 'logs')} />
          </div>
        </section>

        <div id="report-content">
          {/* ANDROID CONFIG SECTION */}
          {androidConfig && (
            <section className="report-section glass-panel">
              <h2 className="section-title"><Lock size={20} /> Configuration de Sécurité Android</h2>
              <div className="grid-2">
                <div className="info-box">
                  <span className="info-label">Cleartext Traffic (HTTP)</span>
                  <span className={`status-badge ${androidConfig.cleartextTrafficPermitted.includes('Oui') ? 'badge-danger' : 'badge-success'}`}>
                    {androidConfig.cleartextTrafficPermitted}
                  </span>
                </div>
                <div className="info-box">
                  <span className="info-label">Certificate Pinning</span>
                  <span className={`status-badge ${androidConfig.certificatePinning ? 'badge-success' : 'badge-warning'}`}>
                    {androidConfig.certificatePinning ? 'Actif' : 'Non détecté'}
                  </span>
                </div>
              </div>
              {androidConfig.pins.length > 0 && (
                <div className="pins-box">
                  <span className="info-label">Pins détectés :</span>
                  <code>{androidConfig.pins.join(', ')}</code>
                </div>
              )}
            </section>
          )}

          {/* ENDPOINTS & AI SECTION */}
          {endpoints.length > 0 && (
            <section className="report-section glass-panel">
              <div className="section-header">
                <h2 className="section-title"><BrainCircuit size={20} /> Analyse des Flux (IA)</h2>
                <button className="ai-btn" onClick={handleAIAnalysis} disabled={loading}>
                  {loading ? <Loader2 className="spinner" size={16} /> : 'Catégoriser avec l\'IA'}
                </button>
              </div>

              {aiAnalysis ? (
                <div className="ai-results">
                  <div className="ai-summary">
                    <p>{aiAnalysis.summary}</p>
                    <h4>Recommandations Prioritaires :</h4>
                    <ul>
                      {aiAnalysis.recommendations.map((rec, i) => <li key={i}>{rec}</li>)}
                    </ul>
                  </div>
                  
                  <div className="grid-2">
                    {Object.entries(aiAnalysis.grouping).map(([groupName, eps]) => (
                      <div key={groupName} className="group-box">
                        <h4 className={groupName.includes('Suspect') ? 'text-danger' : 'text-primary'}>
                          {groupName} ({eps.length})
                        </h4>
                        <ul className="endpoint-list">
                          {eps.map(ep => (
                            <li key={ep} className="endpoint-item">
                              <span>{ep}</span>
                              <button 
                                className="tls-btn" 
                                onClick={() => handleTLSScan(ep)}
                                disabled={scanningTls[ep]}
                              >
                                {scanningTls[ep] ? <Loader2 size={14} className="spinner"/> : 'Scan TLS'}
                              </button>
                            </li>
                          ))}
                        </ul>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="raw-endpoints">
                  <p>{endpoints.length} endpoints découverts. Lancez l'IA pour les classer.</p>
                </div>
              )}
            </section>
          )}

          {/* TLS SCAN RESULTS SECTION */}
          {Object.entries(tlsScans).length > 0 && (
            <section className="report-section glass-panel">
              <div className="section-header">
                <h2 className="section-title"><Activity size={20} /> Audit Posture TLS (Backend)</h2>
                <button onClick={handleDownloadPDF} className="download-btn">
                  <Download size={16} /> Exporter PDF
                </button>
              </div>

              <div className="tls-results-grid">
                {Object.entries(tlsScans).map(([host, scan]) => (
                  <div key={host} className="tls-card">
                    <h3>{host}</h3>
                    
                    <div className="tls-row">
                      <span>TLS 1.2 / 1.3 :</span>
                      {(scan.protocols['TLS 1.2'] || scan.protocols['TLS 1.3']) ? 
                        <span className="badge-success"><CheckCircle size={14}/> Supporté</span> : 
                        <span className="badge-danger"><XCircle size={14}/> Non Supporté</span>}
                    </div>
                    
                    <div className="tls-row">
                      <span>Protocoles Obsolètes (SSL/TLS 1.0) :</span>
                      {(scan.protocols['SSL 2.0'] || scan.protocols['SSL 3.0'] || scan.protocols['TLS 1.0'] || scan.protocols['TLS 1.1']) ? 
                        <span className="badge-danger"><AlertTriangle size={14}/> Actif</span> : 
                        <span className="badge-success"><CheckCircle size={14}/> Désactivé</span>}
                    </div>

                    <div className="tls-row">
                      <span>HSTS (Strict-Transport-Security) :</span>
                      {scan.security_headers['HSTS (Strict-Transport-Security)'] ? 
                        <span className="badge-success">Présent</span> : 
                        <span className="badge-warning">Absent</span>}
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>
      </main>
    </div>
  );
}

export default App;
