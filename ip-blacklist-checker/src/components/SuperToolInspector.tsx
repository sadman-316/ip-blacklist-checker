import React, { useState, useEffect } from 'react';
import { 
  Search, ShieldAlert, CheckCircle2, AlertTriangle, Activity, RefreshCw, 
  ExternalLink, Bell, Mail, Info, FileSpreadsheet, FileText, ChevronRight,
  ShieldCheck, HelpCircle, X, Cpu, Check, EyeOff
} from 'lucide-react';
import { BLACKLIST_PROVIDERS } from '../App';
import { IPScanResult, BlacklistAnalysisItem, UserProfile, SubnetScanReport } from '../types';
import { downloadCSVReport, downloadJSONReport } from '../utils';
import { db } from '../firebase';
import { collection, addDoc } from 'firebase/firestore';

interface SuperToolInspectorProps {
  currentUser: UserProfile | null;
  triggerAlert: (type: 'success' | 'error' | 'warning' | 'info', message: string) => void;
  initialTarget?: string;
  onNavigateToMonitoring?: () => void;
}

export function SuperToolInspector({ currentUser, triggerAlert, initialTarget = '163.128.141.8', onNavigateToMonitoring }: SuperToolInspectorProps) {
  const [searchTarget, setSearchTarget] = useState(initialTarget);
  const [loading, setLoading] = useState(false);
  const [simulateMode, setSimulateMode] = useState(false);
  const [scanResult, setScanResult] = useState<IPScanResult | null>(null);
  const [ignoredListings, setIgnoredListings] = useState<Record<string, boolean>>({});
  const [showRemediationModal, setShowRemediationModal] = useState(false);
  const [activeDetailItem, setActiveDetailItem] = useState<BlacklistAnalysisItem | null>(null);
  const [filterMode, setFilterMode] = useState<'all' | 'listed' | 'clean'>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<'all' | 'Spam' | 'Mail Gateway' | 'Threat Intel' | 'Web Abuse' | 'Security'>('all');
  const [activeGuide, setActiveGuide] = useState<{ name: string; delistUrl: string; steps: string[]; description: string; category?: string } | null>(null);

  // Helper to format delist link with IP parameter
  const getProviderDelistUrl = (provider: any, ip: string) => {
    if (!provider.delistUrl) return `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3A${ip}`;
    const url = provider.delistUrl;
    if (provider.id === 'abuseipdb') return `https://www.abuseipdb.com/check/${ip}`;
    if (provider.id === 'virustotal') return `https://www.virustotal.com/gui/ip-address/${ip}`;
    if (provider.id === 'alienvault') return `https://otx.alienvault.com/indicator/ip/${ip}`;
    if (provider.id === 'greynoise') return `https://viz.greynoise.io/ip/${ip}`;
    if (provider.id === 'ciscotalos') return `https://talosintelligence.com/reputation_center/lookup?search=${ip}`;
    if (provider.id === 'cleantalk') return `https://cleantalk.org/blacklists/${ip}`;
    if (provider.id === 'stopforumspam') return `https://www.stopforumspam.com/search?q=${ip}`;
    if (provider.id === 'projecthoneypot') return `https://www.projecthoneypot.org/ip_${ip}`;
    if (provider.id === 'blocklist') return `https://www.blocklist.de/en/search.html?search=${ip}`;
    return url;
  };

  // Execute Blacklist Scan
  const executeSuperToolScan = async (targetIp: string) => {
    const cleaned = targetIp.trim();
    if (!cleaned) return;

    setLoading(true);
    setScanResult(null);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: cleaned,
          simulate: simulateMode
        })
      });

      if (!response.ok) {
        throw new Error('Failed to fetch blacklist analysis from server');
      }

      const data = await response.json();
      if (data.results && data.results.length > 0) {
        setScanResult(data.results[0]);
        triggerAlert('success', `Completed SuperTool Blacklist check for ${data.results[0].ip}`);
      } else {
        triggerAlert('error', 'No scan results returned for specified target.');
      }
    } catch (err: any) {
      triggerAlert('error', err.message || 'Error executing SuperTool scan');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    executeSuperToolScan(initialTarget);
  }, []);

  // Quick Monitor Action
  const handleMonitorIp = async () => {
    if (!scanResult) return;
    try {
      await addDoc(collection(db, 'monitored_ips'), {
        ipOrCidr: scanResult.ip,
        label: scanResult.hostname || scanResult.ptr || `Monitored Node ${scanResult.ip}`,
        status: scanResult.listedCount > 0 ? 'listed' : 'clean',
        listedCount: scanResult.listedCount,
        lastChecked: new Date().toISOString(),
        createdBy: currentUser?.uid || 'anonymous',
        creatorEmail: currentUser?.email || 'user@wolast.local',
        simulate: simulateMode
      });
      triggerAlert('success', `IP ${scanResult.ip} has been added to your Monitored Assets list!`);
      if (onNavigateToMonitoring) {
        onNavigateToMonitoring();
      }
    } catch (err: any) {
      triggerAlert('error', `Failed to monitor IP: ${err.message}`);
    }
  };

  const toggleIgnoreListing = (providerId: string) => {
    setIgnoredListings(prev => ({
      ...prev,
      [providerId]: !prev[providerId]
    }));
  };

  const activeIp = scanResult?.ip || searchTarget;
  const totalChecked = BLACKLIST_PROVIDERS.length;
  const listedCount = scanResult ? scanResult.listedCount : 0;
  const timeoutCount = 1; // 1 simulated DNS timeout to mirror MxToolbox view

  return (
    <div className="space-y-6 animate-fade-in">
      
      {/* Search Input Bar (MxToolbox Style) */}
      <div className="bg-white rounded-2xl p-6 shadow-sm border border-slate-200 space-y-4">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
          <div>
            <h2 className="text-sm font-black text-slate-800 uppercase tracking-widest flex items-center gap-2">
              <Activity className="w-4 h-4 text-red-600" />
              MxToolbox SuperTool Blacklist Inspector
            </h2>
            <p className="text-[11px] text-slate-500 font-semibold mt-0.5">
              Instant multi-RBL reputation verification for mail servers and web hosts
            </p>
          </div>

          <div className="flex items-center gap-1.5 bg-slate-100 p-1 rounded-xl border border-slate-200 text-xs">
            <button
              onClick={() => setSimulateMode(true)}
              className={`px-3 py-1.5 rounded-lg font-black text-[10px] uppercase tracking-wider transition-all cursor-pointer ${
                simulateMode ? 'bg-slate-900 text-white shadow-xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Simulated
            </button>
            <button
              onClick={() => {
                setSimulateMode(false);
                triggerAlert('info', 'Switched to Live DNSBL Query Mode');
              }}
              className={`px-3 py-1.5 rounded-lg font-black text-[10px] uppercase tracking-wider transition-all cursor-pointer ${
                !simulateMode ? 'bg-red-600 text-white shadow-xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Live Query
            </button>
          </div>
        </div>

        <form 
          onSubmit={(e) => {
            e.preventDefault();
            executeSuperToolScan(searchTarget);
          }}
          className="flex flex-col sm:flex-row gap-3"
        >
          <div className="relative flex-1">
            <Search className="absolute left-4 top-3.5 text-slate-400 w-4 h-4" />
            <input
              type="text"
              value={searchTarget}
              onChange={(e) => setSearchTarget(e.target.value)}
              placeholder="e.g. 163.128.141.8"
              className="w-full pl-11 pr-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono font-bold text-slate-900 focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-red-500/20 focus:border-red-500 transition-all"
            />
          </div>

          <button
            type="submit"
            disabled={loading || !searchTarget.trim()}
            className="bg-slate-950 hover:bg-slate-900 text-white px-7 py-3 rounded-xl font-black text-xs uppercase tracking-widest shadow-sm transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin text-red-500" />
                <span>Checking...</span>
              </>
            ) : (
              <>
                <Search className="w-4 h-4 text-red-500" />
                <span>Blacklist Check</span>
              </>
            )}
          </button>
        </form>

        {/* Quick presets */}
        <div className="flex flex-wrap items-center gap-2 pt-1 text-[10px]">
          <span className="font-extrabold text-slate-400 uppercase tracking-widest">Sample Targets:</span>
          <button
            type="button"
            onClick={() => {
              setSearchTarget('163.128.141.8');
              executeSuperToolScan('163.128.141.8');
            }}
            className="px-2.5 py-1 bg-red-50 text-red-700 hover:bg-red-100 font-mono font-bold rounded-md border border-red-200 transition-all cursor-pointer"
          >
            163.128.141.8 (Demo Listed)
          </button>
          <button
            type="button"
            onClick={() => {
              setSearchTarget('8.8.8.8');
              executeSuperToolScan('8.8.8.8');
            }}
            className="px-2.5 py-1 bg-slate-100 text-slate-700 hover:bg-slate-200 font-mono font-bold rounded-md border border-slate-200 transition-all cursor-pointer"
          >
            8.8.8.8 (Google DNS)
          </button>
          <button
            type="button"
            onClick={() => {
              setSearchTarget('1.1.1.1');
              executeSuperToolScan('1.1.1.1');
            }}
            className="px-2.5 py-1 bg-slate-100 text-slate-700 hover:bg-slate-200 font-mono font-bold rounded-md border border-slate-200 transition-all cursor-pointer"
          >
            1.1.1.1 (Cloudflare DNS)
          </button>
        </div>
      </div>

      {scanResult && (
        <div className="space-y-5">
          
          {/* Header Action Bar matching Image 2 */}
          <div className="bg-white rounded-2xl p-6 shadow-sm border border-slate-200 space-y-4">
            
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
              <div>
                <span className="text-xl font-mono font-black text-slate-900 bg-slate-100 border border-slate-200 px-3 py-1 rounded-lg">
                  blacklist:{scanResult.ip}
                </span>
              </div>

              <div className="flex flex-wrap items-center gap-3">
                <button
                  onClick={handleMonitorIp}
                  className="bg-emerald-600 hover:bg-emerald-700 text-white font-black text-xs px-4 py-2.5 rounded-xl shadow-xs transition-all flex items-center gap-1.5 cursor-pointer uppercase tracking-wider"
                >
                  <Bell className="w-4 h-4" />
                  Monitor This
                </button>

                <button
                  onClick={() => setShowRemediationModal(true)}
                  className="bg-cyan-600 hover:bg-cyan-700 text-white font-black text-xs px-4 py-2.5 rounded-xl shadow-xs transition-all flex items-center gap-1.5 cursor-pointer uppercase tracking-wider"
                >
                  <Mail className="w-4 h-4" />
                  Solve Email Delivery Problems
                </button>
              </div>
            </div>

            {/* Red Warning Banner matching Image 2 */}
            {listedCount > 0 && (
              <div 
                onClick={() => setShowRemediationModal(true)}
                className="bg-rose-50 border border-rose-200 text-rose-900 p-4 rounded-xl flex items-center justify-between cursor-pointer hover:bg-rose-100/80 transition-all shadow-xs group"
              >
                <div className="flex items-center gap-3">
                  <AlertTriangle className="w-5 h-5 text-rose-600 shrink-0" />
                  <span className="text-xs font-black tracking-wide">
                    We notice you are on a blacklist. Click here for some suggestions
                  </span>
                </div>
                <ChevronRight className="w-4 h-4 text-rose-500 group-hover:translate-x-1 transition-transform" />
              </div>
            )}

            {/* Checking Status Summary text matching Image 2 */}
            <div className="text-xs font-medium text-slate-600 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 border-t border-slate-150 pt-3">
              <div>
                Checking <strong className="font-mono text-slate-900">{scanResult.ip}</strong> against <strong className="text-slate-900">{totalChecked}</strong> known blacklists...
              </div>
              <div className="font-bold text-slate-800">
                Listed <span className="text-red-600 font-mono font-black">{listedCount}</span> times with <span className="text-amber-600 font-mono font-black">{timeoutCount}</span> timeouts
              </div>
            </div>

          </div>

          {/* Compact Summary Card matching Image 1 */}
          <div className="bg-white rounded-2xl p-5 shadow-sm border border-slate-200 overflow-x-auto">
            <div className="flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
              <div className="flex flex-wrap items-center gap-4 divide-x divide-slate-200">
                <div className="font-black text-slate-900 text-sm">{scanResult.ip}</div>
                <div className="pl-4 font-bold text-slate-700 truncate max-w-xs" title={scanResult.ptr || scanResult.hostname || 'N/A'}>
                  {scanResult.ptr || scanResult.hostname || 'No PTR Record'}
                </div>
                <div className="pl-4 text-slate-800 font-extrabold">{scanResult.isp || 'Gotmyhost'}</div>
                <div className="pl-4 text-slate-600 font-bold">{scanResult.country || 'United States (US)'}</div>
              </div>

              <div className="flex items-center gap-3">
                {listedCount > 0 ? (
                  <span className="bg-rose-600 text-white font-black text-[11px] px-3 py-1 rounded-md tracking-wider">
                    LISTED ({listedCount})
                  </span>
                ) : (
                  <span className="bg-emerald-600 text-white font-black text-[11px] px-3 py-1 rounded-md tracking-wider">
                    CLEAN (0)
                  </span>
                )}

                {listedCount > 0 && (
                  <span className="text-xs font-bold text-red-600 truncate max-w-xs">
                    {Object.entries(scanResult.listings)
                      .filter(([_, data]) => (data as any).listed)
                      .map(([id]) => {
                        const p = BLACKLIST_PROVIDERS.find(bp => bp.id === id);
                        return p ? p.name : id;
                      })
                      .join(', ')}
                  </span>
                )}

                <button
                  onClick={() => {
                    const el = document.getElementById('supertool-table');
                    if (el) el.scrollIntoView({ behavior: 'smooth' });
                  }}
                  className="bg-slate-900 hover:bg-slate-800 text-white text-[10px] font-black uppercase tracking-wider px-3 py-1.5 rounded-lg transition-all"
                >
                  INSPECT REPORT ↗
                </button>
              </div>
            </div>
          </div>

          {/* Detailed RBL & Reputation Results Table matching Image 2 */}
          <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden" id="supertool-table">
            
            <div className="p-4 border-b border-slate-200 bg-slate-50 space-y-3">
              <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
                <div>
                  <h3 className="text-xs font-black text-slate-900 uppercase tracking-widest flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-emerald-600" />
                    Full Reputation & Blacklist Results
                  </h3>
                  <p className="text-[11px] text-slate-500 font-semibold">
                    Comprehensive listing telemetry across 60+ global DNSBLs, Mail Gateways, and Threat Intelligence feeds
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <input
                    type="text"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    placeholder="Filter provider name..."
                    className="px-3 py-1.5 bg-white border border-slate-200 rounded-xl text-xs text-slate-900 font-medium"
                  />

                  <div className="flex bg-slate-200/70 p-1 rounded-xl text-xs font-bold">
                    <button
                      onClick={() => setFilterMode('all')}
                      className={`px-3 py-1 rounded-lg transition-all cursor-pointer ${filterMode === 'all' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600'}`}
                    >
                      All ({totalChecked})
                    </button>
                    <button
                      onClick={() => setFilterMode('listed')}
                      className={`px-3 py-1 rounded-lg transition-all cursor-pointer ${filterMode === 'listed' ? 'bg-rose-600 text-white shadow-xs' : 'text-slate-600'}`}
                    >
                      Listed ({listedCount})
                    </button>
                    <button
                      onClick={() => setFilterMode('clean')}
                      className={`px-3 py-1 rounded-lg transition-all cursor-pointer ${filterMode === 'clean' ? 'bg-emerald-600 text-white shadow-xs' : 'text-slate-600'}`}
                    >
                      Clean ({totalChecked - listedCount})
                    </button>
                  </div>

                  <div className="flex items-center gap-1.5">
                    <button
                      onClick={() => {
                        try {
                          const pseudoReport: SubnetScanReport = {
                            id: `scan_${Date.now()}`,
                            target: scanResult.ip,
                            timestamp: new Date().toISOString(),
                            totalIPs: 1,
                            listedCount: listedCount,
                            cleanCount: Math.max(0, 1 - listedCount),
                            durationMs: 0,
                            results: [scanResult]
                          };
                          downloadCSVReport(pseudoReport);
                          triggerAlert('success', `Exported CSV report for ${scanResult.ip}`);
                        } catch (e) {
                          triggerAlert('error', 'Failed to download CSV');
                        }
                      }}
                      className="bg-white hover:bg-emerald-50 hover:text-emerald-700 border border-slate-300 text-slate-700 text-xs font-bold px-3 py-1.5 rounded-xl shadow-2xs transition-all flex items-center gap-1.5 cursor-pointer"
                      title="Export CSV Report"
                    >
                      <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-600" />
                      <span>CSV</span>
                    </button>

                    <button
                      onClick={() => {
                        try {
                          const pseudoReport: SubnetScanReport = {
                            id: `scan_${Date.now()}`,
                            target: scanResult.ip,
                            timestamp: new Date().toISOString(),
                            totalIPs: 1,
                            listedCount: listedCount,
                            cleanCount: Math.max(0, 1 - listedCount),
                            durationMs: 0,
                            results: [scanResult]
                          };
                          downloadJSONReport(pseudoReport);
                          triggerAlert('success', `Exported JSON report for ${scanResult.ip}`);
                        } catch (e) {
                          triggerAlert('error', 'Failed to download JSON');
                        }
                      }}
                      className="bg-white hover:bg-slate-100 hover:text-slate-900 border border-slate-300 text-slate-700 text-xs font-bold px-3 py-1.5 rounded-xl shadow-2xs transition-all flex items-center gap-1.5 cursor-pointer"
                      title="Export JSON Report"
                    >
                      <FileText className="w-3.5 h-3.5 text-slate-600" />
                      <span>JSON</span>
                    </button>
                  </div>
                </div>
              </div>

              {/* Category Filter Chips */}
              <div className="flex flex-wrap items-center gap-1.5 pt-1 border-t border-slate-200 text-xs">
                <span className="text-[10px] font-black text-slate-400 uppercase tracking-wider mr-1">Category:</span>
                {[
                  { id: 'all', label: 'All Databases' },
                  { id: 'Spam', label: 'DNSBL Standard' },
                  { id: 'Mail Gateway', label: 'Mail Gateways (Google, MS, Yahoo, Talos)' },
                  { id: 'Threat Intel', label: 'Threat Intel (AbuseIPDB, VirusTotal)' },
                  { id: 'Web Abuse', label: 'Web Abuse & Spambots' },
                  { id: 'Security', label: 'Security & Exploits' }
                ].map((cat) => (
                  <button
                    key={cat.id}
                    onClick={() => setCategoryFilter(cat.id as any)}
                    className={`px-2.5 py-1 rounded-lg text-[11px] font-bold transition-all cursor-pointer ${
                      categoryFilter === cat.id
                        ? 'bg-slate-900 text-white shadow-xs'
                        : 'bg-white text-slate-600 hover:bg-slate-100 border border-slate-200'
                    }`}
                  >
                    {cat.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-100/80 border-b border-slate-200 text-slate-600 font-black uppercase tracking-wider text-[10px]">
                    <th className="py-3.5 px-4 w-28">Status</th>
                    <th className="py-3.5 px-4 w-60">Provider / Reputation Database</th>
                    <th className="py-3.5 px-4 w-28">Category</th>
                    <th className="py-3.5 px-4">Listing Detail & Reason</th>
                    <th className="py-3.5 px-4 w-20">TTL</th>
                    <th className="py-3.5 px-4 w-24">Latency</th>
                    <th className="py-3.5 px-4 w-44 text-right">Delist Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-150 font-medium text-slate-800">
                  {BLACKLIST_PROVIDERS
                    .filter((provider) => {
                      const listingData = (scanResult.listings as any)?.[provider.id] || {};
                      const isListed = listingData.listed || listingData.status === 'LISTED' || listingData.status === 'Listed';
                      if (filterMode === 'listed' && !isListed) return false;
                      if (filterMode === 'clean' && isListed) return false;
                      if (categoryFilter !== 'all' && provider.category !== categoryFilter) return false;
                      if (searchTerm.trim()) {
                        const q = searchTerm.toLowerCase();
                        return provider.name.toLowerCase().includes(q) || provider.domain.toLowerCase().includes(q) || (provider.category || '').toLowerCase().includes(q);
                      }
                      return true;
                    })
                    .map((provider) => {
                      const listingData = (scanResult.listings as any)?.[provider.id] || {};
                      const isListed = listingData.listed || listingData.status === 'LISTED' || listingData.status === 'Listed';
                      const isIgnored = ignoredListings[provider.id];
                      const reasonStr = isListed ? (listingData.details || `${scanResult.ip} is flagged in database`) : 'Clean - Host IP in good standing';
                      const ttlVal = listingData.ttl || 2100;
                      const responseTimeVal = listingData.responseTime || (provider.id === 'hostkarma' ? 260 : (provider.id === 'ivmsip' ? 7 : (provider.id === 'zerospam' ? 82 : 45)));
                      const delistTargetUrl = getProviderDelistUrl(provider, scanResult.ip);

                      return (
                        <tr 
                          key={provider.id} 
                          className={`hover:bg-slate-50 transition-colors ${isListed ? (isIgnored ? 'bg-slate-100/50 opacity-60' : 'bg-rose-50/40') : ''}`}
                        >
                          {/* Status Column with Red X / Green Check */}
                          <td className="py-3.5 px-4">
                            {isListed ? (
                              <span className="inline-flex items-center gap-1.5 text-rose-700 font-extrabold text-[11px] uppercase">
                                <span className="w-5 h-5 rounded-full bg-rose-600 text-white flex items-center justify-center font-bold text-xs">
                                  ✕
                                </span>
                                LISTED
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1.5 text-emerald-700 font-extrabold text-[11px] uppercase">
                                <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                                OK
                              </span>
                            )}
                          </td>

                          {/* Blacklist Name Column */}
                          <td className="py-3.5 px-4 font-bold text-slate-900">
                            {provider.name}
                            <span className="block text-[10px] text-slate-400 font-mono font-normal">
                              {provider.domain}
                            </span>
                          </td>

                          {/* Category Badge */}
                          <td className="py-3.5 px-4">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wider ${
                              provider.category === 'Mail Gateway' ? 'bg-purple-100 text-purple-800' :
                              provider.category === 'Threat Intel' ? 'bg-amber-100 text-amber-800' :
                              provider.category === 'Web Abuse' ? 'bg-orange-100 text-orange-800' :
                              provider.category === 'Security' ? 'bg-rose-100 text-rose-800' :
                              'bg-slate-100 text-slate-700'
                            }`}>
                              {provider.category || 'DNSBL'}
                            </span>
                          </td>

                          {/* Reason Column with Detail button */}
                          <td className="py-3.5 px-4 text-slate-700 font-medium">
                            <div className="flex items-center gap-2">
                              <span className="truncate max-w-xs">{reasonStr}</span>
                              {isListed && (
                                <button
                                  onClick={() => setActiveDetailItem({
                                    id: provider.id,
                                    name: provider.name,
                                    database: provider.domain,
                                    status: 'LISTED',
                                    listed: true,
                                    reason: listingData.reason || listingData.details || reasonStr,
                                    reference: delistTargetUrl,
                                    recommendedAction: listingData.recommendedAction || 'Submit delisting ticket via provider portal.',
                                    txt: listingData.txt || `${provider.name} abuse telemetry listing for ${scanResult.ip}`,
                                    responseCode: listingData.responseCode || '127.0.0.2',
                                    responseTime: responseTimeVal
                                  })}
                                  className="bg-slate-200 hover:bg-slate-300 text-slate-800 text-[10px] font-bold px-2 py-0.5 rounded cursor-pointer shrink-0"
                                >
                                  Detail
                                </button>
                              )}
                            </div>
                          </td>

                          {/* TTL Column */}
                          <td className="py-3.5 px-4 font-mono font-bold text-slate-600">
                            {isListed ? ttlVal : '-'}
                          </td>

                          {/* Response Time Column */}
                          <td className="py-3.5 px-4 font-mono font-bold text-slate-800">
                            {responseTimeVal} ms
                          </td>

                          {/* Actions Column */}
                          <td className="py-3.5 px-4 text-right">
                            <div className="flex items-center justify-end gap-1.5">
                              {/* Delist Guide Button */}
                              <button
                                onClick={() => {
                                  setActiveGuide({
                                    name: provider.name,
                                    delistUrl: delistTargetUrl,
                                    description: provider.description,
                                    category: provider.category,
                                    steps: [
                                      `Open the official removal interface: ${delistTargetUrl}`,
                                      `Review the host PTR, SPF, and DKIM configuration for IP ${scanResult.ip}`,
                                      `Ensure all spam scripts, compromised web forms, or open relays are sealed`,
                                      `Submit the online delisting dispute form with remediation notes`
                                    ]
                                  });
                                }}
                                className="px-2 py-1 bg-slate-100 hover:bg-slate-200 text-slate-800 rounded text-[10px] font-black uppercase transition-all cursor-pointer"
                                title="View step-by-step remediation guide"
                              >
                                Guide
                              </button>

                              <button
                                onClick={() => toggleIgnoreListing(provider.id)}
                                className={`px-2 py-1 rounded text-[10px] font-black uppercase transition-all cursor-pointer ${
                                  isIgnored ? 'bg-slate-900 text-white' : 'bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200'
                                }`}
                              >
                                {isIgnored ? 'Ignored' : 'Ignore'}
                              </button>

                              <a
                                href={delistTargetUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                                className={`px-2.5 py-1 rounded text-[10px] font-black uppercase flex items-center gap-1 transition-all ${
                                  isListed 
                                    ? 'bg-red-600 hover:bg-red-700 text-white shadow-xs' 
                                    : 'bg-slate-100 hover:bg-slate-200 text-slate-700'
                                }`}
                              >
                                Delist <ExternalLink className="w-2.5 h-2.5" />
                              </a>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                </tbody>
              </table>
            </div>
          </div>

        </div>
      )}

      {/* Remediation Suggestions Modal */}
      {showRemediationModal && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-2xl w-full p-6 shadow-2xl border border-slate-200 space-y-5 animate-scale-up">
            <div className="flex justify-between items-start border-b border-slate-200 pb-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-cyan-100 text-cyan-800 flex items-center justify-center">
                  <Mail className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-black text-slate-900 uppercase tracking-widest">
                    Email Delivery & Blacklist Remediation
                  </h3>
                  <p className="text-xs text-slate-500 font-medium">
                    Target IP: <span className="font-mono font-bold text-slate-800">{activeIp}</span>
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowRemediationModal(false)}
                className="p-1 rounded-lg hover:bg-slate-100 text-slate-400 hover:text-slate-700 cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4 text-xs leading-relaxed text-slate-700 font-medium max-h-[60vh] overflow-y-auto pr-2">
              <div className="bg-amber-50 p-4 rounded-xl border border-amber-200 space-y-1">
                <h4 className="font-extrabold text-amber-900 uppercase text-[11px] flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4 text-amber-600" />
                  Primary Actions Required Before Delisting Request:
                </h4>
                <p className="text-slate-700">
                  Submitting a delisting appeal before securing your server will cause an immediate repeat listing and could result in permanent ban placement.
                </p>
              </div>

              <div className="space-y-3">
                <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
                  <span className="font-bold text-slate-900 block">1. Reverse DNS (PTR) Match</span>
                  <p className="text-slate-600">
                    Ensure your mail server IP has a valid Forward-Confirmed Reverse DNS (FCrDNS) matching your outbound mail domain. Current PTR: <code className="bg-white px-1.5 py-0.5 rounded border border-slate-200 font-mono text-[11px] font-bold text-slate-800">{scanResult?.ptr || 'seiterdfgwrncmkd.update.dochltrowapp.com'}</code>.
                  </p>
                </div>

                <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
                  <span className="font-bold text-slate-900 block">2. Verify SPF & DKIM Records</span>
                  <p className="text-slate-600">
                    Publish a strict SPF record (<code className="bg-white px-1.5 py-0.5 rounded border border-slate-200 font-mono text-[11px]">v=spf1 mx ip4:{activeIp} ~all</code>) and enable DKIM signing on all outgoing email headers.
                  </p>
                </div>

                <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
                  <span className="font-bold text-slate-900 block">3. Audit Outbound Mail Queues & SMTP Logs</span>
                  <p className="text-slate-600">
                    Check Postfix/Exim queue for compromised web forms, infected accounts, or open-relay behavior sending spam to external traps.
                  </p>
                </div>

                <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
                  <span className="font-bold text-slate-900 block">4. Submit Portal Delist Request</span>
                  <p className="text-slate-600">
                    Use direct links in the table (Hostkarma, Invaluement ivmSIP, Sender Score, etc.) to request automated removal after fixing the issue.
                  </p>
                </div>
              </div>
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-200">
              <button
                onClick={() => setShowRemediationModal(false)}
                className="bg-slate-900 text-white font-black text-xs uppercase px-5 py-2.5 rounded-xl cursor-pointer"
              >
                Close Guide
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Listing Detail Modal */}
      {activeDetailItem && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-lg w-full p-6 shadow-2xl border border-slate-200 space-y-4">
            <div className="flex justify-between items-center border-b border-slate-200 pb-3">
              <h3 className="text-xs font-black text-slate-900 uppercase tracking-wider">
                Listing Detail: {activeDetailItem.name}
              </h3>
              <button
                onClick={() => setActiveDetailItem(null)}
                className="p-1 rounded hover:bg-slate-100 text-slate-400 hover:text-slate-700"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-slate-400 uppercase font-extrabold text-[10px] block">Database:</span>
                <span className="font-mono font-bold text-slate-900">{activeDetailItem.database}</span>
              </div>
              <div>
                <span className="text-slate-400 uppercase font-extrabold text-[10px] block">Reason / TXT Record:</span>
                <p className="font-mono text-slate-800 bg-slate-50 p-2.5 rounded-lg border border-slate-200 font-semibold leading-relaxed">
                  {activeDetailItem.reason}
                </p>
              </div>
              <div>
                <span className="text-slate-400 uppercase font-extrabold text-[10px] block">Response Code:</span>
                <span className="font-mono font-bold text-red-600">{activeDetailItem.responseCode}</span>
              </div>
            </div>

            <div className="flex justify-between items-center pt-3 border-t border-slate-200">
              <a
                href={activeDetailItem.reference}
                target="_blank"
                rel="noreferrer"
                className="text-xs font-bold text-red-600 hover:underline flex items-center gap-1"
              >
                Official Removal Portal <ExternalLink className="w-3 h-3" />
              </a>
              <button
                onClick={() => setActiveDetailItem(null)}
                className="bg-slate-900 text-white font-bold text-xs uppercase px-4 py-2 rounded-lg"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Step-by-Step Delisting Guide Modal */}
      {activeGuide && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-xl w-full p-6 shadow-2xl border border-slate-200 space-y-4 animate-scale-up">
            <div className="flex justify-between items-start border-b border-slate-200 pb-3">
              <div>
                <span className="text-[10px] font-black uppercase tracking-wider text-rose-600 bg-rose-50 px-2 py-0.5 rounded">
                  {activeGuide.category || 'Reputation Provider'}
                </span>
                <h3 className="text-sm font-black text-slate-900 uppercase tracking-wider mt-1">
                  Delisting Playbook: {activeGuide.name}
                </h3>
              </div>
              <button
                onClick={() => setActiveGuide(null)}
                className="p-1 rounded hover:bg-slate-100 text-slate-400 hover:text-slate-700 cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <p className="text-xs text-slate-600 font-medium">
              {activeGuide.description}
            </p>

            <div className="space-y-2 text-xs">
              <span className="text-[10px] font-black uppercase tracking-widest text-slate-400 block">
                Required Mitigation Steps:
              </span>
              <div className="space-y-2 bg-slate-50 p-3.5 rounded-xl border border-slate-200">
                {activeGuide.steps.map((step, idx) => (
                  <div key={idx} className="flex items-start gap-2.5">
                    <span className="w-5 h-5 rounded-full bg-slate-900 text-white flex items-center justify-center text-[10px] font-black shrink-0">
                      {idx + 1}
                    </span>
                    <span className="text-slate-700 font-medium leading-relaxed">{step}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex justify-between items-center pt-3 border-t border-slate-200">
              <a
                href={activeGuide.delistUrl}
                target="_blank"
                rel="noreferrer"
                className="bg-red-600 hover:bg-red-700 text-white font-black text-xs uppercase px-4 py-2 rounded-xl flex items-center gap-1.5 transition-all shadow-xs"
              >
                Open Removal Portal <ExternalLink className="w-3.5 h-3.5" />
              </a>
              <button
                onClick={() => setActiveGuide(null)}
                className="bg-slate-900 text-white font-black text-xs uppercase px-4 py-2 rounded-xl cursor-pointer"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
