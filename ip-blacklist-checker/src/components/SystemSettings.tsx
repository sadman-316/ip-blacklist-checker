import React, { useState, useEffect } from "react";
import { UserProfile } from "../types";
import { db } from "../firebase";
import { collection, getDocs, getDoc, setDoc, doc } from "firebase/firestore";
import { Shield, Settings, Server, Database, Save, Loader2, Key, HardDrive, Cpu, Network, Activity, CheckCircle, AlertTriangle, RefreshCw, Play } from "lucide-react";
import { motion } from "motion/react";

interface SystemSettingsProps {
  currentUser: UserProfile;
  triggerAlert: (type: "success" | "error" | "info" | "warning", message: string) => void;
}

export const SystemSettings: React.FC<SystemSettingsProps> = ({ currentUser, triggerAlert }) => {
  const [monitorInterval, setMonitorInterval] = useState("10");
  const [dnsResolvers, setDnsResolvers] = useState("1.1.1.1, 8.8.8.8, 9.9.9.9");
  const [saveLoading, setSaveLoading] = useState(false);
  const [dbStats, setDbStats] = useState({ users: 0, ips: 0, alerts: 0 });

  useEffect(() => {
    const fetchStatsAndSettings = async () => {
      try {
        const usersSnap = await getDocs(collection(db, "users"));
        const ipsSnap = await getDocs(collection(db, "monitored_ips"));
        const alertsSnap = await getDocs(collection(db, "notifications"));
        setDbStats({
          users: usersSnap.size,
          ips: ipsSnap.size,
          alerts: alertsSnap.size
        });

        const settingsSnap = await getDoc(doc(db, "system_settings", "global"));
        if (settingsSnap.exists()) {
          const data = settingsSnap.data();
          if (data.monitorInterval) {
            setMonitorInterval(data.monitorInterval);
          }
          if (data.dnsResolvers) {
            setDnsResolvers(data.dnsResolvers);
          }
        }
      } catch (err) {
        console.error("Error loading stats and settings:", err);
      }
    };
    fetchStatsAndSettings();
  }, []);

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaveLoading(true);
    try {
      const resolverList = dnsResolvers.split(',')
        .map(ip => ip.trim())
        .filter(ip => ip.length > 0);

      const ipPattern = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/;
      const invalidIps = resolverList.filter(ip => !ipPattern.test(ip));

      if (invalidIps.length > 0) {
        throw new Error(`Invalid DNS Resolver IP format: ${invalidIps.join(', ')}`);
      }

      await setDoc(doc(db, "system_settings", "global"), {
        monitorInterval,
        dnsResolvers: resolverList.join(', '),
        updatedAt: new Date().toISOString()
      }, { merge: true });

      triggerAlert("success", "System administrative parameters updated successfully.");
    } catch (err: any) {
      console.error("Failed to save settings:", err);
      triggerAlert("error", err.message || "Failed to update administrative parameters.");
    } finally {
      setSaveLoading(false);
    }
  };

  const [diagIp, setDiagIp] = useState("127.0.0.2");
  const [diagLoading, setDiagLoading] = useState(false);
  const [diagResult, setDiagResult] = useState<any | null>(null);
  const [diagError, setDiagError] = useState<string | null>(null);

  const handleRunDiagnostics = async () => {
    setDiagLoading(true);
    setDiagError(null);
    setDiagResult(null);
    try {
      const response = await fetch(`/api/diagnose?ip=${encodeURIComponent(diagIp)}`);
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || "Failed to perform diagnostics.");
      }
      const data = await response.json();
      setDiagResult(data);
      triggerAlert("success", `DNSBL Diagnostic scan completed for ${diagIp}`);
    } catch (err: any) {
      setDiagError(err.message || "An unexpected error occurred during raw DNS lookups.");
      triggerAlert("error", err.message || "Diagnostics failed.");
    } finally {
      setDiagLoading(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h2 className="text-sm font-black text-slate-700 uppercase tracking-widest flex items-center gap-2">
          <Settings className="w-4 h-4 text-blue-600" />
          Enterprise System Settings
        </h2>
        <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mt-1">
          Configure continuous monitoring daemons, view database telemetry, and manage admin overrides.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="p-5 bg-slate-50 border border-slate-200/80 rounded-2xl space-y-2 hover:border-blue-500/10 hover:shadow-[0_8px_30px_rgb(0,0,0,0.01)] transition-all duration-300">
          <div className="flex justify-between items-center">
            <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest">Registered Accounts</span>
            <HardDrive className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-2xl font-black text-slate-850 font-mono">{dbStats.users}</div>
          <span className="text-[9px] text-slate-400 font-bold uppercase tracking-wider block">Auth Profile Documents</span>
        </div>

        <div className="p-5 bg-slate-50 border border-slate-200/80 rounded-2xl space-y-2 hover:border-blue-500/10 hover:shadow-[0_8px_30px_rgb(0,0,0,0.01)] transition-all duration-300">
          <div className="flex justify-between items-center">
            <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest">Monitored Hosts</span>
            <Network className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-2xl font-black text-slate-850 font-mono">{dbStats.ips}</div>
          <span className="text-[9px] text-slate-400 font-bold uppercase tracking-wider block">IPs & CIDR Subnets</span>
        </div>

        <div className="p-5 bg-slate-50 border border-slate-200/80 rounded-2xl space-y-2 hover:border-blue-500/10 hover:shadow-[0_8px_30px_rgb(0,0,0,0.01)] transition-all duration-300">
          <div className="flex justify-between items-center">
            <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest">Logged Warnings</span>
            <Cpu className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-2xl font-black text-slate-850 font-mono">{dbStats.alerts}</div>
          <span className="text-[9px] text-slate-400 font-bold uppercase tracking-wider block">RBL Reputation Alerts</span>
        </div>
      </div>

      <div className="bg-white border border-slate-200/80 rounded-2xl p-6 shadow-[0_8px_30px_rgb(0,0,0,0.02)]">
        <h3 className="text-xs font-black text-slate-700 uppercase tracking-widest border-b border-slate-100 pb-3 flex items-center gap-2">
          <Server className="w-4 h-4 text-slate-600" />
          Continuous Daemon Configurations
        </h3>

        <form onSubmit={handleSaveSettings} className="space-y-5 mt-5">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                Continuous Monitor Daemon Cycle Interval
              </label>
              <select
                value={monitorInterval}
                onChange={(e) => setMonitorInterval(e.target.value)}
                className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-xs focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-blue-500/10 focus:border-blue-500/80 text-slate-900 font-bold cursor-pointer transition-all"
              >
                <option value="5">Every 5 Minutes (Development Mode)</option>
                <option value="10">Every 10 Minutes (Recommended)</option>
                <option value="30">Every 30 Minutes</option>
                <option value="60">Every 1 Hour (Standard Enterprise)</option>
                <option value="360">Every 6 Hours</option>
              </select>
            </div>

            <div className="space-y-1.5">
              <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                DNSBL Query Concurrency Batch Limit
              </label>
              <input
                type="number"
                disabled
                value="10"
                className="w-full bg-slate-100 border border-slate-200 rounded-xl px-4 py-3 text-xs text-slate-500 font-bold cursor-not-allowed"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
              Explicit Custom & Private DNS Resolvers
            </label>
            <input
              type="text"
              value={dnsResolvers}
              onChange={(e) => setDnsResolvers(e.target.value)}
              placeholder="e.g. 1.1.1.1, 8.8.8.8, 127.0.0.1"
              className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-xs font-mono font-bold focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-blue-500/10 focus:border-blue-500/80 text-slate-900 transition-all"
            />
            <p className="text-[9px] text-slate-400 font-medium">
              Comma-separated list of IPv4 addresses. The backend scanner will use these servers explicitly (e.g., Cloudflare <code className="font-mono bg-slate-100 px-1 py-0.5 rounded text-indigo-600 font-bold">1.1.1.1</code>, Google <code className="font-mono bg-slate-100 px-1 py-0.5 rounded text-indigo-600 font-bold">8.8.8.8</code>, or a private VPS caching server like Unbound on <code className="font-mono bg-slate-100 px-1 py-0.5 rounded text-indigo-600 font-bold">127.0.0.1</code>) to bypass DNSBL rate limits or blocks on public cloud networks.
            </p>
          </div>

          <div className="border-t border-slate-100 pt-5 flex justify-end">
            <button
              type="submit"
              disabled={saveLoading}
              className="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white px-5 py-3 rounded-xl text-xs font-black uppercase tracking-widest shadow-[0_4px_12px_rgba(37,99,235,0.18)] flex items-center gap-1.5 cursor-pointer disabled:opacity-50 border border-white/5 transition-all"
            >
              {saveLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
              Save Configuration
            </button>
          </div>
        </form>
      </div>

      <div className="bg-white border border-slate-200/80 rounded-2xl p-6 shadow-[0_8px_30px_rgb(0,0,0,0.02)] space-y-5">
        <div>
          <h3 className="text-xs font-black text-slate-700 uppercase tracking-widest border-b border-slate-100 pb-3 flex items-center gap-2">
            <Activity className="w-4 h-4 text-violet-600 animate-pulse" />
            DNSBL Multi-Tier Diagnostic Utility
          </h3>
          <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mt-1">
            Perform live raw A-record & TXT-reason lookups across 3 layers (Node.js default, public Quad9, and authoritative servers).
          </p>
        </div>

        <div className="bg-slate-50 border border-slate-150 rounded-2xl p-4 flex flex-col sm:flex-row gap-3 items-center justify-between">
          <div className="w-full sm:w-2/3 space-y-1">
            <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
              Diagnostic Target IP Address
            </label>
            <input
              type="text"
              value={diagIp}
              onChange={(e) => setDiagIp(e.target.value)}
              placeholder="e.g. 127.0.0.2"
              className="w-full bg-white border border-slate-200 rounded-xl px-4 py-2.5 text-xs font-mono font-bold focus:outline-hidden focus:ring-4 focus:ring-violet-500/10 focus:border-violet-500 text-slate-900"
            />
          </div>
          <button
            onClick={handleRunDiagnostics}
            disabled={diagLoading}
            className="w-full sm:w-auto self-end bg-gradient-to-r from-violet-600 to-fuchsia-600 hover:from-violet-500 hover:to-fuchsia-500 text-white px-5 py-3 rounded-xl text-xs font-black uppercase tracking-widest shadow-[0_4px_12px_rgba(139,92,246,0.18)] flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50 transition-all border border-white/5"
          >
            {diagLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-white" />}
            Run Live DNS Diagnostics
          </button>
        </div>

        {diagError && (
          <div className="p-4 bg-rose-50 border border-rose-200 text-rose-800 rounded-xl text-xs font-mono">
            <strong>Error:</strong> {diagError}
          </div>
        )}

        {diagResult && (
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row justify-between text-[10px] uppercase font-bold text-slate-400 bg-slate-50 p-3 rounded-xl border border-slate-100">
              <span>Tested IP: <strong className="font-mono text-slate-700">{diagResult.testedIp}</strong></span>
              <span>DNS Query Suffix: <strong className="font-mono text-slate-700">{diagResult.reversedIp}.[Provider]</strong></span>
              <span>Time: <strong className="font-mono text-slate-700">{new Date(diagResult.timestamp).toLocaleTimeString()}</strong></span>
            </div>

            <div className="space-y-3 max-h-[400px] overflow-y-auto pr-1">
              {diagResult.diagnostics.map((diag: any) => {
                const hasA = diag.defaultResolver.a || diag.publicResolver.a || diag.authoritativeResolver.a;
                return (
                  <div key={diag.providerId} className="border border-slate-150 rounded-xl overflow-hidden shadow-[0_2px_8px_rgba(0,0,0,0.01)] bg-white">
                    <div className="bg-slate-50 px-4 py-2.5 border-b border-slate-150 flex justify-between items-center">
                      <div>
                        <span className="text-xs font-black text-slate-700">{diag.providerName}</span>
                        <span className="text-[9px] font-mono font-bold text-slate-400 block">{diag.lookupQuery}</span>
                      </div>
                      <span className={`text-[9px] px-2 py-0.5 rounded-full font-black uppercase tracking-wider ${hasA ? 'bg-amber-100 text-amber-800' : 'bg-emerald-100 text-emerald-800'}`}>
                        {hasA ? 'Listed' : 'Clean / NX'}
                      </span>
                    </div>

                    <div className="p-4 grid grid-cols-1 md:grid-cols-3 gap-3">
                      {/* Default Resolver */}
                      <div className="p-3 bg-slate-50/50 rounded-lg border border-slate-100 space-y-1.5">
                        <div className="text-[9px] font-black uppercase tracking-widest text-slate-400 flex justify-between">
                          <span>1. default node.js</span>
                          {diag.defaultResolver.status === 'success' ? (
                            <span className="text-emerald-600">● SUCCESS</span>
                          ) : (
                            <span className="text-rose-500">● {diag.defaultResolver.error || 'ERROR'}</span>
                          )}
                        </div>
                        <div className="text-xs font-mono text-slate-700 space-y-1">
                          <div>A: <span className="font-bold text-indigo-600">{diag.defaultResolver.a ? JSON.stringify(diag.defaultResolver.a) : 'None'}</span></div>
                          <div className="text-[10px] text-slate-500 truncate" title={diag.defaultResolver.txt}>
                            TXT: {diag.defaultResolver.txt || 'None'}
                          </div>
                        </div>
                      </div>

                      {/* Custom Configured Resolver */}
                      <div className="p-3 bg-slate-50/50 rounded-lg border border-slate-100 space-y-1.5">
                        <div className="text-[9px] font-black uppercase tracking-widest text-slate-400 flex justify-between">
                          <span>2. custom ({diag.publicResolver.resolverIp || '1.1.1.1'})</span>
                          {diag.publicResolver.status === 'success' ? (
                            <span className="text-emerald-600">● SUCCESS</span>
                          ) : (
                            <span className="text-rose-500">● {diag.publicResolver.error || 'ERROR'}</span>
                          )}
                        </div>
                        <div className="text-xs font-mono text-slate-700 space-y-1">
                          <div>A: <span className="font-bold text-indigo-600">{diag.publicResolver.a ? JSON.stringify(diag.publicResolver.a) : 'None'}</span></div>
                          <div className="text-[10px] text-slate-500 truncate" title={diag.publicResolver.txt}>
                            TXT: {diag.publicResolver.txt || 'None'}
                          </div>
                        </div>
                      </div>

                      {/* Authoritative Resolver */}
                      <div className="p-3 bg-slate-50/50 rounded-lg border border-slate-100 space-y-1.5">
                        <div className="text-[9px] font-black uppercase tracking-widest text-slate-400 flex justify-between">
                          <span>3. auth ns cache</span>
                          {diag.authoritativeResolver.status === 'success' ? (
                            <span className="text-emerald-600">● ONLINE</span>
                          ) : diag.authoritativeResolver.status === 'not_available' ? (
                            <span className="text-slate-400">● UNUSED</span>
                          ) : (
                            <span className="text-amber-500">● {diag.authoritativeResolver.error || 'ERROR'}</span>
                          )}
                        </div>
                        <div className="text-xs font-mono text-slate-700 space-y-1">
                          <div>A: <span className="font-bold text-indigo-600">{diag.authoritativeResolver.a ? JSON.stringify(diag.authoritativeResolver.a) : 'None'}</span></div>
                          <div className="text-[10px] text-slate-500 truncate" title={diag.authoritativeResolver.txt}>
                            TXT: {diag.authoritativeResolver.txt || 'None'}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
