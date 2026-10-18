import React, { useState, useEffect } from "react";
import { UserProfile, OfficeMailAccount } from "../types";
import { db } from "../firebase";
import { collection, getDocs, getDoc, setDoc, doc } from "firebase/firestore";
import { Shield, Settings, Server, Database, Save, Loader2, Key, HardDrive, Cpu, Network, Activity, CheckCircle, AlertTriangle, RefreshCw, Play, Mail, Send, Lock, Check, Plus, Trash2, Building, Star, CheckSquare, Info, ExternalLink, ShieldAlert } from "lucide-react";
import { motion } from "motion/react";

interface SystemSettingsProps {
  currentUser: UserProfile;
  triggerAlert: (type: "success" | "error" | "info" | "warning", message: string) => void;
}

export const SystemSettings: React.FC<SystemSettingsProps> = ({ currentUser, triggerAlert }) => {
  const [monitorInterval, setMonitorInterval] = useState("10");
  const [dnsResolvers, setDnsResolvers] = useState("1.1.1.1, 8.8.8.8, 9.9.9.9");
  const [invaluementQueryKey, setInvaluementQueryKey] = useState("");
  const [invaluementListings, setInvaluementListings] = useState<Record<string, any>>({});
  const [manualInvaluementIp, setManualInvaluementIp] = useState("");
  const [invaluementActionLoading, setInvaluementActionLoading] = useState(false);
  const [saveLoading, setSaveLoading] = useState(false);
  const [dbStats, setDbStats] = useState({ users: 0, ips: 0, alerts: 0 });

  // Office Email Accounts State (Multiple accounts support)
  const [officeAccounts, setOfficeAccounts] = useState<OfficeMailAccount[]>([]);
  const [activeAccountTab, setActiveAccountTab] = useState<string>('primary');
  
  // Single/Default SMTP Settings State
  const [smtpHost, setSmtpHost] = useState("");
  const [smtpPort, setSmtpPort] = useState(587);
  const [smtpSecure, setSmtpSecure] = useState(false);
  const [smtpUser, setSmtpUser] = useState("");
  const [smtpPass, setSmtpPass] = useState("");
  const [smtpFromName, setSmtpFromName] = useState("Wolast Security NOC");
  const [smtpFromEmail, setSmtpFromEmail] = useState("abuse@wolast.com");
  const [smtpCompanyName, setSmtpCompanyName] = useState("Wolast Technology Ltd.");
  const [smtpConfigured, setSmtpConfigured] = useState(false);
  const [smtpSaveLoading, setSmtpSaveLoading] = useState(false);
  const [testEmail, setTestEmail] = useState("");
  const [testLoading, setTestLoading] = useState(false);
  const [detectingSmtp, setDetectingSmtp] = useState(false);
  const [detectedSmtpMsg, setDetectedSmtpMsg] = useState<string | null>(null);

  useEffect(() => {
    const fetchStatsAndSettings = async () => {
      // Check local storage defaults
      try {
        const savedSettings = localStorage.getItem("wolast_system_settings");
        if (savedSettings) {
          const parsed = JSON.parse(savedSettings);
          if (parsed.monitorInterval) setMonitorInterval(parsed.monitorInterval);
          if (parsed.dnsResolvers) setDnsResolvers(parsed.dnsResolvers);
        }
      } catch (e) {}

      try {
        const [usersSnap, ipsSnap, alertsSnap] = await Promise.all([
          Promise.race([
            getDocs(collection(db, "users")),
            new Promise<any>((_, reject) => setTimeout(() => reject(new Error("Timeout")), 2000))
          ]).catch(() => ({ size: 3 })),
          Promise.race([
            getDocs(collection(db, "monitored_ips")),
            new Promise<any>((_, reject) => setTimeout(() => reject(new Error("Timeout")), 2000))
          ]).catch(() => ({ size: 1 })),
          Promise.race([
            getDocs(collection(db, "notifications")),
            new Promise<any>((_, reject) => setTimeout(() => reject(new Error("Timeout")), 2000))
          ]).catch(() => ({ size: 0 }))
        ]);

        setDbStats({
          users: usersSnap.size || 0,
          ips: ipsSnap.size || 0,
          alerts: alertsSnap.size || 0
        });

        const settingsSnap = await Promise.race([
          getDoc(doc(db, "system_settings", "global")),
          new Promise<any>((_, reject) => setTimeout(() => reject(new Error("Timeout")), 2000))
        ]).catch(() => null);

        if (settingsSnap && settingsSnap.exists && settingsSnap.exists()) {
          const data = settingsSnap.data();
          if (data.monitorInterval) setMonitorInterval(data.monitorInterval);
          if (data.dnsResolvers) setDnsResolvers(data.dnsResolvers);
        }
      } catch (err) {
        console.warn("Error loading stats and settings:", err);
      }

      // Fetch general system settings including Invaluement subscriber key
      try {
        const genRes = await fetch("/api/settings/general");
        if (genRes.ok) {
          const gen = await genRes.json();
          if (gen.monitorInterval) setMonitorInterval(String(gen.monitorInterval));
          if (gen.dnsResolvers) {
            setDnsResolvers(Array.isArray(gen.dnsResolvers) ? gen.dnsResolvers.join(', ') : String(gen.dnsResolvers));
          }
          if (gen.invaluementQueryKey) setInvaluementQueryKey(gen.invaluementQueryKey);
        }
      } catch (e) {}

      // Fetch Invaluement verified listings registry
      try {
        const invRes = await fetch("/api/invaluement/listings");
        if (invRes.ok) {
          const invData = await invRes.json();
          if (invData.listings) setInvaluementListings(invData.listings);
        }
      } catch (e) {}

      // Fetch SMTP Configuration
      try {
        const smtpRes = await fetch("/api/settings/smtp");
        if (smtpRes.ok) {
          const s = await smtpRes.json();
          if (s.host) setSmtpHost(s.host);
          if (s.port) setSmtpPort(s.port);
          if (typeof s.secure === "boolean") setSmtpSecure(s.secure);
          if (s.user) setSmtpUser(s.user);
          if (s.fromName) setSmtpFromName(s.fromName);
          if (s.fromEmail) setSmtpFromEmail(s.fromEmail);
          if (s.companyName) setSmtpCompanyName(s.companyName);
          if (Array.isArray(s.accounts)) setOfficeAccounts(s.accounts);
          setSmtpConfigured(Boolean(s.isConfigured));
        }
      } catch (e) {
        console.warn("Could not load SMTP settings:", e);
      }
    };
    fetchStatsAndSettings();
  }, []);

  const handleSaveSmtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setSmtpSaveLoading(true);
    try {
      const res = await fetch("/api/settings/smtp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          host: smtpHost,
          port: Number(smtpPort),
          secure: smtpSecure,
          user: smtpUser,
          pass: smtpPass,
          fromName: smtpFromName,
          fromEmail: smtpFromEmail,
          companyName: smtpCompanyName,
          accounts: officeAccounts
        })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setSmtpConfigured(true);
        triggerAlert("success", "Office mail accounts & SMTP configurations saved successfully.");
      } else {
        throw new Error(data.error || "Failed to save SMTP settings.");
      }
    } catch (err: any) {
      triggerAlert("error", err.message || "Failed to save SMTP settings.");
    } finally {
      setSmtpSaveLoading(false);
    }
  };

  const handleTestSmtp = async (accountId?: string) => {
    setTestLoading(true);
    try {
      let payload: any = {
        host: smtpHost,
        port: Number(smtpPort),
        secure: smtpSecure,
        user: smtpUser,
        pass: smtpPass,
        fromName: smtpFromName,
        fromEmail: smtpFromEmail,
        testEmail: testEmail || smtpFromEmail
      };

      if (accountId && accountId !== 'primary') {
        const acc = officeAccounts.find(a => a.id === accountId);
        if (acc) {
          payload = {
            accountId,
            host: acc.host,
            port: acc.port,
            secure: acc.secure,
            user: acc.user,
            pass: acc.pass,
            fromName: acc.fromName,
            fromEmail: acc.fromEmail,
            testEmail: testEmail || acc.fromEmail
          };
        }
      }

      const res = await fetch("/api/settings/smtp/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (res.ok && data.success) {
        if (data.verifiedHost && data.verifiedHost !== smtpHost) {
          setSmtpHost(data.verifiedHost);
        }
        triggerAlert("success", `✓ ${data.message || `Connection verified! Test email delivered to ${payload.testEmail}`}`);
      } else {
        throw new Error(data.error || "SMTP test failed. Check host, port, username or app-password.");
      }
    } catch (err: any) {
      triggerAlert("error", err.message || "SMTP test failed.");
    } finally {
      setTestLoading(false);
    }
  };

  const handleAutoDetectWebmail = async () => {
    if (!smtpFromEmail || !smtpFromEmail.includes('@')) {
      triggerAlert("warning", "Please enter a valid webmail address first (e.g. abuse@yourdomain.com)");
      return;
    }
    setDetectingSmtp(true);
    setDetectedSmtpMsg(null);
    try {
      const res = await fetch(`/api/settings/smtp/detect?email=${encodeURIComponent(smtpFromEmail)}`);
      const data = await res.json();
      if (data.suggestedHost) {
        setSmtpHost(data.suggestedHost);
        setSmtpPort(data.port || 465);
        setSmtpSecure(data.secure !== undefined ? data.secure : true);
        if (!smtpUser) setSmtpUser(smtpFromEmail);
        const msg = data.notes || `Detected direct mail server: ${data.suggestedHost}`;
        setDetectedSmtpMsg(msg);
        triggerAlert("success", msg);
      }
    } catch {
      const domain = smtpFromEmail.split('@')[1];
      if (domain) {
        setSmtpHost(`mail.${domain}`);
        setSmtpPort(465);
        setSmtpSecure(true);
        if (!smtpUser) setSmtpUser(smtpFromEmail);
      }
    } finally {
      setDetectingSmtp(false);
    }
  };

  // Helper functions for multiple office accounts
  const handleAddOfficeAccount = () => {
    const newAcc: OfficeMailAccount = {
      id: `acc_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      label: `Account ${officeAccounts.length + 1} (e.g. NOC Desk)`,
      host: smtpHost || 'mail.yourcompany.com',
      port: 587,
      secure: false,
      user: '',
      pass: '',
      fromName: `${smtpCompanyName} NOC Team`,
      fromEmail: `noc@${smtpFromEmail.split('@')[1] || 'yourcompany.com'}`,
      companyName: smtpCompanyName,
      isDefault: false
    };
    const updated = [...officeAccounts, newAcc];
    setOfficeAccounts(updated);
    setActiveAccountTab(newAcc.id);
  };

  const handleUpdateOfficeAccount = (id: string, field: keyof OfficeMailAccount, value: any) => {
    setOfficeAccounts(prev => prev.map(acc => {
      if (acc.id === id) {
        return { ...acc, [field]: value };
      }
      return acc;
    }));
  };

  const handleRemoveOfficeAccount = (id: string) => {
    setOfficeAccounts(prev => prev.filter(acc => acc.id !== id));
    if (activeAccountTab === id) {
      setActiveAccountTab('primary');
    }
  };

  const handleSetDefaultAccount = (id: string) => {
    setOfficeAccounts(prev => prev.map(acc => ({
      ...acc,
      isDefault: acc.id === id
    })));
  };

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

      const settingsObj = {
        monitorInterval,
        dnsResolvers: resolverList.join(', '),
        invaluementQueryKey: invaluementQueryKey.trim(),
        updatedAt: new Date().toISOString()
      };

      // Save to Express server persistent storage
      try {
        await fetch("/api/settings/general", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            monitorInterval: Number(monitorInterval),
            dnsResolvers: resolverList,
            invaluementQueryKey: invaluementQueryKey.trim()
          })
        });
      } catch (srvErr) {
        console.warn("Failed to persist server system config:", srvErr);
      }

      // Save locally
      try {
        localStorage.setItem("wolast_system_settings", JSON.stringify(settingsObj));
      } catch (e) {}

      triggerAlert("success", "System administrative & Invaluement query parameters updated successfully.");
    } catch (err: any) {
      console.error("Failed to save settings:", err);
      triggerAlert("error", err.message || "Failed to update administrative parameters.");
    } finally {
      setSaveLoading(false);
    }
  };

  const handleToggleInvaluementManual = async (targetIp: string, listed: boolean) => {
    if (!targetIp || !targetIp.trim()) return;
    setInvaluementActionLoading(true);
    try {
      const res = await fetch("/api/invaluement/toggle", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ip: targetIp.trim(),
          listed,
          listType: "ivmsip",
          details: "Invaluement ivmSIP: High-emission spam source (Direct Web Verified)"
        })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setInvaluementListings(data.listings || {});
        setManualInvaluementIp("");
        triggerAlert(
          "success",
          listed
            ? `✓ Added ${targetIp.trim()} to Invaluement ivmSIP verified listed registry.`
            : `✓ Removed ${targetIp.trim()} from Invaluement listed registry.`
        );
      } else {
        throw new Error(data.error || "Failed to update Invaluement listing");
      }
    } catch (err: any) {
      triggerAlert("error", err.message || "Failed to update Invaluement listing");
    } finally {
      setInvaluementActionLoading(false);
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
          <div className="text-2xl font-black text-slate-900 font-mono">{dbStats.users}</div>
          <span className="text-[9px] text-slate-400 font-bold uppercase tracking-wider block">Auth Profile Documents</span>
        </div>

        <div className="p-5 bg-slate-50 border border-slate-200/80 rounded-2xl space-y-2 hover:border-blue-500/10 hover:shadow-[0_8px_30px_rgb(0,0,0,0.01)] transition-all duration-300">
          <div className="flex justify-between items-center">
            <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest">Monitored Hosts</span>
            <Network className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-2xl font-black text-slate-900 font-mono">{dbStats.ips}</div>
          <span className="text-[9px] text-slate-400 font-bold uppercase tracking-wider block">IPs & CIDR Subnets</span>
        </div>

        <div className="p-5 bg-slate-50 border border-slate-200/80 rounded-2xl space-y-2 hover:border-blue-500/10 hover:shadow-[0_8px_30px_rgb(0,0,0,0.01)] transition-all duration-300">
          <div className="flex justify-between items-center">
            <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest">Logged Warnings</span>
            <Cpu className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-2xl font-black text-slate-900 font-mono">{dbStats.alerts}</div>
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

          <div className="space-y-1.5 bg-slate-50 p-4 rounded-xl border border-slate-200">
            <div className="flex items-center justify-between">
              <label className="text-[9px] font-black text-slate-700 uppercase tracking-widest block flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5 text-blue-600" />
                Invaluement ivmSIP Commercial Subscriber Query Key (Optional)
              </label>
              <a 
                href="https://www.invaluement.com/lookup/" 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-[10px] font-bold text-blue-600 hover:text-blue-800 flex items-center gap-1"
              >
                Invaluement Web Lookup <ExternalLink className="w-3 h-3" />
              </a>
            </div>
            <input
              type="text"
              value={invaluementQueryKey}
              onChange={(e) => setInvaluementQueryKey(e.target.value)}
              placeholder="e.g. your-subscriber-key (leaves blank for Direct Web Verification mode)"
              className="w-full bg-white border border-slate-200 rounded-xl px-4 py-2.5 text-xs font-mono font-bold focus:outline-hidden focus:ring-4 focus:ring-blue-500/10 focus:border-blue-500/80 text-slate-900 transition-all"
            />
            <p className="text-[9px] text-slate-500 font-medium">
              Invaluement decommissioned anonymous public queries in 2018. If your company holds an active Invaluement commercial subscription, enter your private query key here to resolve directly via <code className="font-mono bg-slate-100 px-1 py-0.5 rounded font-bold">[reversed].[key].sip.invaluement.com</code>.
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

      {/* Invaluement ivmSIP Intelligence & Verified Registry Hub */}
      <div className="bg-white border border-slate-200/80 rounded-2xl p-6 shadow-[0_8px_30px_rgb(0,0,0,0.02)] space-y-5">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 border-b border-slate-100 pb-3">
          <div>
            <h3 className="text-xs font-black text-slate-700 uppercase tracking-widest flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-600" />
              Invaluement ivmSIP Intelligence &amp; Verified Registry
            </h3>
            <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mt-0.5">
              Sync and manage IPs flagged on Invaluement ivmSIP. Verified listings are automatically tracked in audits, delisting appeals, and daily email notifications.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <a
              href="https://www.invaluement.com/lookup/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs font-bold bg-slate-100 hover:bg-slate-200 text-slate-700 px-3 py-1.5 rounded-xl transition-all flex items-center gap-1.5"
            >
              Open invaluement.com/lookup/ <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>

        <div className="space-y-4">
          <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex items-start gap-3 text-xs text-amber-900">
            <Info className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
            <div className="space-y-1 text-[11px] leading-relaxed">
              <p className="font-bold">
                Why do some IPs on Invaluement require verification?
              </p>
              <p className="text-amber-800">
                Invaluement transitioned from free public DNS to private subscription zones in 2018. Any free public DNS query returns a standard deprecation notice. WolastShield provides both commercial subscriber key queries and direct verified listing sync so any IP listed on Invaluement is accurately flagged in your monitoring fleet and delist appeals.
              </p>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row gap-3 items-center">
            <div className="flex-1 w-full space-y-1">
              <label className="text-[10px] font-black text-slate-600 uppercase tracking-wider block">
                Quick-Add Flagged IP to Invaluement Registry
              </label>
              <input
                type="text"
                value={manualInvaluementIp}
                onChange={(e) => setManualInvaluementIp(e.target.value)}
                placeholder="e.g. 192.0.2.1"
                className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-2.5 text-xs font-mono font-bold focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-red-500/10 focus:border-red-500 text-slate-900 transition-all"
              />
            </div>
            <div className="sm:self-end w-full sm:w-auto">
              <button
                type="button"
                disabled={invaluementActionLoading || !manualInvaluementIp.trim()}
                onClick={() => handleToggleInvaluementManual(manualInvaluementIp, true)}
                className="w-full sm:w-auto bg-red-600 hover:bg-red-700 text-white px-5 py-2.5 rounded-xl text-xs font-black uppercase tracking-wider flex items-center justify-center gap-1.5 transition-all cursor-pointer disabled:opacity-40 shadow-sm"
              >
                {invaluementActionLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
                Flag as Listed on ivmSIP
              </button>
            </div>
          </div>

          <div className="border border-slate-200 rounded-xl overflow-hidden">
            <div className="bg-slate-50 px-4 py-2.5 border-b border-slate-200 flex items-center justify-between text-xs font-black uppercase text-slate-600 tracking-wider">
              <span>Active Verified Invaluement Listings</span>
              <span className="text-[10px] bg-red-100 text-red-700 px-2 py-0.5 rounded-full font-mono">
                {Object.keys(invaluementListings).length} Listed
              </span>
            </div>

            {Object.keys(invaluementListings).length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 font-medium">
                No IP addresses are currently flagged on Invaluement ivmSIP. Use the input above or the 1-click &ldquo;Flag Listed&rdquo; toggle in the Blacklist Check table when an IP is verified on invaluement.com.
              </div>
            ) : (
              <div className="divide-y divide-slate-100 max-h-60 overflow-y-auto">
                {Object.entries(invaluementListings).map(([ip, entry]: [string, any]) => (
                  <div key={ip} className="p-3.5 px-4 flex items-center justify-between hover:bg-slate-50 transition-colors">
                    <div className="flex items-center gap-3">
                      <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse" />
                      <div>
                        <span className="font-mono font-bold text-xs text-slate-900">{ip}</span>
                        <span className="text-[10px] text-slate-400 block">
                          Verified: {entry?.verifiedAt ? new Date(entry.verifiedAt).toLocaleDateString() : 'Active'} &bull; Database: Invaluement ivmSIP
                        </span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <a
                        href={`https://www.invaluement.com/lookup/`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-[10px] font-bold text-slate-500 hover:text-slate-900 bg-slate-100 hover:bg-slate-200 px-2.5 py-1 rounded-lg transition-colors flex items-center gap-1"
                      >
                        Lookup <ExternalLink className="w-2.5 h-2.5" />
                      </a>
                      <button
                        type="button"
                        onClick={() => handleToggleInvaluementManual(ip, false)}
                        className="text-[10px] font-bold text-emerald-700 hover:text-emerald-900 bg-emerald-50 hover:bg-emerald-100 border border-emerald-200 px-2.5 py-1 rounded-lg transition-colors cursor-pointer flex items-center gap-1"
                      >
                        <Check className="w-3 h-3 text-emerald-600" />
                        Mark Clean
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Webmail & Domain SMTP Gateway Configuration */}
      <div className="bg-white border border-slate-200/80 rounded-2xl p-6 shadow-[0_8px_30px_rgb(0,0,0,0.02)] space-y-5">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 border-b border-slate-100 pb-3">
          <div>
            <h3 className="text-xs font-black text-slate-800 uppercase tracking-widest flex items-center gap-2">
              <Mail className="w-4 h-4 text-red-600" />
              Webmail &amp; Domain SMTP Gateway Configuration
            </h3>
            <p className="text-[10px] text-slate-500 font-bold uppercase tracking-wider mt-0.5">
              Configure your cPanel or Custom Domain Webmail to send automated Daily Blacklist Alerts and 1-Click Delist Appeals.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className={`text-[10px] font-black uppercase px-2.5 py-1 rounded-full ${smtpConfigured ? 'bg-emerald-100 text-emerald-800' : 'bg-amber-100 text-amber-800'}`}>
              {smtpConfigured ? `● Webmail Active (${smtpFromEmail || 'Configured'})` : '○ Webmail Not Configured'}
            </span>
            <button
              type="button"
              onClick={handleAddOfficeAccount}
              className="px-3 py-1.5 bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 rounded-lg text-xs font-bold flex items-center gap-1 cursor-pointer transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add Webmail Account</span>
            </button>
          </div>
        </div>

        {/* Office Account Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 border-b border-slate-100">
          <button
            type="button"
            onClick={() => setActiveAccountTab('primary')}
            className={`px-3 py-2 rounded-xl text-xs font-bold whitespace-nowrap transition-all cursor-pointer flex items-center gap-1.5 ${
              activeAccountTab === 'primary'
                ? 'bg-slate-900 text-white shadow-xs'
                : 'bg-slate-100 hover:bg-slate-200 text-slate-700'
            }`}
          >
            <Building className="w-3.5 h-3.5" />
            <span>Primary Account ({smtpFromEmail || 'abuse@wolast.com'})</span>
          </button>

          {officeAccounts.map((acc, index) => (
            <button
              key={acc.id}
              type="button"
              onClick={() => setActiveAccountTab(acc.id)}
              className={`px-3 py-2 rounded-xl text-xs font-bold whitespace-nowrap transition-all cursor-pointer flex items-center gap-1.5 ${
                activeAccountTab === acc.id
                  ? 'bg-slate-900 text-white shadow-xs'
                  : 'bg-slate-100 hover:bg-slate-200 text-slate-700'
              }`}
            >
              <Mail className="w-3.5 h-3.5" />
              <span>{acc.label || `Account #${index + 1}`}</span>
              {acc.isDefault && <Star className="w-3 h-3 text-amber-400 fill-amber-400" />}
            </button>
          ))}
        </div>

        {/* Primary Account Form */}
        {activeAccountTab === 'primary' && (
          <form onSubmit={handleSaveSmtp} className="space-y-4">
            <div className="bg-slate-50/70 p-3 rounded-xl border border-slate-200/80 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-blue-500"></span>
                <span className="text-xs font-bold text-slate-700">Primary Company Outbound Gateway</span>
              </div>
              <span className="text-[10px] text-slate-400 font-mono">Default Relay</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="space-y-1">
                <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                  Organization / Company Name
                </label>
                <input
                  type="text"
                  value={smtpCompanyName}
                  onChange={(e) => setSmtpCompanyName(e.target.value)}
                  placeholder="e.g. Wolast Technology Ltd."
                  className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs text-slate-900 font-bold focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                  Default Sender / Contact Name
                </label>
                <input
                  type="text"
                  value={smtpFromName}
                  onChange={(e) => setSmtpFromName(e.target.value)}
                  placeholder="e.g. Wolast Security NOC"
                  className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs text-slate-900 font-bold focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
                />
              </div>

              <div className="space-y-1">
                <div className="flex justify-between items-center">
                  <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                    Webmail Email Address
                  </label>
                  {smtpFromEmail && smtpFromEmail.includes('@') && (
                    <button
                      type="button"
                      disabled={detectingSmtp}
                      onClick={handleAutoDetectWebmail}
                      className="text-[9px] font-bold text-red-600 hover:text-red-700 cursor-pointer underline flex items-center gap-1"
                    >
                      {detectingSmtp ? 'Detecting Mail Host...' : 'Auto-detect cPanel Webmail'}
                    </button>
                  )}
                </div>
                <input
                  type="email"
                  value={smtpFromEmail}
                  onChange={(e) => {
                    const val = e.target.value;
                    setSmtpFromEmail(val);
                    if (!smtpUser) setSmtpUser(val);
                  }}
                  placeholder="e.g. abuse@yourdomain.com"
                  className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs text-slate-900 font-bold focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
                />
                {detectedSmtpMsg && (
                  <div className="text-[9px] text-emerald-700 font-bold bg-emerald-50 border border-emerald-200/60 rounded-lg px-2.5 py-1 mt-1">
                    ✓ {detectedSmtpMsg}
                  </div>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 pt-1">
              <div className="sm:col-span-2 space-y-1">
                <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                  Webmail SMTP Host Server
                </label>
                <input
                  type="text"
                  value={smtpHost}
                  onChange={(e) => setSmtpHost(e.target.value)}
                  placeholder="e.g. mail.yourdomain.com or cPanel server name"
                  className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs font-mono text-slate-900 font-bold focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
                />
                <p className="text-[9px] text-slate-400 font-medium">
                  Cloudflare Notice: Do NOT use root domain if proxied by Cloudflare. Use direct cPanel hostname (e.g. <span className="font-mono text-slate-600 font-bold">sgx3.noc223.com</span>) or click Auto-detect.
                </p>
              </div>

              <div className="space-y-1">
                <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                  SMTP Port
                </label>
                <input
                  type="number"
                  value={smtpPort}
                  onChange={(e) => setSmtpPort(Number(e.target.value))}
                  placeholder="465"
                  className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs font-mono text-slate-900 font-bold focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
                />
              </div>

              <div className="space-y-1 flex flex-col justify-end">
                <label className="flex items-center gap-2 p-2.5 bg-slate-50 border border-slate-200 rounded-xl cursor-pointer hover:bg-slate-100 transition-colors">
                  <input
                    type="checkbox"
                    checked={smtpSecure}
                    onChange={(e) => {
                      const next = e.target.checked;
                      setSmtpSecure(next);
                      if (next && smtpPort === 587) setSmtpPort(465);
                      if (!next && smtpPort === 465) setSmtpPort(587);
                    }}
                    className="rounded text-red-600 focus:ring-red-500"
                  />
                  <span className="text-xs font-bold text-slate-700">SSL / TLS (Port 465)</span>
                </label>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1">
                <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                  Webmail Username / Email Address
                </label>
                <input
                  type="text"
                  value={smtpUser}
                  onChange={(e) => setSmtpUser(e.target.value)}
                  placeholder="e.g. abuse@yourdomain.com"
                  className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs text-slate-900 font-bold focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                  Webmail Account Password
                </label>
                <input
                  type="password"
                  value={smtpPass}
                  onChange={(e) => setSmtpPass(e.target.value)}
                  placeholder={smtpConfigured ? "••••••••••••" : "Enter email password or app password"}
                  className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs text-slate-900 font-bold focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
                />
              </div>
            </div>

            <div className="border-t border-slate-150 pt-4 flex flex-col sm:flex-row justify-between items-center gap-3">
              <div className="flex items-center gap-2 w-full sm:w-auto">
                <input
                  type="email"
                  value={testEmail}
                  onChange={(e) => setTestEmail(e.target.value)}
                  placeholder="Test recipient email..."
                  className="px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs w-full sm:w-56 focus:outline-hidden"
                />
                <button
                  type="button"
                  onClick={() => handleTestSmtp('primary')}
                  disabled={testLoading || !smtpHost}
                  className="px-3 py-2 bg-slate-100 hover:bg-slate-200 disabled:opacity-50 text-slate-700 font-bold rounded-xl text-xs flex items-center gap-1.5 cursor-pointer whitespace-nowrap"
                >
                  {testLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                  <span>Test Connection</span>
                </button>
              </div>

              <button
                type="submit"
                disabled={smtpSaveLoading}
                className="w-full sm:w-auto bg-red-600 hover:bg-red-700 text-white px-5 py-2.5 rounded-xl text-xs font-black uppercase tracking-wider flex items-center justify-center gap-1.5 cursor-pointer shadow-xs disabled:opacity-50 transition-all"
              >
                {smtpSaveLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
                <span>Save Webmail Configuration</span>
              </button>
            </div>
          </form>
        )}

        {/* Additional Office Accounts Form */}
        {activeAccountTab !== 'primary' && (() => {
          const acc = officeAccounts.find(a => a.id === activeAccountTab);
          if (!acc) return null;

          return (
            <div className="space-y-4">
              <div className="bg-slate-50/70 p-3 rounded-xl border border-slate-200/80 flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                  <span className="text-xs font-bold text-slate-800">{acc.label}</span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => handleSetDefaultAccount(acc.id)}
                    className={`px-2.5 py-1 rounded-lg text-xs font-bold flex items-center gap-1 cursor-pointer transition-colors ${
                      acc.isDefault ? 'bg-amber-100 text-amber-800 border border-amber-300' : 'bg-white hover:bg-slate-100 text-slate-600 border border-slate-200'
                    }`}
                  >
                    <Star className={`w-3 h-3 ${acc.isDefault ? 'fill-amber-500 text-amber-500' : ''}`} />
                    <span>{acc.isDefault ? 'Default Account' : 'Set as Default'}</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => handleRemoveOfficeAccount(acc.id)}
                    className="px-2.5 py-1 bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 rounded-lg text-xs font-bold flex items-center gap-1 cursor-pointer transition-colors"
                  >
                    <Trash2 className="w-3 h-3" />
                    <span>Delete</span>
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="space-y-1">
                  <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                    Account Display Label
                  </label>
                  <input
                    type="text"
                    value={acc.label}
                    onChange={(e) => handleUpdateOfficeAccount(acc.id, 'label', e.target.value)}
                    placeholder="e.g. NOC Operations Desk"
                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs text-slate-900 font-bold focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                    Sender Display Name
                  </label>
                  <input
                    type="text"
                    value={acc.fromName}
                    onChange={(e) => handleUpdateOfficeAccount(acc.id, 'fromName', e.target.value)}
                    placeholder="e.g. NOC Engineer / Abuse Officer"
                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs text-slate-900 font-bold focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                    Email Address
                  </label>
                  <input
                    type="email"
                    value={acc.fromEmail}
                    onChange={(e) => handleUpdateOfficeAccount(acc.id, 'fromEmail', e.target.value)}
                    placeholder="e.g. noc@yourcompany.com"
                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs text-slate-900 font-bold focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 pt-1">
                <div className="sm:col-span-2 space-y-1">
                  <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                    SMTP Host Server
                  </label>
                  <input
                    type="text"
                    value={acc.host}
                    onChange={(e) => handleUpdateOfficeAccount(acc.id, 'host', e.target.value)}
                    placeholder="e.g. smtp.gmail.com or mail.yourcompany.com"
                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs font-mono text-slate-900 font-bold focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                    SMTP Port
                  </label>
                  <input
                    type="number"
                    value={acc.port}
                    onChange={(e) => handleUpdateOfficeAccount(acc.id, 'port', Number(e.target.value))}
                    placeholder="587"
                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs font-mono text-slate-900 font-bold focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
                  />
                </div>

                <div className="space-y-1 flex flex-col justify-end">
                  <label className="flex items-center gap-2 p-2.5 bg-slate-50 border border-slate-200 rounded-xl cursor-pointer hover:bg-slate-100 transition-colors">
                    <input
                      type="checkbox"
                      checked={acc.secure}
                      onChange={(e) => handleUpdateOfficeAccount(acc.id, 'secure', e.target.checked)}
                      className="rounded text-red-600 focus:ring-red-500"
                    />
                    <span className="text-xs font-bold text-slate-700">SSL / TLS (465)</span>
                  </label>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                    SMTP Username / Login
                  </label>
                  <input
                    type="text"
                    value={acc.user}
                    onChange={(e) => handleUpdateOfficeAccount(acc.id, 'user', e.target.value)}
                    placeholder="e.g. noc@yourcompany.com"
                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs text-slate-900 font-bold focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                    Password / App Password
                  </label>
                  <input
                    type="password"
                    value={acc.pass}
                    onChange={(e) => handleUpdateOfficeAccount(acc.id, 'pass', e.target.value)}
                    placeholder="Enter email account password"
                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs text-slate-900 font-bold focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
                  />
                </div>
              </div>

              <div className="border-t border-slate-150 pt-4 flex flex-col sm:flex-row justify-between items-center gap-3">
                <div className="flex items-center gap-2 w-full sm:w-auto">
                  <input
                    type="email"
                    value={testEmail}
                    onChange={(e) => setTestEmail(e.target.value)}
                    placeholder="Test recipient email..."
                    className="px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs w-full sm:w-56 focus:outline-hidden"
                  />
                  <button
                    type="button"
                    onClick={() => handleTestSmtp(acc.id)}
                    disabled={testLoading || !acc.host}
                    className="px-3 py-2 bg-slate-100 hover:bg-slate-200 disabled:opacity-50 text-slate-700 font-bold rounded-xl text-xs flex items-center gap-1.5 cursor-pointer whitespace-nowrap"
                  >
                    {testLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                    <span>Test This Account</span>
                  </button>
                </div>

                <button
                  type="button"
                  onClick={handleSaveSmtp}
                  disabled={smtpSaveLoading}
                  className="w-full sm:w-auto bg-red-600 hover:bg-red-700 text-white px-5 py-2.5 rounded-xl text-xs font-black uppercase tracking-wider flex items-center justify-center gap-1.5 cursor-pointer shadow-xs disabled:opacity-50 transition-all"
                >
                  {smtpSaveLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
                  <span>Save All Email Configurations</span>
                </button>
              </div>
            </div>
          );
        })()}
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
