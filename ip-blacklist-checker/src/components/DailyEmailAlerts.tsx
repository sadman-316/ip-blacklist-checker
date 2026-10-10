import React, { useState, useEffect } from 'react';
import { 
  Bell, 
  BellOff, 
  Mail, 
  Send, 
  CheckCircle2, 
  AlertTriangle, 
  Clock, 
  ShieldCheck, 
  ShieldAlert, 
  Sliders, 
  RefreshCw, 
  Loader2, 
  ExternalLink, 
  Trash2, 
  Eye, 
  Check, 
  Info,
  Sparkles,
  Building,
  Settings,
  HelpCircle,
  Layers,
  ArrowRight
} from 'lucide-react';
import { UserProfile, DailyAlertSettings, DailyAlertLog, OfficeMailAccount, MonitoredIP } from '../types';

interface DailyEmailAlertsProps {
  currentUser: UserProfile;
  triggerAlert: (type: 'success' | 'error' | 'info' | 'warning', message: string) => void;
  onOpenDelistAppeal?: (targetIP: string, providerId?: string) => void;
  onNavigateToSettings?: () => void;
}

export const DailyEmailAlerts: React.FC<DailyEmailAlertsProps> = ({
  currentUser,
  triggerAlert,
  onOpenDelistAppeal,
  onNavigateToSettings
}) => {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [dispatching, setDispatching] = useState(false);

  // Settings State
  const [enabled, setEnabled] = useState(true);
  const [recipientEmails, setRecipientEmails] = useState(currentUser.email || 'mzpranto71@gmail.com');
  const [frequency, setFrequency] = useState<'immediate' | 'daily_digest' | 'both'>('both');
  const [onlyWhenListed, setOnlyWhenListed] = useState(false);
  const [scheduleHour, setScheduleHour] = useState(8);
  const [preferredAccountId, setPreferredAccountId] = useState('');
  const [lastSentAt, setLastSentAt] = useState<string | null>(null);
  const [totalAlertsDispatched, setTotalAlertsDispatched] = useState(0);

  // Office Accounts & SMTP status
  const [officeAccounts, setOfficeAccounts] = useState<OfficeMailAccount[]>([]);
  const [smtpConfigured, setSmtpConfigured] = useState(false);
  const [primaryFromEmail, setPrimaryFromEmail] = useState('');

  // Logs & Monitored IPs
  const [logs, setLogs] = useState<DailyAlertLog[]>([]);
  const [monitoredIPs, setMonitoredIPs] = useState<MonitoredIP[]>([]);
  const [previewTab, setPreviewTab] = useState<'sample_listed' | 'sample_clean'>('sample_listed');

  // Fetch initial data
  const fetchData = async () => {
    setLoading(true);
    try {
      // 1. Fetch Alert Settings & Logs
      const alertRes = await fetch('/api/alerts/settings');
      if (alertRes.ok) {
        const data = await alertRes.json();
        if (data.settings) {
          setEnabled(Boolean(data.settings.enabled));
          if (data.settings.recipientEmails) setRecipientEmails(data.settings.recipientEmails);
          if (data.settings.frequency) setFrequency(data.settings.frequency);
          if (typeof data.settings.onlyWhenListed === 'boolean') setOnlyWhenListed(data.settings.onlyWhenListed);
          if (typeof data.settings.scheduleHour === 'number') setScheduleHour(data.settings.scheduleHour);
          if (data.settings.preferredAccountId) setPreferredAccountId(data.settings.preferredAccountId);
          if (data.settings.lastSentAt) setLastSentAt(data.settings.lastSentAt);
          if (data.settings.totalAlertsDispatched) setTotalAlertsDispatched(data.settings.totalAlertsDispatched);
        }
        if (Array.isArray(data.logs)) {
          setLogs(data.logs);
        }
      }

      // 2. Fetch SMTP / Office Accounts
      const smtpRes = await fetch('/api/settings/smtp');
      if (smtpRes.ok) {
        const s = await smtpRes.json();
        setSmtpConfigured(Boolean(s.isConfigured));
        if (s.fromEmail) setPrimaryFromEmail(s.fromEmail);
        if (Array.isArray(s.accounts)) {
          setOfficeAccounts(s.accounts);
          if (!preferredAccountId && s.accounts.length > 0) {
            const def = s.accounts.find((a: OfficeMailAccount) => a.isDefault) || s.accounts[0];
            if (def) setPreferredAccountId(def.id);
          }
        }
      }

      // 3. Fetch current monitored IPs
      const ipsRes = await fetch('/api/monitored-ips');
      if (ipsRes.ok) {
        const ipsData = await ipsRes.json();
        if (Array.isArray(ipsData.ips)) {
          setMonitoredIPs(ipsData.ips);
        }
      }
    } catch (err) {
      console.warn('Error loading daily email alert data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Save Settings
  const handleSaveSettings = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setSaving(true);
    try {
      const res = await fetch('/api/alerts/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enabled,
          recipientEmails,
          frequency,
          onlyWhenListed,
          scheduleHour: Number(scheduleHour),
          preferredAccountId
        })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        triggerAlert('success', 'Daily blacklist email alert preferences saved successfully.');
      } else {
        throw new Error(data.error || 'Failed to save alert settings.');
      }
    } catch (err: any) {
      triggerAlert('error', err.message || 'Failed to save alert settings.');
    } finally {
      setSaving(false);
    }
  };

  // Send Test Alert Email
  const handleSendTestEmail = async () => {
    if (!smtpConfigured) {
      triggerAlert('warning', 'Company Outgoing Mail (SMTP) is not configured yet. Please configure your mail server in System Settings to send real alert emails.');
      if (onNavigateToSettings) onNavigateToSettings();
      return;
    }
    if (!recipientEmails.trim()) {
      triggerAlert('warning', 'Please enter at least one recipient email address.');
      return;
    }
    setTesting(true);
    triggerAlert('info', `Dispatching test reputation notification to ${recipientEmails.split(',')[0]}...`);
    try {
      const res = await fetch('/api/alerts/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipientEmail: recipientEmails })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        triggerAlert('success', `Test email successfully delivered to ${data.recipients?.join(', ') || recipientEmails}! Check your inbox.`);
        fetchData();
      } else {
        throw new Error(data.error || data.message || 'Failed to send test alert email.');
      }
    } catch (err: any) {
      triggerAlert('error', err.message || 'Failed to dispatch test email. Ensure Company Mail is configured.');
    } finally {
      setTesting(false);
    }
  };

  // Dispatch Daily Digest Now
  const handleDispatchNow = async () => {
    if (!smtpConfigured) {
      triggerAlert('warning', 'Company Outgoing Mail (SMTP) is not configured yet. Please configure your mail server in System Settings.');
      if (onNavigateToSettings) onNavigateToSettings();
      return;
    }
    setDispatching(true);
    triggerAlert('info', 'Compiling current monitoring results and sending alert email...');
    try {
      const res = await fetch('/api/alerts/dispatch-now', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await res.json();
      if (res.ok && data.success) {
        triggerAlert('success', `Alert email delivered! Found ${data.blacklistedCount || 0} blacklisted IPs.`);
        fetchData();
      } else {
        throw new Error(data.error || data.message || 'Failed to dispatch daily alert.');
      }
    } catch (err: any) {
      triggerAlert('error', err.message || 'Failed to dispatch daily digest email.');
    } finally {
      setDispatching(false);
    }
  };

  // Clear Logs
  const handleClearLogs = async () => {
    try {
      const res = await fetch('/api/alerts/logs', { method: 'DELETE' });
      if (res.ok) {
        setLogs([]);
        triggerAlert('info', 'Alert dispatch history cleared.');
      }
    } catch (err) {}
  };

  // Calculate live stats
  const totalMonitoredHosts = monitoredIPs.reduce((sum, item) => sum + (item.totalIPs || 1), 0);
  const blacklistedTargets = monitoredIPs.filter(item => item.status === 'listed');
  const cleanTargets = monitoredIPs.filter(item => item.status === 'clean');

  const allBlacklistedIPsList: Array<{ ip: string; parentLabel: string; parentTarget: string; rbls: string[] }> = [];
  blacklistedTargets.forEach(target => {
    if (target.blacklistedIPs && Array.isArray(target.blacklistedIPs) && target.blacklistedIPs.length > 0) {
      target.blacklistedIPs.forEach(b => {
        const rbls: string[] = [];
        if (b.listings) {
          Object.entries(b.listings).forEach(([k, v]: any) => {
            if (v && (v.listed || v.status === 'Listed' || v.status === 'LISTED')) {
              rbls.push(v.name || k);
            }
          });
        }
        allBlacklistedIPsList.push({
          ip: b.ip,
          parentLabel: target.label || 'Target Subnet',
          parentTarget: target.ipOrCidr,
          rbls
        });
      });
    } else {
      const rbls: string[] = [];
      if (target.listings) {
        Object.entries(target.listings).forEach(([k, v]: any) => {
          if (v && (v.listed || v.status === 'Listed' || v.status === 'LISTED')) {
            rbls.push(v.name || k);
          }
        });
      }
      allBlacklistedIPsList.push({
        ip: target.ipOrCidr,
        parentLabel: target.label || 'Host',
        parentTarget: target.ipOrCidr,
        rbls
      });
    }
  });

  return (
    <div className="space-y-6" id="daily-email-alerts-container">
      
      {/* Top Hero Banner */}
      <div className="bg-gradient-to-br from-slate-950 via-slate-900 to-zinc-950 text-white rounded-2xl p-6 sm:p-8 border border-slate-800 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-red-600/10 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20"></div>
        
        <div className="relative z-10 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-1 bg-red-600/20 text-red-400 border border-red-500/30 rounded-lg text-[10px] font-black uppercase tracking-wider flex items-center gap-1.5">
                <Bell className="w-3 h-3 text-red-500 animate-pulse" />
                Continuous Blacklist Intelligence
              </span>
              <span className="text-xs text-slate-400 font-mono">
                Auto-Dispatched via Company Mail
              </span>
            </div>
            
            <h1 className="text-2xl sm:text-3xl font-black text-white tracking-tight">
              Daily IP Blacklist Alert &amp; Email Notifier
            </h1>
            <p className="text-sm text-slate-300 max-w-2xl leading-relaxed">
              Automated Daily Email Alerts: Instantly dispatches alerts and daily reputation digests from your company mail whenever any monitored IP is listed on Spamhaus, Barracuda, SpamCop, Invaluement, or other RBL blacklists.
            </p>
          </div>

          {/* Quick Active Toggle & Action Buttons */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 shrink-0 w-full sm:w-auto">
            <div className={`flex items-center justify-between gap-3 px-4 py-3 rounded-xl border transition-all ${
              enabled 
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' 
                : 'bg-slate-800 border-slate-700 text-slate-400'
            }`}>
              <div className="flex items-center gap-2 text-xs font-bold">
                <span className={`w-2.5 h-2.5 rounded-full ${enabled ? 'bg-emerald-400 animate-ping' : 'bg-slate-500'}`}></span>
                <span>{enabled ? 'Alerts Active' : 'Alerts Paused'}</span>
              </div>
              <button
                type="button"
                onClick={() => {
                  const nextState = !enabled;
                  setEnabled(nextState);
                  fetch('/api/alerts/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ enabled: nextState })
                  });
                  triggerAlert('info', nextState ? 'Daily alerts activated.' : 'Daily alerts paused.');
                }}
                className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-hidden ${
                  enabled ? 'bg-emerald-600' : 'bg-slate-700'
                }`}
              >
                <span
                  className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ease-in-out ${
                    enabled ? 'translate-x-5' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>

            <button
              type="button"
              disabled={testing}
              onClick={handleSendTestEmail}
              className="px-4 py-3 bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white rounded-xl text-xs font-black uppercase tracking-wider flex items-center justify-center gap-2 transition-all cursor-pointer shadow-md"
              title={smtpConfigured ? "Dispatches a live test report email to verify delivery" : "Click to configure SMTP mail server"}
            >
              {testing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              <span>Send Test Email</span>
            </button>
          </div>
        </div>

        {/* Quick telemetry metrics strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6 pt-6 border-t border-slate-800">
          <div className="bg-white/5 border border-white/10 rounded-xl p-3">
            <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Monitored Host IPs</div>
            <div className="text-xl font-black text-white mt-1">{totalMonitoredHosts} Hosts</div>
            <div className="text-[11px] text-slate-400 mt-0.5">{monitoredIPs.length} targets configured</div>
          </div>

          <div className="bg-white/5 border border-white/10 rounded-xl p-3">
            <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Blacklisted IPs</div>
            <div className={`text-xl font-black mt-1 ${allBlacklistedIPsList.length > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
              {allBlacklistedIPsList.length} Nodes
            </div>
            <div className="text-[11px] text-slate-400 mt-0.5">
              {allBlacklistedIPsList.length > 0 ? '⚠️ Immediate delist required' : '✓ 100% clean across all RBLs'}
            </div>
          </div>

          <div className="bg-white/5 border border-white/10 rounded-xl p-3">
            <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Sender Company Mail</div>
            <div className="text-xs font-black text-white truncate mt-1.5" title={primaryFromEmail || 'Not Configured'}>
              {primaryFromEmail || (officeAccounts[0]?.fromEmail) || 'Not Configured'}
            </div>
            <div className="text-[11px] text-slate-400 mt-0.5">
              {smtpConfigured ? (
                <span className="text-emerald-400 font-bold flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> SMTP Verified
                </span>
              ) : (
                <span className="text-amber-400 font-bold">Needs Configuration</span>
              )}
            </div>
          </div>

          <div className="bg-white/5 border border-white/10 rounded-xl p-3">
            <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Alerts Delivered</div>
            <div className="text-xl font-black text-white mt-1">{totalAlertsDispatched} Emails</div>
            <div className="text-[11px] text-slate-400 mt-0.5 truncate">
              {lastSentAt ? `Last: ${new Date(lastSentAt).toLocaleDateString()}` : 'No alerts dispatched yet'}
            </div>
          </div>
        </div>
      </div>

      {/* Warning Notice if SMTP is not configured */}
      {!smtpConfigured && (
        <div className="bg-amber-50 border-l-4 border-amber-500 p-4 rounded-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-xs">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
            <div>
              <h4 className="text-xs font-bold text-amber-900 uppercase tracking-wider">
                Company Outgoing Mail (SMTP) Not Configured Yet
              </h4>
              <p className="text-xs text-amber-800 mt-0.5">
                Configure your company outgoing mail server (Google Workspace, Outlook 365, Zoho, or cPanel Webmail) in System Settings to enable automated email dispatches.
              </p>
            </div>
          </div>
          {onNavigateToSettings && (
            <button
              type="button"
              onClick={onNavigateToSettings}
              className="px-3.5 py-1.5 bg-amber-600 hover:bg-amber-700 text-white rounded-lg text-xs font-bold flex items-center gap-1.5 shrink-0 transition-colors cursor-pointer"
            >
              <Settings className="w-3.5 h-3.5" />
              <span>Configure in System Settings</span>
            </button>
          )}
        </div>
      )}

      {/* Main Grid: Configuration on Left, Live Alert Status / Preview on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

        {/* LEFT COLUMN: Settings & Rules Form (7 Cols) */}
        <div className="lg:col-span-7 space-y-6">
          <div className="bg-white rounded-2xl border border-slate-200/90 shadow-sm p-6 space-y-5">
            <div className="flex justify-between items-center border-b border-slate-100 pb-4">
              <div>
                <h3 className="text-sm font-black text-slate-900 uppercase tracking-wider flex items-center gap-2">
                  <Sliders className="w-4 h-4 text-red-600" />
                  <span>Daily Alert Configuration &amp; Schedule</span>
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Choose who receives notifications and what conditions trigger automated emails.
                </p>
              </div>

              <span className={`text-[10px] font-black uppercase px-2 py-0.5 rounded-full ${
                enabled ? 'bg-emerald-100 text-emerald-800' : 'bg-slate-100 text-slate-600'
              }`}>
                {enabled ? 'Active' : 'Disabled'}
              </span>
            </div>

            <form onSubmit={handleSaveSettings} className="space-y-4">
              
              {/* Recipient Emails */}
              <div>
                <label className="text-xs font-bold text-slate-700 block mb-1">
                  Recipient Email Addresses (Alert Destination) <span className="text-red-500">*</span>
                </label>
                <div className="relative">
                  <input
                    type="text"
                    value={recipientEmails}
                    onChange={(e) => setRecipientEmails(e.target.value)}
                    placeholder="e.g. mzpranto71@gmail.com, noc@company.com"
                    className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold text-slate-900 focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
                  />
                </div>
                <div className="flex items-center justify-between text-[11px] text-slate-400 mt-1">
                  <span>Multiple emails separated by comma or semicolon.</span>
                  {currentUser.email && !recipientEmails.includes(currentUser.email) && (
                    <button
                      type="button"
                      onClick={() => setRecipientEmails(prev => prev ? `${prev}, ${currentUser.email}` : currentUser.email)}
                      className="text-red-600 font-bold hover:underline cursor-pointer"
                    >
                      + Add My Email ({currentUser.email})
                    </button>
                  )}
                </div>
              </div>

              {/* Alert Frequency Mode */}
              <div>
                <label className="text-xs font-bold text-slate-700 block mb-1.5">
                  Notification Trigger Mode (Schedule & Frequency)
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                  
                  <button
                    type="button"
                    onClick={() => setFrequency('both')}
                    className={`p-3 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between ${
                      frequency === 'both'
                        ? 'bg-red-50/80 border-red-500 text-red-900 ring-2 ring-red-500/20 shadow-xs'
                        : 'bg-white border-slate-200 hover:bg-slate-50 text-slate-700'
                    }`}
                  >
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-black">🚀 Enterprise</span>
                        {frequency === 'both' && <Check className="w-3.5 h-3.5 text-red-600" />}
                      </div>
                      <div className="text-[11px] text-slate-500 leading-snug">
                        Immediate alert on new blacklist + Daily morning digest.
                      </div>
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={() => setFrequency('immediate')}
                    className={`p-3 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between ${
                      frequency === 'immediate'
                        ? 'bg-red-50/80 border-red-500 text-red-900 ring-2 ring-red-500/20 shadow-xs'
                        : 'bg-white border-slate-200 hover:bg-slate-50 text-slate-700'
                    }`}
                  >
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-black">⚡ Instant Alert</span>
                        {frequency === 'immediate' && <Check className="w-3.5 h-3.5 text-red-600" />}
                      </div>
                      <div className="text-[11px] text-slate-500 leading-snug">
                        Alert instantly only when an IP changes status to Listed.
                      </div>
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={() => setFrequency('daily_digest')}
                    className={`p-3 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between ${
                      frequency === 'daily_digest'
                        ? 'bg-red-50/80 border-red-500 text-red-900 ring-2 ring-red-500/20 shadow-xs'
                        : 'bg-white border-slate-200 hover:bg-slate-50 text-slate-700'
                    }`}
                  >
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-black">📅 Daily Digest</span>
                        {frequency === 'daily_digest' && <Check className="w-3.5 h-3.5 text-red-600" />}
                      </div>
                      <div className="text-[11px] text-slate-500 leading-snug">
                        Consolidated summary email once per day at scheduled time.
                      </div>
                    </div>
                  </button>

                </div>
              </div>

              {/* Conditions & Filters */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                
                {/* Only When Listed toggle */}
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl flex items-center justify-between gap-3">
                  <div>
                    <div className="text-xs font-bold text-slate-900">Only Alert on Blacklists</div>
                    <div className="text-[10px] text-slate-500">
                      Skip sending when all IPs are 100% clean to prevent inbox noise.
                    </div>
                  </div>
                  <input
                    type="checkbox"
                    checked={onlyWhenListed}
                    onChange={(e) => setOnlyWhenListed(e.target.checked)}
                    className="w-4 h-4 text-red-600 rounded border-slate-300 focus:ring-red-500 cursor-pointer"
                  />
                </div>

                {/* Scheduled Hour */}
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl flex items-center justify-between gap-3">
                  <div>
                    <div className="text-xs font-bold text-slate-900">Daily Digest Time</div>
                    <div className="text-[10px] text-slate-500">Scheduled time for daily report.</div>
                  </div>
                  <select
                    value={scheduleHour}
                    onChange={(e) => setScheduleHour(Number(e.target.value))}
                    className="bg-white border border-slate-200 rounded-lg text-xs font-bold px-2 py-1 text-slate-900 focus:outline-hidden"
                  >
                    <option value={6}>06:00 AM</option>
                    <option value={8}>08:00 AM</option>
                    <option value={10}>10:00 AM</option>
                    <option value={12}>12:00 PM</option>
                    <option value={18}>06:00 PM</option>
                    <option value={0}>00:00 (Midnight)</option>
                  </select>
                </div>

              </div>

              {/* Outgoing Mail Account Selector */}
              {officeAccounts.length > 0 && (
                <div>
                  <label className="text-xs font-bold text-slate-700 block mb-1">
                    Outgoing Sender Office Account (From Address)
                  </label>
                  <select
                    value={preferredAccountId}
                    onChange={(e) => setPreferredAccountId(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-bold text-slate-900 focus:outline-hidden"
                  >
                    {officeAccounts.map(acc => (
                      <option key={acc.id} value={acc.id}>
                        {acc.label} ({acc.fromEmail}) - {acc.host}:{acc.port}
                      </option>
                    ))}
                  </select>
                </div>
              )}

              {/* Save & Action Buttons */}
              <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-100">
                <div className="flex items-center gap-2">
                  <button
                    type="submit"
                    disabled={saving}
                    className="px-5 py-2.5 bg-slate-900 hover:bg-slate-800 text-white rounded-xl text-xs font-black uppercase tracking-wider flex items-center gap-2 transition-all cursor-pointer shadow-xs disabled:opacity-50"
                  >
                    {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                    <span>Save Preferences</span>
                  </button>

                  <button
                    type="button"
                    disabled={dispatching}
                    onClick={handleDispatchNow}
                    className="px-4 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-800 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
                    title="Triggers manual dispatch of current status report"
                  >
                    {dispatching ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
                    <span>Dispatch Digest Now</span>
                  </button>
                </div>

                <button
                  type="button"
                  disabled={testing}
                  onClick={handleSendTestEmail}
                  className="text-xs font-bold text-red-600 hover:text-red-700 flex items-center gap-1 cursor-pointer disabled:opacity-50"
                >
                  <Send className="w-3 h-3" />
                  <span>Send Test Sample</span>
                </button>
              </div>

            </form>
          </div>

          {/* Current Blacklisted Nodes Banner (If any) */}
          {allBlacklistedIPsList.length > 0 ? (
            <div className="bg-red-50 border border-red-200 rounded-2xl p-5 shadow-xs space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-red-700 font-black text-xs uppercase tracking-wider">
                  <ShieldAlert className="w-4 h-4" />
                  <span>Currently Blacklisted Nodes Detected ({allBlacklistedIPsList.length})</span>
                </div>
                <span className="text-[10px] bg-red-200 text-red-800 font-extrabold px-2 py-0.5 rounded-full">
                  High Attention
                </span>
              </div>
              
              <div className="space-y-2">
                {allBlacklistedIPsList.map((item, idx) => (
                  <div key={idx} className="bg-white p-3 rounded-xl border border-red-100 flex flex-col sm:flex-row sm:items-center justify-between gap-2 shadow-2xs">
                    <div>
                      <div className="font-mono text-xs font-bold text-red-600 flex items-center gap-2">
                        <span>{item.ip}</span>
                        <span className="text-[10px] font-sans font-normal text-slate-500">
                          ({item.parentLabel})
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-600 mt-0.5">
                        Listed on: <span className="font-semibold text-slate-800">{item.rbls.join(', ') || 'RBL Provider'}</span>
                      </div>
                    </div>
                    {onOpenDelistAppeal && (
                      <button
                        type="button"
                        onClick={() => onOpenDelistAppeal(item.ip)}
                        className="px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded-lg text-xs font-bold flex items-center justify-center gap-1 cursor-pointer transition-colors shrink-0"
                      >
                        <Mail className="w-3 h-3" />
                        <span>Appeal Delisting</span>
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="bg-emerald-50 border border-emerald-200 rounded-2xl p-5 shadow-xs flex items-center gap-3.5">
              <div className="w-10 h-10 rounded-xl bg-emerald-600/10 border border-emerald-500/20 flex items-center justify-center text-emerald-600 shrink-0">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <div>
                <h4 className="text-xs font-black text-emerald-950 uppercase tracking-wider">
                  Zero Blacklists Detected
                </h4>
                <p className="text-xs text-emerald-800 mt-0.5">
                  All {totalMonitoredHosts} monitored hosts across your network subnets are completely clean on Spamhaus, Barracuda, SpamCop, Invaluement, and 20+ DNSBLs.
                </p>
              </div>
            </div>
          )}

        </div>

        {/* RIGHT COLUMN: Live Email Preview & Dispatch Logs (5 Cols) */}
        <div className="lg:col-span-5 space-y-6">
          
          {/* Email Preview Mockup */}
          <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden flex flex-col">
            <div className="bg-slate-900 text-white p-3.5 px-4 flex items-center justify-between border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Eye className="w-3.5 h-3.5 text-slate-400" />
                <span className="text-xs font-bold uppercase tracking-wider text-slate-200">
                  Recipient Inbox Preview
                </span>
              </div>

              <div className="flex items-center gap-1 bg-slate-800 p-0.5 rounded-lg text-[10px]">
                <button
                  type="button"
                  onClick={() => setPreviewTab('sample_listed')}
                  className={`px-2 py-0.5 rounded cursor-pointer ${
                    previewTab === 'sample_listed' ? 'bg-red-600 text-white font-bold' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Alert Email
                </button>
                <button
                  type="button"
                  onClick={() => setPreviewTab('sample_clean')}
                  className={`px-2 py-0.5 rounded cursor-pointer ${
                    previewTab === 'sample_clean' ? 'bg-emerald-600 text-white font-bold' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Clean Report
                </button>
              </div>
            </div>

            {/* Email Body Simulation */}
            <div className="p-4 bg-slate-100 text-xs font-sans">
              <div className="bg-white rounded-xl shadow-xs border border-slate-200 overflow-hidden">
                
                {/* Simulated Email Header */}
                <div className="bg-slate-950 p-3 text-white">
                  <div className="text-[9px] font-black uppercase tracking-wider text-red-400">
                    WolastShield IP Reputation
                  </div>
                  <div className="text-xs font-extrabold text-white mt-0.5">
                    {previewTab === 'sample_listed'
                      ? `🚨 [ALERT] Blacklisted IP(s) Detected - ${officeAccounts[0]?.companyName || 'Wolast Technology'}`
                      : `✓ [STATUS: CLEAN] Zero Blacklists Detected across Monitored IPs`}
                  </div>
                </div>

                {/* Simulated Stats Strip */}
                <div className="grid grid-cols-3 gap-2 p-2.5 bg-slate-50 border-b border-slate-200 text-center text-[10px]">
                  <div className="bg-white p-1.5 rounded border border-slate-200">
                    <div className="text-slate-500 font-bold uppercase">Targets</div>
                    <div className="text-xs font-black text-slate-800">{monitoredIPs.length || 2}</div>
                  </div>
                  <div className="bg-white p-1.5 rounded border border-slate-200">
                    <div className="text-slate-500 font-bold uppercase">Hosts</div>
                    <div className="text-xs font-black text-slate-800">{totalMonitoredHosts || 16}</div>
                  </div>
                  <div className={`p-1.5 rounded border ${previewTab === 'sample_listed' ? 'bg-red-50 border-red-200 text-red-700' : 'bg-emerald-50 border-emerald-200 text-emerald-700'}`}>
                    <div className="font-bold uppercase">Status</div>
                    <div className="text-xs font-black">
                      {previewTab === 'sample_listed' ? '1 Listed' : '100% Clean'}
                    </div>
                  </div>
                </div>

                {/* Simulated Content */}
                <div className="p-3 text-[11px] text-slate-700 space-y-2">
                  {previewTab === 'sample_listed' ? (
                    <>
                      <div className="font-bold text-red-600 flex items-center gap-1">
                        <AlertTriangle className="w-3 h-3" />
                        <span>Active Listing Detected:</span>
                      </div>
                      <div className="bg-red-50/80 p-2 rounded border border-red-100 font-mono text-[10px] space-y-0.5">
                        <div className="font-bold text-red-700">185.190.140.4 (Mail Gateway)</div>
                        <div className="text-slate-600 font-sans">Listed on: Spamhaus ZEN, Invaluement ivmSIP</div>
                        <div className="text-red-500 font-sans font-bold pt-1">Action: Open Delist Appeal</div>
                      </div>
                    </>
                  ) : (
                    <div className="text-center py-2 text-emerald-700">
                      <div className="font-bold text-xs">✓ All Subnets Clean</div>
                      <div className="text-[10px] text-slate-500 mt-0.5">Zero active blocklist hits detected.</div>
                    </div>
                  )}

                  <div className="pt-2 border-t border-slate-100 text-[9px] text-slate-400">
                    Dispatched from: {primaryFromEmail || 'abuse@wolast.com'}<br/>
                    Recipient: {recipientEmails.split(',')[0]}
                  </div>
                </div>

              </div>
            </div>
          </div>

          {/* Dispatch Audit Logs */}
          <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-5 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div className="flex items-center gap-2 text-xs font-black uppercase tracking-wider text-slate-900">
                <Clock className="w-3.5 h-3.5 text-blue-600" />
                <span>Alert Dispatch History ({logs.length})</span>
              </div>
              {logs.length > 0 && (
                <button
                  type="button"
                  onClick={handleClearLogs}
                  className="text-[10px] text-slate-400 hover:text-red-600 font-bold cursor-pointer"
                >
                  Clear Logs
                </button>
              )}
            </div>

            {logs.length === 0 ? (
              <div className="text-center py-6 text-slate-400 text-xs">
                No alert notifications have been dispatched yet.
              </div>
            ) : (
              <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                {logs.slice(0, 10).map((log) => (
                  <div key={log.id} className="p-2.5 bg-slate-50 rounded-xl border border-slate-200 text-xs space-y-1">
                    <div className="flex items-center justify-between">
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-black uppercase ${
                        log.status === 'sent' ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'
                      }`}>
                        {log.status === 'sent' ? 'Delivered' : 'Failed'}
                      </span>
                      <span className="text-[10px] font-mono text-slate-400">
                        {new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>

                    <div className="text-[11px] font-semibold text-slate-800 truncate" title={log.recipient}>
                      To: {log.recipient}
                    </div>

                    <div className="flex items-center justify-between text-[10px] text-slate-500">
                      <span>
                        {log.triggerType === 'status_change' ? '⚡ Status Change' : log.triggerType === 'daily_digest' ? '📅 Daily Digest' : '🧪 Manual Test'}
                      </span>
                      <span className={log.blacklistedCount > 0 ? 'text-red-600 font-bold' : 'text-emerald-600 font-bold'}>
                        {log.blacklistedCount} Blacklisted
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

        </div>

      </div>

    </div>
  );
};
