import React, { useState, useEffect, useMemo } from 'react';
import { 
  Mail, 
  Send, 
  ExternalLink, 
  Copy, 
  Check, 
  ShieldAlert, 
  CheckCircle2, 
  Building2, 
  User, 
  FileText, 
  Sparkles, 
  AlertCircle, 
  Info, 
  HelpCircle,
  X,
  Loader2,
  RefreshCw
} from 'lucide-react';
import { UserProfile, DelistRequest } from '../types';

interface DelistRequestModalProps {
  isOpen: boolean;
  onClose: () => void;
  targetIP: string;
  ptr?: string;
  isp?: string;
  org?: string;
  listedProviders: Array<{
    id: string;
    name: string;
    domain: string;
    delistUrl: string;
    delistEmail?: string;
    reason?: string;
  }>;
  initialProviderId?: string;
  currentUser: UserProfile;
  triggerAlert: (type: 'success' | 'error' | 'info' | 'warning', message: string) => void;
  onSuccess?: (newRequest: DelistRequest) => void;
}

// Standard fallback removal emails for major DNSBL and threat feeds
const DEFAULT_PROVIDER_EMAILS: Record<string, string> = {
  spamhaus: 'removal@spamhaus.org',
  barracuda: 'intent@barracudacentral.org',
  spamcop: 'deputy@admin.spamcop.net',
  uceprotect1: 'delist@uceprotect.net',
  uceprotect2: 'delist@uceprotect.net',
  uceprotect3: 'delist@uceprotect.net',
  blocklist: 'info@blocklist.de',
  sorbs: 'delist@sorbs.net',
  sorbsduhl: 'delist@sorbs.net',
  dronebl: 'staff@dronebl.org',
  gbudb: 'support@gbudb.com',
  spfbl: 'abuse@spfbl.net',
  lashback: 'removal@lashback.com',
  psbl: 'psbl@surriel.com',
  wpbl: 'admin@wpbl.info',
  ivmsip: 'removal@invaluement.com',
  ivmuri: 'removal@invaluement.com',
  spamrats: 'removal@spamrats.com',
  spamratssb: 'removal@spamrats.com',
  spamratsnoptr: 'removal@spamrats.com',
  mailspikebl: 'support@mailspike.org',
  mailspikez: 'support@mailspike.org',
  hostkarma: 'support@junkemailfilter.com',
  nixspam: 'abuse@nixspam.net',
  nordspam: 'abuse@nordspam.com',
  '0spam': 'delist@0spam.org',
  backscatterer: 'delist@backscatterer.org',
  spameatingmonkey: 'admin@spameatingmonkey.com',
  abuseat_cbl: 'cbl@abuseat.org',
  suomispam: 'abuse@suomispam.net',
  zapbl: 'abuse@zapbl.net',
  protectedsky: 'support@protectedsky.com',
  swinog: 'abuse@swinog.ch'
};

const REASON_TEMPLATES = [
  {
    id: 'clean_compromise',
    label: 'Compromised Account / Malware Cleaned & Secured',
    summary: 'The outbound abusive behavior was caused by a compromised user account/script which has been fully terminated, malware removed, and passwords rotated.',
    actionsTaken: [
      'Identified and terminated the compromised script/account sending unauthorized traffic.',
      'Full rootkit and antivirus malware audit executed; system verified clean.',
      'Enforced mandatory 2FA and rotated all SMTP and administrative credentials.',
      'Implemented strict outbound rate-limiting on port 25/587.'
    ]
  },
  {
    id: 'new_ip_alloc',
    label: 'New Clean Static IP Allocation (Clean Handover)',
    summary: 'This IP address was recently allocated to our organization by our ISP/datacenter. The prior malicious activities occurred under the previous leaseholder.',
    actionsTaken: [
      'IP was freshly assigned by our hosting carrier/ISP to our infrastructure.',
      'Configured dedicated clean forward and reverse DNS (PTR) records.',
      'No unsolicited bulk email or malicious traffic originates from this host.',
      'Full ownership documentation and ARIN/RIPE assignment verified.'
    ]
  },
  {
    id: 'config_fix',
    label: 'Email Configuration Fixed (rDNS / SPF / DKIM / DMARC)',
    summary: 'Misconfiguration in mail server settings or DNS records has been resolved and verified compliant with RFC 5321 and RFC 7208 standards.',
    actionsTaken: [
      'Corrected matching FQDN Forward and Reverse DNS (PTR) records.',
      'Implemented and published valid SPF, DKIM 2048-bit, and DMARC enforcement records.',
      'Tested mail server with RFC standards verification tools - 100% pass.',
      'Confirmed sender reputation and postmaster contact address is active.'
    ]
  },
  {
    id: 'relay_secured',
    label: 'Open Relay / Unauthorized Port 25 Leak Closed',
    summary: 'An accidental open relay or proxy port was identified and permanently closed. The mail transfer agent now enforces strict SASL authentication.',
    actionsTaken: [
      'Closed open relay vulnerability; outbound relaying now strictly requires SASL TLS authentication.',
      'Restricted port 25 egress traffic to authenticated internal services only.',
      'Audited firewall rules and verified zero unauthorized outbound connections.',
      'Verified with third-party open-relay test suites.'
    ]
  },
  {
    id: 'rate_limit',
    label: 'Rate Limiting & Bounce Backscatter Prevention Enabled',
    summary: 'Outbound rate limits have been implemented and NDR / backscatter generation has been completely disabled on the mail transport agent.',
    actionsTaken: [
      'Configured throttling limits: max 50 emails per hour per authenticated client.',
      'Disabled backscatter/out-of-office bounce messages to unverified external senders.',
      'Real-time postfix/exim queue monitoring deployed with instant alerting.',
      'Clean queue status verified with zero backlogged messages.'
    ]
  },
  {
    id: 'custom',
    label: 'Custom Security & Operations Appeal',
    summary: 'Comprehensive administrative review conducted by our Network Operations & Security team.',
    actionsTaken: [
      'Comprehensive security and log analysis conducted by the postmaster team.',
      'Confirmed zero unauthorized or spam activities originating from this address.',
      'Continuous 24/7 telemetry monitoring active on the host IP.'
    ]
  }
];

const ALL_DEFAULT_PROVIDERS = [
  { id: 'spamhaus', name: 'Spamhaus ZEN', domain: 'zen.spamhaus.org', delistUrl: 'https://www.spamhaus.org/lookup/', delistEmail: 'removal@spamhaus.org' },
  { id: 'barracuda', name: 'Barracuda BRBL', domain: 'b.barracudacentral.org', delistUrl: 'https://www.barracudacentral.org/rbl/removal-request', delistEmail: 'intent@barracudacentral.org' },
  { id: 'spamcop', name: 'SpamCop', domain: 'bl.spamcop.net', delistUrl: 'https://www.spamcop.net/bl.shtml', delistEmail: 'deputy@admin.spamcop.net' },
  { id: 'uceprotect1', name: 'UCEPROTECT Level 1', domain: 'dnsbl-1.uceprotect.net', delistUrl: 'http://www.uceprotect.net/en/rblcheck.php', delistEmail: 'delist@uceprotect.net' },
  { id: 'uceprotect2', name: 'UCEPROTECT Level 2', domain: 'dnsbl-2.uceprotect.net', delistUrl: 'http://www.uceprotect.net/en/rblcheck.php', delistEmail: 'delist@uceprotect.net' },
  { id: 'uceprotect3', name: 'UCEPROTECT Level 3', domain: 'dnsbl-3.uceprotect.net', delistUrl: 'http://www.uceprotect.net/en/rblcheck.php', delistEmail: 'delist@uceprotect.net' },
  { id: 'sorbs', name: 'SORBS Combined', domain: 'dnsbl.sorbs.net', delistUrl: 'http://www.sorbs.net/delisting/overview.shtml', delistEmail: 'delist@sorbs.net' },
  { id: 'dronebl', name: 'DroneBL', domain: 'dnsbl.dronebl.org', delistUrl: 'https://dronebl.org/lookup', delistEmail: 'staff@dronebl.org' },
  { id: 'blocklist', name: 'Blocklist.de', domain: 'bl.blocklist.de', delistUrl: 'https://www.blocklist.de/en/delist.html', delistEmail: 'info@blocklist.de' },
  { id: 'lashback', name: 'LashBack UBL', domain: 'ubl.unsubscore.com', delistUrl: 'https://www.lashback.com/support/ubl_removal.html', delistEmail: 'removal@lashback.com' },
  { id: 'abuseat_cbl', name: 'Abuseat CBL', domain: 'cbl.abuseat.org', delistUrl: 'https://www.abuseat.org/lookup.cgi', delistEmail: 'cbl@abuseat.org' }
];

export function DelistRequestModal({
  isOpen,
  onClose,
  targetIP,
  ptr,
  isp,
  org,
  listedProviders,
  initialProviderId,
  currentUser,
  triggerAlert,
  onSuccess
}: DelistRequestModalProps) {
  if (!isOpen) return null;

  // Editable Target IP state
  const [currentIP, setCurrentIP] = useState<string>(targetIP || '');
  const [currentPtr, setCurrentPtr] = useState<string>(ptr || '');
  const [currentOrg, setCurrentOrg] = useState<string>(org || isp || '');
  const [scanningIP, setScanningIP] = useState<boolean>(false);
  const [liveCheckStatus, setLiveCheckStatus] = useState<{ listedCount: number; clean: boolean } | null>(null);

  // Available Providers: combine incoming listedProviders with fallback defaults
  const [availableProviders, setAvailableProviders] = useState(() => {
    if (listedProviders && listedProviders.length > 0) {
      const merged = [...listedProviders];
      ALL_DEFAULT_PROVIDERS.forEach(dp => {
        if (!merged.some(p => p.id === dp.id)) merged.push(dp);
      });
      return merged;
    }
    return ALL_DEFAULT_PROVIDERS;
  });

  // Selected provider
  const [selectedProviderId, setSelectedProviderId] = useState<string>(() => {
    if (initialProviderId && availableProviders.some(p => p.id === initialProviderId)) {
      return initialProviderId;
    }
    return availableProviders[0]?.id || 'spamhaus';
  });

  const activeProvider = useMemo(() => {
    return availableProviders.find(p => p.id === selectedProviderId) || availableProviders[0] || ALL_DEFAULT_PROVIDERS[0];
  }, [availableProviders, selectedProviderId]);

  // Recipient email
  const recipientEmail = useMemo(() => {
    if (activeProvider.delistEmail) return activeProvider.delistEmail;
    if (DEFAULT_PROVIDER_EMAILS[activeProvider.id]) return DEFAULT_PROVIDER_EMAILS[activeProvider.id];
    // derive standard abuse / delist address from domain
    const cleanDomain = activeProvider.domain.replace(/^([a-z0-9-]+\.)*(dnsbl|bl|zen|rbl|truncate|sip|uri)\./i, '');
    return `abuse@${cleanDomain}`;
  }, [activeProvider]);

  // Live Quick Scan for the typed IP address
  const handleQuickScan = async () => {
    const ip = currentIP.trim();
    if (!ip) {
      triggerAlert('warning', 'Please enter an IP address first.');
      return;
    }
    setScanningIP(true);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ipOrCidr: ip })
      });
      if (res.ok) {
        const data = await res.json();
        const scanRes = data.results?.[0];
        if (scanRes) {
          if (scanRes.ptr) setCurrentPtr(scanRes.ptr);
          if (scanRes.location?.isp || scanRes.location?.org) {
            setCurrentOrg(scanRes.location.org || scanRes.location.isp || '');
          }
          const detectedListings: any[] = [];
          if (scanRes.listings) {
            Object.entries(scanRes.listings).forEach(([key, val]: any) => {
              if (val && val.listed) {
                const matched = ALL_DEFAULT_PROVIDERS.find(p => p.id === key);
                detectedListings.push({
                  id: key,
                  name: val.name || matched?.name || key,
                  domain: val.domain || matched?.domain || `${key}.org`,
                  delistUrl: val.delistUrl || matched?.delistUrl || 'https://www.spamhaus.org/lookup/',
                  delistEmail: matched?.delistEmail || DEFAULT_PROVIDER_EMAILS[key],
                  reason: val.details
                });
              }
            });
          }

          if (detectedListings.length > 0) {
            const merged = [...detectedListings];
            ALL_DEFAULT_PROVIDERS.forEach(dp => {
              if (!merged.some(p => p.id === dp.id)) merged.push(dp);
            });
            setAvailableProviders(merged);
            setSelectedProviderId(detectedListings[0].id);
            setLiveCheckStatus({ listedCount: detectedListings.length, clean: false });
            triggerAlert('warning', `Detected ${detectedListings.length} blacklist listing(s) for ${ip}. Provider auto-selected!`);
          } else {
            setLiveCheckStatus({ listedCount: 0, clean: true });
            triggerAlert('info', `No active DNSBL listings found for ${ip}. You can still choose any provider for appeal.`);
          }
        }
      }
    } catch (err) {
      console.warn('Live IP scan check error:', err);
    } finally {
      setScanningIP(false);
    }
  };

  // Sender details
  const [companyName, setCompanyName] = useState<string>(() => {
    return localStorage.getItem('wolast_delist_company') || 'Wolast Technology Ltd.';
  });
  const [senderName, setSenderName] = useState<string>(() => {
    return localStorage.getItem('wolast_delist_sender_name') || currentUser.displayName || 'Md. Pranto';
  });
  const [senderEmail, setSenderEmail] = useState<string>(() => {
    return localStorage.getItem('wolast_delist_sender_email') || currentUser.email || 'abuse@wolast.com';
  });

  // Reason & Appeal Letter
  const [reasonId, setReasonId] = useState<string>('clean_compromise');
  const [customNotes, setCustomNotes] = useState<string>('');
  const [subject, setSubject] = useState<string>('');
  const [messageBody, setMessageBody] = useState<string>('');
  const [copied, setCopied] = useState<boolean>(false);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  // Generate Letter Body whenever template, IP, or provider details change
  useEffect(() => {
    const selectedTemplate = REASON_TEMPLATES.find(t => t.id === reasonId) || REASON_TEMPLATES[0];
    const target = currentIP.trim() || '[TARGET_IP_ADDRESS]';
    const newSubject = `[Delisting Request] Blacklist Removal Appeal for IP ${target} - ${companyName}`;
    
    const actionsList = selectedTemplate.actionsTaken.map(a => `  * ${a}`).join('\n');
    const customSection = customNotes.trim() ? `\n\nAdditional Technical Details:\n${customNotes.trim()}` : '';

    const body = `Dear ${activeProvider.name} Review & Security Team,

I am writing on behalf of ${companyName} to formally request the re-evaluation and removal of IP address ${target} from the ${activeProvider.name} (${activeProvider.domain}) blacklist database.

Target IP Details:
- IP Address: ${target}
- Reverse DNS (PTR): ${currentPtr || ptr || 'Configured & Verified'}
- Organization / ISP: ${currentOrg || org || isp || companyName}
- Database: ${activeProvider.name} (${activeProvider.domain})

Root Cause & Investigation Summary:
${selectedTemplate.summary}

Corrective Remediation Measures Implemented:
${actionsList}${customSection}

We have strictly verified that the issue is fully resolved and that no abusive or unsolicited traffic will originate from this IP address in the future. Our mail servers and network endpoints are operated strictly in accordance with RFC standards and best security practices.

We kindly ask that you review our submission and delist IP ${target} at your earliest convenience. If you require any additional diagnostic logs or verification, please contact me directly at ${senderEmail}.

Thank you for your time and assistance in maintaining internet security.

Sincerely,

${senderName}
Network Operations & Abuse Contact
${companyName}
Email: ${senderEmail}
Target Host: ${target}`;

    setSubject(newSubject);
    setMessageBody(body);
  }, [activeProvider, currentIP, currentPtr, currentOrg, ptr, isp, org, companyName, senderName, senderEmail, reasonId, customNotes]);

  // Persist sender info locally
  const saveSenderInfo = () => {
    try {
      localStorage.setItem('wolast_delist_company', companyName);
      localStorage.setItem('wolast_delist_sender_name', senderName);
      localStorage.setItem('wolast_delist_sender_email', senderEmail);
    } catch (e) {}
  };

  // Copy Appeal to Clipboard
  const handleCopyText = async () => {
    try {
      await navigator.clipboard.writeText(`${subject}\n\n${messageBody}`);
      setCopied(true);
      triggerAlert('success', 'Delisting appeal text copied to clipboard!');
      setTimeout(() => setCopied(false), 2500);
    } catch (err) {
      triggerAlert('error', 'Could not copy to clipboard. Please select and copy manually.');
    }
  };

  // 1-Click Send via Email Client (mailto:)
  const handleOpenMailClient = () => {
    const ipToSend = currentIP.trim();
    if (!ipToSend) {
      triggerAlert('error', 'Please enter a valid IP address to delist.');
      return;
    }
    saveSenderInfo();
    const mailtoUrl = `mailto:${encodeURIComponent(recipientEmail)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(messageBody)}`;
    window.open(mailtoUrl, '_blank');
    
    // Save to request log as client-dispatched
    saveDelistRecord('client_mailto');
    triggerAlert('info', `Opened default email client for ${recipientEmail}. Request logged as Pending.`);
  };

  // Direct Server SMTP Dispatch
  const handleSendViaServerSMTP = async () => {
    const ipToSend = currentIP.trim();
    if (!ipToSend) {
      triggerAlert('error', 'Please enter a valid IP address to delist.');
      return;
    }
    saveSenderInfo();
    setIsSubmitting(true);

    try {
      const response = await fetch('/api/delist/send-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip: ipToSend,
          providerId: activeProvider.id,
          providerName: activeProvider.name,
          recipientEmail: recipientEmail,
          delistUrl: activeProvider.delistUrl,
          companyName: companyName,
          senderName: senderName,
          senderEmail: senderEmail,
          reasonCategory: REASON_TEMPLATES.find(t => t.id === reasonId)?.label || reasonId,
          subject: subject,
          message: messageBody
        })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        triggerAlert('success', `Delisting appeal successfully dispatched to ${recipientEmail}!`);
        if (onSuccess && data.request) {
          onSuccess(data.request);
        }
        onClose();
      } else if (data.code === 'SMTP_NOT_CONFIGURED') {
        // Offer instant 1-click fallback to mail client
        triggerAlert('warning', data.message || 'Server SMTP not yet configured. Opening your mail client instead...');
        handleOpenMailClient();
      } else {
        throw new Error(data.error || 'Failed to dispatch delist email.');
      }
    } catch (err: any) {
      console.error('Delist submission error:', err);
      triggerAlert('error', err.message || 'Failed to send appeal. You can use the 1-click mail client option.');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Save record to database / tracker
  const saveDelistRecord = async (method: 'smtp' | 'client_mailto' | 'web_portal') => {
    const ipToSend = currentIP.trim();
    if (!ipToSend) return;
    try {
      const record: Partial<DelistRequest> = {
        ip: ipToSend,
        providerId: activeProvider.id,
        providerName: activeProvider.name,
        recipientEmail: recipientEmail,
        delistUrl: activeProvider.delistUrl,
        companyName,
        senderName,
        senderEmail,
        reasonCategory: REASON_TEMPLATES.find(t => t.id === reasonId)?.label || reasonId,
        subject,
        message: messageBody,
        status: 'pending',
        sendMethod: method,
        submittedAt: new Date().toISOString()
      };

      const res = await fetch('/api/delist/requests', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(record)
      });
      const data = await res.json();
      if (res.ok && data.request && onSuccess) {
        onSuccess(data.request);
      }
    } catch (err) {
      console.warn('Could not save delist record to server:', err);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-slate-950/75 backdrop-blur-xs overflow-y-auto animate-fade-in" id="delist-request-modal">
      <div className="bg-white rounded-2xl max-w-3xl w-full border border-slate-200 shadow-2xl overflow-hidden my-6 flex flex-col max-h-[92vh]">
        
        {/* Header */}
        <div className="bg-slate-900 text-white p-5 flex justify-between items-center border-b border-slate-800 shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-red-600/20 border border-red-500/30 flex items-center justify-center text-red-500">
              <Mail className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm sm:text-base font-black uppercase tracking-wider text-white">
                  Blacklist Removal Appeal Engine
                </h3>
                {currentIP && (
                  <span className="bg-red-500/20 text-red-400 border border-red-500/30 text-[10px] font-mono px-2 py-0.5 rounded-full font-bold">
                    {currentIP}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Submit formal NOC delisting requests to blacklist maintainers and security desks
              </p>
            </div>
          </div>
          <button 
            onClick={onClose}
            className="text-slate-400 hover:text-white transition-colors cursor-pointer p-1.5 rounded-lg hover:bg-white/10"
            title="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Scrollable Body */}
        <div className="p-5 sm:p-6 overflow-y-auto space-y-5 text-slate-800 text-xs">
          
          {/* Top Bar: Target IP & Provider Selector */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 bg-slate-50 p-4 rounded-xl border border-slate-200">
            <div>
              <label className="text-[10px] font-black uppercase tracking-wider text-slate-500 block mb-1.5">
                Target IP Address To Delist <span className="text-red-500">*</span>
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={currentIP}
                  onChange={(e) => setCurrentIP(e.target.value.trim())}
                  placeholder="Enter IP to delist (e.g. 103.150.12.5)"
                  className="flex-1 px-3.5 py-2.5 bg-white border border-slate-300 rounded-xl text-xs font-mono font-bold text-slate-900 focus:outline-hidden focus:ring-2 focus:ring-red-500/20 focus:border-red-500"
                />
                <button
                  type="button"
                  onClick={handleQuickScan}
                  disabled={scanningIP || !currentIP.trim()}
                  className="px-3 py-2 bg-slate-900 hover:bg-black text-white text-xs font-bold rounded-xl flex items-center gap-1.5 shrink-0 transition-all cursor-pointer disabled:opacity-50"
                  title="Check live reputation & listings for this IP"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${scanningIP ? 'animate-spin' : ''}`} />
                  <span>{scanningIP ? 'Checking...' : 'Check RBLs'}</span>
                </button>
              </div>
              <div className="flex items-center justify-between text-[11px] text-slate-500 mt-1.5">
                <span className="truncate max-w-xs">{currentPtr || ptr || 'rDNS PTR verification'}</span>
                {liveCheckStatus ? (
                  <span className={`text-[10px] font-black uppercase px-2 py-0.5 rounded-md ${
                    liveCheckStatus.listedCount > 0 ? 'bg-rose-100 text-rose-700' : 'bg-emerald-100 text-emerald-700'
                  }`}>
                    {liveCheckStatus.listedCount > 0 ? `${liveCheckStatus.listedCount} Listed` : 'Clean'}
                  </span>
                ) : (
                  <span className="text-[10px] text-slate-400">Type IP & click Check RBLs</span>
                )}
              </div>
            </div>

            <div>
              <label className="text-[10px] font-black uppercase tracking-wider text-slate-500 block mb-1.5">
                Select Blacklist Provider ({availableProviders.length} Available)
              </label>
              <select
                value={selectedProviderId}
                onChange={(e) => setSelectedProviderId(e.target.value)}
                className="w-full bg-white px-3.5 py-2.5 rounded-xl border border-slate-300 text-xs font-bold text-slate-900 focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
              >
                {availableProviders.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.domain})
                  </option>
                ))}
              </select>
              <div className="flex items-center justify-between text-[11px] text-slate-500 mt-1.5">
                <span>Official Appeal Desk: <strong className="text-slate-800 font-mono">{recipientEmail}</strong></span>
                {activeProvider.delistUrl && (
                  <a 
                    href={activeProvider.delistUrl} 
                    target="_blank" 
                    rel="noreferrer"
                    className="text-red-600 hover:text-red-700 font-bold inline-flex items-center gap-0.5"
                  >
                    Portal <ExternalLink className="w-2.5 h-2.5" />
                  </a>
                )}
              </div>
            </div>
          </div>

          {/* Company & Sender Information Inputs */}
          <div className="space-y-3">
            <h4 className="text-xs font-black uppercase tracking-wider text-slate-900 flex items-center gap-1.5">
              <Building2 className="w-3.5 h-3.5 text-red-600" />
              <span>Your Company & Contact Information</span>
            </h4>
            
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="text-[10px] font-black uppercase tracking-wider text-slate-500 block mb-1">
                  Company Name <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={companyName}
                  onChange={(e) => setCompanyName(e.target.value)}
                  placeholder="e.g. Wolast Technology Ltd."
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold text-slate-900 focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
                />
              </div>

              <div>
                <label className="text-[10px] font-black uppercase tracking-wider text-slate-500 block mb-1">
                  Sender / Contact Name <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={senderName}
                  onChange={(e) => setSenderName(e.target.value)}
                  placeholder="e.g. Md. Pranto / Network Admin"
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold text-slate-900 focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
                />
              </div>

              <div>
                <label className="text-[10px] font-black uppercase tracking-wider text-slate-500 block mb-1">
                  Official Contact Email <span className="text-red-500">*</span>
                </label>
                <input
                  type="email"
                  value={senderEmail}
                  onChange={(e) => setSenderEmail(e.target.value)}
                  placeholder="e.g. abuse@wolast.com"
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold text-slate-900 focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
                />
              </div>
            </div>
          </div>

          {/* Reason & Resolution Template Selector */}
          <div className="space-y-2.5">
            <h4 className="text-xs font-black uppercase tracking-wider text-slate-900 flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-amber-500" />
              <span>Remediation Reason & Root Cause Resolution</span>
            </h4>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {REASON_TEMPLATES.map((tpl) => (
                <button
                  key={tpl.id}
                  type="button"
                  onClick={() => setReasonId(tpl.id)}
                  className={`p-2.5 rounded-xl text-left border transition-all cursor-pointer flex flex-col justify-between ${
                    reasonId === tpl.id 
                      ? 'bg-red-50/70 border-red-500 text-red-900 shadow-2xs' 
                      : 'bg-white border-slate-200 hover:bg-slate-50 text-slate-700'
                  }`}
                >
                  <span className="font-extrabold text-[11px] block">{tpl.label}</span>
                  <span className="text-[10px] text-slate-500 line-clamp-1 mt-1">{tpl.summary}</span>
                </button>
              ))}
            </div>

            {/* Custom Notes addendum */}
            <div className="pt-1">
              <input
                type="text"
                value={customNotes}
                onChange={(e) => setCustomNotes(e.target.value)}
                placeholder="Optional: Enter specific incident ID, ticket #, or custom diagnostic note..."
                className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-800 placeholder-slate-400 focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
              />
            </div>
          </div>

          {/* Preview & Edit Generated Appeal Letter */}
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <h4 className="text-xs font-black uppercase tracking-wider text-slate-900 flex items-center gap-1.5">
                <FileText className="w-3.5 h-3.5 text-blue-600" />
                <span>Formal NOC Appeal Letter (Editable)</span>
              </h4>
              <button
                type="button"
                onClick={handleCopyText}
                className="text-[11px] font-bold text-slate-600 hover:text-slate-900 flex items-center gap-1 cursor-pointer bg-slate-100 hover:bg-slate-200 px-2.5 py-1 rounded-lg transition-colors"
              >
                {copied ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                <span>{copied ? 'Copied!' : 'Copy Appeal'}</span>
              </button>
            </div>

            <div>
              <label className="text-[10px] font-black uppercase tracking-wider text-slate-400 block mb-1">
                Subject Line
              </label>
              <input
                type="text"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl font-mono text-xs font-bold text-slate-900 focus:outline-hidden"
              />
            </div>

            <div>
              <label className="text-[10px] font-black uppercase tracking-wider text-slate-400 block mb-1">
                Message Body
              </label>
              <textarea
                rows={9}
                value={messageBody}
                onChange={(e) => setMessageBody(e.target.value)}
                className="w-full p-3.5 bg-slate-50 border border-slate-200 rounded-xl font-mono text-xs text-slate-800 leading-relaxed focus:outline-hidden focus:ring-2 focus:ring-red-500/20 resize-y"
              />
            </div>
          </div>

        </div>

        {/* Modal Footer with 3 Sending Options */}
        <div className="p-4 sm:p-5 bg-slate-50 border-t border-slate-200 shrink-0 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-slate-500 text-[11px]">
            <Info className="w-4 h-4 text-blue-600 shrink-0" />
            <span>Sends formal review appeal to <strong className="text-slate-800">{recipientEmail}</strong></span>
          </div>

          <div className="flex flex-wrap items-center justify-end gap-2.5 w-full sm:w-auto">
            
            {/* Option A: Web Portal Fallback */}
            {activeProvider.delistUrl && (
              <a
                href={activeProvider.delistUrl}
                target="_blank"
                rel="noreferrer"
                onClick={() => {
                  saveSenderInfo();
                  handleCopyText();
                  saveDelistRecord('web_portal');
                }}
                className="px-3.5 py-2.5 bg-white hover:bg-slate-100 border border-slate-300 text-slate-700 font-bold rounded-xl text-xs transition-all flex items-center gap-1.5 cursor-pointer"
                title="Copies appeal text & opens official delist portal"
              >
                <span>Web Portal</span>
                <ExternalLink className="w-3.5 h-3.5 text-slate-500" />
              </a>
            )}

            {/* Option B: 1-Click Send via Email Client (Gmail/Outlook) */}
            <button
              type="button"
              onClick={handleOpenMailClient}
              className="px-3.5 py-2.5 bg-white hover:bg-slate-100 border border-slate-300 text-slate-800 font-bold rounded-xl text-xs transition-all flex items-center gap-1.5 cursor-pointer shadow-2xs"
              title="Opens your installed email client with all details filled in"
            >
              <Mail className="w-3.5 h-3.5 text-slate-700" />
              <span>Send via Email Client</span>
            </button>

            {/* Option C: Direct Server SMTP Dispatch */}
            <button
              type="button"
              disabled={isSubmitting}
              onClick={handleSendViaServerSMTP}
              className="px-5 py-2.5 bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white font-extrabold rounded-xl text-xs transition-all flex items-center gap-2 cursor-pointer shadow-xs"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Dispatching Email...</span>
                </>
              ) : (
                <>
                  <Send className="w-3.5 h-3.5" />
                  <span>Dispatch Delist Email (SMTP)</span>
                </>
              )}
            </button>

          </div>
        </div>

      </div>
    </div>
  );
}
