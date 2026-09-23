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
  X,
  Loader2,
  RefreshCw,
  Globe,
  ArrowRight,
  ShieldCheck,
  CheckCircle,
  HelpCircle,
  SlidersHorizontal,
  ChevronRight
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

// Standard removal emails & turnaround time for major DNSBLs
const PROVIDER_METADATA: Record<string, { email: string; avgTime: string; priority: 'high' | 'medium' | 'critical' }> = {
  spamhaus: { email: 'removal@spamhaus.org', avgTime: '1 - 4 hours', priority: 'critical' },
  barracuda: { email: 'intent@barracudacentral.org', avgTime: '12 - 24 hours', priority: 'critical' },
  spamcop: { email: 'deputy@admin.spamcop.net', avgTime: '24 - 48 hours', priority: 'high' },
  uceprotect1: { email: 'delist@uceprotect.net', avgTime: '7 days auto-expire', priority: 'high' },
  uceprotect2: { email: 'delist@uceprotect.net', avgTime: '7 days auto-expire', priority: 'medium' },
  uceprotect3: { email: 'delist@uceprotect.net', avgTime: '7 days auto-expire', priority: 'medium' },
  blocklist: { email: 'info@blocklist.de', avgTime: '2 - 6 hours', priority: 'high' },
  sorbs: { email: 'delist@sorbs.net', avgTime: 'Manual portal', priority: 'medium' },
  dronebl: { email: 'staff@dronebl.org', avgTime: '24 hours', priority: 'critical' },
  gbudb: { email: 'support@gbudb.com', avgTime: 'Dynamic decay', priority: 'medium' },
  spfbl: { email: 'abuse@spfbl.net', avgTime: '2 - 12 hours', priority: 'high' },
  lashback: { email: 'removal@lashback.com', avgTime: '12 hours', priority: 'medium' },
  psbl: { email: 'psbl@surriel.com', avgTime: 'Auto-delist 7 days', priority: 'medium' },
  wpbl: { email: 'admin@wpbl.info', avgTime: '12 - 24 hours', priority: 'medium' },
  ivmsip: { email: 'removal@invaluement.com', avgTime: '4 - 12 hours', priority: 'critical' },
  ivmuri: { email: 'removal@invaluement.com', avgTime: '4 - 12 hours', priority: 'high' },
  spamrats: { email: 'removal@spamrats.com', avgTime: 'Portal lookup', priority: 'medium' },
  abuseat_cbl: { email: 'cbl@abuseat.org', avgTime: 'Instant portal', priority: 'critical' },
  hostkarma: { email: 'support@junkemailfilter.com', avgTime: '1 - 3 days', priority: 'medium' },
  nixspam: { email: 'abuse@nixspam.net', avgTime: 'Dynamic decay', priority: 'medium' },
  nordspam: { email: 'abuse@nordspam.com', avgTime: '12 hours', priority: 'medium' },
  '0spam': { email: 'delist@0spam.org', avgTime: 'Instant portal', priority: 'medium' },
  backscatterer: { email: 'delist@backscatterer.org', avgTime: '4 weeks decay', priority: 'medium' }
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

  // Server SMTP config check
  const [serverSmtpConfigured, setServerSmtpConfigured] = useState<boolean>(false);

  useEffect(() => {
    fetch('/api/settings/smtp')
      .then(res => res.json())
      .then(data => {
        if (data && data.isConfigured) {
          setServerSmtpConfigured(true);
        }
      })
      .catch(() => {});
  }, []);

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
    if (PROVIDER_METADATA[activeProvider.id]?.email) return PROVIDER_METADATA[activeProvider.id].email;
    const cleanDomain = activeProvider.domain.replace(/^([a-z0-9-]+\.)*(dnsbl|bl|zen|rbl|truncate|sip|uri)\./i, '');
    return `abuse@${cleanDomain}`;
  }, [activeProvider]);

  const providerTurnaround = useMemo(() => {
    return PROVIDER_METADATA[activeProvider.id]?.avgTime || '24 - 48 hours';
  }, [activeProvider]);

  // Detected listings specifically for this IP
  const detectedListings = useMemo(() => {
    return listedProviders || [];
  }, [listedProviders]);

  // Live Quick Scan for typed IP address
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
          const foundListings: any[] = [];
          if (scanRes.listings) {
            Object.entries(scanRes.listings).forEach(([key, val]: any) => {
              if (val && val.listed) {
                const matched = ALL_DEFAULT_PROVIDERS.find(p => p.id === key);
                foundListings.push({
                  id: key,
                  name: val.name || matched?.name || key,
                  domain: val.domain || matched?.domain || `${key}.org`,
                  delistUrl: val.delistUrl || matched?.delistUrl || 'https://www.spamhaus.org/lookup/',
                  delistEmail: matched?.delistEmail || PROVIDER_METADATA[key]?.email,
                  reason: val.details
                });
              }
            });
          }

          if (foundListings.length > 0) {
            const merged = [...foundListings];
            ALL_DEFAULT_PROVIDERS.forEach(dp => {
              if (!merged.some(p => p.id === dp.id)) merged.push(dp);
            });
            setAvailableProviders(merged);
            setSelectedProviderId(foundListings[0].id);
            setLiveCheckStatus({ listedCount: foundListings.length, clean: false });
            triggerAlert('warning', `Detected ${foundListings.length} blacklist listing(s) for ${ip}. Provider auto-selected!`);
          } else {
            setLiveCheckStatus({ listedCount: 0, clean: true });
            triggerAlert('info', `No active DNSBL listings found for ${ip}. You can choose any provider for appeal.`);
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
  const [copiedSubject, setCopiedSubject] = useState<boolean>(false);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  // Generate Letter Body
  useEffect(() => {
    const selectedTemplate = REASON_TEMPLATES.find(t => t.id === reasonId) || REASON_TEMPLATES[0];
    const target = currentIP.trim() || '[TARGET_IP_ADDRESS]';
    const newSubject = `[Delisting Request] Blacklist Removal Appeal for IP ${target} - ${companyName}`;
    
    const actionsList = selectedTemplate.actionsTaken.map(a => `  * ${a}`).join('\n');
    const customSection = customNotes.trim() ? `\n\nAdditional Incident Notes:\n${customNotes.trim()}` : '';

    const body = `Dear ${activeProvider.name} Review & Security Team,

I am writing on behalf of ${companyName} to formally request the re-evaluation and removal of IP address ${target} from the ${activeProvider.name} (${activeProvider.domain}) database.

Target IP Details:
- IP Address: ${target}
- Reverse DNS (PTR): ${currentPtr || ptr || 'Configured & Verified'}
- Organization / ISP: ${currentOrg || org || isp || companyName}
- Blacklist Database: ${activeProvider.name} (${activeProvider.domain})

Root Cause & Investigation Summary:
${selectedTemplate.summary}

Remediation Measures Implemented:
${actionsList}${customSection}

We have verified that the incident is fully resolved and that no abusive, bulk, or unauthorized traffic will originate from this IP address. Our mail servers and network endpoints comply strictly with RFC 5321, RFC 7208, and industry best practices.

We kindly request that you review our submission and delist IP ${target} at your earliest convenience. If further diagnostic logs or verification are required, please contact me directly at ${senderEmail}.

Thank you for your assistance in maintaining internet security.

Sincerely,

${senderName}
Network Operations & Abuse Desk
${companyName}
Official Contact: ${senderEmail}
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
      triggerAlert('success', 'Appeal subject and letter copied to clipboard!');
      setTimeout(() => setCopied(false), 2500);
    } catch (err) {
      triggerAlert('error', 'Could not copy to clipboard.');
    }
  };

  const handleCopySubject = async () => {
    try {
      await navigator.clipboard.writeText(subject);
      setCopiedSubject(true);
      triggerAlert('success', 'Subject line copied!');
      setTimeout(() => setCopiedSubject(false), 2000);
    } catch (err) {}
  };

  // Save record to backend tracker
  const recordAppeal = async (method: 'smtp' | 'client_mailto' | 'web_portal' | 'gmail_web' | 'outlook_web' | 'clipboard') => {
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
        status: method === 'smtp' ? 'submitted' : 'pending',
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

  // 1-Click Launch via Gmail Webmail (100% reliable, zero SMTP issues!)
  const handleOpenGmailWeb = () => {
    const ipToSend = currentIP.trim();
    if (!ipToSend) {
      triggerAlert('error', 'Please enter a valid IP address.');
      return;
    }
    saveSenderInfo();
    const gmailUrl = `https://mail.google.com/mail/?view=cm&fs=1&to=${encodeURIComponent(recipientEmail)}&su=${encodeURIComponent(subject)}&body=${encodeURIComponent(messageBody)}`;
    window.open(gmailUrl, '_blank', 'noopener,noreferrer');
    recordAppeal('gmail_web');
    triggerAlert('success', `Opened in Gmail for ${recipientEmail}! Just click 'Send' in your Gmail tab.`);
  };

  // 1-Click Launch via Microsoft Outlook / Office 365 Web
  const handleOpenOutlookWeb = () => {
    const ipToSend = currentIP.trim();
    if (!ipToSend) {
      triggerAlert('error', 'Please enter a valid IP address.');
      return;
    }
    saveSenderInfo();
    const outlookUrl = `https://outlook.office.com/mail/deeplink/compose?to=${encodeURIComponent(recipientEmail)}&subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(messageBody)}`;
    window.open(outlookUrl, '_blank', 'noopener,noreferrer');
    recordAppeal('outlook_web');
    triggerAlert('success', `Opened in Outlook Web for ${recipientEmail}! Just click 'Send' in Outlook.`);
  };

  // 1-Click Send via Default Native Email Client (mailto:)
  const handleOpenNativeMail = () => {
    const ipToSend = currentIP.trim();
    if (!ipToSend) {
      triggerAlert('error', 'Please enter a valid IP address.');
      return;
    }
    saveSenderInfo();
    const mailtoUrl = `mailto:${encodeURIComponent(recipientEmail)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(messageBody)}`;
    window.location.href = mailtoUrl;
    recordAppeal('client_mailto');
    triggerAlert('info', `Opened default mail client for ${recipientEmail}. Request logged in tracker.`);
  };

  // Open Web Delist Portal & Auto-copy Letter
  const handleOpenWebPortal = () => {
    saveSenderInfo();
    handleCopyText();
    if (activeProvider.delistUrl) {
      window.open(activeProvider.delistUrl, '_blank', 'noopener,noreferrer');
    }
    recordAppeal('web_portal');
    triggerAlert('success', `Copied appeal text to clipboard & opened ${activeProvider.name} portal!`);
  };

  // Server SMTP Dispatch
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
        triggerAlert('success', `Appeal successfully dispatched via Server SMTP to ${recipientEmail}!`);
        if (onSuccess && data.request) {
          onSuccess(data.request);
        }
        onClose();
      } else if (data.code === 'SMTP_NOT_CONFIGURED') {
        triggerAlert('warning', 'Server SMTP is not configured yet. Opening 1-Click Gmail composer instead...');
        handleOpenGmailWeb();
      } else {
        throw new Error(data.error || 'Failed to dispatch delist email.');
      }
    } catch (err: any) {
      console.error('Delist submission error:', err);
      triggerAlert('error', err.message || 'SMTP dispatch failed. Try using 1-Click Gmail or Outlook!');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-slate-950/80 backdrop-blur-xs overflow-y-auto animate-fade-in" id="delist-request-modal">
      <div className="bg-white rounded-2xl max-w-4xl w-full border border-slate-200/90 shadow-2xl overflow-hidden my-4 flex flex-col max-h-[94vh]">
        
        {/* Luxury Enterprise Header */}
        <div className="bg-slate-950 text-white p-5 flex justify-between items-center border-b border-slate-800 shrink-0">
          <div className="flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-red-600/20 border border-red-500/30 flex items-center justify-center text-red-500 shrink-0">
              <Mail className="w-5 h-5" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-sm sm:text-base font-black tracking-tight text-white uppercase">
                  Blacklist Removal Appeal Engine
                </h3>
                {currentIP && (
                  <span className="bg-red-500/20 text-red-400 border border-red-500/30 text-[11px] font-mono px-2.5 py-0.5 rounded-md font-bold">
                    {currentIP}
                  </span>
                )}
                <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded">
                  Direct NOC Desk
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Official remediation appeals formatted for DNSBL maintainers, email gateways & threat desks
              </p>
            </div>
          </div>
          <button 
            onClick={onClose}
            className="text-slate-400 hover:text-white transition-colors cursor-pointer p-2 rounded-xl hover:bg-white/10"
            title="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Scrollable Body */}
        <div className="p-5 sm:p-6 overflow-y-auto space-y-6 text-slate-800 text-xs">
          
          {/* Quick Listing Pills for detected RBLs */}
          {detectedListings.length > 0 && (
            <div className="p-3 bg-red-50/70 border border-red-200/80 rounded-xl space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-black uppercase tracking-wider text-red-900 flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-red-600" />
                  <span>Detected Blacklist Listings on this IP ({detectedListings.length})</span>
                </span>
                <span className="text-[10px] text-red-700 font-semibold">Click to appeal each provider:</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {detectedListings.map(item => {
                  const isSelected = selectedProviderId === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => setSelectedProviderId(item.id)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
                        isSelected 
                          ? 'bg-red-600 text-white shadow-xs' 
                          : 'bg-white hover:bg-red-100/70 text-red-800 border border-red-200'
                      }`}
                    >
                      <span>{item.name}</span>
                      {isSelected ? <CheckCircle className="w-3 h-3 text-white" /> : <span className="text-red-500 font-mono text-[10px]">✕</span>}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Section 1: Target IP & Provider Details Card */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-slate-50/80 p-4.5 rounded-xl border border-slate-200/90">
            <div>
              <label className="text-[10px] font-black uppercase tracking-wider text-slate-500 block mb-1.5">
                Target IP Address To Delist <span className="text-red-500">*</span>
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={currentIP}
                  onChange={(e) => setCurrentIP(e.target.value.trim())}
                  placeholder="Enter IP address (e.g. 185.190.140.5)"
                  className="flex-1 px-3.5 py-2.5 bg-white border border-slate-300 rounded-xl text-xs font-mono font-bold text-slate-900 focus:outline-hidden focus:ring-2 focus:ring-red-500/20 focus:border-red-500"
                />
                <button
                  type="button"
                  onClick={handleQuickScan}
                  disabled={scanningIP || !currentIP.trim()}
                  className="px-3.5 py-2.5 bg-slate-900 hover:bg-black text-white text-xs font-bold rounded-xl flex items-center gap-1.5 shrink-0 transition-all cursor-pointer disabled:opacity-50"
                  title="Verify live blacklist listings for this IP"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${scanningIP ? 'animate-spin' : ''}`} />
                  <span>{scanningIP ? 'Checking...' : 'Check RBLs'}</span>
                </button>
              </div>
              <div className="flex items-center justify-between text-[11px] text-slate-500 mt-2">
                <span className="truncate max-w-xs font-mono text-[11px] text-slate-600">
                  rDNS: {currentPtr || ptr || 'No PTR Verified'}
                </span>
                {liveCheckStatus ? (
                  <span className={`text-[10px] font-black uppercase px-2 py-0.5 rounded-md ${
                    liveCheckStatus.listedCount > 0 ? 'bg-red-100 text-red-800' : 'bg-emerald-100 text-emerald-800'
                  }`}>
                    {liveCheckStatus.listedCount > 0 ? `${liveCheckStatus.listedCount} Listed` : 'Clean'}
                  </span>
                ) : (
                  <span className="text-[10px] text-slate-400">Target host ready</span>
                )}
              </div>
            </div>

            <div>
              <label className="text-[10px] font-black uppercase tracking-wider text-slate-500 block mb-1.5">
                Blacklist Authority Database ({availableProviders.length} Providers)
              </label>
              <select
                value={selectedProviderId}
                onChange={(e) => setSelectedProviderId(e.target.value)}
                className="w-full bg-white px-3.5 py-2.5 rounded-xl border border-slate-300 text-xs font-bold text-slate-900 focus:outline-hidden focus:ring-2 focus:ring-red-500/20 cursor-pointer"
              >
                {availableProviders.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.domain})
                  </option>
                ))}
              </select>
              <div className="flex items-center justify-between text-[11px] text-slate-600 mt-2">
                <span>
                  Official Desk: <strong className="text-slate-900 font-mono">{recipientEmail}</strong>
                </span>
                <span className="text-[10px] text-slate-500 font-medium">
                  SLA: <strong className="text-slate-700">{providerTurnaround}</strong>
                </span>
              </div>
            </div>
          </div>

          {/* Section 2: One-Click Send Hub (Highlighted Fast Actions) */}
          <div className="bg-gradient-to-br from-slate-900 to-zinc-950 text-white p-5 rounded-2xl border border-slate-800 shadow-md space-y-3.5">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 border-b border-slate-800 pb-3">
              <div>
                <span className="text-[10px] font-black uppercase tracking-widest text-red-400 block">
                  Fast-Track Delist Dispatch Hub
                </span>
                <h4 className="text-sm font-extrabold text-white flex items-center gap-1.5 mt-0.5">
                  <Sparkles className="w-4 h-4 text-amber-400" />
                  <span>Choose Your Preferred Sending Method</span>
                </h4>
              </div>
              <span className="text-[11px] text-slate-400">
                Recipient: <strong className="text-white font-mono">{recipientEmail}</strong>
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
              
              {/* Option 1: 1-Click Gmail Web (Zero SMTP configuration required) */}
              <button
                type="button"
                onClick={handleOpenGmailWeb}
                className="p-3.5 bg-white/10 hover:bg-white/15 border border-white/15 hover:border-red-500/50 rounded-xl text-left transition-all cursor-pointer group flex flex-col justify-between space-y-2 shadow-xs"
                title="Opens official Gmail composer with recipient, subject, and letter pre-filled"
              >
                <div className="flex items-center justify-between">
                  <div className="w-8 h-8 rounded-lg bg-red-600/30 border border-red-500/40 flex items-center justify-center text-red-400 group-hover:scale-105 transition-transform">
                    <Mail className="w-4 h-4" />
                  </div>
                  <span className="text-[9px] font-black uppercase tracking-wider bg-red-500/20 text-red-300 px-1.5 py-0.5 rounded">
                    Popular
                  </span>
                </div>
                <div>
                  <div className="font-extrabold text-xs text-white group-hover:text-red-400 transition-colors">
                    1-Click Gmail
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5 leading-snug">
                    Opens your Gmail tab with everything pre-filled. No setup needed!
                  </div>
                </div>
                <div className="text-[10px] font-bold text-red-400 flex items-center gap-1">
                  <span>Open &amp; Send</span>
                  <ExternalLink className="w-3 h-3" />
                </div>
              </button>

              {/* Option 2: 1-Click Outlook / Office 365 Web */}
              <button
                type="button"
                onClick={handleOpenOutlookWeb}
                className="p-3.5 bg-white/10 hover:bg-white/15 border border-white/15 hover:border-blue-500/50 rounded-xl text-left transition-all cursor-pointer group flex flex-col justify-between space-y-2 shadow-xs"
                title="Opens Outlook.com or Office 365 composer with letter pre-filled"
              >
                <div className="flex items-center justify-between">
                  <div className="w-8 h-8 rounded-lg bg-blue-600/30 border border-blue-500/40 flex items-center justify-center text-blue-400 group-hover:scale-105 transition-transform">
                    <Mail className="w-4 h-4" />
                  </div>
                  <span className="text-[9px] font-black uppercase tracking-wider bg-blue-500/20 text-blue-300 px-1.5 py-0.5 rounded">
                    Webmail
                  </span>
                </div>
                <div>
                  <div className="font-extrabold text-xs text-white group-hover:text-blue-400 transition-colors">
                    1-Click Outlook
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5 leading-snug">
                    Direct compose in Outlook/Office365 browser webmail.
                  </div>
                </div>
                <div className="text-[10px] font-bold text-blue-400 flex items-center gap-1">
                  <span>Open &amp; Send</span>
                  <ExternalLink className="w-3 h-3" />
                </div>
              </button>

              {/* Option 3: Web Delist Portal */}
              <button
                type="button"
                onClick={handleOpenWebPortal}
                className="p-3.5 bg-white/10 hover:bg-white/15 border border-white/15 hover:border-emerald-500/50 rounded-xl text-left transition-all cursor-pointer group flex flex-col justify-between space-y-2 shadow-xs"
                title="Copies appeal text and opens official web portal"
              >
                <div className="flex items-center justify-between">
                  <div className="w-8 h-8 rounded-lg bg-emerald-600/30 border border-emerald-500/40 flex items-center justify-center text-emerald-400 group-hover:scale-105 transition-transform">
                    <Globe className="w-4 h-4" />
                  </div>
                  <span className="text-[9px] font-black uppercase tracking-wider bg-emerald-500/20 text-emerald-300 px-1.5 py-0.5 rounded">
                    Official
                  </span>
                </div>
                <div>
                  <div className="font-extrabold text-xs text-white group-hover:text-emerald-400 transition-colors">
                    Web Removal Portal
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5 leading-snug">
                    Copies appeal to clipboard &amp; opens the portal form.
                  </div>
                </div>
                <div className="text-[10px] font-bold text-emerald-400 flex items-center gap-1">
                  <span>Open Portal</span>
                  <ExternalLink className="w-3 h-3" />
                </div>
              </button>

              {/* Option 4: Server SMTP Automated Dispatch */}
              <button
                type="button"
                disabled={isSubmitting}
                onClick={handleSendViaServerSMTP}
                className="p-3.5 bg-white/10 hover:bg-white/15 border border-white/15 hover:border-purple-500/50 rounded-xl text-left transition-all cursor-pointer group flex flex-col justify-between space-y-2 shadow-xs disabled:opacity-50"
                title="Direct background server delivery via Nodemailer"
              >
                <div className="flex items-center justify-between">
                  <div className="w-8 h-8 rounded-lg bg-purple-600/30 border border-purple-500/40 flex items-center justify-center text-purple-400 group-hover:scale-105 transition-transform">
                    {isSubmitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                  </div>
                  <span className={`text-[9px] font-black uppercase tracking-wider px-1.5 py-0.5 rounded ${
                    serverSmtpConfigured ? 'bg-purple-500/20 text-purple-300' : 'bg-amber-500/20 text-amber-300'
                  }`}>
                    {serverSmtpConfigured ? 'Ready' : 'Auto-Route'}
                  </span>
                </div>
                <div>
                  <div className="font-extrabold text-xs text-white group-hover:text-purple-400 transition-colors">
                    Server Direct SMTP
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5 leading-snug">
                    {serverSmtpConfigured 
                      ? 'Nodemailer background dispatch is active.' 
                      : 'Dispatches instantly or falls back cleanly.'}
                  </div>
                </div>
                <div className="text-[10px] font-bold text-purple-400 flex items-center gap-1">
                  <span>{isSubmitting ? 'Sending...' : 'Dispatch'}</span>
                  <ChevronRight className="w-3 h-3" />
                </div>
              </button>

            </div>
          </div>

          {/* Section 3: Sender Contact Info */}
          <div className="space-y-3">
            <h4 className="text-xs font-black uppercase tracking-wider text-slate-900 flex items-center gap-1.5">
              <Building2 className="w-3.5 h-3.5 text-red-600" />
              <span>NOC Sender &amp; Organization Details</span>
            </h4>
            
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="text-[10px] font-black uppercase tracking-wider text-slate-500 block mb-1">
                  Company / Carrier Name <span className="text-red-500">*</span>
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
                  Sender Contact Name <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={senderName}
                  onChange={(e) => setSenderName(e.target.value)}
                  placeholder="e.g. Md. Pranto"
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold text-slate-900 focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
                />
              </div>

              <div>
                <label className="text-[10px] font-black uppercase tracking-wider text-slate-500 block mb-1">
                  Official Abuse / Contact Email <span className="text-red-500">*</span>
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

          {/* Section 4: Remediation Reason Selector */}
          <div className="space-y-2.5">
            <h4 className="text-xs font-black uppercase tracking-wider text-slate-900 flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-amber-500" />
              <span>Remediation Classification &amp; Root Cause Explanation</span>
            </h4>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {REASON_TEMPLATES.map((tpl) => (
                <button
                  key={tpl.id}
                  type="button"
                  onClick={() => setReasonId(tpl.id)}
                  className={`p-3 rounded-xl text-left border transition-all cursor-pointer flex flex-col justify-between ${
                    reasonId === tpl.id 
                      ? 'bg-red-50/80 border-red-500 text-red-900 shadow-2xs' 
                      : 'bg-white border-slate-200 hover:bg-slate-50 text-slate-700'
                  }`}
                >
                  <span className="font-extrabold text-[11px] block">{tpl.label}</span>
                  <span className="text-[10px] text-slate-500 line-clamp-1 mt-1">{tpl.summary}</span>
                </button>
              ))}
            </div>

            <div className="pt-1">
              <input
                type="text"
                value={customNotes}
                onChange={(e) => setCustomNotes(e.target.value)}
                placeholder="Optional: Add incident ticket number, server hostname, or custom technical note..."
                className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-800 placeholder-slate-400 focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
              />
            </div>
          </div>

          {/* Section 5: Formatted Appeal Letter (Preview & Edit) */}
          <div className="space-y-2.5">
            <div className="flex justify-between items-center">
              <h4 className="text-xs font-black uppercase tracking-wider text-slate-900 flex items-center gap-1.5">
                <FileText className="w-3.5 h-3.5 text-blue-600" />
                <span>Formal NOC Appeal Letter (Editable)</span>
              </h4>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleCopySubject}
                  className="text-[11px] font-bold text-slate-600 hover:text-slate-900 flex items-center gap-1 cursor-pointer bg-slate-100 hover:bg-slate-200 px-2.5 py-1 rounded-lg transition-colors"
                >
                  {copiedSubject ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedSubject ? 'Subject Copied' : 'Copy Subject'}</span>
                </button>
                <button
                  type="button"
                  onClick={handleCopyText}
                  className="text-[11px] font-bold text-slate-800 hover:text-black flex items-center gap-1.5 cursor-pointer bg-slate-200 hover:bg-slate-300 px-3 py-1 rounded-lg transition-colors font-mono"
                >
                  {copied ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3 text-slate-700" />}
                  <span>{copied ? 'Copied Full Appeal!' : 'Copy Entire Appeal'}</span>
                </button>
              </div>
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
                rows={8}
                value={messageBody}
                onChange={(e) => setMessageBody(e.target.value)}
                className="w-full p-3.5 bg-slate-50 border border-slate-200 rounded-xl font-mono text-xs text-slate-800 leading-relaxed focus:outline-hidden focus:ring-2 focus:ring-red-500/20 resize-y"
              />
            </div>
          </div>

        </div>

        {/* Modal Bottom Action Bar */}
        <div className="p-4 sm:p-5 bg-slate-50 border-t border-slate-200 shrink-0 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-slate-500 text-[11px]">
            <Info className="w-4 h-4 text-blue-600 shrink-0" />
            <span>Sends formal appeal to <strong className="text-slate-900 font-mono">{recipientEmail}</strong></span>
          </div>

          <div className="flex flex-wrap items-center justify-end gap-2.5 w-full sm:w-auto">
            {/* Quick Mailto for local clients */}
            <button
              type="button"
              onClick={handleOpenNativeMail}
              className="px-3.5 py-2.5 bg-white hover:bg-slate-100 border border-slate-300 text-slate-700 font-bold rounded-xl text-xs transition-all flex items-center gap-1.5 cursor-pointer shadow-2xs"
              title="Open default system mail client"
            >
              <Mail className="w-3.5 h-3.5 text-slate-600" />
              <span>Mail App</span>
            </button>

            {/* 1-Click Gmail Action in footer as well */}
            <button
              type="button"
              onClick={handleOpenGmailWeb}
              className="px-4 py-2.5 bg-red-600 hover:bg-red-700 text-white font-black rounded-xl text-xs transition-all flex items-center gap-2 cursor-pointer shadow-sm"
              title="Open in Gmail (Recommended & Easiest)"
            >
              <Mail className="w-3.5 h-3.5" />
              <span>Send with Gmail (1-Click)</span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
