import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Search, Shield, ShieldAlert, ShieldCheck, Activity, Download, 
  RefreshCw, Sliders, Database, BookOpen, History, Plus, 
  AlertCircle, ArrowRight, MapPin, Info, X, CheckCircle, 
  Clock, Edit3, ExternalLink, FileSpreadsheet, Cpu, Globe, Building, Check, FileText,
  LogOut, Settings, Users, Bell, BellOff, Loader2, Sun, Moon
} from 'lucide-react';
import { IPScanResult, SubnetScanReport, BlacklistProvider, SavedReport, UserProfile } from './types';
import { downloadCSVReport, downloadJSONReport } from './utils';

// Firebase Imports
import { auth, db } from './firebase';
import { onAuthStateChanged, signOut } from 'firebase/auth';
import { doc, getDoc, collection, addDoc, getDocs, query, where, deleteDoc } from 'firebase/firestore';

// Custom Components
import { AuthPage } from './components/AuthPage';
import { IPMonitoring } from './components/IPMonitoring';
import { UserManagement } from './components/UserManagement';
import { SystemSettings } from './components/SystemSettings';
import { COMPANY_CREDENTIALS } from './company-credentials';

// Static Blacklist list for UI rendering & reference
const BLACKLIST_PROVIDERS: BlacklistProvider[] = [
  {
    id: 'spamhaus',
    name: 'Spamhaus ZEN',
    domain: 'zen.spamhaus.org',
    description: 'The Gold Standard. Combines SBL, SBL-CSS, XBL, and PBL. Identifies verified spam sources, exploits, dynamic ranges, and hijacked devices.',
    delistUrl: 'https://www.spamhaus.org/lookup/',
    category: 'Spam'
  },
  {
    id: 'barracuda',
    name: 'Barracuda BRBL',
    domain: 'b.barracudacentral.org',
    description: 'Barracuda Reputation Block List. Highly effective list containing active spam-sending mail servers.',
    delistUrl: 'https://www.barracudacentral.org/rbl/removal-request',
    category: 'Spam'
  },
  {
    id: 'spamcop',
    name: 'SpamCop',
    domain: 'bl.spamcop.net',
    description: 'SpamCop Blocklist. Dynamic list based on reporting from users, spam traps, and automated systems.',
    delistUrl: 'https://www.spamcop.net/bl.shtml',
    category: 'Spam'
  },
  {
    id: 'uceprotect1',
    name: 'UCEPROTECT Level 1',
    domain: 'dnsbl-1.uceprotect.net',
    description: 'UCEPROTECT Level 1. Identifies single IP addresses that sent spam or were detected as abusive within the last 7 days.',
    delistUrl: 'http://www.uceprotect.net/en/rblcheck.php',
    category: 'Spam'
  },
  {
    id: 'uceprotect2',
    name: 'UCEPROTECT Level 2',
    domain: 'dnsbl-2.uceprotect.net',
    description: 'UCEPROTECT Level 2. Identifies entire subnets that contain active spam or abusive activity.',
    delistUrl: 'http://www.uceprotect.net/en/rblcheck.php',
    category: 'Spam'
  },
  {
    id: 'uceprotect3',
    name: 'UCEPROTECT Level 3',
    domain: 'dnsbl-3.uceprotect.net',
    description: 'UCEPROTECT Level 3. Identifies entire service providers (ASNs) exhibiting persistent, systemic abuse.',
    delistUrl: 'http://www.uceprotect.net/en/rblcheck.php',
    category: 'Spam'
  },
  {
    id: 'blocklist',
    name: 'Blocklist.de',
    domain: 'bl.blocklist.de',
    description: 'Real-time security reporting service. Lists malicious IPs participating in SSH, Mail, FTP, and Web attacks.',
    delistUrl: 'https://www.blocklist.de/en/search.html',
    category: 'General'
  },
  {
    id: 'sorbs',
    name: 'SORBS Aggregate',
    domain: 'dnsbl.sorbs.net',
    description: 'SORBS aggregate database. Detects spam-sending servers, compromised servers, open proxies, and dynamic host addresses.',
    delistUrl: 'http://www.sorbs.net/lookup.shtml',
    category: 'Spam'
  },
  {
    id: 'sorbsduhl',
    name: 'SORBS DUHL',
    domain: 'duhl.dnsbl.sorbs.net',
    description: 'SORBS Dynamic User and Host List. Lists dynamic IP ranges that are not supposed to send emails directly.',
    delistUrl: 'http://www.sorbs.net/lookup.shtml',
    category: 'Spam'
  },
  {
    id: 'dronebl',
    name: 'DroneBL',
    domain: 'dnsbl.dronebl.org',
    description: 'Real-time lookup tracking open proxies, compromised IoT, IRC bots, rootkits, and active brute-forcers.',
    delistUrl: 'https://dronebl.org/lookup',
    category: 'General'
  },
  {
    id: 'gbudb',
    name: 'GBUdb Truncate',
    domain: 'truncate.gbudb.net',
    description: 'Highly accurate real-time IP reputation blacklist compiled dynamically by GBUdb nodes.',
    delistUrl: 'http://www.gbudb.com/',
    category: 'Spam'
  },
  {
    id: 'spfbl',
    name: 'SPFBL DNSBL',
    domain: 'dnsbl.spfbl.net',
    description: 'Collaborative peer-to-peer blacklist designed to filter spam, malicious senders, and dynamic ranges.',
    delistUrl: 'https://spfbl.net/en/dnsbl/',
    category: 'Spam'
  },
  {
    id: 'lashback',
    name: 'Lashback UBL',
    domain: 'ubl.lashback.com',
    description: 'Lashback Unsubscribe Blacklist. Specifically targets servers sending mail to harvested opt-out / unsubscribe lists.',
    delistUrl: 'https://www.lashback.com/blacklist/',
    category: 'Spam'
  },
  {
    id: 'psbl',
    name: 'Passive Spam Block List (PSBL)',
    domain: 'psbl.surriel.com',
    description: 'Easy-to-whitelist spam blocklist. Only lists IPs that send email to spam traps and have no SMTP feedback loop.',
    delistUrl: 'https://psbl.org/lookup',
    category: 'Spam'
  },
  {
    id: 'wpbl',
    name: 'Weighted Private Block List',
    domain: 'db.wpbl.info',
    description: 'WPBL focuses on resolving spam sources via automated algorithmic detection and responsive removal.',
    delistUrl: 'http://www.wpbl.info/',
    category: 'Spam'
  },
  {
    id: 'ivmsip',
    name: 'Invaluement ivmSIP',
    domain: 'sip.invaluement.com',
    description: 'ivmSIP by Invaluement. Highly accurate database focusing on high-emission spam IP addresses, including snowshoe spam.',
    delistUrl: 'https://www.invaluement.com/lookup/',
    category: 'Spam'
  },
  {
    id: 'spamratsdyna',
    name: 'SpamRats Dyna',
    domain: 'dyna.spamrats.com',
    description: 'Identifies dynamic IP ranges or residential connections running unauthenticated SMTP servers.',
    delistUrl: 'https://www.spamrats.com/',
    category: 'Spam'
  },
  {
    id: 'spamrats',
    name: 'SpamRats Spam',
    domain: 'spam.spamrats.com',
    description: 'SpamRats Spam database. Identifies IP addresses that have been detected sending spam, having invalid reverse DNS, or other suspicious mail-sending behaviors.',
    delistUrl: 'https://www.spamrats.com/',
    category: 'Spam'
  },
  {
    id: 'spamratsnoptr',
    name: 'SpamRats NoPtr',
    domain: 'noptr.spamrats.com',
    description: 'SpamRats NoPtr. Identifies IP addresses with invalid or missing reverse DNS (PTR) records.',
    delistUrl: 'https://www.spamrats.com/',
    category: 'Spam'
  },
  {
    id: 'mailspikebl',
    name: 'Mailspike Blacklist',
    domain: 'bl.mailspike.net',
    description: 'Reputable IP reputation blocklist that identifies active spam sources, email relays, and unauthenticated botnet nodes.',
    delistUrl: 'https://mailspike.org/an-ip-is-listed-on-mailspike/',
    category: 'Spam'
  },
  {
    id: 'mailspikez',
    name: 'Mailspike Zombie',
    domain: 'z.mailspike.net',
    description: 'Zombie blocklist detecting compromised workstation/consumer IPs sending email traffic as part of active botnets.',
    delistUrl: 'https://mailspike.org/an-ip-is-listed-on-mailspike/',
    category: 'Spam'
  },
  {
    id: 'hostkarma',
    name: 'Hostkarma Black',
    domain: 'hostkarma.junkemailfilter.com',
    description: 'Hostkarma reputation RBL. Accurately categorizes mail senders as blacklist (spam), whitelist, yellowlist (suspicious), or NoPTR.',
    delistUrl: 'http://www.junkemailfilter.com/spam/lookup.php',
    category: 'General'
  },
  {
    id: 's5hnet',
    name: 's5h.net',
    domain: 'all.s5h.net',
    description: 'Aggregates multiple security feeds to identify dynamic residential lines, malware hosts, and spam-originating mail servers.',
    delistUrl: 'http://s5h.net/dnsbl/',
    category: 'Spam'
  },
  {
    id: 'abusech',
    name: 'Abuse.ch SSLIPBL',
    domain: 'sslipbl.abuse.ch',
    description: 'Tracks IP addresses associated with malicious SSL certificates, botnet command and control (C2) servers, and active cyber threats.',
    delistUrl: 'https://ssl.abuse.ch/sslipbl/',
    category: 'Malware'
  },
  {
    id: 'cbl',
    name: 'CBL (Composite Blocking List)',
    domain: 'cbl.abuseat.org',
    description: 'Specializes in detecting botnets, open proxies, stealth spambots, and infected machines emitting malicious traffic.',
    delistUrl: 'https://www.abuseat.org/lookup.xhtml',
    category: 'Spam'
  },
  {
    id: 'spameatingmonkeybackscatter',
    name: 'SpamEatingMonkey Backscatter',
    domain: 'backscatter.spameatingmonkey.net',
    description: 'Detects mail servers sending misdirected bounce messages or backscatter mail spam.',
    delistUrl: 'https://spameatingmonkey.com/lookup',
    category: 'Spam'
  },
  {
    id: 'rbliprangenet',
    name: 'IPRange.net RBL',
    domain: 'rbl.iprange.net',
    description: 'Monitors ranges of hosting, cloud, and ISP networks that tolerate or facilitate systemic malicious activity or outbound bulk spam.',
    delistUrl: 'https://iprange.net/rbl/',
    category: 'General'
  },
  {
    id: 'madavidnsbl',
    name: 'MADAVI DNSBL',
    domain: 'dnsbl.madavi.de',
    description: 'Tracks mail-sending systems that are not configured with proper reverse DNS credentials or exhibit dynamic residential setup characteristics.',
    delistUrl: 'https://dnsbl.madavi.de/',
    category: 'Spam'
  }
];

const BLACKLIST_GUIDES: Record<string, { name: string; url: string; steps: string[]; description: string }> = {
  spamhaus: {
    name: 'Spamhaus ZEN',
    url: 'https://www.spamhaus.org/lookup/',
    description: 'The premier global IP reputation authority. If listed here, SMTP mail delivery will fail at 90%+ of mail servers worldwide.',
    steps: [
      'Navigate to the Spamhaus IP Address Lookup Tool.',
      'Check if the listing is an SBL (spam source), XBL (exploit/malware), or PBL (policy dynamic IP).',
      'If XBL, scan your server immediately for active outbound spam scripts, botnet infections, or open relays.',
      'If PBL, verify you are not attempting to send mail directly from a consumer/dynamic broadband range (use a SMTP Smarthost/Relay instead).',
      'Ensure your reverse DNS (rDNS) PTR record matches your mail domain.',
      'Submit the removal form once the underlying threat has been resolved.'
    ]
  },
  barracuda: {
    name: 'Barracuda BRBL',
    url: 'https://www.barracudacentral.org/rbl/removal-request',
    description: 'Managed by Barracuda Networks. Mostly affects delivery to organizations utilizing Barracuda ESG security appliances.',
    steps: [
      'Visit the Barracuda Reputation System lookup portal.',
      'Identify whether the block is due to high volume, bad reputation, or suspicious connection bursts.',
      'Ensure your server has a valid SPF and DKIM record set up.',
      'Confirm there are no backscatter (NDR) loops sending messages to invalid addresses.',
      'Apply for delisting via their online removal request form.'
    ]
  },
  spamcop: {
    name: 'SpamCop',
    url: 'https://www.spamcop.net/bl.shtml',
    description: 'An aggressive, dynamic reporting-based blocklist. Listings are highly time-sensitive, usually expiring automatically in 24-48 hours.',
    steps: [
      'Access the SpamCop IP lookup form to see the specific spam report frequency and timeline.',
      'Investigate outbound mail headers at the reported time to identify the compromised inbox/user.',
      'Implement strict outbound rate limits on your mail system.',
      'Wait for the listing to self-expire once spam reports cease, or request early mitigation if available.'
    ]
  },
  sorbs: {
    name: 'SORBS Aggregate',
    url: 'http://www.sorbs.net/lookup.shtml',
    description: 'Provides lists categorized by vulnerability type (HTTP proxy, SMTP relay, compromised dial-up, etc.).',
    steps: [
      'Log into the SORBS Support System (requires a free account).',
      'Query your listed IP address to find the exact database sub-list (e.g., DUHL, Spam, Proxy).',
      'Fix any open proxy ports (8080, 1080, 3128) or open SMTP relays on your server.',
      'Submit a Support Ticket / Delisting Request through the SORBS interface.'
    ]
  },
  lashback: {
    name: 'Lashback UBL',
    url: 'https://www.lashback.com/blacklist/',
    description: 'Focuses on protecting harvested email unsubscribe and opt-out addresses from list fatigue and abuse.',
    steps: [
      'Search the Lashback lookup tool with your public IP.',
      'Check system logs for marketing emails targeting harvested lists without proper double opt-in.',
      'Remove unconfirmed addresses and clean email marketing lists.',
      'Request free delisting on the Lashback portal.'
    ]
  },
  ivmsip: {
    name: 'Invaluement ivmSIP',
    url: 'https://www.invaluement.com/lookup/',
    description: 'A highly respected anti-spam database that tracks high-emission spam IP addresses, particularly focus-targeting snowshoe spam operations.',
    steps: [
      'Visit the Invaluement IP lookup utility page.',
      'Provide your IP address to check if it is actively listed on ivmSIP.',
      'Verify that your server is not hosting any snowshoe spam setups or unauthenticated bulk mail-sending services.',
      'Ensure proper reverse DNS PTR records, SPF, and DKIM parameters are configured on your outbound mail domains.',
      'Submit a removal request on Invaluement’s website if your system is verified clean.'
    ]
  },
  spamrats: {
    name: 'SpamRats Spam',
    url: 'https://www.spamrats.com/',
    description: 'SpamRats detects mail-sending IP addresses that violate basic setup standards, emit spam, or have bad reverse DNS settings.',
    steps: [
      'Go to the SpamRats lookup tool to check your listing details.',
      'Check if your IP address is flagged under RATS-Spam (active spam emitting), RATS-Dyna (dynamic IP range), or RATS-NoPTR (missing or invalid reverse DNS).',
      'Set up a valid, fully qualified domain name (FQDN) as your reverse DNS (PTR) record.',
      'Audit your server to ensure it is not acting as an open SMTP relay or open proxy.',
      'Submit a delisting request via the SpamRats removal mechanism once configuration errors or infections are resolved.'
    ]
  },
  abusech: {
    name: 'Abuse.ch SSLIPBL',
    url: 'https://ssl.abuse.ch/sslipbl/',
    description: 'Maintained by Abuse.ch, tracking active malware and botnet command & control servers. A listing here is critical.',
    steps: [
      'Search the Abuse.ch SSLIPBL lookup tool to view specific malicious SSL certificate or C2 flags.',
      'Check if your system was infected with malware or had a compromised service mimicking bad SSL profiles.',
      'Perform a thorough rootkit and virus scan on your servers.',
      'Request delisting once the malicious traffic has been fully stopped.'
    ]
  },
  cbl: {
    name: 'CBL (Composite Blocking List)',
    url: 'https://www.abuseat.org/lookup.xhtml',
    description: 'Monitors machines emitting spam, brute force attacks, or acting as open relays or botnet nodes.',
    steps: [
      'Access the CBL lookup tool and read the detailed listing diagnostics provided for your IP.',
      'Ensure the server is not infected with stealth trojans or participating in DDoS attacks.',
      'Close any unauthenticated open mail relay ports (typically port 25).',
      'Follow the on-screen self-removal procedure after sealing all leaks.'
    ]
  },
  spameatingmonkeybackscatter: {
    name: 'SpamEatingMonkey Backscatter',
    url: 'https://spameatingmonkey.com/lookup',
    description: 'Focuses on misdirected outbound bounce messages, also known as backscatter.',
    steps: [
      'Visit SpamEatingMonkey lookup page to check active listing status.',
      'Disable Out-of-Office auto-responders for unknown addresses to prevent auto-reply loops.',
      'Configure SPF, DKIM, and DMARC with hard-reject rules to prevent spoofing bouncebacks.',
      'Request delisting or wait for automatic expiration.'
    ]
  },
  rbliprangenet: {
    name: 'IPRange.net RBL',
    url: 'https://iprange.net/rbl/',
    description: 'Monitors host networks and dynamic ISP allocations hosting systemic spam or botnet activity.',
    steps: [
      'Search your IP on the IPRange.net reputation console.',
      'Confirm with your hosting/network provider that your range is not flagged for sub-tenant abuse.',
      'Submit the removal request form outlining your anti-abuse configurations.'
    ]
  },
  madavidnsbl: {
    name: 'MADAVI DNSBL',
    url: 'https://dnsbl.madavi.de/',
    description: 'Tracks misconfigured, non-reverse DNS or residential setup IPs sending mail.',
    steps: [
      'Visit the MADAVI reputation checker website.',
      'Configure fully matching Forward and Reverse DNS (rDNS/PTR record) for your mail server.',
      'Submit a direct request form to clear your IP from their database.'
    ]
  }
};

export default function App() {
  // Authentication & Profile States
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
  const [authLoading, setAuthLoading] = useState(true);

  // Input & scan states
  const [target, setTarget] = useState('185.190.140.0/28'); // Preset to a high-quality example IP subnet range
  const [simulate, setSimulate] = useState(false); // Default to live RBL scan
  const [loading, setLoading] = useState(false);
  const [scanningProgress, setScanningProgress] = useState(0);
  const [currentScanningIP, setCurrentScanningIP] = useState('');
  const [scanLogs, setScanLogs] = useState<string[]>([]);
  const [alert, setAlert] = useState<{ type: 'success' | 'error' | 'info' | 'warning'; message: string } | null>(null);

  // Data & Results states
  const [report, setReport] = useState<SubnetScanReport | null>(null);
  const [selectedIP, setSelectedIP] = useState<IPScanResult | null>(null);
  const [providers, setProviders] = useState<BlacklistProvider[]>([]);
  const [historyList, setHistoryList] = useState<SavedReport[]>([]);
  const [archiveConfirmDeleteId, setArchiveConfirmDeleteId] = useState<string | null>(null);

  // Navigation & Filtering
  const [activeTab, setActiveTab] = useState<'dashboard' | 'monitoring' | 'guides' | 'providers' | 'history' | 'users' | 'settings'>('dashboard');
  const [searchQuery, setSearchQuery] = useState('');
  const [filterStatus, setFilterStatus] = useState<'all' | 'clean' | 'listed'>('all');
  const [filterAction, setFilterAction] = useState<string>('all');

  // Inline Note Editor States
  const [noteText, setNoteText] = useState('');
  const [actionStatusVal, setActionStatusVal] = useState<'unresolved' | 'pending' | 'resolved' | 'monitoring' | 'ignored'>('unresolved');
  const [inspectorTab, setInspectorTab] = useState<'listed' | 'all'>('listed');

  // Helper to trigger alert banners
  const triggerAlert = (type: 'success' | 'error' | 'info' | 'warning', message: string) => {
    setAlert({ type, message });
    setTimeout(() => setAlert(null), 4500);
  };

  // Theme State (Light & Night/Dark Mode)
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    const saved = localStorage.getItem('wolast_shield_theme');
    return (saved as 'light' | 'dark') || 'light';
  });

  // Sync theme changes to localStorage and DOM body/documentElement
  useEffect(() => {
    localStorage.setItem('wolast_shield_theme', theme);
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
      document.body.classList.add('dark-active');
    } else {
      document.documentElement.classList.remove('dark');
      document.body.classList.remove('dark-active');
    }
  }, [theme]);

  // Auth State Listener using Manual Credentials & localStorage
  useEffect(() => {
    const loadSavedUser = async () => {
      try {
        const savedUserStr = localStorage.getItem('wolast_shield_user');
        if (savedUserStr) {
          const parsed = JSON.parse(savedUserStr) as UserProfile;
          
          // Verify with latest company credentials in code
          const matchingCred = COMPANY_CREDENTIALS.find(
            (c) => c.email.toLowerCase() === parsed.email.toLowerCase()
          );

          if (matchingCred) {
            if (matchingCred.status === 'suspended') {
              localStorage.removeItem('wolast_shield_user');
              setUserProfile(null);
              triggerAlert('error', 'Your account has been suspended. Please contact the administrator.');
            } else {
              // Keep state in sync with any direct updates made in the code config
              const updatedProfile: UserProfile = {
                uid: matchingCred.uid,
                email: matchingCred.email,
                displayName: matchingCred.displayName,
                role: matchingCred.role,
                createdAt: matchingCred.createdAt,
                status: matchingCred.status,
                passwordHash: matchingCred.passwordHash
              };
              setUserProfile(updatedProfile);
            }
          } else {
            // Check local storage users first
            let localFound: UserProfile | null = null;
            try {
              const localUsersStr = localStorage.getItem("wolast_local_users");
              if (localUsersStr) {
                const localUsers: UserProfile[] = JSON.parse(localUsersStr);
                localFound = localUsers.find((u) => u.email.toLowerCase() === parsed.email.toLowerCase() || u.uid === parsed.uid) || null;
              }
            } catch (e) {}

            if (localFound) {
              if (localFound.status === 'suspended') {
                localStorage.removeItem('wolast_shield_user');
                setUserProfile(null);
                triggerAlert('error', 'Your account has been suspended. Please contact the administrator.');
              } else {
                setUserProfile(localFound);
              }
            } else {
              // Verify with Firestore database for dynamically registered accounts with a 2s timeout
              try {
                const userDocSnap = await Promise.race([
                  getDoc(doc(db, "users", parsed.uid)),
                  new Promise<never>((_, reject) => setTimeout(() => reject(new Error("Timeout")), 2000))
                ]);
                if (userDocSnap.exists()) {
                  const userDoc = userDocSnap.data() as UserProfile;
                  if (userDoc.status === 'suspended') {
                    localStorage.removeItem('wolast_shield_user');
                    setUserProfile(null);
                    triggerAlert('error', 'Your account has been suspended. Please contact the administrator.');
                  } else {
                    setUserProfile(userDoc);
                  }
                } else {
                  // Fallback: keep parsed user if offline/local session active
                  setUserProfile(parsed);
                }
              } catch (fErr) {
                console.warn("Firestore user lookup skipped or timed out, keeping saved session:", fErr);
                setUserProfile(parsed);
              }
            }
          }
        } else {
          setUserProfile(null);
        }
      } catch (err) {
        console.error("Error loading cached auth profile:", err);
        setUserProfile(null);
      } finally {
        setAuthLoading(false);
      }
    };

    loadSavedUser();
  }, []);

  // Load history list and providers when user logs in
  useEffect(() => {
    if (userProfile) {
      loadSavedHistory();
      fetchProviders();
    }
  }, [userProfile]);

  // Fetch Providers list from API
  const fetchProviders = async () => {
    try {
      const res = await fetch('/api/providers');
      if (res.ok) {
        const data = await res.json();
        setProviders(data.providers);
      }
    } catch (err) {
      // Fallback to static RBLs
      setProviders(BLACKLIST_PROVIDERS);
    }
  };

  // Load historical listings from Firestore
  // Load historical listings from server API and local storage
  const loadSavedHistory = async () => {
    if (!userProfile) return;
    try {
      const scanMap = new Map<string, any>();

      // 1. Fetch from server API first
      try {
        const res = await fetch('/api/scans');
        if (res.ok) {
          const data = await res.json();
          if (data && Array.isArray(data.scans)) {
            data.scans.forEach((s: any) => {
              if (s && s.id && (userProfile.role === 'admin' || s.createdBy === userProfile.uid)) {
                scanMap.set(s.id, s);
              }
            });
          }
        }
      } catch (apiErr) {
        console.warn('Server scans API fetch skipped:', apiErr);
      }

      // 2. Fetch from local storage backup
      try {
        const localData = localStorage.getItem('wolast_scans_history');
        if (localData) {
          const parsed = JSON.parse(localData);
          if (Array.isArray(parsed)) {
            parsed.forEach((s: any) => {
              if (s && s.id && !scanMap.has(s.id) && (userProfile.role === 'admin' || s.createdBy === userProfile.uid)) {
                scanMap.set(s.id, s);
              }
            });
          }
        }
      } catch (e) {}

      // 3. Convert to list and sort descending by timestamp
      const rawScans = Array.from(scanMap.values());
      const list: SavedReport[] = rawScans.map((data: any) => ({
        id: data.id,
        name: `Scan of ${data.target}`,
        target: data.target,
        totalIPs: data.totalIPs,
        cleanCount: data.cleanCount,
        listedCount: data.listedCount,
        timestamp: data.timestamp
      }));

      list.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
      setHistoryList(list);
    } catch (err) {
      console.warn('Error loading scans:', err);
    }
  };

  // Save scan to history archive
  const saveScanToHistory = async (newReport: SubnetScanReport) => {
    if (!userProfile) return;
    try {
      const scanWithCreator = {
        ...newReport,
        createdBy: userProfile.uid,
        creatorEmail: userProfile.email
      };
      
      // 1. Save to local storage first for immediate availability
      try {
        const localData = localStorage.getItem('wolast_scans_history');
        const parsed = localData ? JSON.parse(localData) : [];
        const filtered = parsed.filter((s: any) => s.id !== scanWithCreator.id);
        filtered.unshift(scanWithCreator);
        localStorage.setItem('wolast_scans_history', JSON.stringify(filtered));
      } catch (e) {}

      // 2. Send to Express server API
      try {
        await fetch('/api/scans', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(scanWithCreator)
        });
      } catch (apiErr) {
        console.warn('Failed to save scan to server API:', apiErr);
      }

      // Refresh history list
      loadSavedHistory();
    } catch (err) {
      console.warn('Error saving scan history:', err);
    }
  };

  // Load a single detailed report from history
  const loadReportDetails = async (id: string) => {
    try {
      // 1. Check local storage
      try {
        const localData = localStorage.getItem('wolast_scans_history');
        if (localData) {
          const parsed = JSON.parse(localData);
          const found = parsed.find((s: any) => s.id === id);
          if (found) {
            setReport(found as SubnetScanReport);
            setSelectedIP(null);
            setActiveTab('dashboard');
            triggerAlert('success', `Loaded historical scan report for ${found.target}`);
            return;
          }
        }
      } catch (e) {}

      // 2. Check server API
      const res = await fetch('/api/scans');
      if (res.ok) {
        const data = await res.json();
        const found = data.scans?.find((s: any) => s.id === id);
        if (found) {
          setReport(found as SubnetScanReport);
          setSelectedIP(null);
          setActiveTab('dashboard');
          triggerAlert('success', `Loaded historical scan report for ${found.target}`);
          return;
        }
      }

      triggerAlert('error', 'Detailed report file not found in database.');
    } catch (err) {
      triggerAlert('error', 'Could not retrieve historical scan report.');
    }
  };

  // Delete a detailed report from history
  const deleteHistoryReport = async (id: string) => {
    try {
      setHistoryList(prev => prev.filter(h => h.id !== id));
      triggerAlert('info', 'Report deleted successfully.');
      if (report && report.id === id) {
        setReport(null);
      }
      setArchiveConfirmDeleteId(null);

      // Update local storage
      try {
        const localData = localStorage.getItem('wolast_scans_history');
        if (localData) {
          const parsed = JSON.parse(localData);
          const filtered = parsed.filter((s: any) => s.id !== id);
          localStorage.setItem('wolast_scans_history', JSON.stringify(filtered));
        }
      } catch (e) {}

      // Call server API delete
      try {
        await fetch(`/api/scans/${id}`, { method: 'DELETE' });
      } catch (apiErr) {
        console.warn('Error deleting scan via server API:', apiErr);
      }
    } catch (err) {
      triggerAlert('error', 'Failed to delete report.');
    }
  };

  // Handle Logout
  const handleLogout = async () => {
    try {
      localStorage.removeItem('wolast_shield_user');
      setUserProfile(null);
      setReport(null);
      setSelectedIP(null);
      triggerAlert('success', 'Logged out safely.');
    } catch (err) {
      triggerAlert('error', 'Logout failed.');
    }
  };

  // Perform backend scan
  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;

    setLoading(true);
    setScanningProgress(5);
    setScanLogs(['Initializing scanner module...', 'Analyzing target format...']);
    setSelectedIP(null);

    // Dynamic scanner visual progress tickers
    const logStates = [
      'Validating subnet mask configurations...',
      'Mapping individual IP ranges...',
      'Starting GeoIP metadata extraction...',
      'Initializing DNS reverse-resolution pointers...',
      'Querying Spamhaus ZEN cluster database...',
      'Broadcasting payload to SORBS lists...',
      'Querying Barracuda Central reputation blocklist...',
      'Parsing SenderScore metrics database...',
      'Analyzing AbuseIPDB telemetry maps...',
      'Aggregating block responses...'
    ];

    let logIdx = 0;
    const progressInterval = setInterval(() => {
      setScanningProgress(prev => {
        if (prev >= 90) {
          clearInterval(progressInterval);
          return 90;
        }
        
        // Add realistic logs dynamically
        if (Math.random() > 0.4 && logIdx < logStates.length) {
          setScanLogs(logs => [...logs, logStates[logIdx]]);
          logIdx++;
        }
        
        return prev + Math.floor(Math.random() * 8) + 3;
      });
    }, 450);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, simulate })
      });

      clearInterval(progressInterval);

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to complete subnet scan');
      }

      const scanResult = await response.json() as SubnetScanReport;
      
      setScanningProgress(100);
      setScanLogs(logs => [...logs, 'Analysis successfully completed! Syncing report.']);
      
      setTimeout(() => {
        setReport(scanResult);
        saveScanToHistory(scanResult);
        setLoading(false);
        triggerAlert('success', `Completed scanning ${scanResult.totalIPs} IPs. Found ${scanResult.listedCount} listed.`);
      }, 500);

    } catch (err: any) {
      clearInterval(progressInterval);
      setLoading(false);
      triggerAlert('error', err.message || 'An unexpected error occurred during scan.');
    }
  };

  // Save notes and action status for a selected IP
  const handleSaveIPNotes = () => {
    if (!report || !selectedIP) return;

    // Update IP in report structure
    const updatedResults = report.results.map(r => {
      if (r.ip === selectedIP.ip) {
        return {
          ...r,
          notes: noteText,
          actionStatus: actionStatusVal
        };
      }
      return r;
    });

    // Recalculate metrics
    const updatedReport: SubnetScanReport = {
      ...report,
      results: updatedResults
    };

    setReport(updatedReport);
    setSelectedIP({
      ...selectedIP,
      notes: noteText,
      actionStatus: actionStatusVal
    });

    triggerAlert('success', `Successfully saved action report for ${selectedIP.ip}`);
  };

  // Select an IP to inspect
  const handleSelectIP = (ipResult: IPScanResult) => {
    setSelectedIP(ipResult);
    setNoteText(ipResult.notes || '');
    setActionStatusVal(ipResult.actionStatus || 'unresolved');
  };

  // Filters application
  const filteredResults = report ? report.results.filter(r => {
    const matchesSearch = r.ip.includes(searchQuery) || 
      (r.location?.isp && r.location.isp.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (r.location?.country && r.location.country.toLowerCase().includes(searchQuery.toLowerCase()));
    
    const matchesStatus = filterStatus === 'all' || 
      (filterStatus === 'clean' && r.status === 'clean') ||
      (filterStatus === 'listed' && r.status === 'listed');

    const matchesAction = filterAction === 'all' || r.actionStatus === filterAction;

    return matchesSearch && matchesStatus && matchesAction;
  }) : [];

  // Calculate stats based on active listings
  const totalListingsCount = report?.results.reduce((acc, curr) => acc + curr.listedCount, 0) || 0;
  
  // Calculate specific provider listing frequencies for charts
  const providerStats: Record<string, number> = {};
  if (report) {
    report.results.forEach(r => {
      Object.entries(r.listings).forEach(([providerId, rawData]) => {
        const data = rawData as { listed: boolean };
        if (data.listed) {
          providerStats[providerId] = (providerStats[providerId] || 0) + 1;
        }
      });
    });
  }

  // Calculate Health Score
  const healthScore = report 
    ? Math.round((report.cleanCount / report.totalIPs) * 100) 
    : 100;

  // Render Authentication state
  if (authLoading) {
    return (
      <div className={`min-h-screen ${theme === 'dark' ? 'dark bg-slate-950 text-slate-100' : 'bg-slate-50 text-slate-900'} flex items-center justify-center`}>
        <div className="text-center space-y-4">
          <Loader2 className="w-10 h-10 animate-spin text-blue-600 mx-auto" />
          <p className={`text-xs font-extrabold ${theme === 'dark' ? 'text-slate-500' : 'text-slate-400'} uppercase tracking-widest`}>
            Establishing Secure Handshake...
          </p>
        </div>
      </div>
    );
  }

  if (!userProfile) {
    return <AuthPage onAuthSuccess={(profile) => setUserProfile(profile)} />;
  }

  const isAdmin = userProfile.role === 'admin';

  return (
    <div className={`min-h-screen ${theme === 'dark' ? 'dark bg-slate-950 text-slate-100' : 'bg-slate-50 text-slate-900'} flex flex-col font-sans animate-fade-in`} id="app-root">
      
      {/* Dynamic Toast Alerts */}
      <AnimatePresence>
        {alert && (
          <motion.div 
            initial={{ opacity: 0, y: -50, scale: 0.9 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -20, scale: 0.95 }}
            id="toast-alert"
            className={`fixed top-4 right-4 z-50 flex items-center gap-3 px-4 py-3 rounded-xl shadow-xl border text-sm font-semibold ${
              alert.type === 'success' ? 'bg-emerald-50 text-emerald-800 border-emerald-200' :
              alert.type === 'error' ? 'bg-rose-50 text-rose-800 border-rose-200' :
              alert.type === 'warning' ? 'bg-amber-50 text-amber-800 border-amber-200' :
              'bg-blue-50 text-blue-800 border-blue-200'
            }`}
          >
            {alert.type === 'success' && <ShieldCheck className="w-5 h-5 text-emerald-600 animate-bounce" />}
            {alert.type === 'error' && <ShieldAlert className="w-5 h-5 text-rose-600" />}
            {alert.type === 'warning' && <AlertCircle className="w-5 h-5 text-amber-600" />}
            {alert.type === 'info' && <Info className="w-5 h-5 text-blue-600" />}
            <span>{alert.message}</span>
            <button onClick={() => setAlert(null)} className="ml-2 hover:opacity-75 cursor-pointer">
              <X className="w-4 h-4" />
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Enterprise Layout Navigation Header */}
      <header className="bg-black/95 text-white px-6 sm:px-8 py-3.5 flex flex-col xl:flex-row justify-between items-center shrink-0 shadow-[0_10px_30px_rgba(0,0,0,0.5)] sticky top-0 z-45 gap-4 border-b border-zinc-900" id="main-header">
        <div className="flex flex-col sm:flex-row items-center justify-between xl:justify-start gap-5 w-full xl:w-auto">
          <div className="flex items-center gap-3.5 w-full sm:w-auto">
            <div className="w-9 h-9 bg-gradient-to-tr from-red-600 to-black rounded-lg flex items-center justify-center text-white shrink-0 shadow-[0_0_15px_rgba(220,38,38,0.4)] border border-red-500/30">
              <Shield className="w-5 h-5 text-red-500" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="text-[8px] font-black uppercase tracking-[0.25em] text-red-500">
                  Wolast Technologies
                </span>
              </div>
              <h1 className="text-base font-black tracking-tight uppercase flex items-center gap-1 mt-0.5">
                WolastShield<span className="text-red-600 font-light">Pro</span>
              </h1>
            </div>
          </div>
 
          {/* User profile details container */}
          <div className="flex items-center gap-2.5 bg-zinc-900/85 px-3 py-1.5 rounded-xl border border-zinc-800 w-full sm:w-auto shadow-sm">
            <div className="w-6.5 h-6.5 rounded-lg bg-gradient-to-tr from-red-600 to-zinc-900 flex items-center justify-center font-extrabold text-xs text-white">
              {userProfile.displayName[0].toUpperCase()}
            </div>
            <div className="text-left shrink-0">
              <div className="text-[10px] font-black text-zinc-100 max-w-[130px] truncate">{userProfile.displayName}</div>
              <div className="flex items-center gap-1">
                <span className="text-[8px] text-zinc-500 font-bold uppercase tracking-wide truncate max-w-[110px]">{userProfile.email}</span>
                {isAdmin ? (
                  <span className="bg-red-500/10 text-red-400 border border-red-500/20 text-[7px] font-black uppercase px-1 rounded">Admin</span>
                ) : (
                  <span className="bg-zinc-800 text-zinc-400 border border-zinc-700 text-[7px] font-black uppercase px-1 rounded">User</span>
                )}
              </div>
            </div>
          </div>
        </div>
        
        <div className="flex flex-col sm:flex-row items-center gap-6 w-full xl:w-auto justify-between xl:justify-end">
          {/* Navigation Tabs (Dynamic based on Role) */}
          <nav className="flex flex-wrap items-center gap-4 sm:gap-6 text-xs font-bold text-zinc-400 uppercase tracking-wider w-full sm:w-auto" id="nav-tabs">
            <button 
              onClick={() => setActiveTab('dashboard')}
              className={`pb-1 transition-all cursor-pointer border-b-2 ${
                activeTab === 'dashboard' ? 'text-red-500 border-red-500 font-extrabold' : 'border-transparent hover:text-white'
              }`}
            >
              Network Scan
            </button>
            <button 
              onClick={() => setActiveTab('monitoring')}
              className={`pb-1 transition-all cursor-pointer flex items-center gap-1 border-b-2 ${
                activeTab === 'monitoring' ? 'text-red-500 border-red-500 font-extrabold' : 'border-transparent hover:text-white'
              }`}
            >
              IP Monitoring
            </button>
            <button 
              onClick={() => setActiveTab('guides')}
              className={`pb-1 transition-all cursor-pointer border-b-2 ${
                activeTab === 'guides' ? 'text-red-500 border-red-500 font-extrabold' : 'border-transparent hover:text-white'
              }`}
            >
              Delisting Hub
            </button>
            <button 
              onClick={() => setActiveTab('providers')}
              className={`pb-1 transition-all cursor-pointer border-b-2 ${
                activeTab === 'providers' ? 'text-red-500 border-red-500 font-extrabold' : 'border-transparent hover:text-white'
              }`}
            >
              RBL Databases
            </button>
            <button 
              onClick={() => setActiveTab('history')}
              className={`pb-1 transition-all cursor-pointer flex items-center gap-1.5 border-b-2 ${
                activeTab === 'history' ? 'text-red-500 border-red-500 font-extrabold' : 'border-transparent hover:text-white'
              }`}
            >
              Archive
              {historyList.length > 0 && (
                <span className="px-1.5 py-0.5 bg-red-500/20 text-red-500 rounded-full text-[9px] font-black font-mono">
                  {historyList.length}
                </span>
              )}
            </button>
 
            {/* Admin Exclusive Views */}
            {isAdmin && (
              <>
                <button 
                  onClick={() => setActiveTab('users')}
                  className={`pb-1 transition-all cursor-pointer flex items-center gap-1.5 border-b-2 ${
                    activeTab === 'users' ? 'text-red-500 border-red-500 font-extrabold' : 'border-transparent hover:text-white text-rose-300'
                  }`}
                >
                  <Users className="w-3.5 h-3.5" />
                  Users
                </button>
                <button 
                  onClick={() => setActiveTab('settings')}
                  className={`pb-1 transition-all cursor-pointer flex items-center gap-1.5 border-b-2 ${
                    activeTab === 'settings' ? 'text-red-500 border-red-500 font-extrabold' : 'border-transparent hover:text-white'
                  }`}
                >
                  <Settings className="w-3.5 h-3.5" />
                  Settings
                </button>
              </>
            )}
          </nav>
          
          <div className="flex items-center gap-4 pl-6 border-l border-zinc-800 shrink-0">
            {/* Elegant, ultra-small icon-based theme toggle */}
            <button
              onClick={() => {
                const newTheme = theme === 'light' ? 'dark' : 'light';
                setTheme(newTheme);
                triggerAlert('success', `Theme switched to ${newTheme === 'dark' ? 'Night Mode' : 'Light Mode'}`);
              }}
              className="p-1.5 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-red-500/50 hover:bg-zinc-900 text-zinc-400 hover:text-white transition-all cursor-pointer flex items-center justify-center relative group"
              title={theme === 'light' ? 'Switch to Night Mode' : 'Switch to Light Mode'}
            >
              <div className="relative w-4 h-4 flex items-center justify-center">
                {theme === 'light' ? (
                  <Moon className="w-4 h-4 text-rose-500 transition-transform duration-300 rotate-0 group-hover:rotate-12" />
                ) : (
                  <Sun className="w-4 h-4 text-amber-500 transition-transform duration-500 rotate-0 group-hover:rotate-90" />
                )}
              </div>
            </button>
 
            <button
              onClick={handleLogout}
              className="hover:text-red-400 text-zinc-400 transition-colors flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider cursor-pointer"
            >
              <LogOut className="w-4 h-4 text-red-500" />
              Sign Out
            </button>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6" id="main-content">
        
        {/* TAB 1: DASHBOARD & ACTIVE SCANNER */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
                       {/* Input Form, Mode selector & Fast stats row */}
            <div className="flex flex-col xl:flex-row gap-5">
              {/* Left Form: Target input */}
              <section className="flex-1 bg-white p-6 sm:p-8 rounded-2xl shadow-[0_8px_30px_rgb(0,0,0,0.02)] border border-slate-200/80 flex flex-col gap-5 hover:border-blue-500/20 transition-all duration-300" id="scanner-controls">
                <form onSubmit={handleScan} className="space-y-5">
                  <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-slate-100 pb-4">
                    <div>
                      <h2 className="text-xs font-black text-slate-700 uppercase tracking-widest">
                        Target Subnet / Host Scan
                      </h2>
                      <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mt-1">
                        Define IPv4 scope or single host for parallel multi-RBL reputation analysis
                      </p>
                    </div>

                    {/* Simulation / Live Scanner Selector */}
                    <div className="flex items-center gap-1 bg-zinc-900 p-1 rounded-xl border border-zinc-800">
                      <button
                        type="button"
                        onClick={() => setSimulate(true)}
                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-wider transition-all cursor-pointer ${
                          simulate ? 'bg-black text-white shadow-[0_2px_8px_rgba(220,38,38,0.2)] border border-red-500/30' : 'text-zinc-500 hover:text-zinc-300'
                        }`}
                      >
                        <Cpu className="w-3.5 h-3.5" />
                        Simulation
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setSimulate(false);
                          triggerAlert('info', 'Live Mode active. Outbound DNSBL reputation lookups will be dispatched.');
                        }}
                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-wider transition-all cursor-pointer ${
                          !simulate ? 'bg-black text-white shadow-[0_2px_8px_rgba(220,38,38,0.2)] border border-red-500/30' : 'text-zinc-500 hover:text-zinc-300'
                        }`}
                      >
                        <RefreshCw className={`w-3.5 h-3.5 ${!simulate ? 'animate-spin-slow text-red-500' : ''}`} />
                        Live RBL
                      </button>
                    </div>
                  </div>

                  <div className="flex flex-col sm:flex-row gap-3">
                    <div className="flex-1 relative">
                      <Search className="absolute left-4 top-3.5 text-zinc-500 w-4 h-4" />
                      <input 
                        type="text" 
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                        placeholder="e.g. 185.190.140.0/28, 8.8.8.8, 192.168.1.1-50"
                        disabled={loading}
                        className="w-full pl-11 pr-4 py-3.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-red-500/10 focus:border-red-500/80 transition-all text-slate-900 font-bold placeholder:text-slate-400 placeholder:font-sans"
                      />
                    </div>
                    <button
                      type="submit"
                      disabled={loading || !target.trim()}
                      className="bg-gradient-to-r from-red-650 to-red-800 hover:from-red-600 hover:to-red-750 text-white px-7 py-3.5 rounded-xl font-black text-xs uppercase tracking-widest transition-all shadow-[0_4px_12px_rgba(220,38,38,0.25)] disabled:bg-slate-200 disabled:shadow-none flex items-center justify-center gap-2 cursor-pointer border border-white/5"
                    >
                      {loading ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          <span>Executing Lookup...</span>
                        </>
                      ) : (
                        <>
                          <Activity className="w-4 h-4" />
                          <span>Refresh Reputation Analysis</span>
                        </>
                      )}
                    </button>
                  </div>

                  {/* Quick presets helper */}
                  <div className="flex flex-wrap gap-2 items-center pt-1">
                    <span className="text-[9px] text-zinc-500 font-black uppercase tracking-widest mr-1">Presets:</span>
                    <button 
                      type="button" 
                      onClick={() => setTarget('185.190.140.0/28')} 
                      className="text-[9px] bg-slate-50 hover:bg-slate-100 text-slate-600 px-3 py-1.5 rounded-lg font-mono border border-slate-200 transition-all cursor-pointer font-bold"
                    >
                      185.190.140.0/28
                    </button>
                    <button 
                      type="button" 
                      onClick={() => setTarget('8.8.8.8')} 
                      className="text-[9px] bg-slate-50 hover:bg-slate-100 text-slate-600 px-3 py-1.5 rounded-lg font-mono border border-slate-200 transition-all cursor-pointer font-bold"
                    >
                      8.8.8.8
                    </button>
                    <button 
                      type="button" 
                      onClick={() => setTarget('127.0.0.1-5')} 
                      className="text-[9px] bg-slate-50 hover:bg-slate-100 text-slate-600 px-3 py-1.5 rounded-lg font-mono border border-slate-200 transition-all cursor-pointer font-bold"
                    >
                      127.0.0.1-5
                    </button>
                  </div>

                  {/* Live Scanning status panel */}
                  {loading && (
                    <motion.div 
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      className="bg-black text-slate-200 p-5 rounded-xl border border-zinc-900 space-y-3.5 font-mono text-xs overflow-hidden shadow-2xl"
                    >
                      <div className="flex justify-between items-center text-zinc-400 border-b border-zinc-900 pb-2">
                        <div className="flex items-center gap-2.5">
                          <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping" />
                          <span className="uppercase text-[9px] tracking-widest font-black text-red-500">Security Diagnostic Task: {target}</span>
                        </div>
                        <span className="font-bold text-red-500">{scanningProgress}%</span>
                      </div>

                      {/* Progress bar */}
                      <div className="w-full bg-zinc-900 h-1.5 rounded-full overflow-hidden">
                        <motion.div 
                          className="bg-gradient-to-r from-red-500 to-red-700 h-full"
                          style={{ width: `${scanningProgress}%` }}
                        />
                      </div>

                      {/* System outputs */}
                      <div className="space-y-1.5 max-h-24 overflow-y-auto pt-1 text-[11px] text-zinc-500">
                        {scanLogs.map((log, i) => (
                          <div key={i} className="flex gap-2">
                            <span className="text-zinc-650">[{new Date().toLocaleTimeString()}]</span>
                            <span className="text-zinc-650">&gt;&gt;</span>
                            <span className="text-zinc-400 font-semibold">{log}</span>
                          </div>
                        ))}
                      </div>
                    </motion.div>
                  )}
                </form>
              </section>

              {/* Right Mini Score/Status Bento Panel */}
              <section className="xl:w-[380px] w-full bg-white dark:bg-zinc-900 p-6 sm:p-8 rounded-2xl cyber-card flex flex-col justify-between gap-5 transition-all duration-300 border border-slate-200 dark:border-zinc-800 shadow-md relative overflow-hidden before:absolute before:top-0 before:left-0 before:right-0 before:h-1 before:bg-gradient-to-r before:from-red-600 before:to-amber-500">
                <div>
                  <h3 className="text-xs font-black text-slate-900 dark:text-white uppercase tracking-widest">Subnet Reputation Index</h3>
                  <p className="text-[10px] text-slate-600 dark:text-zinc-300 font-extrabold uppercase tracking-wider mt-1">Summary of evaluated network assets</p>
                </div>

                <div className="grid grid-cols-3 gap-3 py-1">
                  <div className="text-center py-2.5 bg-slate-50 dark:bg-zinc-800/80 rounded-xl border border-slate-200 dark:border-zinc-700/80 shadow-xs">
                    <p className="text-[9px] uppercase font-black text-slate-600 dark:text-zinc-300 tracking-wider">Total IPs</p>
                    <p className="text-2xl font-black text-slate-900 dark:text-white font-mono mt-1">
                      {report ? report.totalIPs : '0'}
                    </p>
                  </div>
                  <div className="text-center py-2.5 bg-slate-50 dark:bg-zinc-800/80 rounded-xl border border-slate-200 dark:border-zinc-700/80 shadow-xs">
                    <p className="text-[9px] uppercase font-black text-red-600 dark:text-red-400 tracking-wider">Listed</p>
                    <p className="text-2xl font-black text-red-600 dark:text-red-400 font-mono mt-1">
                      {report ? report.listedCount : '0'}
                    </p>
                  </div>
                  <div className="text-center py-2.5 bg-slate-50 dark:bg-zinc-800/80 rounded-xl border border-slate-200 dark:border-zinc-700/80 shadow-xs">
                    <p className="text-[9px] uppercase font-black text-emerald-600 dark:text-emerald-400 tracking-wider">Clean</p>
                    <p className="text-2xl font-black text-emerald-600 dark:text-emerald-400 font-mono mt-1">
                      {report ? report.cleanCount : '0'}
                    </p>
                  </div>
                </div>

                <div className="bg-slate-950 px-4 py-3 rounded-xl border border-slate-900 flex items-center justify-between text-[11px] text-slate-200 font-black uppercase tracking-wider shadow-inner">
                  <span>Reputation Status:</span>
                  <span className={`font-mono font-black text-xs ${healthScore >= 95 ? 'text-emerald-400' : healthScore >= 80 ? 'text-amber-400' : 'text-rose-400'}`}>
                    {healthScore}% Secure
                  </span>
                </div>
              </section>
            </div>

            {/* SCAN RESULTS DISPLAY */}
            {report ? (
              <div className="space-y-6">
                
                {/* 1. Dashboard metrics bento grid */}
                <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5" id="bento-metrics">
                  
                  {/* Metric 1: Health Index Meter */}
                  <div className="bg-white dark:bg-zinc-900 rounded-2xl p-6 cyber-card flex flex-col items-center justify-center text-center relative overflow-hidden min-h-[210px] shadow-md hover:shadow-xl transition-all duration-300 border border-slate-200 dark:border-zinc-800 before:absolute before:top-0 before:left-0 before:right-0 before:h-1 before:bg-slate-900 dark:before:bg-zinc-700">
                    <div className="absolute top-3.5 left-3.5 bg-slate-100 dark:bg-zinc-800 rounded-lg p-2 border border-slate-200 dark:border-zinc-700 shadow-xs">
                      <Shield className="w-4 h-4 text-red-600 dark:text-red-500" />
                    </div>
                    
                    {/* SVG Radial Progress Ring */}
                    <div className="relative w-24 h-24 mt-2">
                      <svg className="w-full h-full transform -rotate-90">
                        <circle 
                          cx="48" cy="48" r="38" 
                          className="text-slate-200 dark:text-zinc-800" 
                          strokeWidth="8" stroke="currentColor" fill="transparent" 
                        />
                        <circle 
                          cx="48" cy="48" r="38" 
                          className={
                            healthScore >= 95 ? "text-emerald-500" :
                            healthScore >= 80 ? "text-amber-500" : "text-red-500"
                          } 
                          strokeWidth="8" strokeDasharray={2 * Math.PI * 38} 
                          strokeDashoffset={2 * Math.PI * 38 * (1 - healthScore / 100)} 
                          strokeLinecap="round" stroke="currentColor" fill="transparent" 
                        />
                      </svg>
                      <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <span className={`text-2xl font-black font-mono ${healthScore >= 95 ? 'text-emerald-600 dark:text-emerald-400' : healthScore >= 80 ? 'text-amber-600 dark:text-amber-400' : 'text-red-600 dark:text-red-400'}`}>{healthScore}%</span>
                        <span className="text-[10px] text-slate-800 dark:text-zinc-200 font-extrabold uppercase tracking-widest">Clean</span>
                      </div>
                    </div>
                    <div className="mt-3">
                      <h3 className="text-xs font-black text-slate-900 dark:text-white uppercase tracking-widest">Subnet Rep Score</h3>
                      <p className="text-[10px] text-slate-600 dark:text-zinc-300 mt-1 font-extrabold">Ratio of clean, non-blacklisted assets.</p>
                    </div>
                  </div>

                  {/* Metric 2: Scanned Total Assets */}
                  <div className="bg-white dark:bg-zinc-900 rounded-2xl p-6 cyber-card flex flex-col justify-between min-h-[210px] shadow-md hover:shadow-xl transition-all duration-300 border border-slate-200 dark:border-zinc-800 before:absolute before:top-0 before:left-0 before:right-0 before:h-1 before:bg-slate-900 dark:before:bg-zinc-700">
                    <div className="flex justify-between items-start">
                      <div className="bg-slate-100 dark:bg-zinc-800 rounded-lg p-2 border border-slate-200 dark:border-zinc-700 shadow-xs">
                        <Database className="w-4 h-4 text-red-600 dark:text-red-500" />
                      </div>
                      {simulate && (
                        <span className="text-[10px] bg-red-500/10 text-red-600 dark:text-red-400 px-2.5 py-0.8 rounded-lg font-black uppercase tracking-widest border border-red-500/20 shadow-xs">Demo</span>
                      )}
                    </div>
                    <div className="mt-3">
                      <span className="text-5xl font-black text-slate-900 dark:text-white font-mono block leading-none">{report.totalIPs}</span>
                      <span className="text-xs font-black text-slate-900 dark:text-white uppercase tracking-widest block mt-3">Scanned Nodes</span>
                      <p className="text-[10px] text-slate-600 dark:text-zinc-300 mt-1 font-extrabold leading-relaxed">Total active host IPs evaluated within target scope.</p>
                    </div>
                  </div>

                  {/* Metric 3: Listed Threats */}
                  <div className={`bg-white dark:bg-zinc-900 rounded-2xl p-6 cyber-card flex flex-col justify-between min-h-[210px] shadow-md hover:shadow-xl transition-all duration-300 border border-slate-200 dark:border-zinc-800 relative overflow-hidden before:absolute before:top-0 before:left-0 before:right-0 before:h-1 ${report.listedCount > 0 ? 'before:bg-red-600 border-l-4 border-l-red-600 dark:border-l-red-500' : 'before:bg-emerald-500'}`}>
                    <div className="flex justify-between items-start">
                      <div className="bg-red-50 dark:bg-red-950/50 rounded-lg p-2 border border-red-200 dark:border-red-900/50 shadow-xs">
                        <ShieldAlert className="w-4 h-4 text-red-600 dark:text-red-400" />
                      </div>
                      {report.listedCount > 0 ? (
                        <span className="text-[10px] bg-red-500/15 text-red-700 dark:text-red-400 px-2.5 py-0.8 rounded-lg font-black uppercase tracking-widest flex items-center gap-1.5 border border-red-500/30 shadow-xs">
                          <span className="w-2 h-2 rounded-full bg-red-600 dark:bg-red-500 animate-ping" />
                          Action Req.
                        </span>
                      ) : (
                        <span className="text-[10px] bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 px-2.5 py-0.8 rounded-lg font-black uppercase tracking-widest border border-emerald-500/30 shadow-xs">Secure</span>
                      )}
                    </div>
                    <div className="mt-3">
                      <span className={`text-5xl font-black font-mono block leading-none ${report.listedCount > 0 ? 'text-red-600 dark:text-red-400' : 'text-slate-900 dark:text-white'}`}>{report.listedCount}</span>
                      <span className="text-xs font-black text-slate-900 dark:text-white uppercase tracking-widest block mt-3">Blacklisted IPs</span>
                      <p className="text-[10px] text-slate-600 dark:text-zinc-300 mt-1 font-extrabold leading-relaxed">IP nodes actively reported in one or more DNSBL blocklists.</p>
                    </div>
                  </div>

                  {/* Metric 4: Total Blacklist Registrations */}
                  <div className="bg-white dark:bg-zinc-900 rounded-2xl p-6 cyber-card flex flex-col justify-between min-h-[210px] shadow-md hover:shadow-xl transition-all duration-300 border border-slate-200 dark:border-zinc-800 before:absolute before:top-0 before:left-0 before:right-0 before:h-1 before:bg-slate-900 dark:before:bg-zinc-700">
                    <div className="flex justify-between items-start">
                      <div className="bg-slate-100 dark:bg-zinc-800 rounded-lg p-2 border border-slate-200 dark:border-zinc-700 shadow-xs">
                        <Sliders className="w-4 h-4 text-red-600 dark:text-red-500" />
                      </div>
                      <span className="text-[10px] bg-slate-900 dark:bg-zinc-800 text-white dark:text-zinc-200 px-2.5 py-0.8 rounded-lg font-black uppercase tracking-widest border border-slate-800 dark:border-zinc-700 shadow-xs">
                        {BLACKLIST_PROVIDERS.length} RBLs
                      </span>
                    </div>
                    <div className="mt-3">
                      <span className={`text-5xl font-black font-mono block leading-none ${totalListingsCount > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-slate-900 dark:text-white'}`}>{totalListingsCount}</span>
                      <span className="text-xs font-black text-slate-900 dark:text-white uppercase tracking-widest block mt-3">RBL Registrations</span>
                      <p className="text-[10px] text-slate-600 dark:text-zinc-300 mt-1 font-extrabold leading-relaxed">Aggregated count of listings across all providers.</p>
                    </div>
                  </div>

                </section>

                {/* Subnet Threat Distribution Visualizers */}
                {report.listedCount > 0 && (
                  <section className="grid grid-cols-1 lg:grid-cols-2 gap-5" id="distribution-visuals">
                    
                    {/* Visual 1: Flagged Providers list */}
                    <div className="bg-white border border-slate-200/80 rounded-2xl p-6 shadow-[0_8px_30px_rgb(0,0,0,0.02)] space-y-4">
                      <div>
                        <h3 className="text-xs font-black text-slate-700 uppercase tracking-widest">Blacklist Registrations by Provider</h3>
                        <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mt-1">Frequencies of listing entries across verified DNSBL servers</p>
                      </div>

                      <div className="space-y-3 pt-1">
                        {BLACKLIST_PROVIDERS.map(p => {
                          const count = providerStats[p.id] || 0;
                          const percentage = report ? (count / report.totalIPs) * 100 : 0;
                          return (
                            <div key={p.id} className="space-y-1">
                              <div className="flex justify-between items-center text-xs">
                                <span className="font-bold text-slate-800">{p.name} <span className="font-mono text-[9px] text-slate-400 uppercase font-black">({p.domain})</span></span>
                                <span className="font-mono font-black text-slate-950">{count} listed</span>
                              </div>
                              <div className="w-full bg-slate-100 h-2 rounded-full overflow-hidden flex">
                                <div 
                                  className={`h-full rounded-full transition-all duration-500 ${count > 0 ? 'bg-gradient-to-r from-red-500 to-rose-600' : 'bg-slate-300'}`}
                                  style={{ width: `${percentage || (count > 0 ? 5 : 0)}%` }}
                                />
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    {/* Visual 2: Quick mitigation guide selector */}
                    <div className="bg-white border border-slate-200/80 rounded-2xl p-6 shadow-[0_8px_30px_rgb(0,0,0,0.02)] space-y-4 flex flex-col justify-between">
                      <div className="space-y-1">
                        <h3 className="text-xs font-black text-slate-700 uppercase tracking-widest">Rapid Escalation & Mitigation</h3>
                        <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mt-1">Active IP blocks require targeted server auditing and direct delisting appeals</p>
                      </div>

                      <div className="p-4 bg-slate-50/80 rounded-xl border border-slate-200 flex gap-4 items-start">
                        <BookOpen className="w-8 h-8 text-blue-500 shrink-0 mt-0.5" />
                        <div className="space-y-1">
                          <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wide">Threat Mitigation guides</h4>
                          <p className="text-[11px] text-slate-500 font-bold leading-relaxed">
                            Access our expert system guides for specific removal procedures, post-infection mitigation steps, and official request links for the leading lists.
                          </p>
                        </div>
                      </div>

                      <button 
                        onClick={() => setActiveTab('guides')}
                        className="bg-slate-950 hover:bg-slate-900 text-white w-full py-3.2 rounded-xl text-xs font-black uppercase tracking-widest shadow-sm transition-all flex items-center justify-center gap-1.5 cursor-pointer border border-white/5"
                      >
                        Open Delisting Hub <ArrowRight className="w-4 h-4" />
                      </button>
                    </div>

                  </section>
                )}

                {/* 2. Primary Scan results and Node inspector panel */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6" id="results-inspector-panel">
                  
                  {/* Results List (Left 2 columns) */}
                  <div className="lg:col-span-2 bg-white rounded-2xl overflow-hidden cyber-card flex flex-col h-[520px]">
                    
                    {/* Filters bar */}
                    <div className="p-4 border-b border-slate-200 bg-slate-50/50 flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
                      <div>
                        <h3 className="text-xs font-black text-slate-700 uppercase tracking-widest">Evaluation Reports</h3>
                        <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">Showing {filteredResults.length} of {report.results.length} nodes</p>
                      </div>

                      <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
                        <input 
                          type="text"
                          value={searchQuery}
                          onChange={(e) => setSearchQuery(e.target.value)}
                          placeholder="Search IP, country, ISP..."
                          className="pl-3.5 pr-3.5 py-1.8 bg-white border border-slate-200 rounded-xl text-xs focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-red-500/10 focus:border-red-500/80 text-slate-900 font-bold transition-all placeholder:text-slate-400 placeholder:font-normal"
                        />
                        <select
                          value={filterStatus}
                          onChange={(e) => setFilterStatus(e.target.value as any)}
                          className="bg-white border border-slate-200 text-xs font-bold px-3 py-1.8 rounded-xl text-slate-700 focus:outline-hidden focus:ring-4 focus:ring-red-500/10 focus:border-red-500/80 cursor-pointer"
                        >
                          <option value="all">All Status</option>
                          <option value="clean">Clean</option>
                          <option value="listed">Listed</option>
                        </select>
                        <select
                          value={filterAction}
                          onChange={(e) => setFilterAction(e.target.value)}
                          className="bg-white border border-slate-200 text-xs font-bold px-3 py-1.8 rounded-xl text-slate-700 focus:outline-hidden focus:ring-4 focus:ring-red-500/10 focus:border-red-500/80 cursor-pointer"
                        >
                          <option value="all">All Actions</option>
                          <option value="unresolved">Unresolved</option>
                          <option value="pending">Pending</option>
                          <option value="resolved">Resolved</option>
                          <option value="monitoring">Monitoring</option>
                          <option value="ignored">Ignored</option>
                        </select>
                      </div>
                    </div>

                    {/* Table View */}
                    <div className="flex-1 overflow-y-auto">
                      <table className="w-full text-left border-collapse text-xs">
                        <thead>
                          <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 font-extrabold uppercase tracking-widest text-[9px]">
                            <th className="py-2.5 px-4">IP Address</th>
                            <th className="py-2.5 px-4">Reputation</th>
                            <th className="py-2.5 px-4">DNSBLs</th>
                            <th className="py-2.5 px-4">Geolocation (ISP)</th>
                            <th className="py-2.5 px-4">Action State</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-150 font-semibold text-slate-700">
                          {filteredResults.length === 0 ? (
                            <tr>
                              <td colSpan={5} className="text-center py-16 text-slate-400 font-medium bg-slate-50/20">
                                <Info className="w-6 h-6 mx-auto text-slate-300 mb-1" />
                                No assets matched the active filter queries.
                              </td>
                            </tr>
                          ) : (
                            filteredResults.map((r) => {
                              const isSelected = selectedIP && selectedIP.ip === r.ip;
                              return (
                                <tr 
                                  key={r.ip}
                                  onClick={() => handleSelectIP(r)}
                                  className={`hover:bg-slate-50/80 cursor-pointer transition-colors ${isSelected ? 'bg-red-500/5 border-l-2 border-l-red-500' : ''}`}
                                >
                                  <td className="py-3.5 px-4 font-mono font-bold text-slate-900">{r.ip}</td>
                                  <td className="py-3.5 px-4">
                                    {r.status === 'clean' ? (
                                      <span className="bg-emerald-50 text-emerald-700 text-[9px] px-2 py-0.5 rounded-full border border-emerald-100 font-extrabold uppercase tracking-wide">Clean</span>
                                    ) : (
                                      <span className="bg-rose-50 text-rose-700 text-[9px] px-2 py-0.5 rounded-full border border-rose-100 font-extrabold uppercase tracking-wide">Listed ({r.listedCount})</span>
                                    )}
                                  </td>
                                  <td className="py-3.5 px-4 font-mono text-slate-500">
                                    {r.listedCount > 0 ? (
                                      <span className="text-red-600 font-bold truncate block max-w-[120px]">
                                        {Object.entries(r.listings)
                                          .filter(([_, data]) => (data as any).listed)
                                          .map(([key]) => key.toUpperCase())
                                          .join(', ')}
                                      </span>
                                    ) : (
                                      <span className="text-slate-400">-</span>
                                    )}
                                  </td>
                                  <td className="py-3.5 px-4 max-w-[160px] truncate text-slate-600 font-medium">
                                    {r.location?.countryCode ? (
                                      <span className="flex items-center gap-1">
                                        <Globe className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                                        {r.location.city}, {r.location.countryCode} <span className="text-slate-400 text-[10px] font-mono">({r.location.isp?.substring(0, 10)})</span>
                                      </span>
                                    ) : 'Local LAN'}
                                  </td>
                                  <td className="py-3.5 px-4">
                                    {r.actionStatus ? (
                                      <span className={`text-[9px] font-extrabold uppercase px-2 py-0.5 rounded-md border ${
                                        r.actionStatus === 'unresolved' ? 'bg-rose-50 text-rose-700 border-rose-200' :
                                        r.actionStatus === 'pending' ? 'bg-amber-50 text-amber-700 border-amber-200' :
                                        r.actionStatus === 'resolved' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' :
                                        'bg-slate-100 text-slate-700 border-slate-300'
                                      }`}>
                                        {r.actionStatus}
                                      </span>
                                    ) : (
                                      <span className="text-slate-400 font-normal">-</span>
                                    )}
                                  </td>
                                </tr>
                              );
                            })
                          )}
                        </tbody>
                      </table>
                    </div>

                    {/* Exporter Footer */}
                    <div className="p-3.5 border-t border-slate-200 bg-slate-50/40 flex justify-between items-center shrink-0">
                      <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">Report Exporter Suite</span>
                      <div className="flex gap-2">
                        <button 
                          onClick={() => downloadCSVReport(report)}
                          className="bg-white border border-slate-200 hover:border-slate-300 text-slate-700 font-bold text-[10px] uppercase tracking-wider px-3 py-1.5 rounded-lg flex items-center gap-1 shadow-xs cursor-pointer"
                        >
                          <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-600" />
                          CSV Spreadsheet
                        </button>
                        <button 
                          onClick={() => downloadJSONReport(report)}
                          className="bg-white border border-slate-200 hover:border-slate-300 text-slate-700 font-bold text-[10px] uppercase tracking-wider px-3 py-1.5 rounded-lg flex items-center gap-1 shadow-xs cursor-pointer"
                        >
                          <FileText className="w-3.5 h-3.5 text-slate-600" />
                          JSON Data
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Node Inspector (Right Column) */}
                  <div className="bg-white rounded-xl p-5 cyber-card min-h-[580px] flex flex-col justify-between overflow-hidden">
                    {selectedIP ? (
                      <div className="flex-1 flex flex-col justify-between min-h-0 space-y-3">
                        {/* Upper Details - scrollable area */}
                        <div className="space-y-3 overflow-y-auto flex-1 min-h-0 pr-1">
                          <div className="flex justify-between items-start border-b border-slate-150 pb-2.5">
                            <div>
                              <span className="text-[9px] font-extrabold text-slate-400 uppercase tracking-wider block">Inspecting Asset Node</span>
                              <h3 className="text-sm font-black font-mono text-slate-950 mt-0.5">{selectedIP.ip}</h3>
                            </div>
                            {selectedIP.status === 'clean' ? (
                              <span className="bg-emerald-50 text-emerald-800 border border-emerald-200 text-[9px] font-extrabold uppercase px-2 py-0.5 rounded">Safe</span>
                            ) : (
                              <span className="bg-rose-50 text-rose-800 border border-rose-200 text-[9px] font-extrabold uppercase px-2 py-0.5 rounded">Warning</span>
                            )}
                          </div>

                          {/* Location & ISP */}
                          <div className="space-y-2.5">
                            <h4 className="text-[9px] font-black text-slate-400 uppercase tracking-widest">Metadata Attributes</h4>
                            
                            <div className="grid grid-cols-2 gap-3 text-xs">
                              <div className="bg-slate-50 p-2 rounded-lg border border-slate-150 space-y-0.5">
                                <span className="text-[9px] text-slate-400 font-bold uppercase block">ISP/Host Carrier</span>
                                <span className="font-bold text-slate-800 truncate block">{selectedIP.location?.isp || 'LAN Interface'}</span>
                              </div>
                              <div className="bg-slate-50 p-2 rounded-lg border border-slate-150 space-y-0.5">
                                <span className="text-[9px] text-slate-400 font-bold uppercase block">Country/Location</span>
                                <span className="font-bold text-slate-800 truncate block">
                                  {selectedIP.location?.countryCode ? `${selectedIP.location.city}, ${selectedIP.location.countryCode}` : 'Intranet LAN'}
                                </span>
                              </div>
                            </div>
                          </div>

                          {/* RBL Listings Breakdown */}
                          <div className="space-y-2">
                            <div className="flex items-center justify-between border-b border-slate-100 pb-1.5">
                              <h4 className="text-[9px] font-black text-slate-400 uppercase tracking-widest">
                                DNSBL Reputations
                              </h4>
                              <div className="flex gap-1.5">
                                <button
                                  onClick={() => setInspectorTab('listed')}
                                  className={`px-2 py-0.5 text-[8px] font-black uppercase tracking-wider rounded-md transition-all cursor-pointer ${
                                    inspectorTab === 'listed'
                                      ? 'bg-rose-100 text-rose-800 font-extrabold border border-rose-200'
                                      : 'bg-slate-100 text-slate-500 hover:bg-slate-200 border border-slate-150'
                                  }`}
                                >
                                  Listed ({selectedIP.listedCount})
                                </button>
                                <button
                                  onClick={() => setInspectorTab('all')}
                                  className={`px-2 py-0.5 text-[8px] font-black uppercase tracking-wider rounded-md transition-all cursor-pointer ${
                                    inspectorTab === 'all'
                                      ? 'bg-red-500/10 text-red-500 font-extrabold border border-red-500/20'
                                      : 'bg-slate-100 text-slate-500 hover:bg-slate-200 border border-slate-150'
                                  }`}
                                >
                                  All checked ({BLACKLIST_PROVIDERS.length})
                                </button>
                              </div>
                            </div>

                            <div className="space-y-1.5 max-h-[170px] overflow-y-auto pr-0.5">
                              {inspectorTab === 'listed' ? (
                                Object.entries(selectedIP.listings).some(([_, val]) => (val as any).listed) ? (
                                  Object.entries(selectedIP.listings)
                                    .filter(([_, data]) => (data as any).listed)
                                    .map(([providerId, data]: [string, any]) => {
                                      const details = BLACKLIST_PROVIDERS.find(p => p.id === providerId);
                                      return (
                                        <div key={providerId} className="p-2 bg-rose-50/50 rounded-lg border border-rose-100 space-y-1 text-xs">
                                          <div className="flex justify-between items-center">
                                            <span className="font-bold text-slate-900">{details?.name || providerId}</span>
                                            <span className="font-mono text-[9px] text-rose-600 bg-rose-50 px-1 py-0.2 rounded border border-rose-150 font-extrabold uppercase">
                                              {data.responseCode || 'Listed'}
                                            </span>
                                          </div>
                                          <p className="text-[11px] text-slate-600 leading-normal font-semibold">
                                            {data.details || 'Reputation degraded on blacklist.'}
                                          </p>
                                        </div>
                                      );
                                    })
                                ) : (
                                  <div className="p-3 bg-emerald-50/50 rounded-lg border border-emerald-100 flex items-center gap-2 text-emerald-800 text-xs font-semibold">
                                    <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0" />
                                    <span>This asset is clean across all evaluated databases.</span>
                                  </div>
                                )
                              ) : (
                                <div className="divide-y divide-slate-100 border border-slate-150 rounded-lg overflow-hidden bg-white">
                                  {BLACKLIST_PROVIDERS.map((provider) => {
                                    const checkData = (selectedIP.listings as any)?.[provider.id] || { listed: false };
                                    let statusBadge = (
                                      <span className="text-[8px] font-black text-emerald-600 bg-emerald-50 border border-emerald-150 px-1 py-0.2 rounded uppercase tracking-wider">
                                        Clean
                                      </span>
                                    );
                                    let bgClass = "bg-white hover:bg-slate-50/40";
                                    
                                    if (checkData.listed) {
                                      statusBadge = (
                                        <span className="text-[8px] font-black text-rose-600 bg-rose-50 border border-rose-150 px-1 py-0.2 rounded uppercase tracking-wider">
                                          Listed ({checkData.responseCode || '127.0.0.2'})
                                        </span>
                                      );
                                      bgClass = "bg-rose-50/20 hover:bg-rose-50/40";
                                    } else if (checkData.details?.includes('Resolver Refused')) {
                                      statusBadge = (
                                        <span className="text-[8px] font-black text-amber-600 bg-amber-50 border border-amber-150 px-1 py-0.2 rounded uppercase tracking-wider" title="DNSBL query blocked due to Public DNS provider rules (e.g. Google Public DNS). Recheck via private resolver to bypass.">
                                          Refused
                                        </span>
                                      );
                                      bgClass = "bg-amber-50/10 hover:bg-amber-50/20";
                                    } else if (checkData.details?.includes('Timeout')) {
                                      statusBadge = (
                                        <span className="text-[8px] font-black text-amber-500 bg-amber-50 border border-amber-150 px-1 py-0.2 rounded uppercase tracking-wider">
                                          Timeout
                                        </span>
                                      );
                                      bgClass = "bg-amber-50/5 hover:bg-amber-50/10";
                                    } else if (checkData.details?.includes('Query Error')) {
                                      statusBadge = (
                                        <span className="text-[8px] font-black text-slate-500 bg-slate-50 border border-slate-150 px-1 py-0.2 rounded uppercase tracking-wider">
                                          Error
                                        </span>
                                      );
                                    }

                                    return (
                                      <div key={provider.id} className={`p-2 transition-colors flex flex-col gap-0.5 ${bgClass}`}>
                                        <div className="flex justify-between items-center text-xs">
                                          <span className="font-bold text-slate-800">{provider.name}</span>
                                          {statusBadge}
                                        </div>
                                        <div className="text-[10px] text-slate-400 font-medium truncate" title={provider.domain}>
                                          {checkData.listed ? (
                                            <span className="text-rose-600 font-semibold">{checkData.details}</span>
                                          ) : checkData.details ? (
                                            <span className="text-slate-500 font-medium">{checkData.details}</span>
                                          ) : (
                                            <span>Checked: {provider.domain}</span>
                                          )}
                                        </div>
                                      </div>
                                    );
                                  })}
                                </div>
                              )}
                            </div>
                          </div>
                        </div>

                        {/* Action Planner / Inline Notepad - pinned at bottom */}
                        <div className="shrink-0 space-y-2.5 pt-3 border-t border-slate-150">
                          <div className="flex items-center justify-between">
                            <h4 className="text-[9px] font-black text-slate-400 uppercase tracking-widest flex items-center gap-1">
                              <Edit3 className="w-3 h-3 text-slate-400" />
                              Mitigation Notes & Planner
                            </h4>
                            
                            <select
                              value={actionStatusVal}
                              onChange={(e) => setActionStatusVal(e.target.value as any)}
                              className="text-[10px] font-extrabold uppercase bg-slate-100 border border-slate-200 rounded px-1.5 py-0.5 text-slate-700 cursor-pointer"
                            >
                              <option value="unresolved">Unresolved</option>
                              <option value="pending">Pending Appeal</option>
                              <option value="resolved">Resolved</option>
                              <option value="monitoring">Monitoring</option>
                              <option value="ignored">Ignore Node</option>
                            </select>
                          </div>

                          <textarea
                            rows={2}
                            value={noteText}
                            onChange={(e) => setNoteText(e.target.value)}
                            placeholder="Type diagnostic log notes, ISP appeal references..."
                            className="w-full bg-slate-50 border border-slate-200 rounded-lg p-2 text-xs focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-red-500/15 focus:border-red-500/60 transition-all font-semibold text-slate-900 leading-normal resize-none"
                          />

                          <button 
                            onClick={handleSaveIPNotes}
                            className="w-full bg-red-600 hover:bg-red-700 text-white py-2 rounded-lg text-xs font-black uppercase tracking-wider shadow-sm transition-all flex items-center justify-center gap-1.5 cursor-pointer active:scale-[0.99]"
                          >
                            <Check className="w-4 h-4 text-white" />
                            Save Action Plan & Notes
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div className="flex-1 flex flex-col items-center justify-center text-center text-slate-400 p-4">
                        <Shield className="w-10 h-10 text-slate-200 mb-3" />
                        <span className="text-xs font-black text-slate-700 uppercase tracking-wider block">Inspector Module</span>
                        <p className="text-[11px] text-slate-400 max-w-[220px] mt-1 font-semibold leading-relaxed">
                          Select any specific IP address node from the evaluation list to access detailed blacklist response codes and log notes.
                        </p>
                      </div>
                    )}
                  </div>

                </div>

              </div>
            ) : (
              // Initial empty / welcome screen
              <section className="bg-white border border-slate-200 rounded-xl py-14 px-6 text-center max-w-2xl mx-auto shadow-xs space-y-4" id="empty-state">
                <div className="w-14 h-14 rounded-full bg-blue-50 border border-blue-100 flex items-center justify-center mx-auto text-blue-600 shadow-xs">
                  <ShieldCheck className="w-8 h-8" />
                </div>
                <div className="space-y-1">
                  <h2 className="text-sm font-black text-slate-800 uppercase tracking-widest">Active Subnet Scanning Console</h2>
                  <p className="text-xs text-slate-500 font-semibold max-w-md mx-auto leading-relaxed">
                    Query blocks of IP allocations dynamically. WolastShield contacts the gold-standard RBL databases to detect listings in parallel.
                  </p>
                </div>
                
                <div className="pt-2">
                  <button 
                    onClick={handleScan}
                    className="bg-blue-600 hover:bg-blue-700 text-white px-5 py-2.5 rounded-lg font-bold text-xs uppercase tracking-wider transition-colors flex items-center gap-2 mx-auto cursor-pointer shadow-sm"
                  >
                    <Activity className="w-4 h-4" />
                    Trigger Example Subnet Scan
                  </button>
                </div>
              </section>
            )}

          </div>
        )}

        {/* TAB 1.5: IP MONITORING SECTION (NEW) */}
        {activeTab === 'monitoring' && (
          <IPMonitoring currentUser={userProfile} triggerAlert={triggerAlert} />
        )}

        {/* TAB 2: THREAT MITIGATION DELISTING HUBS */}
        {activeTab === 'guides' && (
          <div className="space-y-6">
            <section className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-5">
              <div>
                <h2 className="text-sm font-extrabold text-slate-700 uppercase tracking-wider">Blacklist Removal & Delisting Hub</h2>
                <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mt-0.5">Step-by-step mitigation playbooks to resolve external network listings.</p>
              </div>

              <div className="space-y-6">
                
                {/* General delisting instructions */}
                <div className="bg-blue-50/50 p-4 rounded-xl border border-blue-100/60 flex items-start gap-3 text-xs leading-relaxed font-semibold text-slate-800">
                  <Info className="w-5 h-5 text-blue-500 shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <span className="font-extrabold uppercase text-[10px] text-blue-900 tracking-wider">Critical Standard Procedure (Read First)</span>
                    <p className="text-[11px] text-slate-600 font-semibold leading-relaxed">
                      NEVER submit a delisting request before fixing the core vulnerability. Doing so will result in an immediate automatic re-blacklist and may lead to a permanent ban of your host ranges from the provider networks.
                    </p>
                  </div>
                </div>

                {/* Individual Guides Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {Object.entries(BLACKLIST_GUIDES).map(([id, guide]) => (
                    <div key={id} className="p-4 rounded-xl border border-slate-200 bg-slate-50/50 space-y-4 hover:border-slate-300 transition-colors">
                      <div className="flex justify-between items-start border-b border-slate-200/60 pb-2.5">
                        <div>
                          <h3 className="text-xs font-black text-slate-800 uppercase tracking-wide">{guide.name} playbook</h3>
                          <p className="text-[11px] text-slate-500 mt-0.5">{guide.description}</p>
                        </div>
                        <a 
                          href={guide.url} 
                          target="_blank" 
                          rel="noreferrer"
                          className="text-[10px] text-blue-600 hover:text-blue-800 font-bold flex items-center gap-0.5 cursor-pointer uppercase tracking-wider"
                        >
                          Removal Portal <ExternalLink className="w-3 h-3" />
                        </a>
                      </div>

                      <div className="space-y-1.5">
                        <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">Mitigation Steps:</span>
                        <ul className="list-decimal pl-4 text-xs text-slate-700 font-semibold space-y-1 leading-relaxed">
                          {guide.steps.map((step, i) => (
                            <li key={i}>{step}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  ))}
                </div>

              </div>
            </section>
          </div>
        )}

        {/* TAB 3: BLACKLIST PROVIDERS DATABASE REFERENCE */}
        {activeTab === 'providers' && (
          <div className="space-y-6">
            <section className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-4">
              <div>
                <h2 className="text-sm font-extrabold text-slate-700 uppercase tracking-wider">Supported Real-time DNSBL Providers</h2>
                <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mt-0.5">This analytical tool actively validates hosts across the following high-tier blacklist authorities using direct DNS querying.</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {providers.map((p) => (
                  <div key={p.id} className="p-4 bg-slate-50 border border-slate-200 rounded-lg flex flex-col justify-between space-y-3 shadow-xs hover:border-slate-300 transition-colors">
                    <div className="space-y-1.5">
                      <div className="flex justify-between items-center">
                        <span className="text-xs font-black text-slate-800 uppercase tracking-wider">{p.name}</span>
                        <span className="text-[9px] bg-slate-200 text-slate-700 px-2 py-0.5 rounded font-extrabold uppercase tracking-wide">{p.category}</span>
                      </div>
                      <span className="text-[11px] font-mono text-slate-500 block font-semibold">{p.domain}</span>
                      <p className="text-[11px] text-slate-600 leading-relaxed font-semibold">
                        {p.description}
                      </p>
                    </div>

                    <div className="pt-2 border-t border-slate-200/60 flex justify-between items-center">
                      <span className="text-[10px] text-slate-400 font-bold uppercase font-mono">DNS Query standard</span>
                      <a 
                        href={p.delistUrl} 
                        target="_blank" 
                        rel="noreferrer" 
                        className="text-[10px] text-blue-600 hover:text-blue-800 font-bold flex items-center gap-0.5 cursor-pointer uppercase tracking-wider"
                      >
                        Lookup RBL <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          </div>
        )}

        {/* TAB 4: HISTORICAL REPORT ARCHIVE */}
        {activeTab === 'history' && (
          <div className="space-y-6">
            <section className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
              <div className="border-b border-slate-100 pb-4">
                <h2 className="text-sm font-extrabold text-slate-700 uppercase tracking-wider">Historical Cloud Scan Archive</h2>
                <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mt-0.5">Access past analytical evaluations saved securely on your cloud database.</p>
              </div>

              {historyList.length === 0 ? (
                <div className="text-center py-12 text-slate-400 space-y-3">
                  <div className="w-12 h-12 rounded-lg bg-slate-50 border border-slate-150 flex items-center justify-center mx-auto text-slate-400 shadow-xs">
                    <History className="w-6 h-6" />
                  </div>
                  <span className="text-xs font-bold text-slate-700 uppercase tracking-wider block">No Saved Reports Found</span>
                  <p className="text-[11px] max-w-xs mx-auto font-medium">Reports are stored automatically when you complete a subnet scanning operation.</p>
                </div>
              ) : (
                <div className="divide-y divide-slate-150">
                  {historyList.map((h) => (
                    <div 
                      key={h.id}
                      onClick={() => loadReportDetails(h.id)}
                      className="py-4 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 hover:bg-slate-50/50 px-2 rounded-lg transition-all cursor-pointer group animate-fade-in"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-extrabold text-slate-950 font-mono">{h.target}</span>
                          <span className="text-[10px] text-slate-400 font-bold font-mono">ID: {h.id.substring(0, 6)}</span>
                        </div>
                        <div className="flex flex-wrap items-center gap-2.5 text-[11px] text-slate-500 font-semibold">
                          <span className="flex items-center gap-1">
                            <Clock className="w-3.5 h-3.5 text-slate-400" />
                            {new Date(h.timestamp).toLocaleString()}
                          </span>
                          <span>•</span>
                          <span>{h.totalIPs} IPs checked</span>
                        </div>
                      </div>

                      <div className="flex items-center gap-3 w-full sm:w-auto justify-between sm:justify-end">
                        <div className="flex items-center gap-1.5 text-xs font-bold">
                          {h.listedCount > 0 ? (
                            <span className="text-rose-700 bg-rose-50 px-2 py-0.5 rounded border border-rose-100 font-extrabold text-[10px] uppercase">
                              {h.listedCount} listed
                            </span>
                          ) : (
                            <span className="text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-100 font-extrabold text-[10px] uppercase">
                              Clean
                            </span>
                          )}
                          <span className="text-slate-400 font-bold text-[10px]">
                            ({Math.round((h.cleanCount / h.totalIPs) * 100)}% Health)
                          </span>
                        </div>

                        <div className="flex gap-1.5" onClick={(e) => e.stopPropagation()}>
                          {archiveConfirmDeleteId === h.id ? (
                            <div className="flex items-center gap-1 bg-rose-50 border border-rose-200/60 p-1 rounded-lg">
                              <span className="text-[9px] font-black text-rose-700 uppercase tracking-wider px-1">
                                Confirm?
                              </span>
                              <button
                                onClick={() => deleteHistoryReport(h.id)}
                                className="bg-rose-600 hover:bg-rose-700 text-white p-1 rounded-md text-[9px] font-black uppercase tracking-widest cursor-pointer transition-all flex items-center justify-center"
                                title="Permanently delete report"
                              >
                                <Check className="w-3 h-3" />
                              </button>
                              <button
                                onClick={() => setArchiveConfirmDeleteId(null)}
                                className="bg-slate-200 hover:bg-slate-300 text-slate-700 p-1 rounded-md text-[9px] font-black uppercase tracking-widest cursor-pointer transition-all flex items-center justify-center"
                                title="Cancel deletion"
                              >
                                <X className="w-3 h-3" />
                              </button>
                            </div>
                          ) : (
                            <>
                              <button
                                onClick={() => setArchiveConfirmDeleteId(h.id)}
                                className="bg-white border border-slate-200 hover:bg-rose-50 hover:text-rose-700 hover:border-rose-200 text-slate-500 p-1.5 rounded-lg transition-all cursor-pointer shadow-sm"
                                title="Delete report"
                              >
                                <X className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => loadReportDetails(h.id)}
                                className="bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1 uppercase tracking-wider shadow-sm cursor-pointer"
                              >
                                Load
                                <ArrowRight className="w-3 h-3" />
                              </button>
                            </>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>
          </div>
        )}

        {/* TAB 5: ADMIN - USER ACCOUNTS MANAGEMENT (NEW) */}
        {activeTab === 'users' && isAdmin && (
          <UserManagement currentUser={userProfile} triggerAlert={triggerAlert} />
        )}

        {/* TAB 6: ADMIN - SYSTEM CONFLICTS & SETTINGS (NEW) */}
        {activeTab === 'settings' && isAdmin && (
          <SystemSettings currentUser={userProfile} triggerAlert={triggerAlert} />
        )}

      </main>

      {/* App Footer */}
      <footer className="bg-slate-50 border-t border-slate-200/80 text-center py-6 px-6 text-[9px] text-slate-400 font-extrabold uppercase tracking-widest shrink-0" id="app-footer">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row justify-between items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="text-slate-400 font-black">Wolast Shield Pro</span>
            <span className="text-slate-300">•</span>
            <span>Platform Security Console v2.5</span>
            <span className="text-slate-300">•</span>
            <span className="text-blue-500 font-black">Powered by Wolast Technologies</span>
          </div>
          <div className="flex gap-5 text-[9px] font-bold">
            <a href="https://www.spamhaus.org/" target="_blank" rel="noreferrer" className="hover:text-blue-500 transition-colors">Spamhaus ZEN</a>
            <a href="https://www.barracudacentral.org/" target="_blank" rel="noreferrer" className="hover:text-blue-500 transition-colors">Barracuda BRBL</a>
            <a href="https://www.spamcop.net/" target="_blank" rel="noreferrer" className="hover:text-blue-500 transition-colors">SpamCop</a>
          </div>
        </div>
      </footer>

    </div>
  );
}
