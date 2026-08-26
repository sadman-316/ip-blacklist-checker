import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Search, Shield, ShieldAlert, ShieldCheck, Activity, Download, 
  RefreshCw, Sliders, Database, BookOpen, History, Plus, 
  AlertCircle, ArrowRight, MapPin, Info, X, CheckCircle, CheckCircle2,
  Clock, Edit3, ExternalLink, FileSpreadsheet, Cpu, Globe, Building, Check, FileText,
  LogOut, Settings, Users, Bell, BellOff, Loader2, AlertTriangle, ChevronRight
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
import { SuperToolInspector } from './components/SuperToolInspector';
import { COMPANY_CREDENTIALS } from './company-credentials';

// Static Full Reputation & Blacklist Providers list for UI rendering & reference
export const BLACKLIST_PROVIDERS: BlacklistProvider[] = [
  // 1. Core DNSBL / RBL Standards
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
    description: 'UCEPROTECT Level 3. Autonomous System (ASN) and hosting carrier level escalation for systemic spam.',
    delistUrl: 'http://www.uceprotect.net/en/rblcheck.php',
    category: 'Spam'
  },
  {
    id: 'blocklist',
    name: 'Blocklist.de',
    domain: 'bl.blocklist.de',
    description: 'Real-time security reporting service. Lists malicious IPs participating in SSH, Mail, FTP, and Web attacks.',
    delistUrl: 'https://www.blocklist.de/en/search.html',
    category: 'Security'
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
    category: 'Security'
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
    description: 'ivmSIP by Invaluement. Anti-spam intelligence tracking high-emission spam IP addresses (Direct Web Verification: invaluement.com/lookup/).',
    delistUrl: 'https://www.invaluement.com/lookup/',
    category: 'Spam'
  },
  {
    id: 'ivmuri',
    name: 'Invaluement ivmURI',
    domain: 'uri.invaluement.com',
    description: 'Invaluement URI blocklist detecting links, sending hosts, and phishing/spam domains (Direct Web Verification: invaluement.com/lookup/).',
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
    id: 'nixspam',
    name: 'NiX Spam',
    domain: 'ix.dnsbl.manitu.net',
    description: 'Manitu NiX Spam. Highly active German blocklist detecting active spam senders, mail server abuse, and botnets.',
    delistUrl: 'https://www.manitu.de/nixspam/',
    category: 'Spam'
  },
  {
    id: 'justspam',
    name: 'JustSpam',
    domain: 'dnsbl.justspam.org',
    description: 'JustSpam.org. A highly responsive real-time DNSBL listing active spamming hosts based on spam traps.',
    delistUrl: 'http://www.justspam.org/',
    category: 'Spam'
  },
  {
    id: 'tornevall',
    name: 'Tornevall',
    domain: 'dnsbl.tornevall.org',
    description: 'Tornevall DNSBL. Specializes in identifying compromised hosts, open proxies, Tor exit nodes, and automated scrapers.',
    delistUrl: 'https://dnsbl.tornevall.org/',
    category: 'General'
  },
  {
    id: 'nordspam',
    name: 'NordSpam',
    domain: 'bl.nordspam.com',
    description: 'NordSpam Blocklist. An active public DNSBL targeting spamming mail servers and botnets.',
    delistUrl: 'https://www.nordspam.com/',
    category: 'Spam'
  },
  {
    id: 'zerospam',
    name: '0Spam',
    domain: 'bl.0spam.org',
    description: '0Spam DNSBL. Identifies spam hosts, email spiders, and brute force attackers in real time.',
    delistUrl: 'https://0spam.org/',
    category: 'Spam'
  },
  {
    id: 'suomispam',
    name: 'Suomispam',
    domain: 'bl.suomispam.net',
    description: 'Suomispam DNSBL. A reputation list targeting global and regional spam sources and abusive IPs.',
    delistUrl: 'https://suomispam.net/',
    category: 'Spam'
  },
  {
    id: 'efnetrbl',
    name: 'EFnet RBL',
    domain: 'rbl.efnetrbl.org',
    description: 'EFnet RBL. Detects open proxies, compromised hosts, dynamic IPs, and Tor exit nodes.',
    delistUrl: 'https://rbl.efnetrbl.org/',
    category: 'General'
  },
  {
    id: 'spameatingmonkey',
    name: 'SpamEatingMonkey',
    domain: 'bl.spameatingmonkey.net',
    description: 'SpamEatingMonkey RBL. Tracks active spam-sending mail servers and compromised relays.',
    delistUrl: 'https://spameatingmonkey.com/',
    category: 'Spam'
  },
  {
    id: 'zapbl',
    name: 'ZapBL',
    domain: 'dnsbl.zapbl.net',
    description: 'ZapBL DNSBL. Fast, accurate blacklist targeting active spam servers, brute-forcers, and scrapers.',
    delistUrl: 'https://zapbl.net/',
    category: 'Spam'
  },
  {
    id: 'interserver',
    name: 'Interserver RBL',
    domain: 'rbl.interserver.net',
    description: 'Interserver IP Reputation. An active lookup listing spamming IPs and abusive hosts across the web.',
    delistUrl: 'https://rbl.interserver.net/',
    category: 'Spam'
  },
  {
    id: 'abusech',
    name: 'Abuse.ch SSLIPBL',
    domain: 'sslipbl.abuse.ch',
    description: 'Tracks IP addresses associated with malicious SSL certificates, botnet command and control (C2) servers, and active cyber threats.',
    delistUrl: 'https://ssl.abuse.ch/sslipbl/',
    category: 'Security'
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
    id: 'backscatterer',
    name: 'Backscatterer IPS',
    domain: 'ips.backscatterer.org',
    description: 'Backscatterer blocklist identifying hosts emitting misdirected NDRs and abusive out-of-office bounces.',
    delistUrl: 'http://www.backscatterer.org/?target=test',
    category: 'Spam'
  },
  {
    id: 'danmeuk',
    name: 'Dan.me.uk Tor RBL',
    domain: 'tor.dan.me.uk',
    description: 'Real-time updated registry of active Tor exit relay IP addresses.',
    delistUrl: 'https://www.dan.me.uk/torlist/',
    category: 'Proxy'
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
  },
  {
    id: 'woodys',
    name: 'Woodys SMTP Blacklist',
    domain: 'blacklist.woody.ch',
    description: 'Swiss mail reputation list tracking open relays, unauthenticated SMTP hosts, and bulk spam emitters.',
    delistUrl: 'http://blacklist.woody.ch/',
    category: 'Spam'
  },

  // 2. Major Email Gateway & Postmaster Reputation Portals
  {
    id: 'googlepostmaster',
    name: 'Google Postmaster & Gmail Deliverability',
    domain: 'postmaster.google.com',
    description: 'Google Gmail IP and domain reputation dashboard, SPF/DKIM/DMARC alignment validation, and Gmail bulk sender compliance.',
    delistUrl: 'https://support.google.com/mail/contact/bulk_send_new',
    category: 'Mail Gateway'
  },
  {
    id: 'microsoftsnds',
    name: 'Microsoft SNDS & Outlook Delist Portal',
    domain: 'olcsupport.office.com',
    description: 'Microsoft Smart Network Data Services (SNDS) and Outlook.com / Hotmail / Office365 IP deliverability & sender unblock portal.',
    delistUrl: 'https://olcsupport.office.com/',
    category: 'Mail Gateway'
  },
  {
    id: 'yahoopostmaster',
    name: 'Yahoo Mail & AOL Postmaster Hub',
    domain: 'senders.yahooinc.com',
    description: 'Yahoo, AOL, and Verizon Media sender feedback loop, spam complaint monitoring, and email delivery remediation.',
    delistUrl: 'https://senders.yahooinc.com/contact-us/',
    category: 'Mail Gateway'
  },
  {
    id: 'ciscotalos',
    name: 'Cisco Talos Intelligence (SenderBase)',
    domain: 'talosintelligence.com',
    description: 'Cisco Email & Web Security reputation engine. Classifies host sending reputation as Good, Neutral, or Poor across enterprise firewalls.',
    delistUrl: 'https://talosintelligence.com/reputation_center',
    category: 'Mail Gateway'
  },
  {
    id: 'proofpoint',
    name: 'Proofpoint Dynamic Reputation (PDR)',
    domain: 'ipcheck.proofpoint.com',
    description: 'Enterprise email gateway filtering protecting Fortune 500 networks. Evaluates connection frequency, spam bursts, and malware payloads.',
    delistUrl: 'https://ipcheck.proofpoint.com/',
    category: 'Mail Gateway'
  },
  {
    id: 'trendmicro',
    name: 'Trend Micro Email Reputation (ERS)',
    domain: 'ers.trendmicro.com',
    description: 'Trend Micro Global Email Reputation Services and Site Safety database for enterprise mail gateways.',
    delistUrl: 'https://ers.trendmicro.com/reputations',
    category: 'Mail Gateway'
  },
  {
    id: 'symantec',
    name: 'Symantec / Broadcom Brightmail',
    domain: 'ipremoval.sms.symantec.com',
    description: 'Broadcom Email Security.cloud / Symantec Brightmail automated IP reputation investigation and removal request system.',
    delistUrl: 'https://ipremoval.sms.symantec.com/',
    category: 'Mail Gateway'
  },
  {
    id: 'sophos',
    name: 'Sophos Labs Threat Center',
    domain: 'sophos.com',
    description: 'Sophos endpoint and email appliance IP reputation feed detecting malicious relays and phishing infrastructure.',
    delistUrl: 'https://www.sophos.com/en-us/threat-center/ip-lookup.aspx',
    category: 'Mail Gateway'
  },
  {
    id: 'fortiguard',
    name: 'FortiGuard Antispam & IP Threat',
    domain: 'fortiguard.com',
    description: 'Fortinet FortiGate and FortiMail global threat intelligence categorization and IP risk rating.',
    delistUrl: 'https://www.fortiguard.com/faq/wfraterequest',
    category: 'Mail Gateway'
  },
  {
    id: 'cloudflare',
    name: 'Cloudflare Radar Threat Gateway',
    domain: 'radar.cloudflare.com',
    description: 'Cloudflare global network threat rating, bot management classification, and AS connectivity health.',
    delistUrl: 'https://radar.cloudflare.com/',
    category: 'Mail Gateway'
  },

  // 3. Cyber Threat Intelligence, Web Abuse & Security Feeds
  {
    id: 'abuseipdb',
    name: 'AbuseIPDB Threat Intelligence',
    domain: 'abuseipdb.com',
    description: 'Crowdsourced global cyber threat database reporting active SSH/FTP brute force, web vulnerability scans, port scans, and DDoS abuse.',
    delistUrl: 'https://www.abuseipdb.com/check/',
    category: 'Threat Intel'
  },
  {
    id: 'virustotal',
    name: 'VirusTotal Multi-Engine Scanner',
    domain: 'virustotal.com',
    description: 'Aggregates 80+ security engines to scan IP addresses for associated malware binaries, phishing URLs, and botnet command channels.',
    delistUrl: 'https://www.virustotal.com/gui/ip-address/',
    category: 'Threat Intel'
  },
  {
    id: 'alienvault',
    name: 'AlienVault OTX (Open Threat Exchange)',
    domain: 'otx.alienvault.com',
    description: 'AT&T Cybersecurity crowd-sourced threat exchange tracking Indicators of Compromise (IOCs), threat pulses, and malicious activity.',
    delistUrl: 'https://otx.alienvault.com/indicator/ip/',
    category: 'Threat Intel'
  },
  {
    id: 'cleantalk',
    name: 'CleanTalk Anti-Spam Blacklist',
    domain: 'cleantalk.org',
    description: 'Detects web forum spambots, malicious registration scripts, contact form abuse, and brute-force web spam.',
    delistUrl: 'https://cleantalk.org/blacklists/',
    category: 'Web Abuse'
  },
  {
    id: 'stopforumspam',
    name: 'StopForumSpam Database',
    domain: 'stopforumspam.com',
    description: 'Community-driven registry of IP addresses, emails, and usernames engaged in automated forum spam and comment injection.',
    delistUrl: 'https://www.stopforumspam.com/search',
    category: 'Web Abuse'
  },
  {
    id: 'projecthoneypot',
    name: 'Project Honey Pot Harvester Network',
    domain: 'projecthoneypot.org',
    description: 'Distributed honeypot sensor network detecting email harvesters, dictionary attackers, and comment spammers in real time.',
    delistUrl: 'https://www.projecthoneypot.org/ip_',
    category: 'Web Abuse'
  },
  {
    id: 'greynoise',
    name: 'GreyNoise Threat Telemetry',
    domain: 'greynoise.io',
    description: 'Analyzes internet-wide scan traffic to distinguish benign security scanners (e.g. Shodan) from targeted malicious scanning campaigns.',
    delistUrl: 'https://viz.greynoise.io/ip/',
    category: 'Threat Intel'
  },
  {
    id: 'shadowserver',
    name: 'Shadowserver Foundation',
    domain: 'shadowserver.org',
    description: 'Non-profit internet security reporting tracking infected botnet nodes, open DNS/NTP amplifiers, and compromised enterprise servers.',
    delistUrl: 'https://www.shadowserver.org/',
    category: 'Threat Intel'
  },
  {
    id: 'surbl',
    name: 'SURBL Web URI Blacklist',
    domain: 'surbl.org',
    description: 'Tracks websites, domains, and IP endpoints that appear within the body of unsolicited bulk emails or phishing campaigns.',
    delistUrl: 'https://www.surbl.org/surbl-analysis',
    category: 'Web Abuse'
  },
  {
    id: 'uribl',
    name: 'URIBL Realtime URI Blacklist',
    domain: 'uribl.com',
    description: 'Real-time database listing web domains and IP hosting nodes identified in active unsolicited bulk email text.',
    delistUrl: 'https://admin.uribl.com/',
    category: 'Web Abuse'
  }
];

const BLACKLIST_GUIDES: Record<string, { name: string; url: string; steps: string[]; description: string; category?: string }> = {
  spamhaus: {
    name: 'Spamhaus ZEN',
    url: 'https://www.spamhaus.org/lookup/',
    category: 'DNSBL Standard',
    description: 'The premier global IP reputation authority. If listed here, SMTP mail delivery will fail at 90%+ of mail servers worldwide.',
    steps: [
      'Navigate to the Spamhaus IP Address Lookup Tool.',
      'Check if the listing is an SBL (spam source), XBL (exploit/malware), or PBL (policy dynamic IP).',
      'If XBL, scan your server immediately for active outbound spam scripts, botnet infections, or open relays.',
      'If PBL, verify you are not attempting to send mail directly from a consumer/dynamic broadband range (use an authenticated SMTP Smarthost instead).',
      'Ensure your reverse DNS (rDNS) PTR record matches your forward mail domain (A record).',
      'Submit the removal form once the underlying threat has been resolved.'
    ]
  },
  barracuda: {
    name: 'Barracuda BRBL',
    url: 'https://www.barracudacentral.org/rbl/removal-request',
    category: 'DNSBL Standard',
    description: 'Managed by Barracuda Networks. Affects delivery to enterprise organizations utilizing Barracuda ESG security appliances.',
    steps: [
      'Visit the Barracuda Reputation System removal request portal.',
      'Identify whether the block is due to high volume, bad reputation, or suspicious connection bursts.',
      'Ensure your server has valid SPF, DKIM, and DMARC records set up.',
      'Confirm there are no backscatter (NDR) loops sending messages to invalid addresses.',
      'Apply for delisting via their online removal request form.'
    ]
  },
  spamcop: {
    name: 'SpamCop',
    url: 'https://www.spamcop.net/bl.shtml',
    category: 'DNSBL Standard',
    description: 'An aggressive, dynamic reporting-based blocklist. Listings are time-sensitive and usually expire automatically in 24-48 hours once spam stops.',
    steps: [
      'Access the SpamCop IP lookup form to see the specific spam report frequency and timeline.',
      'Investigate outbound mail headers at the reported time to identify the compromised inbox or web form.',
      'Implement strict outbound rate limits on your mail system.',
      'Wait for the listing to self-expire once spam reports cease, or request early mitigation.'
    ]
  },
  googlepostmaster: {
    name: 'Google Postmaster & Gmail Deliverability',
    url: 'https://support.google.com/mail/contact/bulk_send_new',
    category: 'Mail Gateway',
    description: 'Google Gmail IP/Domain sender reputation system. Listings cause emails to land in Gmail spam folders or get throttled with 421 4.7.0 errors.',
    steps: [
      'Add your domain and IP ranges to Google Postmaster Tools (postmaster.google.com) using TXT DNS verification.',
      'Ensure your spam complaint rate is strictly below 0.10% (never exceed 0.30%).',
      'Validate that 100% of outgoing messages have SPF, DKIM, and DMARC alignment.',
      'Include a one-click List-Unsubscribe header in all bulk or marketing messages.',
      'Submit the Gmail Sender Contact Form if messages are still rejected after configuration.'
    ]
  },
  microsoftsnds: {
    name: 'Microsoft SNDS & Outlook Delist Portal',
    url: 'https://olcsupport.office.com/',
    category: 'Mail Gateway',
    description: 'Microsoft Smart Network Data Services protects Outlook.com, Hotmail, and Office365 inboxes. Blocks result in 550 5.7.1 Service Unavailable errors.',
    steps: [
      'Log into Microsoft SNDS (sendersupport.olc.protection.outlook.com/snds) to view automated spam trap hits and complaint rates.',
      'Sign up for the Junk Email Reporting Program (JERP) feedback loop.',
      'Verify that reverse DNS (PTR) is fully valid and matches your HELO/EHLO hostname.',
      'Visit the Microsoft Sender Information Delist Form (olcsupport.office.com) and submit your IP addresses, server details, and mitigation notes.',
      'Monitor your support ticket email for confirmation from the Outlook Deliverability team.'
    ]
  },
  yahoopostmaster: {
    name: 'Yahoo Mail & AOL Postmaster Hub',
    url: 'https://senders.yahooinc.com/contact-us/',
    category: 'Mail Gateway',
    description: 'Yahoo and AOL Sender Hub. Listings result in 421 4.7.0 Deferred or 553 5.7.1 error codes.',
    steps: [
      'Check sending health on Yahoo Sender Hub (senders.yahooinc.com).',
      'Register for the Yahoo Complaint Feedback Loop (CFL).',
      'Ensure DKIM is signed with a minimum 2048-bit key and DMARC policy is published.',
      'Submit a remediation request via the Yahoo Sender Support Contact Form.'
    ]
  },
  ciscotalos: {
    name: 'Cisco Talos Intelligence (SenderBase)',
    url: 'https://talosintelligence.com/reputation_center',
    category: 'Mail Gateway',
    description: 'Cisco Email Security Appliance (ESA) threat rating. Flags IP addresses with Poor or Neutral reputation scores.',
    steps: [
      'Search your IP on Talos Intelligence Reputation Center (talosintelligence.com).',
      'Review the email volume history and web category classifications.',
      'If flagged for Spam or Malware, investigate local servers for unauthorized SMTP activity.',
      'Create a Cisco Talos account and submit an IP Reputation Dispute Ticket.'
    ]
  },
  abuseipdb: {
    name: 'AbuseIPDB Threat Intelligence',
    url: 'https://www.abuseipdb.com/check/',
    category: 'Threat Intel',
    description: 'Crowdsourced cyber threat registry tracking brute force SSH, port scanning, and automated attack bots.',
    steps: [
      'Look up your IP on AbuseIPDB to inspect individual user abuse reports and timestamps.',
      'Identify which port/protocol was reported (e.g. port 22 SSH brute-force, port 25 SMTP relay, port 80/443 web exploit).',
      'Secure the vulnerable service by enforcing SSH key authentication, installing Fail2ban, and closing open ports.',
      'Claim ownership of your IP/subnet on AbuseIPDB and submit a dispute or false-positive report.'
    ]
  },
  virustotal: {
    name: 'VirusTotal Multi-Engine Intelligence',
    url: 'https://www.virustotal.com/gui/ip-address/',
    category: 'Threat Intel',
    description: 'Multi-engine scanner aggregating 80+ antivirus and threat intelligence vendors (Kaspersky, Sophos, Fortinet, etc.).',
    steps: [
      'Query your IP address on VirusTotal to view which specific security engines flagged the IP.',
      'Check the Relations tab for associated malware hashes, phishing domains, or malicious URLs.',
      'Clean any compromised web scripts or malware binaries hosted on the server.',
      'Contact individual flagging vendors (e.g. Fortinet, CRDF, Dr.Web) through their false-positive dispute forms.'
    ]
  },
  cleantalk: {
    name: 'CleanTalk Anti-Spam Blacklist',
    url: 'https://cleantalk.org/blacklists/',
    category: 'Web Abuse',
    description: 'Blocks IP addresses that submit automated spam comments, web form bots, and malicious website registrations.',
    steps: [
      'Search your IP on the CleanTalk Blacklist Database.',
      'Inspect the reported spam activity log and targeted website CMS platforms.',
      'Audit your network for malware or bots submitting spam form payloads.',
      'Click the "Delist" button on CleanTalk and complete the one-click delisting confirmation.'
    ]
  },
  stopforumspam: {
    name: 'StopForumSpam Database',
    url: 'https://www.stopforumspam.com/search',
    category: 'Web Abuse',
    description: 'Global forum spam and bot registration registry used by millions of web bulletin boards and community portals.',
    steps: [
      'Query your IP on the StopForumSpam search page to view the frequency and last activity timestamp.',
      'Verify that users on your network are not running automated forum account creators.',
      'Submit a removal request on the StopForumSpam Removal page.'
    ]
  },
  proofpoint: {
    name: 'Proofpoint Dynamic Reputation (PDR)',
    url: 'https://ipcheck.proofpoint.com/',
    category: 'Mail Gateway',
    description: 'Filters incoming emails for Fortune 500 companies. Blocks result in 554 5.7.1 Refused on Proofpoint gateways.',
    steps: [
      'Visit the Proofpoint Dynamic Reputation IP Lookup Tool (ipcheck.proofpoint.com).',
      'Check if your sending IP is actively blocked.',
      'Ensure high volume burst emails are smoothly throttled and opt-in verified.',
      'Submit the online delisting request form directly on the Proofpoint portal.'
    ]
  },
  sorbs: {
    name: 'SORBS Aggregate',
    url: 'http://www.sorbs.net/lookup.shtml',
    category: 'DNSBL Standard',
    description: 'Provides lists categorized by vulnerability type (HTTP proxy, SMTP relay, compromised dial-up, etc.).',
    steps: [
      'Log into the SORBS Support System (requires a free account).',
      'Query your listed IP address to find the exact database sub-list (e.g., DUHL, Spam, Proxy).',
      'Fix any open proxy ports (8080, 1080, 3128) or open SMTP relays on your server.',
      'Submit a Support Ticket / Delisting Request through the SORBS interface.'
    ]
  },
  ivmsip: {
    name: 'Invaluement ivmSIP',
    url: 'https://www.invaluement.com/lookup/',
    category: 'DNSBL Standard',
    description: 'A respected anti-spam database tracking high-emission spam IP addresses, particularly targeting snowshoe spam operations.',
    steps: [
      'Visit the Invaluement IP lookup utility page.',
      'Provide your IP address to check if it is actively listed on ivmSIP.',
      'Verify that your server is not hosting any snowshoe spam setups or unauthenticated bulk mail-sending services.',
      'Ensure proper reverse DNS PTR records, SPF, and DKIM parameters are configured on your outbound mail domains.',
      'Submit a removal request on Invaluement’s website if your system is verified clean.'
    ]
  },
  spamrats: {
    name: 'SpamRats Spam & Dyna',
    url: 'https://www.spamrats.com/',
    category: 'DNSBL Standard',
    description: 'SpamRats detects mail-sending IP addresses that violate basic setup standards, emit spam, or have bad reverse DNS settings.',
    steps: [
      'Go to the SpamRats lookup tool to check your listing details.',
      'Check if your IP address is flagged under RATS-Spam (active spam emitting), RATS-Dyna (dynamic IP range), or RATS-NoPTR (missing or invalid reverse DNS).',
      'Set up a valid, fully qualified domain name (FQDN) as your reverse DNS (PTR) record.',
      'Audit your server to ensure it is not acting as an open SMTP relay or open proxy.',
      'Submit a delisting request via the SpamRats removal mechanism once configuration errors are resolved.'
    ]
  },
  blocklist: {
    name: 'Blocklist.de Security Defense',
    url: 'https://www.blocklist.de/en/search.html',
    category: 'Security',
    description: 'Real-time security reporting service. Lists malicious IPs participating in SSH, Mail, FTP, and Web attacks.',
    steps: [
      'Search your IP on Blocklist.de to see specific attack reports (SSH brute force, Postfix auth failure, etc.).',
      'Check local firewall and auth.log to terminate compromised background processes.',
      'Delistings expire automatically after 48 hours without attacks, or request early delist via their web portal.'
    ]
  },
  cbl: {
    name: 'CBL (Composite Blocking List)',
    url: 'https://www.abuseat.org/lookup.xhtml',
    category: 'DNSBL Standard',
    description: 'Monitors machines emitting spam, brute force attacks, or acting as open relays or botnet nodes.',
    steps: [
      'Access the CBL lookup tool and read the detailed listing diagnostics provided for your IP.',
      'Ensure the server is not infected with stealth trojans or participating in DDoS attacks.',
      'Close any unauthenticated open mail relay ports (port 25).',
      'Follow the on-screen self-removal procedure after sealing all leaks.'
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
  const [activeTab, setActiveTab] = useState<'supertool' | 'dashboard' | 'monitoring' | 'guides' | 'providers' | 'history' | 'users' | 'settings'>('supertool');
  const [searchQuery, setSearchQuery] = useState('');
  const [filterStatus, setFilterStatus] = useState<'all' | 'clean' | 'listed'>('all');
  const [filterAction, setFilterAction] = useState<string>('all');

  // Inline Note Editor States
  const [noteText, setNoteText] = useState('');
  const [actionStatusVal, setActionStatusVal] = useState<'unresolved' | 'pending' | 'resolved' | 'monitoring' | 'ignored'>('unresolved');
  const [inspectorTab, setInspectorTab] = useState<'listed' | 'all'>('listed');

  // Report Analysis Filter States
  const [reportFilter, setReportFilter] = useState<'all' | 'listed' | 'clean'>('listed');
  const [blacklistSearch, setBlacklistSearch] = useState('');
  const [selectedGuideProvider, setSelectedGuideProvider] = useState<{ id: string; name: string; delistUrl: string; reason?: string; domain?: string } | null>(null);

  // Auto-sync selectedIP when report changes
  useEffect(() => {
    if (report && report.results && report.results.length > 0) {
      if (!selectedIP || !report.results.some(r => r.ip === selectedIP.ip)) {
        setSelectedIP(report.results[0]);
      }
    }
  }, [report]);

  const getRecommendedAction = (providerId: string, providerName: string, isListed: boolean, reasonText: string) => {
    if (!isListed) {
      return 'No action required. Host IP is clean and in good standing with this provider.';
    }
    const pid = providerId.toLowerCase();
    if (pid.includes('spamhaus')) {
      return '1. Inspect outgoing mail server queues for unauthorized bulk sending.\n2. Fix PTR/rDNS record to match host domain.\n3. Request delisting via Spamhaus IP Query portal.';
    }
    if (pid.includes('barracuda')) {
      return '1. Verify port 25 is not open to public relays.\n2. Scan host for botnet/malware infections.\n3. Submit removal request at Barracuda Central Reputation System.';
    }
    if (pid.includes('spamcop')) {
      return '1. Stop active spam or newsletter emissions hitting spam trap addresses.\n2. Ensure SPF and DKIM records are valid.\n3. SpamCop listings auto-expire after 24-48 hours once spam stops.';
    }
    if (pid.includes('uceprotect')) {
      return '1. Ensure no single host on your subnet is sending high-volume spam.\n2. Level 1 auto-expires after 7 days without new hits.';
    }
    if (pid.includes('sorbs')) {
      return '1. Check for open mail relays or proxy ports (socks/http).\n2. Register an account on SORBS Support system to request delisting.';
    }
    if (pid.includes('blocklist')) {
      return '1. Host performed failed SSH/FTP brute-force attempts.\n2. Audit server security logs, change compromised credentials, and clear fail2ban blocks.';
    }
    if (pid.includes('noptr') || pid.includes('spamrats')) {
      return '1. Configure a valid Reverse DNS (PTR) record pointing your IP to a fully qualified domain name (FQDN).\n2. Request removal on SpamRats web lookup.';
    }
    return `1. Review traffic logs for abuse originating from this IP.\n2. Remediate root cause and visit ${providerName} removal portal to request delisting.`;
  };

  // Helper to trigger alert banners
  const triggerAlert = (type: 'success' | 'error' | 'info' | 'warning', message: string) => {
    setAlert({ type, message });
    setTimeout(() => setAlert(null), 4500);
  };

  // Enforce pure Light Mode
  useEffect(() => {
    localStorage.removeItem('wolast_shield_theme');
    document.documentElement.classList.remove('dark');
    document.body.classList.remove('dark-active');
  }, []);

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
      <div className="min-h-screen bg-slate-50 text-slate-900 flex items-center justify-center">
        <div className="text-center space-y-4">
          <Loader2 className="w-10 h-10 animate-spin text-blue-600 mx-auto" />
          <p className="text-xs font-extrabold text-slate-400 uppercase tracking-widest">
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
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col font-sans animate-fade-in" id="app-root">
      
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
              onClick={() => setActiveTab('supertool')}
              className={`pb-1 transition-all cursor-pointer flex items-center gap-1.5 border-b-2 ${
                activeTab === 'supertool' ? 'text-red-500 border-red-500 font-extrabold' : 'border-transparent hover:text-white'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              SuperTool Check
            </button>
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
        
        {/* TAB 0: SUPERTOOL BLACKLIST INSPECTOR */}
        {activeTab === 'supertool' && (
          <SuperToolInspector
            currentUser={userProfile}
            triggerAlert={triggerAlert}
            initialTarget="163.128.141.8"
            onNavigateToMonitoring={() => setActiveTab('monitoring')}
          />
        )}

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
              <section className="xl:w-[380px] w-full bg-white p-6 sm:p-7 rounded-2xl cyber-card flex flex-col justify-between gap-5 transition-all duration-300 border border-slate-200 shadow-md relative overflow-hidden before:absolute before:top-0 before:left-0 before:right-0 before:h-1 before:bg-gradient-to-r before:from-red-600 before:to-amber-500">
                <div>
                  <h3 className="text-xs font-black text-slate-900 uppercase tracking-widest">Subnet Reputation Index</h3>
                  <p className="text-[10px] text-slate-500 font-bold uppercase tracking-wider mt-0.5">Summary of evaluated network assets</p>
                </div>

                <div className="grid grid-cols-3 gap-3 py-1">
                  <div className="text-center py-3 px-2 bg-slate-50 rounded-xl border border-slate-200 shadow-xs">
                    <p className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Total IPs</p>
                    <p className="text-2xl font-black text-slate-900 font-mono mt-1">
                      {report ? report.totalIPs : '0'}
                    </p>
                  </div>
                  <div className="text-center py-3 px-2 bg-rose-50/70 rounded-xl border border-rose-200/80 shadow-xs">
                    <p className="text-[10px] uppercase font-extrabold text-rose-700 tracking-wider">Listed</p>
                    <p className="text-2xl font-black text-rose-600 font-mono mt-1">
                      {report ? report.listedCount : '0'}
                    </p>
                  </div>
                  <div className="text-center py-3 px-2 bg-emerald-50/70 rounded-xl border border-emerald-200/80 shadow-xs">
                    <p className="text-[10px] uppercase font-extrabold text-emerald-700 tracking-wider">Clean</p>
                    <p className="text-2xl font-black text-emerald-600 font-mono mt-1">
                      {report ? report.cleanCount : '0'}
                    </p>
                  </div>
                </div>

                <div className="bg-slate-100/90 px-4 py-3 rounded-xl border border-slate-200 flex items-center justify-between text-xs text-slate-700 font-black uppercase tracking-wider shadow-xs">
                  <span>Reputation Status:</span>
                  <span className={`px-2.5 py-1 rounded-md font-mono font-black text-xs ${
                    healthScore >= 95 
                      ? 'bg-emerald-100 text-emerald-800 border border-emerald-200' 
                      : healthScore >= 80 
                      ? 'bg-amber-100 text-amber-800 border border-amber-200' 
                      : 'bg-rose-100 text-rose-800 border border-rose-200'
                  }`}>
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
                  <div className="bg-white rounded-2xl p-6 cyber-card flex flex-col justify-between text-center relative overflow-hidden min-h-[220px] shadow-sm hover:shadow-md transition-all duration-300 border border-slate-200 before:absolute before:top-0 before:left-0 before:right-0 before:h-1 before:bg-slate-900">
                    <div className="flex justify-between items-start">
                      <div className="bg-slate-100 rounded-lg p-2 border border-slate-200 shadow-xs">
                        <Shield className="w-4 h-4 text-red-600" />
                      </div>
                      <span className="text-[10px] bg-slate-100 text-slate-700 px-2.5 py-0.8 rounded-lg font-black uppercase tracking-widest border border-slate-200 shadow-xs">
                        Health Meter
                      </span>
                    </div>
                    
                    {/* SVG Radial Progress Ring */}
                    <div className="relative w-22 h-22 mx-auto my-1">
                      <svg className="w-full h-full transform -rotate-90">
                        <circle 
                          cx="44" cy="44" r="34" 
                          className="text-slate-100" 
                          strokeWidth="7" stroke="currentColor" fill="transparent" 
                        />
                        <circle 
                          cx="44" cy="44" r="34" 
                          className={
                            healthScore >= 95 ? "text-emerald-500" :
                            healthScore >= 80 ? "text-amber-500" : "text-rose-500"
                          } 
                          strokeWidth="7" strokeDasharray={2 * Math.PI * 34} 
                          strokeDashoffset={2 * Math.PI * 34 * (1 - healthScore / 100)} 
                          strokeLinecap="round" stroke="currentColor" fill="transparent" 
                        />
                      </svg>
                      <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <span className={`text-xl font-black font-mono ${
                          healthScore >= 95 ? 'text-emerald-600' : healthScore >= 80 ? 'text-amber-600' : 'text-rose-600'
                        }`}>
                          {healthScore}%
                        </span>
                        <span className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">Clean</span>
                      </div>
                    </div>

                    <div className="text-left mt-1">
                      <h3 className="text-xs font-black text-slate-900 uppercase tracking-widest">Subnet Rep Score</h3>
                      <p className="text-[11px] text-slate-500 font-medium mt-0.5">Ratio of clean, non-blacklisted assets.</p>
                    </div>
                  </div>

                  {/* Metric 2: Scanned Total Assets */}
                  <div className="bg-white rounded-2xl p-6 cyber-card flex flex-col justify-between min-h-[220px] shadow-sm hover:shadow-md transition-all duration-300 border border-slate-200 before:absolute before:top-0 before:left-0 before:right-0 before:h-1 before:bg-slate-900">
                    <div className="flex justify-between items-start">
                      <div className="bg-slate-100 rounded-lg p-2 border border-slate-200 shadow-xs">
                        <Database className="w-4 h-4 text-slate-800" />
                      </div>
                      {simulate && (
                        <span className="text-[10px] bg-red-500/10 text-red-600 px-2.5 py-0.8 rounded-lg font-black uppercase tracking-widest border border-red-500/20 shadow-xs">Demo</span>
                      )}
                    </div>
                    <div className="my-auto pt-2 pb-1">
                      <span className="text-4xl sm:text-5xl font-black text-slate-900 font-mono block leading-none tracking-tight">{report.totalIPs}</span>
                      <span className="text-xs font-black text-slate-900 uppercase tracking-widest block mt-3">Scanned Nodes</span>
                    </div>
                    <div>
                      <p className="text-[11px] text-slate-500 font-medium leading-relaxed">Total active host IPs evaluated within target scope.</p>
                    </div>
                  </div>

                  {/* Metric 3: Listed Threats */}
                  <div className={`bg-white rounded-2xl p-6 cyber-card flex flex-col justify-between min-h-[220px] shadow-sm hover:shadow-md transition-all duration-300 border border-slate-200 relative overflow-hidden before:absolute before:top-0 before:left-0 before:right-0 before:h-1 ${report.listedCount > 0 ? 'before:bg-rose-600 border-l-4 border-l-rose-600' : 'before:bg-emerald-500'}`}>
                    <div className="flex justify-between items-start">
                      <div className="bg-rose-50 rounded-lg p-2 border border-rose-200 shadow-xs">
                        <ShieldAlert className="w-4 h-4 text-rose-600" />
                      </div>
                      {report.listedCount > 0 ? (
                        <span className="text-[10px] bg-rose-100 text-rose-800 px-2.5 py-0.8 rounded-lg font-black uppercase tracking-widest flex items-center gap-1.5 border border-rose-200 shadow-xs">
                          <span className="w-2 h-2 rounded-full bg-rose-600 animate-ping" />
                          Action Req.
                        </span>
                      ) : (
                        <span className="text-[10px] bg-emerald-100 text-emerald-800 px-2.5 py-0.8 rounded-lg font-black uppercase tracking-widest border border-emerald-200 shadow-xs">Secure</span>
                      )}
                    </div>
                    <div className="my-auto pt-2 pb-1">
                      <span className={`text-4xl sm:text-5xl font-black font-mono block leading-none tracking-tight ${report.listedCount > 0 ? 'text-rose-600' : 'text-slate-900'}`}>{report.listedCount}</span>
                      <span className="text-xs font-black text-slate-900 uppercase tracking-widest block mt-3">Blacklisted IPs</span>
                    </div>
                    <div>
                      <p className="text-[11px] text-slate-500 font-medium leading-relaxed">IP nodes actively reported in one or more DNSBL blocklists.</p>
                    </div>
                  </div>

                  {/* Metric 4: Total Blacklist Registrations */}
                  <div className="bg-white rounded-2xl p-6 cyber-card flex flex-col justify-between min-h-[220px] shadow-sm hover:shadow-md transition-all duration-300 border border-slate-200 before:absolute before:top-0 before:left-0 before:right-0 before:h-1 before:bg-slate-900">
                    <div className="flex justify-between items-start">
                      <div className="bg-slate-100 rounded-lg p-2 border border-slate-200 shadow-xs">
                        <Sliders className="w-4 h-4 text-slate-800" />
                      </div>
                      <span className="text-[10px] bg-slate-100 text-slate-700 px-2.5 py-0.8 rounded-lg font-black uppercase tracking-widest border border-slate-200 shadow-xs">
                        {BLACKLIST_PROVIDERS.length} RBLs
                      </span>
                    </div>
                    <div className="my-auto pt-2 pb-1">
                      <span className={`text-4xl sm:text-5xl font-black font-mono block leading-none tracking-tight ${totalListingsCount > 0 ? 'text-amber-600' : 'text-slate-900'}`}>{totalListingsCount}</span>
                      <span className="text-xs font-black text-slate-900 uppercase tracking-widest block mt-3">RBL Registrations</span>
                    </div>
                    <div>
                      <p className="text-[11px] text-slate-500 font-medium leading-relaxed">Aggregated count of listings across all providers.</p>
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

                {/* 2. Primary Scan results & Complete MXToolbox Blacklist Analysis Report */}
                <div className="space-y-6" id="results-inspector-panel">
                  
                  {/* Complete IP Blacklist Analysis Report Header & Selector */}
                  {selectedIP && (
                    <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm space-y-5">
                      
                      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-200 pb-5">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="bg-slate-900 text-white text-[10px] font-black uppercase tracking-widest px-2.5 py-1 rounded-md">
                              MXToolbox IP Blacklist Analysis Report
                            </span>
                            <span className="text-slate-400 text-xs font-semibold">
                              Target: <strong className="text-slate-900 font-mono">{report.target}</strong>
                            </span>
                          </div>
                          <h2 className="text-xl font-black text-slate-900 mt-1 flex items-center gap-2">
                            <span>Blacklist Report for <span className="font-mono text-red-600">{selectedIP.ip}</span></span>
                          </h2>
                        </div>

                        {/* Subnet / IP Selector Dropdown */}
                        {report.results.length > 1 && (
                          <div className="flex items-center gap-2 bg-slate-50 p-2 rounded-xl border border-slate-200">
                            <label className="text-xs font-bold text-slate-600 uppercase tracking-wider">Inspect IP in Block:</label>
                            <select
                              value={selectedIP.ip}
                              onChange={(e) => {
                                const found = report.results.find(r => r.ip === e.target.value);
                                if (found) handleSelectIP(found);
                              }}
                              className="bg-white border border-slate-300 text-xs font-mono font-bold px-3 py-1.5 rounded-lg text-slate-900 focus:outline-hidden focus:ring-2 focus:ring-red-500 cursor-pointer"
                            >
                              {report.results.map(r => (
                                <option key={r.ip} value={r.ip}>
                                  {r.ip} {r.listedCount > 0 ? `(LISTED: ${r.listedCount})` : '(CLEAN)'}
                                </option>
                              ))}
                            </select>
                          </div>
                        )}
                      </div>

                      {/* Required Metadata Fields Grid */}
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                        <div className="bg-slate-50 p-3.5 rounded-xl border border-slate-200 space-y-1">
                          <span className="text-[10px] text-slate-400 font-extrabold uppercase tracking-wider block">IP Address</span>
                          <span className="font-mono font-black text-slate-900 text-sm block truncate">{selectedIP.ip}</span>
                        </div>

                        <div className="bg-slate-50 p-3.5 rounded-xl border border-slate-200 space-y-1">
                          <span className="text-[10px] text-slate-400 font-extrabold uppercase tracking-wider block">Reverse DNS (PTR)</span>
                          <span className="font-mono font-bold text-slate-800 text-xs block truncate" title={selectedIP.ptr || selectedIP.location?.ptr || 'No PTR Record Found'}>
                            {selectedIP.ptr || selectedIP.location?.ptr || 'No PTR Record Found'}
                          </span>
                        </div>

                        <div className="bg-slate-50 p-3.5 rounded-xl border border-slate-200 space-y-1">
                          <span className="text-[10px] text-slate-400 font-extrabold uppercase tracking-wider block">Hostname</span>
                          <span className="font-mono font-bold text-slate-800 text-xs block truncate" title={selectedIP.hostname || selectedIP.location?.hostname || selectedIP.ip}>
                            {selectedIP.hostname || selectedIP.location?.hostname || selectedIP.ip}
                          </span>
                        </div>

                        <div className="bg-slate-50 p-3.5 rounded-xl border border-slate-200 space-y-1">
                          <span className="text-[10px] text-slate-400 font-extrabold uppercase tracking-wider block">ISP / Organization</span>
                          <span className="font-bold text-slate-800 text-xs block truncate" title={`${selectedIP.isp || selectedIP.location?.isp || 'Unknown ISP'} / ${selectedIP.org || selectedIP.location?.org || selectedIP.isp || 'N/A'}`}>
                            {selectedIP.isp || selectedIP.location?.isp || 'Unknown ISP'}
                          </span>
                          <span className="text-[10px] text-slate-500 truncate block font-semibold">
                            Org: {selectedIP.org || selectedIP.location?.org || selectedIP.isp || 'N/A'}
                          </span>
                        </div>

                        <div className="bg-slate-50 p-3.5 rounded-xl border border-slate-200 space-y-1">
                          <span className="text-[10px] text-slate-400 font-extrabold uppercase tracking-wider block">Autonomous System (ASN)</span>
                          <span className="font-bold text-slate-800 text-xs block truncate" title={selectedIP.asn || selectedIP.location?.asn || 'AS0 (Unknown)'}>
                            {selectedIP.asn || selectedIP.location?.asn || 'AS0 (Unknown)'}
                          </span>
                        </div>

                        <div className="bg-slate-50 p-3.5 rounded-xl border border-slate-200 space-y-1">
                          <span className="text-[10px] text-slate-400 font-extrabold uppercase tracking-wider block">Country / Location</span>
                          <span className="font-bold text-slate-800 text-xs flex items-center gap-1.5 truncate">
                            <Globe className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                            {selectedIP.country || (selectedIP.location?.country ? `${selectedIP.location.country} (${selectedIP.location.countryCode})` : 'Unknown Country')}
                          </span>
                        </div>

                        <div className="col-span-1 md:col-span-2 bg-slate-50 p-3.5 rounded-xl border border-slate-200 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                          <div>
                            <span className="text-[10px] text-slate-400 font-extrabold uppercase tracking-wider block">Overall Blacklist Status</span>
                            <span className="text-xs text-slate-600 font-bold">
                              Checked across <strong>{BLACKLIST_PROVIDERS.length}</strong> DNSBL provider databases
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            {selectedIP.listedCount > 0 ? (
                              <span className="bg-rose-600 text-white font-extrabold text-xs px-3 py-1.5 rounded-lg tracking-wide uppercase shadow-sm">
                                LISTED ON {selectedIP.listedCount} BLACKLISTS
                              </span>
                            ) : (
                              <span className="bg-emerald-600 text-white font-extrabold text-xs px-3 py-1.5 rounded-lg tracking-wide uppercase shadow-sm">
                                CLEAN / NOT LISTED
                              </span>
                            )}
                            <button
                              onClick={() => downloadCSVReport(report)}
                              className="bg-white border border-slate-300 hover:border-slate-400 text-slate-800 font-bold text-xs px-3 py-1.5 rounded-lg shadow-xs transition-all flex items-center gap-1 cursor-pointer"
                              title="Export CSV"
                            >
                              <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-600" />
                              CSV
                            </button>
                            <button
                              onClick={() => downloadJSONReport(report)}
                              className="bg-white border border-slate-300 hover:border-slate-400 text-slate-800 font-bold text-xs px-3 py-1.5 rounded-lg shadow-xs transition-all flex items-center gap-1 cursor-pointer"
                              title="Export JSON"
                            >
                              <FileText className="w-3.5 h-3.5 text-slate-600" />
                              JSON
                            </button>
                          </div>
                        </div>
                      </div>

                    </div>
                  )}

                  {/* Subnet CIDR Block Analysis Table (For Subnet/Range Searches) */}
                  {report.results.length > 1 && (
                    <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm space-y-0">
                      <div className="p-4 border-b border-slate-200 bg-slate-50/70 flex justify-between items-center">
                        <div>
                          <h3 className="text-sm font-black text-slate-900 uppercase tracking-widest">Subnet CIDR Block Analysis ({report.target})</h3>
                          <p className="text-[11px] text-slate-500 font-semibold">
                            Full breakdown of all {report.results.length} IP addresses in subnet
                          </p>
                        </div>
                        <span className="bg-slate-100 text-slate-700 text-xs font-bold px-3 py-1 rounded-lg border border-slate-200">
                          {report.listedCount} Listed / {report.cleanCount} Clean
                        </span>
                      </div>

                      <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse text-xs">
                          <thead>
                            <tr className="bg-slate-100/70 border-b border-slate-200 text-slate-600 font-black uppercase tracking-wider text-[10px]">
                              <th className="py-3 px-4">IP Address</th>
                              <th className="py-3 px-4">Reverse DNS (PTR)</th>
                              <th className="py-3 px-4">ISP / Organization</th>
                              <th className="py-3 px-4">Country</th>
                              <th className="py-3 px-4">Status</th>
                              <th className="py-3 px-4">Flagged Blacklists</th>
                              <th className="py-3 px-4 text-right">Action</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-150 font-medium text-slate-800">
                            {report.results.map((r) => {
                              const isSelected = selectedIP?.ip === r.ip;
                              const flaggedList = Object.entries(r.listings)
                                .filter(([_, data]) => (data as any).listed)
                                .map(([id]) => {
                                  const p = BLACKLIST_PROVIDERS.find(bp => bp.id === id);
                                  return p ? p.name : id.toUpperCase();
                                });

                              return (
                                <tr 
                                  key={r.ip}
                                  className={`hover:bg-slate-50 transition-colors ${isSelected ? 'bg-red-500/5 font-bold' : ''}`}
                                >
                                  <td className="py-3.5 px-4 font-mono font-bold text-slate-900">{r.ip}</td>
                                  <td className="py-3.5 px-4 font-mono text-slate-600 text-xs">{r.ptr || r.location?.ptr || 'No PTR Record'}</td>
                                  <td className="py-3.5 px-4 text-slate-700 font-medium">{r.isp || r.location?.isp || 'Unknown ISP'}</td>
                                  <td className="py-3.5 px-4 text-slate-700">{r.country || (r.location?.countryCode ? `${r.location.city}, ${r.location.countryCode}` : 'N/A')}</td>
                                  <td className="py-3.5 px-4">
                                    {r.status === 'clean' ? (
                                      <span className="bg-emerald-100 text-emerald-800 text-[10px] font-extrabold px-2 py-0.5 rounded border border-emerald-200 uppercase">Clean</span>
                                    ) : (
                                      <span className="bg-rose-100 text-rose-800 text-[10px] font-extrabold px-2 py-0.5 rounded border border-rose-200 uppercase">Listed ({r.listedCount})</span>
                                    )}
                                  </td>
                                  <td className="py-3.5 px-4 font-mono text-xs">
                                    {flaggedList.length > 0 ? (
                                      <span className="text-red-600 font-bold">{flaggedList.join(', ')}</span>
                                    ) : (
                                      <span className="text-slate-400">-</span>
                                    )}
                                  </td>
                                  <td className="py-3.5 px-4 text-right">
                                    <button
                                      onClick={() => {
                                        handleSelectIP(r);
                                        const el = document.getElementById('results-inspector-panel');
                                        if (el) el.scrollIntoView({ behavior: 'smooth' });
                                      }}
                                      className="bg-slate-900 hover:bg-slate-800 text-white font-bold text-[10px] uppercase tracking-wider px-3 py-1.5 rounded-lg transition-all cursor-pointer"
                                    >
                                      Inspect Report ↗
                                    </button>
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {/* Mitigation Notes & Planner Drawer */}
                  {selectedIP && (
                    <div className="bg-white rounded-2xl p-5 border border-slate-200 shadow-sm space-y-3">
                      <div className="flex items-center justify-between border-b border-slate-150 pb-3">
                        <h4 className="text-xs font-black text-slate-900 uppercase tracking-widest flex items-center gap-1.5">
                          <Edit3 className="w-4 h-4 text-red-600" />
                          Mitigation Notes & Action Log for <span className="font-mono text-red-600">{selectedIP.ip}</span>
                        </h4>
                        
                        <div className="flex items-center gap-2">
                          <label className="text-xs font-bold text-slate-500 uppercase">Action State:</label>
                          <select
                            value={actionStatusVal}
                            onChange={(e) => setActionStatusVal(e.target.value as any)}
                            className="text-xs font-extrabold uppercase bg-slate-100 border border-slate-200 rounded-lg px-2.5 py-1 text-slate-800 cursor-pointer"
                          >
                            <option value="unresolved">Unresolved</option>
                            <option value="pending">Pending Appeal</option>
                            <option value="resolved">Resolved</option>
                            <option value="monitoring">Monitoring</option>
                            <option value="ignored">Ignore Node</option>
                          </select>
                        </div>
                      </div>

                      <textarea
                        rows={2}
                        value={noteText}
                        onChange={(e) => setNoteText(e.target.value)}
                        placeholder="Log diagnostic findings, ISP delisting appeal ticket numbers, or mitigation actions for this IP..."
                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-xs focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-red-500/20 focus:border-red-500 transition-all font-semibold text-slate-900 resize-none"
                      />

                      <div className="flex justify-end">
                        <button 
                          onClick={handleSaveIPNotes}
                          className="bg-red-600 hover:bg-red-700 text-white px-5 py-2 rounded-xl text-xs font-black uppercase tracking-wider shadow-sm transition-all flex items-center gap-1.5 cursor-pointer active:scale-[0.99]"
                        >
                          <Check className="w-4 h-4 text-white" />
                          Save Mitigation Log
                        </button>
                      </div>
                    </div>
                  )}

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

      {/* Dedicated Remediation Modal */}
      {selectedGuideProvider && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-xs animate-fade-in">
          <div className="bg-white rounded-2xl max-w-xl w-full border border-slate-200 shadow-2xl overflow-hidden animate-scale-up">
            <div className="bg-slate-900 text-white p-5 flex justify-between items-center">
              <div className="flex items-center gap-2.5">
                <ShieldAlert className="w-5 h-5 text-rose-500" />
                <div>
                  <h3 className="text-sm font-black uppercase tracking-wider">{selectedGuideProvider.name} Delisting Guide</h3>
                  <p className="text-[10px] text-slate-400 font-mono">{selectedGuideProvider.domain || selectedGuideProvider.id}</p>
                </div>
              </div>
              <button 
                onClick={() => setSelectedGuideProvider(null)}
                className="text-slate-400 hover:text-white transition-colors cursor-pointer p-1 rounded-lg hover:bg-white/10"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-5 text-xs text-slate-700">
              <div className="bg-rose-50 border border-rose-200 p-4 rounded-xl text-rose-900 space-y-1">
                <span className="font-extrabold uppercase text-[10px] text-rose-800 tracking-wider">Detection Finding</span>
                <p className="font-semibold text-xs leading-relaxed">
                  {selectedGuideProvider.reason || `Host IP was detected by ${selectedGuideProvider.name} telemetry.`}
                </p>
              </div>

              <div className="space-y-3">
                <h4 className="font-black text-slate-900 uppercase tracking-wider text-[11px]">Recommended Step-by-Step Remediation</h4>
                <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-2.5 font-medium leading-relaxed">
                  <div className="flex items-start gap-2.5">
                    <span className="w-5 h-5 rounded-full bg-slate-900 text-white flex items-center justify-center font-bold text-[10px] shrink-0 mt-0.5">1</span>
                    <span>Audit outbound mail queues and verify no compromised accounts or unauthenticated SMTP open relays are transmitting spam.</span>
                  </div>
                  <div className="flex items-start gap-2.5">
                    <span className="w-5 h-5 rounded-full bg-slate-900 text-white flex items-center justify-center font-bold text-[10px] shrink-0 mt-0.5">2</span>
                    <span>Verify Reverse DNS (PTR) configuration matches your mail server Fully Qualified Domain Name (FQDN).</span>
                  </div>
                  <div className="flex items-start gap-2.5">
                    <span className="w-5 h-5 rounded-full bg-slate-900 text-white flex items-center justify-center font-bold text-[10px] shrink-0 mt-0.5">3</span>
                    <span>Submit official delisting request via the provider's automated self-service portal below.</span>
                  </div>
                </div>
              </div>

              <div className="flex flex-col sm:flex-row justify-end gap-3 pt-2">
                <button
                  onClick={() => setSelectedGuideProvider(null)}
                  className="px-4 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-bold rounded-xl transition-all cursor-pointer uppercase text-[10px] tracking-wider"
                >
                  Close
                </button>
                <a
                  href={selectedGuideProvider.delistUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="px-5 py-2.5 bg-rose-600 hover:bg-rose-700 text-white font-black rounded-xl shadow-xs transition-all flex items-center justify-center gap-1.5 cursor-pointer uppercase text-[10px] tracking-wider"
                >
                  Open Official Removal Portal <ExternalLink className="w-3.5 h-3.5" />
                </a>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
