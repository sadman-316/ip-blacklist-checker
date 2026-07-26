import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import dns from "dns";
import fs from "fs";
import { initializeApp, getApp, getApps } from "firebase/app";
import { getFirestore, collection, getDocs, updateDoc, doc, addDoc, getDoc, setDoc, onSnapshot } from "firebase/firestore";

const app = express();
const PORT = 3000;

app.set('trust proxy', true);

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

// Global cache for GeoIP responses at the /24 subnet level
const geoIpCache = new Map<string, {
  country: string;
  countryCode: string;
  region: string;
  city: string;
  isp: string;
  lat: number;
  lon: number;
}>();

// Global mutable system settings config
const systemConfig = {
  dnsResolvers: ['1.1.1.1', '8.8.8.8', '9.9.9.9', '208.67.222.222'],
  monitorInterval: 10
};

// Standard Blacklist Providers
const BLACKLIST_PROVIDERS = [
  {
    id: 'spamhaus',
    name: 'Spamhaus ZEN',
    domain: 'zen.spamhaus.org',
    description: 'The Gold Standard. Combines SBL, SBL-CSS, XBL, and PBL. Identifies verified spam sources, exploits, dynamic ranges, and hijacked devices.',
    delistUrl: 'https://www.spamhaus.org/lookup/',
    category: 'Spam' as const
  },
  {
    id: 'barracuda',
    name: 'Barracuda BRBL',
    domain: 'b.barracudacentral.org',
    description: 'Barracuda Reputation Block List. Highly effective list containing active spam-sending mail servers.',
    delistUrl: 'https://www.barracudacentral.org/rbl/removal-request',
    category: 'Spam' as const
  },
  {
    id: 'spamcop',
    name: 'SpamCop',
    domain: 'bl.spamcop.net',
    description: 'SpamCop Blocklist. Dynamic list based on reporting from users, spam traps, and automated systems.',
    delistUrl: 'https://www.spamcop.net/bl.shtml',
    category: 'Spam' as const
  },
  {
    id: 'uceprotect1',
    name: 'UCEPROTECT Level 1',
    domain: 'dnsbl-1.uceprotect.net',
    description: 'UCEPROTECT Level 1. Identifies single IP addresses that sent spam or were detected as abusive within the last 7 days.',
    delistUrl: 'http://www.uceprotect.net/en/rblcheck.php',
    category: 'Spam' as const
  },
  {
    id: 'uceprotect2',
    name: 'UCEPROTECT Level 2',
    domain: 'dnsbl-2.uceprotect.net',
    description: 'UCEPROTECT Level 2. Identifies entire subnets that contain active spam or abusive activity.',
    delistUrl: 'http://www.uceprotect.net/en/rblcheck.php',
    category: 'Spam' as const
  },
  {
    id: 'uceprotect3',
    name: 'UCEPROTECT Level 3',
    domain: 'dnsbl-3.uceprotect.net',
    description: 'UCEPROTECT Level 3. Identifies entire service providers (ASNs) exhibiting persistent, systemic abuse.',
    delistUrl: 'http://www.uceprotect.net/en/rblcheck.php',
    category: 'Spam' as const
  },
  {
    id: 'blocklist',
    name: 'Blocklist.de',
    domain: 'bl.blocklist.de',
    description: 'Real-time security reporting service. Lists malicious IPs participating in SSH, Mail, FTP, and Web attacks.',
    delistUrl: 'https://www.blocklist.de/en/search.html',
    category: 'General' as const
  },
  {
    id: 'sorbs',
    name: 'SORBS Aggregate',
    domain: 'dnsbl.sorbs.net',
    description: 'SORBS aggregate database. Detects spam-sending servers, compromised servers, open proxies, and dynamic host addresses.',
    delistUrl: 'http://www.sorbs.net/lookup.shtml',
    category: 'Spam' as const
  },
  {
    id: 'sorbsduhl',
    name: 'SORBS DUHL',
    domain: 'duhl.dnsbl.sorbs.net',
    description: 'SORBS Dynamic User and Host List. Lists dynamic IP ranges that are not supposed to send emails directly.',
    delistUrl: 'http://www.sorbs.net/lookup.shtml',
    category: 'Spam' as const
  },
  {
    id: 'dronebl',
    name: 'DroneBL',
    domain: 'dnsbl.dronebl.org',
    description: 'Real-time lookup tracking open proxies, compromised IoT, IRC bots, rootkits, and active brute-forcers.',
    delistUrl: 'https://dronebl.org/lookup',
    category: 'General' as const
  },
  {
    id: 'gbudb',
    name: 'GBUdb Truncate',
    domain: 'truncate.gbudb.net',
    description: 'Highly accurate real-time IP reputation blacklist compiled dynamically by GBUdb nodes.',
    delistUrl: 'http://www.gbudb.com/',
    category: 'Spam' as const
  },
  {
    id: 'spfbl',
    name: 'SPFBL DNSBL',
    domain: 'dnsbl.spfbl.net',
    description: 'Collaborative peer-to-peer blacklist designed to filter spam, malicious senders, and dynamic ranges.',
    delistUrl: 'https://spfbl.net/en/dnsbl/',
    category: 'Spam' as const
  },
  {
    id: 'lashback',
    name: 'Lashback UBL',
    domain: 'ubl.lashback.com',
    description: 'Lashback Unsubscribe Blacklist. Specifically targets servers sending mail to harvested opt-out / unsubscribe lists.',
    delistUrl: 'https://www.lashback.com/blacklist/',
    category: 'Spam' as const
  },
  {
    id: 'psbl',
    name: 'Passive Spam Block List (PSBL)',
    domain: 'psbl.surriel.com',
    description: 'Easy-to-whitelist spam blocklist. Only lists IPs that send email to spam traps and have no SMTP feedback loop.',
    delistUrl: 'https://psbl.org/lookup',
    category: 'Spam' as const
  },
  {
    id: 'wpbl',
    name: 'Weighted Private Block List',
    domain: 'db.wpbl.info',
    description: 'WPBL focuses on resolving spam sources via automated algorithmic detection and responsive removal.',
    delistUrl: 'http://www.wpbl.info/',
    category: 'Spam' as const
  },
  {
    id: 'ivmsip',
    name: 'Invaluement ivmSIP',
    domain: 'sip.invaluement.com',
    description: 'ivmSIP by Invaluement. Highly accurate database focusing on high-emission spam IP addresses, including snowshoe spam.',
    delistUrl: 'https://www.invaluement.com/lookup/',
    category: 'Spam' as const
  },
  {
    id: 'spamratsdyna',
    name: 'SpamRats Dyna',
    domain: 'dyna.spamrats.com',
    description: 'Identifies dynamic IP ranges or residential connections running unauthenticated SMTP servers.',
    delistUrl: 'https://www.spamrats.com/',
    category: 'Spam' as const
  },
  {
    id: 'spamrats',
    name: 'SpamRats Spam',
    domain: 'spam.spamrats.com',
    description: 'SpamRats Spam database. Identifies IP addresses that have been detected sending spam, having invalid reverse DNS, or other suspicious mail-sending behaviors.',
    delistUrl: 'https://www.spamrats.com/',
    category: 'Spam' as const
  },
  {
    id: 'spamratsnoptr',
    name: 'SpamRats NoPtr',
    domain: 'noptr.spamrats.com',
    description: 'SpamRats NoPtr. Identifies IP addresses with invalid or missing reverse DNS (PTR) records.',
    delistUrl: 'https://www.spamrats.com/',
    category: 'Spam' as const
  },
  {
    id: 'mailspikebl',
    name: 'Mailspike Blacklist',
    domain: 'bl.mailspike.net',
    description: 'Reputable IP reputation blocklist that identifies active spam sources, email relays, and unauthenticated botnet nodes.',
    delistUrl: 'https://mailspike.org/an-ip-is-listed-on-mailspike/',
    category: 'Spam' as const
  },
  {
    id: 'mailspikez',
    name: 'Mailspike Zombie',
    domain: 'z.mailspike.net',
    description: 'Zombie blocklist detecting compromised workstation/consumer IPs sending email traffic as part of active botnets.',
    delistUrl: 'https://mailspike.org/an-ip-is-listed-on-mailspike/',
    category: 'Spam' as const
  },
  {
    id: 'hostkarma',
    name: 'Hostkarma Black',
    domain: 'hostkarma.junkemailfilter.com',
    description: 'Hostkarma reputation RBL. Accurately categorizes mail senders as blacklist (spam), whitelist, yellowlist (suspicious), or NoPTR.',
    delistUrl: 'http://www.junkemailfilter.com/spam/lookup.php',
    category: 'General' as const
  },
  {
    id: 's5hnet',
    name: 's5h.net',
    domain: 'all.s5h.net',
    description: 'Aggregates multiple security feeds to identify dynamic residential lines, malware hosts, and spam-originating mail servers.',
    delistUrl: 'http://s5h.net/dnsbl/',
    category: 'Spam' as const
  },
  {
    id: 'nixspam',
    name: 'NiX Spam',
    domain: 'ix.dnsbl.manitu.net',
    description: 'Manitu NiX Spam. Highly active German blocklist detecting active spam senders, mail server abuse, and botnets.',
    delistUrl: 'https://www.manitu.de/nixspam/',
    category: 'Spam' as const
  },
  {
    id: 'justspam',
    name: 'JustSpam',
    domain: 'dnsbl.justspam.org',
    description: 'JustSpam.org. A highly responsive real-time DNSBL listing active spamming hosts based on spam traps.',
    delistUrl: 'http://www.justspam.org/',
    category: 'Spam' as const
  },
  {
    id: 'tornevall',
    name: 'Tornevall',
    domain: 'dnsbl.tornevall.org',
    description: 'Tornevall DNSBL. Specializes in identifying compromised hosts, open proxies, Tor exit nodes, and automated scrapers.',
    delistUrl: 'https://dnsbl.tornevall.org/',
    category: 'General' as const
  },
  {
    id: 'nordspam',
    name: 'NordSpam',
    domain: 'bl.nordspam.com',
    description: 'NordSpam Blocklist. An active public DNSBL targeting spamming mail servers and botnets.',
    delistUrl: 'https://www.nordspam.com/',
    category: 'Spam' as const
  },
  {
    id: 'zerospam',
    name: '0Spam',
    domain: 'bl.0spam.org',
    description: '0Spam DNSBL. Identifies spam hosts, email spiders, and brute force attackers in real time.',
    delistUrl: 'https://0spam.org/',
    category: 'Spam' as const
  },
  {
    id: 'suomispam',
    name: 'Suomispam',
    domain: 'bl.suomispam.net',
    description: 'Suomispam DNSBL. A reputation list targeting global and regional spam sources and abusive IPs.',
    delistUrl: 'https://suomispam.net/',
    category: 'Spam' as const
  },
  {
    id: 'efnetrbl',
    name: 'EFnet RBL',
    domain: 'rbl.efnetrbl.org',
    description: 'EFnet RBL. Detects open proxies, compromised hosts, dynamic IPs, and Tor exit nodes.',
    delistUrl: 'https://rbl.efnetrbl.org/',
    category: 'General' as const
  },
  {
    id: 'spameatingmonkey',
    name: 'SpamEatingMonkey',
    domain: 'bl.spameatingmonkey.net',
    description: 'SpamEatingMonkey RBL. Tracks active spam-sending mail servers and compromised relays.',
    delistUrl: 'https://spameatingmonkey.com/',
    category: 'Spam' as const
  },
  {
    id: 'zapbl',
    name: 'ZapBL',
    domain: 'dnsbl.zapbl.net',
    description: 'ZapBL DNSBL. Fast, accurate blacklist targeting active spam servers, brute-forcers, and scrapers.',
    delistUrl: 'https://zapbl.net/',
    category: 'Spam' as const
  },
  {
    id: 'interserver',
    name: 'Interserver RBL',
    domain: 'rbl.interserver.net',
    description: 'Interserver IP Reputation. An active lookup listing spamming IPs and abusive hosts across the web.',
    delistUrl: 'https://rbl.interserver.net/',
    category: 'Spam' as const
  },
  {
    id: 'abusech',
    name: 'Abuse.ch DNSBL',
    domain: 'dnsbl.abuse.ch',
    description: 'Abuse.ch spam and malware tracking database. Flagging botnets, malware hosts, and fast-flux networks.',
    delistUrl: 'https://abuse.ch/',
    category: 'Security' as const
  },
  {
    id: 'cbl',
    name: 'CBL (Composite Blocking List)',
    domain: 'cbl.abuseat.org',
    description: 'Composite Blocking List. Focuses on botnets, open proxies, and compromised systems sending spam.',
    delistUrl: 'https://www.abuseat.org/',
    category: 'Spam' as const
  },
  {
    id: 'spameatingmonkeybackscatter',
    name: 'SpamEatingMonkey Backscatter',
    domain: 'backscatter.spameatingmonkey.net',
    description: 'Tracks servers sending misdirected bounce messages and out-of-office autoresponders (backscatter).',
    delistUrl: 'https://spameatingmonkey.com/',
    category: 'Spam' as const
  },
  {
    id: 'rbliprangenet',
    name: 'IPRange RBL',
    domain: 'rbl.iprange.net',
    description: 'Reputation and volume-based tracking of malicious networks and dedicated spam servers.',
    delistUrl: 'https://rbl.iprange.net/',
    category: 'Spam' as const
  },
  {
    id: 'madavidnsbl',
    name: 'Madavi DNSBL',
    domain: 'dnsbl.madavi.de',
    description: 'Madavi real-time reputation and abuse blacklist tracking server intrusions and spamming bots.',
    delistUrl: 'https://madavi.de/',
    category: 'General' as const
  }
];

// Helper to reverse IPv4 octets
function reverseIP(ip: string): string {
  return ip.split('.').reverse().join('.');
}

// Check private IP networks
function isPrivateIP(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return true;
  
  if (parts[0] === 127) return true; // 127.0.0.0/8
  if (parts[0] === 10) return true;  // 10.0.0.0/8
  if (parts[0] === 192 && parts[1] === 168) return true; // 192.168.0.0/16
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16.0.0/12
  if (parts[0] === 169 && parts[1] === 254) return true; // 169.254.0.0/16 (Link Local)
  if (parts[0] >= 224 && parts[0] <= 239) return true; // Multicast
  
  return false;
}

// Global cache for individual DNSBL check results
// Keys are formatted as `${ip}:${blacklistDomain}`
interface CachedDnsblResult {
  result: any;
  timestamp: number;
}
const dnsblCache = new Map<string, CachedDnsblResult>();
const DNSBL_CACHE_TTL = 10 * 60 * 1000;       // 10 mins TTL for Clean/Listed
const DNSBL_UNREACHABLE_TTL = 1 * 60 * 1000;   // 1 min TTL for temporarily Unreachable

// Global pools for authoritative and fallback DNS resolvers
const providerResolvers = new Map<string, { resolver: dns.Resolver; serverIp: string }[]>();

// Initialize and cache authoritative DNS resolvers for each provider in the background
async function initProviderResolvers() {
  console.log('[WolastShield] Initiating background authoritative NS resolution for blacklist providers...');
  for (const provider of BLACKLIST_PROVIDERS) {
    try {
      dns.resolveNs(provider.domain, (err, hostnames) => {
        if (err || !hostnames || hostnames.length === 0) {
          // Fallback to parent domain lookup
          const parts = provider.domain.split('.');
          if (parts.length > 2) {
            const parentDomain = parts.slice(-2).join('.');
            dns.resolveNs(parentDomain, (err2, parentHostnames) => {
              if (!err2 && parentHostnames && parentHostnames.length > 0) {
                resolveNSHostnames(provider.id, parentHostnames);
              }
            });
          }
          return;
        }
        resolveNSHostnames(provider.id, hostnames);
      });
    } catch (e) {
      console.error(`[WolastShield] Failed to start NS resolution for ${provider.id}:`, e);
    }
  }
}

function resolveNSHostnames(providerId: string, hostnames: string[]) {
  const ips: string[] = [];
  let resolvedCount = 0;
  
  hostnames.forEach(host => {
    dns.resolve4(host, (err, addresses) => {
      resolvedCount++;
      if (!err && addresses && addresses.length > 0) {
        ips.push(...addresses);
      }
      
      if (resolvedCount === hostnames.length && ips.length > 0) {
        const resolvers: { resolver: dns.Resolver; serverIp: string }[] = [];
        ips.forEach(ip => {
          const res = new dns.Resolver();
          res.setServers([ip]);
          resolvers.push({ resolver: res, serverIp: ip });
        });
        providerResolvers.set(providerId, resolvers);
        console.log(`[WolastShield] Successfully cached ${ips.length} authoritative NS resolvers for ${providerId}: ${ips.join(', ')}`);
      }
    });
  });
}

// Get standard DNSBL code response details
function getResponseCodeDetails(domain: string, code: string): string {
  if (domain.includes('spamhaus')) {
    switch (code) {
      case '127.0.0.2': return 'SBL (Spamhaus Block List): Verified spam emission source or direct threat.';
      case '127.0.0.3': return 'CSS (Spamhaus CSS): Low-reputation snowshoe spam or automated spam sending.';
      case '127.0.0.4':
      case '127.0.0.5':
      case '127.0.0.6':
      case '127.0.0.7': return 'XBL (Exploit Block List): Hijacked server, open proxy, or malware-infected system.';
      case '127.0.0.10':
      case '127.0.0.11': return 'PBL (Policy Block List): Dynamic/consumer IP address that should not run a mail server directly.';
      default: return `Listed (${code})`;
    }
  }
  if (domain.includes('sorbs')) {
    switch (code) {
      case '127.0.0.2': return 'SORBS HTTP: Open HTTP Proxy.';
      case '127.0.0.3': return 'SORBS SOCKS: Open SOCKS Proxy.';
      case '127.0.0.4': return 'SORBS MISC: Miscellaneous open relay or vulnerable server.';
      case '127.0.0.5': return 'SORBS SMTP: Verified SMTP spam sending host.';
      case '127.0.0.6': return 'SORBS WEB: Web-based spam sender or spam-supporting web form.';
      case '127.0.0.7': return 'SORBS BLOCK: General blacklisted spam source.';
      case '127.0.0.8': return 'SORBS EXPLOIT: Zombie host or vulnerable compromised machine.';
      case '127.0.0.9': return 'SORBS DUHL: Dynamic IP address with dial-up/consumer hostname.';
      default: return `Listed (${code})`;
    }
  }
  if (domain.includes('uceprotect')) {
    return `UCEPROTECT: Listed as abusive, unmitigated source of spam, or part of a systemic blacklisted range (${code}).`;
  }
  if (domain.includes('blocklist.de')) {
    switch (code) {
      case '127.0.0.2': return 'Blocklist.de: Amavis (Mail virus sender).';
      case '127.0.0.3': return 'Blocklist.de: Badbots (Scrapers, scanners, vulnerability exploits).';
      case '127.0.0.4': return 'Blocklist.de: FTP attacks detected.';
      case '127.0.0.5': return 'Blocklist.de: IMAP server brute-force attacks.';
      case '127.0.0.6': return 'Blocklist.de: IRC attacks or compromised client connection.';
      case '127.0.0.7': return 'Blocklist.de: Mail / SMTP authentication abuse.';
      case '127.0.0.8': return 'Blocklist.de: POP3 server brute-force attacks.';
      case '127.0.0.9': return 'Blocklist.de: SSH brute-force attack host.';
      case '127.0.0.10': return 'Blocklist.de: Web exploits (SQLi, XSS, CMS attacks).';
      default: return `Blocklist.de: Active brute-forcing or malicious attack source (${code}).`;
    }
  }
  if (domain.includes('dronebl')) {
    switch (code) {
      case '127.0.0.2': return 'DroneBL: Sample / general service abuse.';
      case '127.0.0.3': return 'DroneBL: IRC drone or bot connection.';
      case '127.0.0.5': return 'DroneBL: Automated mail/spam bot.';
      case '127.0.0.6': return 'DroneBL: Vulnerable system or open proxy.';
      case '127.0.0.7': return 'DroneBL: Spyware, malware or adware injector.';
      case '127.0.0.8': return 'DroneBL: Automated spider, scraper, or scanner.';
      case '127.0.0.9': return 'DroneBL: Password brute-forcer.';
      case '127.0.0.10': return 'DroneBL: SSH brute forcing attacker.';
      case '127.0.0.13': return 'DroneBL: Compromised web server or CMS exploit.';
      case '127.0.0.14': return 'DroneBL: Compromised router or vulnerable IoT device.';
      default: return `DroneBL: Open proxy, compromised IoT, or botnet member (${code}).`;
    }
  }
  if (domain.includes('gbudb') || domain.includes('truncate')) {
    return 'GBUdb Truncate: Dynamic real-time spam or automated abuse listing.';
  }
  if (domain.includes('spfbl')) {
    return 'SPFBL: Listed in peer-to-peer SMTP reputation system.';
  }
  if (domain.includes('barracuda')) {
    return 'BRBL: Listed as a sender of spam or malicious traffic.';
  }
  if (domain.includes('spamcop')) {
    return 'SpamCop: Reported by users or spamtraps as an active spam source.';
  }
  if (domain.includes('lashback')) {
    return 'UBL: Registered host sending mail to harvested unsubscribe list addresses.';
  }
  if (domain.includes('invaluement')) {
    return 'ivmSIP: Part of the Invaluement blacklist targeting high-emission spam IP addresses.';
  }
  if (domain.includes('spamrats')) {
    if (domain.includes('noptr')) {
      return `SpamRats NoPtr: Listed due to missing or invalid reverse DNS (PTR) record (${code}).`;
    }
    if (domain.includes('dyna')) {
      return `SpamRats Dyna: Listed due to dynamic IP range running unauthenticated SMTP (${code}).`;
    }
    return `SpamRats Spam: Listed due to suspicious connections or spam activity (${code}).`;
  }
  if (domain.includes('mailspike')) {
    if (domain.includes('z.mailspike')) {
      return `Mailspike Zombie: Listed as zombie, compromised workstation, or active botnet member (${code}).`;
    }
    return `Mailspike Blacklist: Listed as a known spam or abuse source (${code}).`;
  }
  if (domain.includes('junkemailfilter.com')) {
    switch (code) {
      case '127.0.0.2': return 'Hostkarma Black: Verified spam-sending host.';
      case '127.0.0.3': return 'Hostkarma Yellow: Suspicious or unverified mail source.';
      case '127.0.0.4': return 'Hostkarma NoPTR: Listed due to invalid or missing reverse DNS (PTR).';
      default: return `Hostkarma Listed (${code})`;
    }
  }
  if (domain.includes('s5h.net')) {
    return 's5h.net: Active spam, dynamic/residential line, or security threat.';
  }
  if (domain.includes('manitu')) {
    return 'NiX Spam: Verified spam-sending host or botnet participant.';
  }
  if (domain.includes('justspam')) {
    return 'JustSpam: Actively sending unsolicited bulk email to spamtraps.';
  }
  if (domain.includes('tornevall')) {
    switch (code) {
      case '127.0.0.1': return 'Tornevall: Anonymous proxy host.';
      case '127.0.0.2': return 'Tornevall: Web/HTTP proxy.';
      case '127.0.0.4': return 'Tornevall: SOCKS proxy.';
      case '127.0.0.8': return 'Tornevall: Outbound mail/scanner proxy.';
      case '127.0.0.16': return 'Tornevall: TOR exit node.';
      default: return `Tornevall proxy/abuse listing (${code})`;
    }
  }
  if (domain.includes('nordspam')) {
    return 'NordSpam: Listed as active spam-sending node or abuse source.';
  }
  if (domain.includes('0spam')) {
    return '0Spam: Dynamic spam source or abusive scraper/scanner.';
  }
  if (domain.includes('suomispam')) {
    return 'Suomispam: Actively sending unsolicited spam or malicious email.';
  }
  if (domain.includes('efnetrbl')) {
    switch (code) {
      case '127.0.0.1': return 'EFnet RBL: Open proxy server.';
      case '127.0.0.2': return 'EFnet RBL: Trojan/IRC drone.';
      case '127.0.0.3': return 'EFnet RBL: TOR exit node.';
      case '127.0.0.4': return 'EFnet RBL: Compromised system or dynamic IP.';
      default: return `EFnet RBL Listed (${code})`;
    }
  }
  if (domain.includes('spameatingmonkey')) {
    return 'SpamEatingMonkey: Listed as a verified spam source.';
  }
  if (domain.includes('zapbl')) {
    return 'ZapBL: Active spam sender, automated scanner, or dynamic IP.';
  }
  if (domain.includes('interserver')) {
    return 'Interserver RBL: Listed due to spam outbound traffic or abusive behavior.';
  }
  return `Listed on blacklist (${code})`;
}

// Multi-tiered DNS resolver helper
async function resolveDnsWithFallback(lookupDomain: string, providerId: string): Promise<{ addresses: string[]; server: string }> {
  // Tier 1: Try authoritative name servers
  const authResolvers = providerResolvers.get(providerId);
  if (authResolvers && authResolvers.length > 0) {
    const promises = authResolvers.slice(0, 2).map(({ resolver, serverIp }) => {
      return new Promise<{ addresses: string[]; server: string }>((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('Timeout')), 1200);
        resolver.resolve4(lookupDomain, (err, addresses) => {
          clearTimeout(t);
          if (err) reject(err);
          else resolve({ addresses, server: `Authoritative NS (${serverIp})` });
        });
      });
    });
    try {
      const result = await Promise.any(promises);
      if (result && result.addresses.length > 0) {
        return result;
      }
    } catch (e) {
      // Fall through on authoritative NS failures
    }
  }

  // Tier 2: Try explicit custom/private DNS resolvers configured in system settings in parallel
  const resolversToTry = systemConfig.dnsResolvers && systemConfig.dnsResolvers.length > 0
    ? systemConfig.dnsResolvers
    : ['1.1.1.1', '8.8.8.8', '9.9.9.9'];

  const fallbackPromises = resolversToTry.map(fallback => {
    return new Promise<{ addresses: string[]; server: string }>((resolve, reject) => {
      const resolver = new dns.Resolver();
      resolver.setServers([fallback]);
      const t = setTimeout(() => reject(new Error('Timeout')), 1000);
      resolver.resolve4(lookupDomain, (err, addresses) => {
        clearTimeout(t);
        if (err) reject(err);
        else resolve({ addresses, server: `Custom Resolver (${fallback})` });
      });
    });
  });

  try {
    const result = await Promise.any(fallbackPromises);
    if (result && result.addresses.length > 0) {
      return result;
    }
  } catch (e) {
    // Fall through
  }

  // Tier 3: Standard Node.js DNS resolve fallback
  return new Promise<{ addresses: string[]; server: string }>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('Timeout')), 1000);
    dns.resolve4(lookupDomain, (err, addresses) => {
      clearTimeout(t);
      if (err) reject(err);
      else resolve({ addresses, server: 'System Default DNS' });
    });
  });
}

// Multi-tiered DNS TXT resolver helper
async function resolveTxtWithFallback(lookupDomain: string, providerId: string): Promise<string> {
  const authResolvers = providerResolvers.get(providerId);
  if (authResolvers && authResolvers.length > 0) {
    try {
      const records = await new Promise<string[][]>((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('Timeout')), 1200);
        authResolvers[0].resolver.resolveTxt(lookupDomain, (err, records) => {
          clearTimeout(t);
          if (err) reject(err);
          else resolve(records);
        });
      });
      if (records && records.length > 0) {
        return records.flat().join(' ');
      }
    } catch (e) {}
  }

  // Try custom/private DNS resolvers configured in system settings in parallel
  const resolversToTry = systemConfig.dnsResolvers && systemConfig.dnsResolvers.length > 0
    ? systemConfig.dnsResolvers
    : ['1.1.1.1', '8.8.8.8', '9.9.9.9'];

  const fallbackTxtPromises = resolversToTry.map(fallback => {
    return new Promise<string[][]>((resolve, reject) => {
      const resolver = new dns.Resolver();
      resolver.setServers([fallback]);
      const t = setTimeout(() => reject(new Error('Timeout')), 1000);
      resolver.resolveTxt(lookupDomain, (err, records) => {
        clearTimeout(t);
        if (err) reject(err);
        else resolve(records);
      });
    });
  });

  try {
    const records = await Promise.any(fallbackTxtPromises);
    if (records && records.length > 0) {
      return records.flat().join(' ');
    }
  } catch (e) {}

  return '';
}

// Perform DNSBL Check
async function checkDNSBL(ip: string, blacklistDomain: string): Promise<{
  listed: boolean;
  status: 'Listed' | 'Not Listed' | 'Unreachable';
  details: string;
  responseCode: string;
  txt: string;
  responseTime: number;
  timestamp: string;
  dnsServerQueried: string;
  error?: boolean;
  errorMessage?: string;
}> {
  const cacheKey = `${ip}:${blacklistDomain}`;
  const cached = dnsblCache.get(cacheKey);
  const now = Date.now();

  if (cached) {
    const isUnreachable = cached.result.status === 'Unreachable';
    const ttl = isUnreachable ? DNSBL_UNREACHABLE_TTL : DNSBL_CACHE_TTL;
    if (now - cached.timestamp < ttl) {
      console.log(`[WolastShield Cache Hit] IP: ${ip} | Blacklist: ${blacklistDomain} | Status: ${cached.result.status}`);
      return {
        ...cached.result,
        responseTime: 0 // Zero out responseTime for cache hits
      };
    }
  }

  const startTime = Date.now();
  const reversed = reverseIP(ip);
  const lookupDomain = `${reversed}.${blacklistDomain}`;
  const provider = BLACKLIST_PROVIDERS.find(p => p.domain === blacklistDomain);
  const providerId = provider ? provider.id : '';
  const nowStr = new Date().toISOString();

  let retries = 2;
  let lastError: any = null;
  let usedServer = 'Unknown DNS';

  console.log(`[WolastShield Lookup] IP: ${ip} | Blacklist: ${blacklistDomain} | Target: ${lookupDomain}`);

  while (retries >= 0) {
    try {
      // Perform DNS query with custom resolver fallback
      const { addresses, server } = await resolveDnsWithFallback(lookupDomain, providerId);
      usedServer = server;
      const responseTime = Date.now() - startTime;

      if (addresses && addresses.length > 0) {
        const code = addresses[0];

        // Handle resolver refusal or block code (127.255.255.*)
        if (code.startsWith('127.255.255.')) {
          console.log(`[WolastShield Refused] DNSBL public DNS restriction detected for ${blacklistDomain} with code ${code}`);
          const resObj = {
            listed: false,
            status: 'Unreachable' as const,
            details: 'Resolver Refused (Public DNS Restrictions)',
            responseCode: code,
            txt: '',
            responseTime,
            timestamp: nowStr,
            dnsServerQueried: usedServer,
            error: true,
            errorMessage: 'Resolver Refused (Public DNS Restrictions)'
          };
          dnsblCache.set(cacheKey, { result: resObj, timestamp: now });
          return resObj;
        }

        // 127.0.0.1 represents "whitelisted/clean" on lists like Hostkarma, ignore it
        if (code === '127.0.0.1') {
          console.log(`[WolastShield Whitelist] ${ip} is whitelisted on ${blacklistDomain}`);
          const resObj = {
            listed: false,
            status: 'Not Listed' as const,
            details: 'Listed as Whitelisted/Clean',
            responseCode: code,
            txt: '',
            responseTime,
            timestamp: nowStr,
            dnsServerQueried: usedServer
          };
          dnsblCache.set(cacheKey, { result: resObj, timestamp: now });
          return resObj;
        }

        // Query real TXT record to fetch dynamic listing reasons
        let txtDetail = '';
        try {
          txtDetail = await resolveTxtWithFallback(lookupDomain, providerId);
        } catch (e: any) {
          console.log(`[WolastShield TXT Skip] No TXT record for ${lookupDomain} on ${blacklistDomain}: ${e.message || e}`);
        }

        const defaultDetail = getResponseCodeDetails(blacklistDomain, code);
        const combinedDetails = txtDetail ? `${defaultDetail} | TXT: ${txtDetail}` : defaultDetail;

        console.log(`[WolastShield Match] LISTED: ${ip} on ${blacklistDomain} | Code: ${code} | Details: ${combinedDetails}`);

        const resObj = {
          listed: true,
          status: 'Listed' as const,
          details: combinedDetails,
          responseCode: code,
          txt: txtDetail,
          responseTime,
          timestamp: nowStr,
          dnsServerQueried: usedServer
        };
        dnsblCache.set(cacheKey, { result: resObj, timestamp: now });
        return resObj;
      }

      // No addresses returned (clean result)
      console.log(`[WolastShield Clean] ${ip} is clean on ${blacklistDomain} (NXDOMAIN)`);
      const resObj = {
        listed: false,
        status: 'Not Listed' as const,
        details: 'Not Listed',
        responseCode: 'NXDOMAIN',
        txt: '',
        responseTime,
        timestamp: nowStr,
        dnsServerQueried: usedServer
      };
      dnsblCache.set(cacheKey, { result: resObj, timestamp: now });
      return resObj;

    } catch (err: any) {
      lastError = err;
      const errCode = err.code || '';
      const responseTime = Date.now() - startTime;

      // ENOTFOUND/ENODATA means clean (NXDOMAIN), so no need to retry or log as error
      if (errCode === 'ENOTFOUND' || errCode === 'ENODATA') {
        console.log(`[WolastShield Clean] ${ip} is clean on ${blacklistDomain} (NXDOMAIN/ENOTFOUND)`);
        const resObj = {
          listed: false,
          status: 'Not Listed' as const,
          details: 'Not Listed',
          responseCode: 'NXDOMAIN',
          txt: '',
          responseTime,
          timestamp: nowStr,
          dnsServerQueried: usedServer
        };
        dnsblCache.set(cacheKey, { result: resObj, timestamp: now });
        return resObj;
      }

      console.warn(`[WolastShield Query Fail] Attempt ${3 - retries}/3 failed for ${lookupDomain} on ${blacklistDomain}: ${errCode || err.message}`);

      // If it is a transient error (SERVFAIL, REFUSED) and we have retries left, continue the loop. Do NOT retry on general Timeout.
      if (retries > 0 && (errCode === 'EREFUSED' || errCode === 'ESERVFAIL')) {
        retries--;
        // Introduce a small delay before retry
        await new Promise(resolve => setTimeout(resolve, 300));
        continue;
      }

      // Out of retries or non-transient error
      console.error(`[WolastShield Critical Fail] ${lookupDomain} lookup failed: ${errCode || err.message}`);
      const resObj = {
        listed: false,
        status: 'Unreachable' as const,
        details: errCode === 'EREFUSED' || errCode === 'ESERVFAIL' 
          ? 'Resolver Refused (Public DNS Restrictions)' 
          : `Query Error (${errCode || err.message || 'Unknown'})`,
        responseCode: errCode || 'ERROR',
        txt: '',
        responseTime,
        timestamp: nowStr,
        dnsServerQueried: usedServer,
        error: true,
        errorMessage: err.message || String(err)
      };
      dnsblCache.set(cacheKey, { result: resObj, timestamp: now });
      return resObj;
    }
  }

  // Fallback in case loop terminates without returning
  const responseTime = Date.now() - startTime;
  const resObj = {
    listed: false,
    status: 'Unreachable' as const,
    details: `Query Error (Retries exhausted: ${lastError?.message || 'Unknown'})`,
    responseCode: lastError?.code || 'TIMEOUT',
    txt: '',
    responseTime,
    timestamp: nowStr,
    dnsServerQueried: usedServer,
    error: true,
    errorMessage: lastError?.message || 'Retries exhausted'
  };
  dnsblCache.set(cacheKey, { result: resObj, timestamp: now });
  return resObj;
}

// IP GeoIP lookup with /24 caching & fallback
async function fetchGeoIP(ip: string): Promise<{
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  isp?: string;
  lat?: number;
  lon?: number;
}> {
  if (isPrivateIP(ip)) {
    return {
      country: 'Local Network',
      countryCode: 'LAN',
      region: 'Intranet',
      city: 'Private Space',
      isp: 'RFC 1918 Private Address',
      lat: 0,
      lon: 0
    };
  }

  // Segment cache key at /24 subnet level (e.g. 192.0.2.35 -> 192.0.2.0)
  const octets = ip.split('.');
  const subnetKey = `${octets[0]}.${octets[1]}.${octets[2]}.0`;

  if (geoIpCache.has(subnetKey)) {
    return geoIpCache.get(subnetKey)!;
  }

  try {
    const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,isp,lat,lon`);
    if (response.ok) {
      const data = await response.json() as any;
      if (data.status === 'success') {
        const result = {
          country: data.country,
          countryCode: data.countryCode,
          region: data.regionName,
          city: data.city,
          isp: data.isp,
          lat: data.lat,
          lon: data.lon
        };
        geoIpCache.set(subnetKey, result);
        return result;
      }
    }
  } catch (error) {
    // Graceful catch for offline / local-only runs
  }

  return {
    country: 'Global Space',
    countryCode: 'UN',
    region: 'Unknown',
    city: 'Unknown Location',
    isp: 'Generic ISP Allocation',
  };
}

// Parser IP logic
function parseTarget(target: string): { ips: string[]; error?: string } {
  const cleaned = target.trim();
  if (!cleaned) return { ips: [], error: 'Input target is empty' };

  // Comma, space, or newline list
  if (cleaned.includes(',') || cleaned.includes('\n') || cleaned.includes(' ')) {
    const ips = cleaned
      .split(/[\s,]+/)
      .map(ip => ip.trim())
      .filter(ip => isValidIP(ip));
    if (ips.length === 0) return { ips: [], error: 'No valid IPv4 addresses found in the list.' };
    return { ips: ips.slice(0, 256) };
  }

  // CIDR
  if (cleaned.includes('/')) {
    const parts = cleaned.split('/');
    const baseIP = parts[0].trim();
    const mask = parseInt(parts[1], 10);
    
    if (!isValidIP(baseIP)) return { ips: [], error: `Invalid base IP address: ${baseIP}` };
    if (isNaN(mask) || mask < 0 || mask > 32) return { ips: [], error: `Invalid subnet mask: ${parts[1]}` };
    if (mask < 24) {
      return { ips: [], error: 'Subnet block is too large. Maximum supported scan range is a /24 subnet (256 IPs) to ensure optimal response times.' };
    }

    const ips = getIPsFromCIDR(baseIP, mask);
    return { ips };
  }

  // Range e.g. 192.168.1.1-192.168.1.50 or 192.168.1.1-50
  if (cleaned.includes('-')) {
    const parts = cleaned.split('-');
    const startIP = parts[0].trim();
    let endIP = parts[1].trim();

    if (!isValidIP(startIP)) return { ips: [], error: `Invalid start IP address: ${startIP}` };

    if (!endIP.includes('.')) {
      const octets = startIP.split('.');
      octets[3] = endIP;
      endIP = octets.join('.');
    }

    if (!isValidIP(endIP)) return { ips: [], error: `Invalid end IP address: ${endIP}` };

    const ips = getIPsFromRange(startIP, endIP);
    if (ips.length > 256) {
      return { ips: ips.slice(0, 256), error: 'Range exceeds 256 IPs. Automatically limited to first 256 IPs.' };
    }
    return { ips };
  }

  // Single IP
  if (isValidIP(cleaned)) {
    return { ips: [cleaned] };
  }

  return { ips: [], error: 'Invalid address format. Specify a single IP (e.g. 8.8.8.8), CIDR (e.g. 1.1.1.0/24), Range (e.g. 1.1.1.1-50), or comma-separated lists.' };
}

function isValidIP(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every(part => {
    const num = parseInt(part, 10);
    return !isNaN(num) && num >= 0 && num <= 255 && num.toString() === part;
  });
}

// Helper to strip out all non-listed/clean RBL database records to save Firestore document size (1MB limit)
function stripCleanListings(listings: any): any {
  if (!listings) return {};
  const stripped: any = {};
  for (const [key, value] of Object.entries(listings)) {
    if (value && ((value as any).listed || (value as any).error || (value as any).status === 'Unreachable')) {
      stripped[key] = value;
    }
  }
  return stripped;
}

function ipToLong(ip: string): number {
  return ip.split('.').reduce((ipInt, octet) => (ipInt << 8) + parseInt(octet, 10), 0) >>> 0;
}

function longToIP(long: number): string {
  return [
    (long >>> 24) & 255,
    (long >>> 16) & 255,
    (long >>> 8) & 255,
    long & 255
  ].join('.');
}

function getIPsFromCIDR(baseIP: string, mask: number): string[] {
  const ipLong = ipToLong(baseIP);
  const totalIPs = Math.pow(2, 32 - mask);
  const networkMask = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;
  const networkLong = (ipLong & networkMask) >>> 0;
  
  const ips: string[] = [];
  for (let i = 0; i < totalIPs; i++) {
    ips.push(longToIP(networkLong + i));
  }
  return ips;
}

function getIPsFromRange(startIP: string, endIP: string): string[] {
  const startLong = ipToLong(startIP);
  const endLong = ipToLong(endIP);
  
  if (startLong > endLong) return [];
  
  const ips: string[] = [];
  const limit = Math.min(endLong - startLong + 1, 512);
  for (let i = 0; i < limit; i++) {
    ips.push(longToIP(startLong + i));
  }
  return ips;
}

// Generate intelligent simulated results when DNS is blocked or "Simulate" requested
// This creates realistic, production-relevant data patterns for learning/demo use
function generateSimulatedScan(ips: string[]): any[] {
  const isps = [
    { name: 'DigitalOcean, LLC', country: 'United States', countryCode: 'US', city: 'New York', region: 'New York', lat: 40.7128, lon: -74.0060 },
    { name: 'OVH SAS', country: 'France', countryCode: 'FR', city: 'Roubaix', region: 'Hauts-de-France', lat: 50.6927, lon: 3.1778 },
    { name: 'Amazon Technologies', country: 'Ireland', countryCode: 'IE', city: 'Dublin', region: 'Leinster', lat: 53.3498, lon: -6.2603 },
    { name: 'Hetzner Online GmbH', country: 'Germany', countryCode: 'DE', city: 'Falkenstein', region: 'Saxony', lat: 50.4779, lon: 12.3713 },
    { name: 'Linode, LLC', country: 'United Kingdom', countryCode: 'GB', city: 'London', region: 'England', lat: 51.5074, lon: -0.1278 }
  ];

  const now = new Date().toISOString();
  
  return ips.map((ip, index) => {
    // Seeded random based on IP hash to keep results consistent for the same IP
    const sum = ip.split('.').reduce((acc, curr) => acc + parseInt(curr, 10), 0);
    const listedChance = (sum % 10) === 0 || (sum % 17) === 0; // Realistic listing frequency (~15-20%)
    
    // Choose ISP based on IP octets
    const ispIndex = sum % isps.length;
    const geo = isPrivateIP(ip) ? {
      country: 'Local Network',
      countryCode: 'LAN',
      region: 'Intranet',
      city: 'Private Space',
      isp: 'RFC 1918 Private Address',
      lat: 0,
      lon: 0
    } : isps[ispIndex];

    const listings: Record<string, {
      listed: boolean;
      status: 'Listed' | 'Not Listed' | 'Unreachable';
      details: string;
      responseCode: string;
      txt: string;
      responseTime: number;
      timestamp: string;
      dnsServerQueried: string;
      evidenceUrl: string;
      error: boolean;
      errorMessage: string;
    }> = {};
    let listedCount = 0;

    BLACKLIST_PROVIDERS.forEach(provider => {
      let isListed = false;
      let responseCode = '127.0.0.2';
      let details = '';
      let txt = '';

      if (!isPrivateIP(ip) && listedChance) {
        // Distribute listings among different providers realistically
        if (provider.id === 'spamhaus' && (sum % 3 === 0)) {
          isListed = true;
          responseCode = (sum % 2 === 0) ? '127.0.0.2' : '127.0.0.4';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = `Spamhaus query matching code ${responseCode}. See https://www.spamhaus.org/query/ip/${ip}`;
        } else if (provider.id === 'barracuda' && (sum % 2 === 0)) {
          isListed = true;
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = 'Barracuda BRBL: Listed as spam source.';
        } else if (provider.id === 'spamcop' && (sum % 4 === 0)) {
          isListed = true;
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = 'SpamCop: System received automated spam reports.';
        } else if (provider.id === 'sorbs' && (sum % 5 === 0)) {
          isListed = true;
          responseCode = '127.0.0.5';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = 'SORBS SMTP: Listed due to spam sending.';
        } else if (provider.id === 'uceprotect1' && (sum % 6 === 0)) {
          isListed = true;
          responseCode = '127.0.0.2';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = 'UCEPROTECT: Listed on Level 1 due to spam reports.';
        } else if (provider.id === 'blocklist' && (sum % 7 === 0)) {
          isListed = true;
          responseCode = '127.0.0.9';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = 'Blocklist.de: Host detected running brute-force attacks.';
        } else if (provider.id === 'dronebl' && (sum % 8 === 0)) {
          isListed = true;
          responseCode = '127.0.0.10';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = 'DroneBL: Active IRC botnet crawler detected.';
        } else if (provider.id === 'gbudb' && (sum % 9 === 0)) {
          isListed = true;
          responseCode = '127.0.0.2';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = 'GBUdb: High volume automated abuse activity.';
        } else if (provider.id === 'spamratsnoptr' && (sum % 11 === 0)) {
          isListed = true;
          responseCode = '127.0.0.2';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = 'SpamRats: Reverse DNS pointer (PTR) record missing or invalid.';
        } else if (provider.id === 'mailspikebl' && (sum % 12 === 0)) {
          isListed = true;
          responseCode = '127.0.0.2';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = 'Mailspike: Unfavorable sending IP reputation.';
        } else if (provider.id === 'mailspikez' && (sum % 13 === 0)) {
          isListed = true;
          responseCode = '127.0.0.2';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = 'Mailspike Zombie: Device part of an active botnet cluster.';
        } else if (provider.id === 'hostkarma' && (sum % 14 === 0)) {
          isListed = true;
          responseCode = (sum % 2 === 0) ? '127.0.0.2' : '127.0.0.3';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = `Hostkarma: Listed on Hostkarma database as ${responseCode === '127.0.0.2' ? 'black' : 'yellow'}.`;
        } else if (provider.id === 's5hnet' && (sum % 15 === 0)) {
          isListed = true;
          responseCode = '127.0.0.2';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = 's5h.net: Malicious/abusive background traffic detected.';
        } else if (provider.id === 'nixspam' && (sum % 16 === 0)) {
          isListed = true;
          responseCode = '127.0.0.2';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = 'Manitu NiX Spam: IP detected sending bulk spam emails.';
        } else if (provider.id === 'justspam' && (sum % 18 === 0)) {
          isListed = true;
          responseCode = '127.0.0.2';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = 'JustSpam: Bulk unsolicited emails hit spam traps.';
        } else if (provider.id === 'tornevall' && (sum % 19 === 0)) {
          isListed = true;
          responseCode = '127.0.0.16';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = 'Tornevall: Compromised host proxying open connections.';
        } else if (provider.id === 'nordspam' && (sum % 21 === 0)) {
          isListed = true;
          responseCode = '127.0.0.2';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = 'NordSpam: Identified as dynamic/unauthorized mail relay.';
        } else if (provider.id === 'zerospam' && (sum % 22 === 0)) {
          isListed = true;
          responseCode = '127.0.0.2';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = '0Spam: Host flagged for real-time automated bulk abuse.';
        } else if (provider.id === 'suomispam' && (sum % 23 === 0)) {
          isListed = true;
          responseCode = '127.0.0.2';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = 'Suomispam: Regional/global threat telemetry alert.';
        } else if (provider.id === 'efnetrbl' && (sum % 24 === 0)) {
          isListed = true;
          responseCode = '127.0.0.3';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = 'EFnet RBL: TOR Exit Node listed.';
        } else if (provider.id === 'spameatingmonkey' && (sum % 25 === 0)) {
          isListed = true;
          responseCode = '127.0.0.2';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = 'SpamEatingMonkey: Spamtraps triggered by active mail delivery.';
        } else if (provider.id === 'zapbl' && (sum % 26 === 0)) {
          isListed = true;
          responseCode = '127.0.0.2';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = 'ZapBL: High volume spam sending patterns identified.';
        } else if (provider.id === 'interserver' && (sum % 27 === 0)) {
          isListed = true;
          responseCode = '127.0.0.2';
          details = getResponseCodeDetails(provider.domain, responseCode);
          txt = 'Interserver: Security abuse scan hit from local network segment.';
        }
      }

      if (isListed) {
        listedCount++;
      }

      listings[provider.id] = {
        listed: isListed,
        status: isListed ? 'Listed' : 'Not Listed',
        details: isListed ? (txt ? `${details} | TXT: ${txt}` : details) : 'Not Listed',
        responseCode: isListed ? responseCode : 'NXDOMAIN',
        txt: isListed ? txt : '',
        responseTime: Math.floor(Math.random() * 80) + 10, // 10ms - 90ms simulation
        timestamp: now,
        dnsServerQueried: 'Authoritative NS (Simulated)',
        evidenceUrl: provider.delistUrl || '',
        error: false,
        errorMessage: ''
      };
    });

    return {
      ip,
      status: listedCount > 0 ? 'listed' : 'clean',
      listedCount,
      listings: listings,
      location: geo,
      timestamp: now,
      ...(listedCount > 0 ? { actionStatus: 'unresolved' } : {})
    };
  });
}

// API: Get Blacklist Providers Info
app.get("/api/providers", (req, res) => {
  res.json({ providers: BLACKLIST_PROVIDERS });
});

// API: Diagnose DNSBL lookup issues for a specific IP
app.get("/api/diagnose", async (req, res) => {
  const ip = (req.query.ip as string) || "127.0.0.2";
  
  if (isPrivateIP(ip) && ip !== "127.0.0.2") {
    res.status(400).json({ error: "Private network IPs cannot be looked up on public DNSBLs." });
    return;
  }

  console.log(`[WolastShield Diagnostic] Starting DNSBL diagnostic scan for target IP: ${ip}`);
  const reversed = reverseIP(ip);
  const diagnostics: any[] = [];

  for (const provider of BLACKLIST_PROVIDERS) {
    const lookupDomain = `${reversed}.${provider.domain}`;
    const result: any = {
      providerId: provider.id,
      providerName: provider.name,
      domain: provider.domain,
      lookupQuery: lookupDomain,
      defaultResolver: { status: 'pending', a: null, txt: null, error: null },
      publicResolver: { status: 'pending', a: null, txt: null, error: null },
      authoritativeResolver: { status: 'pending', a: null, txt: null, error: null }
    };

    // 1. Standard Default Node.js DNS Resolver
    try {
      const defaultA = await new Promise<string[]>((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('Timeout after 2s')), 2000);
        dns.resolve4(lookupDomain, (err, addresses) => {
          clearTimeout(t);
          if (err) reject(err);
          else resolve(addresses);
        });
      });
      result.defaultResolver.a = defaultA;
      result.defaultResolver.status = 'success';
    } catch (err: any) {
      if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') {
        result.defaultResolver.a = [];
        result.defaultResolver.status = 'success';
      } else {
        result.defaultResolver.error = err.code || err.message;
        result.defaultResolver.status = 'error';
      }
    }

    try {
      const defaultTxt = await new Promise<string[][]>((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('Timeout after 2s')), 2000);
        dns.resolveTxt(lookupDomain, (err, records) => {
          clearTimeout(t);
          if (err) reject(err);
          else resolve(records);
        });
      });
      result.defaultResolver.txt = defaultTxt.flat().join(' ');
    } catch (err: any) {
      // Ignore text lookup error on diagnostic level
    }

    // 2. Configured Custom/Private DNS Resolver
    const customResolverIp = systemConfig.dnsResolvers[0] || '1.1.1.1';
    result.publicResolver.resolverIp = customResolverIp;
    try {
      const publicResolver = new dns.Resolver();
      publicResolver.setServers([customResolverIp]);
      const publicA = await new Promise<string[]>((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('Timeout after 2s')), 2000);
        publicResolver.resolve4(lookupDomain, (err, addresses) => {
          clearTimeout(t);
          if (err) reject(err);
          else resolve(addresses);
        });
      });
      result.publicResolver.a = publicA;
      result.publicResolver.status = 'success';
    } catch (err: any) {
      if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') {
        result.publicResolver.a = [];
        result.publicResolver.status = 'success';
      } else {
        result.publicResolver.error = err.code || err.message;
        result.publicResolver.status = 'error';
      }
    }

    try {
      const publicResolver = new dns.Resolver();
      publicResolver.setServers([customResolverIp]);
      const publicTxt = await new Promise<string[][]>((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('Timeout after 2s')), 2000);
        publicResolver.resolveTxt(lookupDomain, (err, records) => {
          clearTimeout(t);
          if (err) reject(err);
          else resolve(records);
        });
      });
      result.publicResolver.txt = publicTxt.flat().join(' ');
    } catch (err: any) {
      // Ignore text error
    }

    // 3. Authoritative DNS resolver, if we resolved and cached any
    const authResolvers = providerResolvers.get(provider.id);
    if (authResolvers && authResolvers.length > 0) {
      try {
        const authA = await new Promise<string[]>((resolve, reject) => {
          const t = setTimeout(() => reject(new Error('Timeout after 2s')), 2000);
          authResolvers[0].resolver.resolve4(lookupDomain, (err, addresses) => {
            clearTimeout(t);
            if (err) reject(err);
            else resolve(addresses);
          });
        });
        result.authoritativeResolver.a = authA;
        result.authoritativeResolver.status = 'success';
      } catch (err: any) {
        if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') {
          result.authoritativeResolver.a = [];
          result.authoritativeResolver.status = 'success';
        } else {
          result.authoritativeResolver.error = err.code || err.message;
          result.authoritativeResolver.status = 'error';
        }
      }

      try {
        const authTxt = await new Promise<string[][]>((resolve, reject) => {
          const t = setTimeout(() => reject(new Error('Timeout after 2s')), 2000);
          authResolvers[0].resolver.resolveTxt(lookupDomain, (err, records) => {
            clearTimeout(t);
            if (err) reject(err);
            else resolve(records);
          });
        });
        result.authoritativeResolver.txt = authTxt.flat().join(' ');
      } catch (err: any) {
        // Ignore text error
      }
    } else {
      result.authoritativeResolver.status = 'not_available';
      result.authoritativeResolver.error = 'No authoritative servers cached for this provider';
    }

    const defaultDesc = result.defaultResolver.status === 'success' 
      ? (result.defaultResolver.a && result.defaultResolver.a.length > 0 ? `resolved [${result.defaultResolver.a.join(', ')}]` : 'resolved (NX)')
      : `restricted (${result.defaultResolver.error})`;

    const publicDesc = result.publicResolver.status === 'success'
      ? (result.publicResolver.a && result.publicResolver.a.length > 0 ? `resolved [${result.publicResolver.a.join(', ')}]` : 'resolved (NX)')
      : `restricted (${result.publicResolver.error})`;

    console.log(`[WolastShield Diagnostic] ${provider.name} lookup: Default=${defaultDesc}, Public=${publicDesc}`);
    diagnostics.push(result);
  }

  res.json({
    timestamp: new Date().toISOString(),
    testedIp: ip,
    reversedIp: reversed,
    diagnostics
  });
});

// API: Perform Subnet/IP scan
app.post("/api/scan", async (req, res) => {
  const { target, simulate = false } = req.body;
  
  if (!target) {
    res.status(400).json({ error: 'A target IP, CIDR, or Range is required.' });
    return;
  }

  const { ips, error } = parseTarget(target);
  
  if (error && (!ips || ips.length === 0)) {
    res.status(400).json({ error });
    return;
  }

  const startTime = Date.now();
  let results: any[] = [];

  try {
    if (simulate) {
      // Demo / Simulator Mode
      results = generateSimulatedScan(ips);
    } else {
      // Real DNSBL + GeoIP Scan Mode
      const batchSize = 10; // Batch requests to preserve CPU and local network handles
      results = [];

      for (let i = 0; i < ips.length; i += batchSize) {
        const batch = ips.slice(i, i + batchSize);
        const batchPromises = batch.map(async (ip) => {
          const geo = await fetchGeoIP(ip);
          const listings: Record<string, {
            listed: boolean;
            status: 'Listed' | 'Not Listed' | 'Unreachable';
            details: string;
            responseCode: string;
            txt: string;
            responseTime: number;
            timestamp: string;
            dnsServerQueried: string;
            evidenceUrl: string;
            error: boolean;
            errorMessage: string;
          }> = {};
          let listedCount = 0;

          if (isPrivateIP(ip)) {
            // Private network IPs cannot be on public RBLs
            BLACKLIST_PROVIDERS.forEach(provider => {
              listings[provider.id] = {
                listed: false,
                status: 'Not Listed',
                details: 'Not Listed (RFC 1918 Private IP Range)',
                responseCode: 'NXDOMAIN',
                txt: '',
                responseTime: 0,
                timestamp: new Date().toISOString(),
                dnsServerQueried: 'Local Network',
                evidenceUrl: provider.delistUrl || '',
                error: false,
                errorMessage: ''
              };
            });
          } else {
            // Query DNS blacklists in parallel for this IP
            const blacklistChecks = await Promise.all(
              BLACKLIST_PROVIDERS.map(async (provider) => {
                const check = await checkDNSBL(ip, provider.domain);
                return { id: provider.id, ...check };
              })
            );

            blacklistChecks.forEach(check => {
              listings[check.id] = {
                listed: check.listed,
                status: check.status,
                details: check.details,
                responseCode: check.responseCode,
                txt: check.txt,
                responseTime: check.responseTime,
                timestamp: check.timestamp,
                dnsServerQueried: check.dnsServerQueried,
                evidenceUrl: BLACKLIST_PROVIDERS.find(p => p.id === check.id)?.delistUrl || '',
                error: check.error || false,
                errorMessage: check.errorMessage || ''
              };
              if (check.listed) {
                listedCount++;
              }
            });
          }

          return {
            ip,
            status: listedCount > 0 ? 'listed' : 'clean',
            listedCount,
            listings: listings,
            location: geo,
            timestamp: new Date().toISOString(),
            actionStatus: listedCount > 0 ? 'unresolved' : undefined
          };
        });

        const batchResults = await Promise.all(batchPromises);
        results.push(...batchResults);
      }
    }

    const listedCount = results.filter(r => r.status === 'listed').length;
    const cleanCount = results.length - listedCount;

    res.json({
      id: `scan_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
      target,
      totalIPs: results.length,
      cleanCount,
      listedCount,
      results,
      timestamp: new Date().toISOString(),
      durationMs: Date.now() - startTime
    });
  } catch (err: any) {
    res.status(500).json({ error: `Scanning execution failed: ${err.message || err}` });
  }
});

// Providers API
app.get("/api/providers", (req, res) => {
  res.json({ providers: BLACKLIST_PROVIDERS });
});

// Persistent User Accounts Store
const USERS_FILE_PATH = path.join(process.cwd(), "users_store.json");

const DEFAULT_USERS = [
  {
    uid: "admin_pranto",
    email: "mzpranto71@gmail.com",
    displayName: "Admin Pranto",
    role: "admin",
    status: "active",
    createdAt: "2026-07-12T00:00:00.000Z",
    passwordHash: "admin1234"
  },
  {
    uid: "emp_redwan",
    email: "redwan@wolast.com",
    displayName: "Redwan (Wolast)",
    role: "admin",
    status: "active",
    createdAt: "2026-07-12T00:00:00.000Z",
    passwordHash: "redwan1234"
  },
  {
    uid: "emp_sarah",
    email: "sarah@company.com",
    displayName: "Sarah Connor (Operations)",
    role: "user",
    status: "active",
    createdAt: "2026-07-12T00:00:00.000Z",
    passwordHash: "sarah5678"
  },
  {
    uid: "emp_john",
    email: "john@company.com",
    displayName: "John Doe (Support)",
    role: "user",
    status: "active",
    createdAt: "2026-07-12T00:00:00.000Z",
    passwordHash: "john9012"
  }
];

function loadServerUsers(): any[] {
  try {
    if (fs.existsSync(USERS_FILE_PATH)) {
      const data = fs.readFileSync(USERS_FILE_PATH, "utf-8");
      const parsed = JSON.parse(data);
      if (Array.isArray(parsed)) {
        return parsed;
      }
    }
  } catch (err) {
    console.error("Error reading users_store.json:", err);
  }
  try {
    fs.writeFileSync(USERS_FILE_PATH, JSON.stringify(DEFAULT_USERS, null, 2), "utf-8");
  } catch (e) {}
  return DEFAULT_USERS;
}

function saveServerUsers(users: any[]) {
  try {
    fs.writeFileSync(USERS_FILE_PATH, JSON.stringify(users, null, 2), "utf-8");
  } catch (err) {
    console.error("Error writing users_store.json:", err);
  }
}

// User API Routes
app.get("/api/users", (req, res) => {
  const users = loadServerUsers();
  res.json({ users });
});

app.post("/api/users", (req, res) => {
  try {
    const { email, displayName, passwordHash, role } = req.body;
    if (!email || !displayName || !passwordHash) {
      res.status(400).json({ error: "Email, display name, and password are required." });
      return;
    }

    const trimmedEmail = email.trim().toLowerCase();
    const users = loadServerUsers();

    const existing = users.find((u: any) => u.email.toLowerCase() === trimmedEmail);
    if (existing) {
      res.status(400).json({ error: `User with email ${trimmedEmail} already exists in employee directory.` });
      return;
    }

    const newUser = {
      uid: `usr_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      email: trimmedEmail,
      displayName: displayName.trim(),
      role: role || "user",
      status: "active",
      createdAt: new Date().toISOString(),
      passwordHash: passwordHash.trim()
    };

    users.push(newUser);
    saveServerUsers(users);

    res.json({ success: true, user: newUser });
  } catch (err: any) {
    res.status(500).json({ error: `Failed to create user: ${err.message}` });
  }
});

app.put("/api/users/:uid", (req, res) => {
  try {
    const { uid } = req.params;
    const { email, displayName, passwordHash, role, status } = req.body;

    const users = loadServerUsers();
    const index = users.findIndex((u: any) => u.uid === uid || u.email.toLowerCase() === (email || "").toLowerCase());

    if (index === -1) {
      res.status(404).json({ error: "User not found." });
      return;
    }

    const current = users[index];
    const updated = {
      ...current,
      ...(email ? { email: email.trim().toLowerCase() } : {}),
      ...(displayName ? { displayName: displayName.trim() } : {}),
      ...(passwordHash ? { passwordHash: passwordHash.trim() } : {}),
      ...(role ? { role } : {}),
      ...(status ? { status } : {})
    };

    users[index] = updated;
    saveServerUsers(users);

    res.json({ success: true, user: updated });
  } catch (err: any) {
    res.status(500).json({ error: `Failed to update user: ${err.message}` });
  }
});

app.delete("/api/users/:uid", (req, res) => {
  try {
    const { uid } = req.params;
    const emailQuery = (req.query.email as string || "").trim().toLowerCase();
    const targetUidOrEmail = decodeURIComponent(uid).trim().toLowerCase();
    let users = loadServerUsers();

    const initialLen = users.length;
    users = users.filter((u: any) => {
      const uUid = (u.uid || "").trim().toLowerCase();
      const uEmail = (u.email || "").trim().toLowerCase();
      
      const matchUid = uUid === targetUidOrEmail;
      const matchEmail = uEmail === targetUidOrEmail;
      const matchQueryEmail = emailQuery && uEmail === emailQuery;

      return !(matchUid || matchEmail || matchQueryEmail);
    });

    saveServerUsers(users);
    res.json({ success: true, count: initialLen - users.length });
  } catch (err: any) {
    res.status(500).json({ error: `Failed to delete user: ${err.message}` });
  }
});

app.post("/api/auth/login", (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email) {
      res.status(400).json({ error: "Email address is required." });
      return;
    }

    const trimmedEmail = email.trim().toLowerCase();
    const users = loadServerUsers();

    let user = users.find((u: any) => u.email && u.email.toLowerCase() === trimmedEmail);

    if (!user) {
      // Auto-provision employee if they belong to company domain or are staff
      const namePart = trimmedEmail.split("@")[0].replace(".", " ").replace("_", " ");
      const displayName = namePart.charAt(0).toUpperCase() + namePart.slice(1) + " (Wolast Staff)";
      const role = (trimmedEmail.includes("admin") || trimmedEmail.includes("redwan") || trimmedEmail.includes("wolast")) ? "admin" : "user";

      user = {
        uid: `usr_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
        email: trimmedEmail,
        displayName,
        role,
        status: "active",
        createdAt: new Date().toISOString(),
        passwordHash: password ? password.trim() : "wolast1234"
      };

      users.push(user);
      saveServerUsers(users);
    } else {
      // If user exists and password is provided, sync initial placeholder password if necessary
      if (user.passwordHash !== password && (user.passwordHash === "redwan1234" || user.passwordHash === "wolast1234") && password) {
        user.passwordHash = password.trim();
        saveServerUsers(users);
      }
    }

    if (user.passwordHash && user.passwordHash !== password) {
      res.status(401).json({ error: "Invalid email or password. Please verify your credentials." });
      return;
    }

    if (user.status === "suspended") {
      res.status(403).json({ error: "Your account has been suspended. Please contact the administrator." });
      return;
    }

    res.json({ success: true, user });
  } catch (err: any) {
    res.status(500).json({ error: `Authentication error: ${err.message}` });
  }
});

// Persistent Scans Store
const SCANS_FILE_PATH = path.join(process.cwd(), "scans_store.json");

function loadServerScans(): any[] {
  try {
    if (fs.existsSync(SCANS_FILE_PATH)) {
      const data = fs.readFileSync(SCANS_FILE_PATH, "utf-8");
      return JSON.parse(data) || [];
    }
  } catch (err) {
    console.error("Error reading scans_store.json:", err);
  }
  return [];
}

function saveServerScans(scans: any[]) {
  try {
    fs.writeFileSync(SCANS_FILE_PATH, JSON.stringify(scans, null, 2), "utf-8");
  } catch (err) {
    console.error("Error writing scans_store.json:", err);
  }
}

app.get("/api/scans", (req, res) => {
  const scans = loadServerScans();
  res.json({ scans });
});

app.post("/api/scans", (req, res) => {
  try {
    const scanData = req.body;
    if (!scanData || !scanData.target) {
      res.status(400).json({ error: "Invalid scan payload" });
      return;
    }

    const scans = loadServerScans();
    const newScan = {
      id: scanData.id || `scan_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      ...scanData,
      timestamp: scanData.timestamp || new Date().toISOString()
    };

    scans.unshift(newScan);
    saveServerScans(scans);

    res.json({ success: true, scan: newScan });
  } catch (err: any) {
    res.status(500).json({ error: `Failed to save scan: ${err.message}` });
  }
});

app.delete("/api/scans/:id", (req, res) => {
  try {
    const { id } = req.params;
    let scans = loadServerScans();
    scans = scans.filter((s: any) => s.id !== id);
    saveServerScans(scans);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: `Failed to delete scan: ${err.message}` });
  }
});

// Persistent Monitored IPs Store
const MONITORED_IPS_FILE_PATH = path.join(process.cwd(), "monitored_ips_store.json");

function loadServerMonitoredIPs(): any[] {
  try {
    if (fs.existsSync(MONITORED_IPS_FILE_PATH)) {
      const data = fs.readFileSync(MONITORED_IPS_FILE_PATH, "utf-8");
      return JSON.parse(data) || [];
    }
  } catch (err) {
    console.error("Error reading monitored_ips_store.json:", err);
  }
  return [];
}

function saveServerMonitoredIPs(ips: any[]) {
  try {
    fs.writeFileSync(MONITORED_IPS_FILE_PATH, JSON.stringify(ips, null, 2), "utf-8");
  } catch (err) {
    console.error("Error writing monitored_ips_store.json:", err);
  }
}

app.get("/api/monitored-ips", (req, res) => {
  const ips = loadServerMonitoredIPs();
  res.json({ ips });
});

app.post("/api/monitored-ips", (req, res) => {
  try {
    const ipData = req.body;
    if (!ipData || !ipData.ipOrCidr) {
      res.status(400).json({ error: "Invalid IP data payload" });
      return;
    }

    const ips = loadServerMonitoredIPs();
    const newIP = {
      id: ipData.id || `ip_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      ...ipData
    };

    const existingIndex = ips.findIndex((i: any) => i.id === newIP.id || i.ipOrCidr === newIP.ipOrCidr);
    if (existingIndex >= 0) {
      ips[existingIndex] = { ...ips[existingIndex], ...newIP };
    } else {
      ips.unshift(newIP);
    }

    saveServerMonitoredIPs(ips);
    res.json({ success: true, ip: newIP });
  } catch (err: any) {
    res.status(500).json({ error: `Failed to save monitored IP: ${err.message}` });
  }
});

app.put("/api/monitored-ips/:id", (req, res) => {
  try {
    const { id } = req.params;
    const updateData = req.body;
    const ips = loadServerMonitoredIPs();

    const index = ips.findIndex((i: any) => i.id === id);
    if (index === -1) {
      res.status(404).json({ error: "Monitored IP not found" });
      return;
    }

    ips[index] = { ...ips[index], ...updateData };
    saveServerMonitoredIPs(ips);

    res.json({ success: true, ip: ips[index] });
  } catch (err: any) {
    res.status(500).json({ error: `Failed to update monitored IP: ${err.message}` });
  }
});

app.delete("/api/monitored-ips/:id", (req, res) => {
  try {
    const { id } = req.params;
    let ips = loadServerMonitoredIPs();
    ips = ips.filter((i: any) => i.id !== id);
    saveServerMonitoredIPs(ips);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: `Failed to delete monitored IP: ${err.message}` });
  }
});

// API: Get Daily Blacklist Reports
const DAILY_REPORTS_FILE_PATH = path.join(process.cwd(), "daily_reports_store.json");

function loadServerDailyReports(): any[] {
  try {
    if (fs.existsSync(DAILY_REPORTS_FILE_PATH)) {
      const data = fs.readFileSync(DAILY_REPORTS_FILE_PATH, "utf-8");
      return JSON.parse(data) || [];
    }
  } catch (err) {
    console.error("Error reading daily_reports_store.json:", err);
  }
  return [];
}

function saveServerDailyReport(report: any) {
  try {
    const reports = loadServerDailyReports();
    const index = reports.findIndex((r: any) => r.id === report.id || r.date === report.date);
    if (index >= 0) {
      reports[index] = { ...reports[index], ...report };
    } else {
      reports.unshift(report);
    }
    fs.writeFileSync(DAILY_REPORTS_FILE_PATH, JSON.stringify(reports, null, 2), "utf-8");
  } catch (err) {
    console.error("Error writing daily_reports_store.json:", err);
  }
}

app.get("/api/reports/daily", async (req, res) => {
  const reportsMap = new Map<string, any>();
  
  // 1. Load local server reports
  const localReports = loadServerDailyReports();
  localReports.forEach(r => {
    if (r && (r.id || r.date)) {
      reportsMap.set(r.id || r.date, r);
    }
  });

  // 2. Load Firestore reports if available
  if (serverDb) {
    try {
      const querySnapshot = await Promise.race([
        getDocs(collection(serverDb, "daily_reports")),
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error("Timeout")), 2000))
      ]);
      querySnapshot.forEach((doc) => {
        const data = doc.data();
        const id = doc.id;
        reportsMap.set(id, { id, ...data });
      });
    } catch (err: any) {
      console.warn("Firestore daily_reports fetch skipped:", err.message);
    }
  }

  const reports = Array.from(reportsMap.values());
  reports.sort((a, b) => (b.date || '').localeCompare(a.date || ''));
  res.json({ reports });
});

// API: Manually Trigger / Generate Daily Report
app.post("/api/reports/daily/generate", async (req, res) => {
  try {
    // Run the daemon first to refresh all monitored hosts
    await runMonitoringDaemon();
    
    // Generate/compile the daily report
    const report = await generateDailyReportInternal(serverDb);
    res.json({ success: true, report });
  } catch (err: any) {
    res.status(500).json({ error: `Failed to compile daily report: ${err.message}` });
  }
});

// Initialize Firebase on server
let serverDb: any = null;
try {
  const configPath = path.join(process.cwd(), "firebase-applet-config.json");
  if (fs.existsSync(configPath)) {
    const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
    const app = getApps().length === 0 ? initializeApp(config, "server-app") : getApp("server-app");
    serverDb = getFirestore(app, config.firestoreDatabaseId);
    console.log("[WolastShield] Server-side Firebase connected successfully.");

    // Real-time listener for system settings config
    onSnapshot(doc(serverDb, "system_settings", "global"), (snapshot) => {
      if (snapshot.exists()) {
        const data = snapshot.data();
        if (data.dnsResolvers) {
          const list = data.dnsResolvers.split(',')
            .map((ip: string) => ip.trim())
            .filter((ip: string) => ip.length > 0);
          if (list.length > 0) {
            systemConfig.dnsResolvers = list;
            console.log(`[WolastShield] Real-time DNS resolvers synced: ${list.join(', ')}`);
          }
        }
        if (data.monitorInterval) {
          systemConfig.monitorInterval = parseInt(data.monitorInterval, 10) || 10;
          console.log(`[WolastShield] Real-time monitor interval synced: ${systemConfig.monitorInterval} min`);
        }
      } else {
        console.log("[WolastShield] Global system settings initialized in memory.");
      }
    }, (error) => {
      console.error("[WolastShield] Error listening to system_settings:", error);
    });

  } else {
    console.log("[WolastShield] firebase-applet-config.json not found on server yet. Daemon waiting for client setup.");
  }
} catch (err) {
  console.error("[WolastShield] Error initializing server-side Firebase:", err);
}

// Reports compiler helper
async function generateDailyReportInternal(dbRef: any) {
  const todayStr = new Date().toISOString().split('T')[0];
  console.log(`[WolastShield Reports] Compiling daily blacklist report for ${todayStr}...`);
  
  try {
    const monitoredListMap = new Map<string, any>();
    
    // 1. Load from server local store
    loadServerMonitoredIPs().forEach((item: any) => {
      if (item && item.id) monitoredListMap.set(item.id, item);
    });

    // 2. Load from Firestore if available
    if (dbRef) {
      try {
        const querySnapshot = await Promise.race([
          getDocs(collection(dbRef, "monitored_ips")),
          new Promise<never>((_, reject) => setTimeout(() => reject(new Error("Timeout")), 2000))
        ]);
        querySnapshot.forEach((doc) => {
          monitoredListMap.set(doc.id, { id: doc.id, ...doc.data() });
        });
      } catch (fErr: any) {
        console.warn(`[WolastShield Reports] Firestore getDocs skipped: ${fErr.message}`);
      }
    }

    const monitoredList = Array.from(monitoredListMap.values());

    let totalMonitoredIPs = 0;
    let totalTargets = monitoredList.length;
    let listedTargetsCount = 0;
    let cleanTargetsCount = 0;
    const allBlacklistedIPs: any[] = [];

    for (const item of monitoredList) {
      const targetTotal = item.totalIPs || 1;
      totalMonitoredIPs += targetTotal;

      if (item.status === 'listed') {
        listedTargetsCount++;
        if (item.blacklistedIPs && Array.isArray(item.blacklistedIPs)) {
          item.blacklistedIPs.forEach((b: any) => {
            allBlacklistedIPs.push({
              ip: b.ip || "",
              parentTarget: item.ipOrCidr || "",
              parentLabel: item.label || "",
              listedCount: b.listedCount || 0,
              listings: stripCleanListings(b.listings || {}),
              location: b.location || null
            });
          });
        } else if (item.listings) {
          allBlacklistedIPs.push({
            ip: item.ipOrCidr || "",
            parentTarget: item.ipOrCidr || "",
            parentLabel: item.label || "",
            listedCount: item.listedCount || 0,
            listings: stripCleanListings(item.listings || {}),
            location: item.location || null
          });
        }
      } else {
        cleanTargetsCount++;
      }
    }

    const summary = `Daily audit of ${totalTargets} monitoring targets (${totalMonitoredIPs} total IP hosts) complete. Identified ${allBlacklistedIPs.length} blacklisted IP nodes active on RBL databases.`;

    const reportData = {
      id: `report_${todayStr}`,
      date: todayStr,
      timestamp: new Date().toISOString(),
      totalMonitoredIPs,
      totalTargets,
      listedTargetsCount,
      cleanTargetsCount,
      blacklistedIPsCount: allBlacklistedIPs.length,
      blacklistedIPs: allBlacklistedIPs,
      summary
    };

    // Save to local daily reports store
    saveServerDailyReport(reportData);

    console.log(`[WolastShield Reports] Daily report compiled for ${todayStr}.`);
    return reportData;
  } catch (err) {
    console.error("[WolastShield Reports] Error compiling daily report:", err);
    return null;
  }
}

// Sanitize object for Firestore to recursively remove/replace undefined with default values
function sanitizeFirestoreData(data: any): any {
  if (data === undefined) return null;
  if (data === null) return null;
  
  if (Array.isArray(data)) {
    return data.map(item => sanitizeFirestoreData(item));
  }
  
  if (typeof data === 'object') {
    const sanitized: any = {};
    for (const [key, value] of Object.entries(data)) {
      if (value !== undefined) {
        sanitized[key] = sanitizeFirestoreData(value);
      }
    }
    return sanitized;
  }
  
  return data;
}

// Background Monitoring Daemon
async function runMonitoringDaemon() {
  console.log("[WolastShield Daemon] Running automated background blacklist reputation check cycle...");
  try {
    const monitoredListMap = new Map<string, any>();

    // Load from local store
    loadServerMonitoredIPs().forEach((item: any) => {
      if (item && item.id) monitoredListMap.set(item.id, item);
    });

    // Load from Firestore if available
    if (serverDb) {
      try {
        const querySnapshot = await Promise.race([
          getDocs(collection(serverDb, "monitored_ips")),
          new Promise<never>((_, reject) => setTimeout(() => reject(new Error("Timeout")), 2000))
        ]);
        querySnapshot.forEach((doc) => {
          monitoredListMap.set(doc.id, { id: doc.id, ...doc.data() });
        });
      } catch (fErr: any) {
        console.warn(`[WolastShield Daemon] Firestore getDocs skipped: ${fErr.message}`);
      }
    }

    const monitoredList = Array.from(monitoredListMap.values());
    console.log(`[WolastShield Daemon] Found ${monitoredList.length} monitored nodes to evaluate.`);

    const updatedIPsList = [...loadServerMonitoredIPs()];

    for (const item of monitoredList) {
      console.log(`[WolastShield Daemon] Checking reputation for: ${item.ipOrCidr} (${item.label})`);
      
      const { ips, error } = parseTarget(item.ipOrCidr);
      if (error || ips.length === 0) continue;

      let results: any[] = [];
      const simulate = item.simulate !== false; // Default to simulate if not explicitly false
      const nowStr = new Date().toISOString();

      if (simulate) {
        results = generateSimulatedScan(ips);
      } else {
        // Real DNSBL + GeoIP Scan Mode
        const batchSize = 10;
        for (let i = 0; i < ips.length; i += batchSize) {
          const batch = ips.slice(i, i + batchSize);
          const batchPromises = batch.map(async (ip) => {
            const geo = await fetchGeoIP(ip);
            const listings: Record<string, {
              listed: boolean;
              details: string;
              responseCode: string;
              txt: string;
              responseTime: number;
              timestamp: string;
              error: boolean;
              errorMessage: string;
            }> = {};
            let listedCount = 0;

            if (isPrivateIP(ip)) {
              BLACKLIST_PROVIDERS.forEach(provider => {
                listings[provider.id] = {
                  listed: false,
                  details: 'Not Listed',
                  responseCode: 'NXDOMAIN',
                  txt: '',
                  responseTime: 0,
                  timestamp: nowStr,
                  error: false,
                  errorMessage: ''
                };
              });
            } else {
              const blacklistChecks = await Promise.all(
                BLACKLIST_PROVIDERS.map(async (provider) => {
                  const check = await checkDNSBL(ip, provider.domain);
                  return { id: provider.id, ...check };
                })
              );

              blacklistChecks.forEach(check => {
                listings[check.id] = {
                  listed: check.listed,
                  details: check.details || "Not Listed",
                  responseCode: check.responseCode || "NXDOMAIN",
                  txt: check.txt || "",
                  responseTime: check.responseTime || 0,
                  timestamp: check.timestamp || nowStr,
                  error: check.error || false,
                  errorMessage: check.errorMessage || ""
                };
                if (check.listed) {
                  listedCount++;
                }
              });
            }

            return {
              ip,
              status: listedCount > 0 ? 'listed' : 'clean',
              listedCount,
              listings: stripCleanListings(listings),
              location: geo,
              timestamp: nowStr
            };
          });

          const batchResults = await Promise.all(batchPromises);
          results.push(...batchResults);
        }
      }

      const dbResults = results.map(r => ({
        ...r,
        listings: stripCleanListings(r.listings)
      }));

      const blacklistedIPs = dbResults.filter(r => r.status === 'listed');
      const listedCount = blacklistedIPs.length;
      const newStatus = listedCount > 0 ? "listed" : "clean";
      const oldStatus = item.status || "unknown";

      const listings = dbResults[0]?.listings || {};

      const updatedFields = {
        ...item,
        status: newStatus,
        listedCount,
        listings,
        totalIPs: results.length,
        blacklistedIPs,
        lastChecked: new Date().toISOString()
      };

      // Update in local array
      const idx = updatedIPsList.findIndex(u => u.id === item.id);
      if (idx >= 0) {
        updatedIPsList[idx] = updatedFields;
      } else {
        updatedIPsList.push(updatedFields);
      }

      if (oldStatus !== "unknown" && oldStatus !== newStatus) {
        console.log(`[WolastShield Daemon] DETECTED STATUS CHANGE for ${item.ipOrCidr}: ${oldStatus} -> ${newStatus}`);
      }
    }
    
    saveServerMonitoredIPs(updatedIPsList);

    // Auto compile/generate daily blacklist report for today
    await generateDailyReportInternal(serverDb);
    console.log("[WolastShield Daemon] Automated background blacklist check cycle complete.");
  } catch (err) {
    console.error("[WolastShield Daemon] Background monitoring cycle failed:", err);
  }
}

// App server & dev setup
async function startServer() {
  // Initialize authoritative resolvers
  await initProviderResolvers();

  // Start the continuous background monitoring daemon
  if (serverDb) {
    // Dynamic recursive scheduler respecting systemConfig.monitorInterval
    const scheduleNext = () => {
      const intervalMs = (systemConfig.monitorInterval || 10) * 60 * 1000;
      setTimeout(async () => {
        try {
          await runMonitoringDaemon();
        } catch (e) {
          console.error("[WolastShield Daemon] Automated run error:", e);
        }
        scheduleNext();
      }, intervalMs);
    };

    // First run 10 seconds after boot
    setTimeout(async () => {
      try {
        await runMonitoringDaemon();
      } catch (e) {
        console.error("[WolastShield Daemon] Automated run error:", e);
      }
      scheduleNext();
    }, 10000);
  }

  // Vite integration
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer();
