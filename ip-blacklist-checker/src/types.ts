export interface BlacklistAnalysisItem {
  id: string;
  name: string;
  database: string;
  status: 'LISTED' | 'NOT LISTED' | 'UNREACHABLE';
  listed: boolean;
  reason: string;
  reference: string;
  recommendedAction: string;
  responseCode?: string;
  txt?: string;
  responseTime?: number;
  details?: string;
}

export interface IPScanResult {
  ip: string;
  ptr?: string;
  hostname?: string;
  isp?: string;
  org?: string;
  asn?: string;
  country?: string;
  status: 'clean' | 'listed' | 'failed';
  listedCount: number;
  listings: Record<string, BlacklistAnalysisItem | { listed: boolean; details?: string; responseCode?: string }>;
  location?: {
    country?: string;
    countryCode?: string;
    region?: string;
    city?: string;
    isp?: string;
    org?: string;
    asn?: string;
    ptr?: string;
    hostname?: string;
    lat?: number;
    lon?: number;
  };
  timestamp: string;
  notes?: string;
  actionStatus?: 'unresolved' | 'pending' | 'resolved' | 'monitoring' | 'ignored';
}

export interface SubnetScanReport {
  id: string;
  target: string;
  totalIPs: number;
  cleanCount: number;
  listedCount: number;
  results: IPScanResult[];
  timestamp: string;
  durationMs: number;
  createdBy?: string;
}

export interface BlacklistProvider {
  id: string;
  name: string;
  domain: string;
  description: string;
  delistUrl: string;
  delistEmail?: string;
  category: 'Spam' | 'Malware' | 'Proxy' | 'General' | 'Security' | 'Mail Gateway' | 'Threat Intel' | 'Web Abuse';
}

export interface DelistRequest {
  id: string;
  ip: string;
  providerId: string;
  providerName: string;
  recipientEmail?: string;
  delistUrl?: string;
  companyName: string;
  senderName: string;
  senderEmail: string;
  reasonCategory: string;
  subject: string;
  message: string;
  status: 'pending' | 'submitted' | 'under_review' | 'delisted' | 'rejected';
  submittedAt: string;
  lastCheckedAt?: string;
  notes?: string;
  sendMethod?: 'smtp' | 'client_mailto' | 'web_portal' | 'gmail_web' | 'outlook_web' | 'clipboard';
}

export interface SMTPSettings {
  host: string;
  port: number;
  secure: boolean;
  user: string;
  pass: string;
  fromName: string;
  fromEmail: string;
  companyName: string;
  isConfigured?: boolean;
}

export interface SavedReport {
  id: string;
  name: string;
  target: string;
  totalIPs: number;
  cleanCount: number;
  listedCount: number;
  timestamp: string;
}

export interface UserProfile {
  uid: string;
  email: string;
  displayName: string;
  role: 'admin' | 'user';
  createdAt: string;
  status: 'active' | 'suspended';
  passwordHash?: string;
}

export interface MonitoredIP {
  id: string;
  ipOrCidr: string;
  label: string;
  status: 'clean' | 'listed' | 'unknown' | 'failed';
  listedCount: number;
  listings?: Record<string, { listed: boolean; details?: string }>;
  lastChecked: string;
  createdBy: string;
  creatorEmail: string;
  totalIPs?: number;
  blacklistedIPs?: IPScanResult[];
  simulate?: boolean;
}

export interface AlertNotification {
  id: string;
  ip: string;
  oldStatus: string;
  newStatus: string;
  listedCount: number;
  timestamp: string;
  read: boolean;
  userId: string;
}

export interface DailyReport {
  id: string;
  date: string; // YYYY-MM-DD
  timestamp: string;
  totalMonitoredIPs: number;
  totalTargets: number;
  listedTargetsCount: number;
  cleanTargetsCount: number;
  blacklistedIPsCount: number;
  blacklistedIPs: Array<{
    ip: string;
    parentTarget: string;
    parentLabel: string;
    listedCount: number;
    listings: Record<string, { listed: boolean; details?: string; responseCode?: string }>;
    location?: {
      country?: string;
      countryCode?: string;
      region?: string;
      city?: string;
      isp?: string;
    };
  }>;
  summary: string;
}

