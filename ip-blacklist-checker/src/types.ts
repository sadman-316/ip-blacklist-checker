export interface IPScanResult {
  ip: string;
  status: 'clean' | 'listed' | 'failed';
  listedCount: number;
  listings: Record<string, { listed: boolean; details?: string; responseCode?: string }>;
  location?: {
    country?: string;
    countryCode?: string;
    region?: string;
    city?: string;
    isp?: string;
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
  category: 'Spam' | 'Malware' | 'Proxy' | 'General';
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

