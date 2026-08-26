import React, { useEffect, useState } from "react";
import { db } from "../firebase";
import { collection, getDocs, doc, writeBatch } from "firebase/firestore";
import { MonitoredIP, UserProfile, AlertNotification, DailyReport } from "../types";
import { downloadSubnetMatrixCSV, downloadDailyReportCSV, downloadDailyReportJSON } from "../utils";
import { 
  ShieldCheck, 
  ShieldAlert, 
  Plus, 
  Trash2, 
  Search, 
  Loader2, 
  RefreshCw, 
  Bell, 
  BellOff, 
  Info, 
  Check, 
  FileText, 
  Calendar, 
  ChevronRight, 
  X, 
  Globe, 
  CheckCircle2, 
  Edit2, 
  Eye, 
  Copy, 
  Download, 
  ChevronLeft, 
  Activity, 
  Shield, 
  Layers, 
  AlertTriangle,
  Server,
  Radio,
  Clock,
  FileSpreadsheet
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";

interface IPMonitoringProps {
  currentUser: UserProfile;
  triggerAlert: (type: "success" | "error" | "info" | "warning", message: string) => void;
}

// Subnet metrics calculation helper
export interface SubnetStats {
  isSubnet: boolean;
  subnetType: string;
  totalIPs: number;
  listedCount: number;
  cleanCount: number;
  healthScore: number;
  flaggedRBLs: string[];
  status: "clean" | "listed" | "unknown";
}

export function computeSubnetStats(item: MonitoredIP): SubnetStats {
  const target = (item.ipOrCidr || "").trim();
  const isSubnet = target.includes("/") || target.includes("-") || target.includes(",") || target.includes(" ");
  
  let subnetType = "Single Host (/32)";
  if (target.includes("/")) {
    const mask = target.split("/")[1];
    subnetType = `Subnet (/${mask})`;
  } else if (target.includes("-")) {
    subnetType = "IP Range";
  } else if (target.includes(",") || target.includes(" ")) {
    subnetType = "IP Cluster";
  }

  // Calculate total IP count
  let totalIPs = item.totalIPs || 1;
  if (!item.totalIPs && target.includes("/")) {
    const mask = parseInt(target.split("/")[1], 10);
    if (!isNaN(mask) && mask >= 0 && mask <= 32) {
      totalIPs = Math.min(Math.pow(2, 32 - mask), 256);
    }
  }

  // Blacklisted IPs list
  const blacklisted = item.blacklistedIPs || [];
  let listedCount = 0;
  if (blacklisted.length > 0) {
    listedCount = Math.max(blacklisted.length, item.listedCount || 0);
  } else if (item.listedCount !== undefined && item.listedCount !== null && item.listedCount > 0) {
    listedCount = item.listedCount;
  } else if (item.status === "listed") {
    listedCount = 1;
  }

  const cleanCount = Math.max(0, totalIPs - listedCount);
  const healthScore = totalIPs > 0 ? Math.round((cleanCount / totalIPs) * 100) : (item.status === "clean" ? 100 : 0);

  // Extract unique flagged RBL names
  const rblSet = new Set<string>();
  if (blacklisted.length > 0) {
    blacklisted.forEach(b => {
      if (b.listings) {
        Object.entries(b.listings).forEach(([key, val]: any) => {
          if (val && val.listed) rblSet.add(val.name || key);
        });
      }
    });
  } else if (item.listings) {
    Object.entries(item.listings).forEach(([key, val]: any) => {
      if (val && val.listed) rblSet.add(val.name || key);
    });
  }

  const status: "clean" | "listed" | "unknown" = 
    item.status === "unknown" ? "unknown" : listedCount > 0 ? "listed" : "clean";

  return {
    isSubnet,
    subnetType,
    totalIPs,
    listedCount,
    cleanCount,
    healthScore,
    flaggedRBLs: Array.from(rblSet),
    status
  };
}

export const IPMonitoring: React.FC<IPMonitoringProps> = ({ currentUser, triggerAlert }) => {
  const [monitoredIPs, setMonitoredIPs] = useState<MonitoredIP[]>([]);
  const [notifications, setNotifications] = useState<AlertNotification[]>([]);
  const [loading, setLoading] = useState(true);
  
  // Add IP form state
  const [ipOrCidr, setIpOrCidr] = useState("");
  const [label, setLabel] = useState("");
  const [addLoading, setAddLoading] = useState(false);
  const [scanAllLoading, setScanAllLoading] = useState(false);
  const [scanProgress, setScanProgress] = useState<{ current: number; total: number; target: string } | null>(null);
  const [scanningTargetId, setScanningTargetId] = useState<string | null>(null);

  // Filter/Search states
  const [searchQuery, setSearchQuery] = useState("");
  const [filterStatus, setFilterStatus] = useState<"all" | "clean" | "listed" | "unknown" | "subnets">("all");

  const isAdmin = currentUser.role === "admin";

  // Sub-tabs and Reports States
  const [activeSubTab, setActiveSubTab] = useState<"hosts" | "reports">("hosts");
  const [dailyReports, setDailyReports] = useState<DailyReport[]>([]);
  const [reportsLoading, setReportsLoading] = useState(false);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [selectedReport, setSelectedReport] = useState<DailyReport | null>(null);

  // Custom Actions Modals states
  const [editingIP, setEditingIP] = useState<MonitoredIP | null>(null);
  const [editLabel, setEditLabel] = useState("");
  const [editIpOrCidr, setEditIpOrCidr] = useState("");
  const [editLoading, setEditLoading] = useState(false);

  const [deletingIP, setDeletingIP] = useState<MonitoredIP | null>(null);
  const [deleteLoading, setDeleteLoading] = useState(false);

  const [viewingIP, setViewingIP] = useState<MonitoredIP | null>(null);
  const [viewIpSearchQuery, setViewIpSearchQuery] = useState("");
  const [viewIpStatusFilter, setViewIpStatusFilter] = useState<"all" | "clean" | "listed">("all");
  const [viewIpCurrentPage, setViewIpCurrentPage] = useState(1);
  const [modalScanning, setModalScanning] = useState(false);
  const viewIpPageSize = 10;
  const [copiedIp, setCopiedIp] = useState<string | null>(null);

  const fetchDailyReports = async () => {
    setReportsLoading(true);
    try {
      const res = await fetch("/api/reports/daily");
      if (res.ok) {
        const data = await res.json();
        setDailyReports(data.reports || []);
      }
    } catch (err) {
      console.error("Error fetching daily reports:", err);
    } finally {
      setReportsLoading(false);
    }
  };

  const handleGenerateDailyReport = async () => {
    setGeneratingReport(true);
    triggerAlert("info", "Compiling scan states and generating fresh daily blacklist report...");
    try {
      const res = await fetch("/api/reports/daily/generate", { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        triggerAlert("success", `Daily blacklist report compiled successfully for today: ${data.report.date}`);
        fetchDailyReports();
        fetchMonitoredData();
      } else {
        const err = await res.json();
        throw new Error(err.error || "Failed to generate daily report.");
      }
    } catch (err: any) {
      console.error("Error generating daily report:", err);
      triggerAlert("error", err.message || "Manual daily report compilation failed.");
    } finally {
      setGeneratingReport(false);
    }
  };

  const saveLocalIPs = (list: MonitoredIP[]) => {
    try {
      localStorage.setItem("wolast_local_monitored_ips", JSON.stringify(list));
    } catch (e) {}
  };

  const getLocalIPs = (): MonitoredIP[] => {
    try {
      const data = localStorage.getItem("wolast_local_monitored_ips");
      return data ? JSON.parse(data) : [];
    } catch (e) {
      return [];
    }
  };

  const saveLocalNotifs = (list: AlertNotification[]) => {
    try {
      localStorage.setItem("wolast_local_notifications", JSON.stringify(list));
    } catch (e) {}
  };

  const getLocalNotifs = (): AlertNotification[] => {
    try {
      const data = localStorage.getItem("wolast_local_notifications");
      return data ? JSON.parse(data) : [];
    } catch (e) {
      return [];
    }
  };

  const fetchMonitoredData = async () => {
    setLoading(true);
    try {
      const combinedIPs = new Map<string, MonitoredIP>();
      const combinedNotifs = new Map<string, AlertNotification>();

      // 1. Load local storage first
      getLocalIPs().forEach(item => {
        if (item && (item.id || item.ipOrCidr)) {
          combinedIPs.set(item.id || item.ipOrCidr, item);
        }
      });
      getLocalNotifs().forEach(item => {
        if (item && item.id) combinedNotifs.set(item.id, item);
      });

      // 2. Fetch from Firestore if available
      try {
        const querySnapshot = await Promise.race([
          getDocs(collection(db, "monitored_ips")),
          new Promise<never>((_, reject) => setTimeout(() => reject(new Error("Timeout")), 2500))
        ]);
        querySnapshot.forEach((docSnap) => {
          const data = docSnap.data() as MonitoredIP;
          const id = docSnap.id;
          if (isAdmin || data.createdBy === currentUser.uid) {
            combinedIPs.set(id, { id, ...data });
          }
        });
      } catch (fErr) {
        // Firestore fetch fallback to server API
      }

      // 3. Fetch from Express server API
      try {
        const res = await fetch("/api/monitored-ips");
        if (res.ok) {
          const data = await res.json();
          if (data && Array.isArray(data.ips)) {
            data.ips.forEach((item: MonitoredIP) => {
              if (item && item.id && (isAdmin || item.createdBy === currentUser.uid)) {
                combinedIPs.set(item.id, item);
              }
            });
          }
        }
      } catch (apiErr) {
        console.warn("Server monitored-ips API fetch skipped:", apiErr);
      }

      const ipList = Array.from(combinedIPs.values());
      const notifList = Array.from(combinedNotifs.values());

      notifList.sort((a, b) => (b.timestamp || "").localeCompare(a.timestamp || ""));

      setMonitoredIPs(ipList);
      saveLocalIPs(ipList);

      setNotifications(notifList);
      saveLocalNotifs(notifList);

    } catch (err) {
      console.error("Error loading monitored data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMonitoredData();
    fetchDailyReports();
  }, [currentUser, isAdmin]);

  // Real-time scan for a single target / subnet
  const handleScanSingleTarget = async (item: MonitoredIP) => {
    setScanningTargetId(item.id);
    triggerAlert("info", `Initiating live real-time reputation check for ${item.ipOrCidr}...`);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: item.ipOrCidr, simulate: false }) // Live RBL scan
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "Failed to scan subnet target.");
      }

      const scanResult = await res.json();
      const firstResult = scanResult.results[0] || { status: "unknown", listedCount: 0, listings: {} };
      const blacklisted = scanResult.results.filter((r: any) => r.status === "listed");
      const newStatus = scanResult.listedCount > 0 ? "listed" : "clean";
      const oldStatus = item.status;

      const updatedFields: MonitoredIP = {
        ...item,
        status: newStatus,
        listedCount: scanResult.listedCount,
        listings: firstResult.listings,
        totalIPs: scanResult.totalIPs,
        blacklistedIPs: blacklisted,
        simulate: false,
        lastChecked: new Date().toISOString()
      };

      // 1. Update React state & localStorage
      const updatedList = monitoredIPs.map(i => i.id === item.id ? updatedFields : i);
      setMonitoredIPs(updatedList);
      saveLocalIPs(updatedList);

      if (viewingIP && viewingIP.id === item.id) {
        setViewingIP(updatedFields);
      }

      // 2. Persist to Express API
      try {
        await fetch(`/api/monitored-ips/${item.id}`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(updatedFields)
        });
      } catch (apiErr) {
        console.warn("Express API update monitored IP skipped:", apiErr);
      }

      // 3. Persist to Firestore if available
      try {
        const ipDocRef = doc(db, "monitored_ips", item.id);
        const batch = writeBatch(db);
        batch.update(ipDocRef, {
          status: newStatus,
          listedCount: scanResult.listedCount,
          listings: firstResult.listings || {},
          totalIPs: scanResult.totalIPs,
          blacklistedIPs: blacklisted,
          simulate: false,
          lastChecked: new Date().toISOString()
        });

        if (oldStatus !== "unknown" && oldStatus !== newStatus) {
          const newNotification: AlertNotification = {
            id: `notif_${Date.now()}`,
            ip: item.ipOrCidr,
            oldStatus,
            newStatus,
            listedCount: scanResult.listedCount,
            timestamp: new Date().toISOString(),
            read: false,
            userId: item.createdBy
          };
          const notifDocRef = doc(collection(db, "notifications"));
          batch.set(notifDocRef, newNotification);

          setNotifications(prev => [newNotification, ...prev]);
          saveLocalNotifs([newNotification, ...notifications]);
        }
        await batch.commit();
      } catch (fErr) {
        // Fallback notification in local store if Firestore fails
        if (oldStatus !== "unknown" && oldStatus !== newStatus) {
          const newNotification: AlertNotification = {
            id: `notif_${Date.now()}`,
            ip: item.ipOrCidr,
            oldStatus,
            newStatus,
            listedCount: scanResult.listedCount,
            timestamp: new Date().toISOString(),
            read: false,
            userId: item.createdBy
          };
          setNotifications(prev => [newNotification, ...prev]);
          saveLocalNotifs([newNotification, ...notifications]);
        }
      }

      const cleanCount = scanResult.totalIPs - scanResult.listedCount;
      const score = Math.round((cleanCount / scanResult.totalIPs) * 100);

      if (scanResult.listedCount > 0) {
        triggerAlert("warning", `Real-time scan for ${item.ipOrCidr} complete: ${scanResult.listedCount} listed node(s) detected (${score}% Subnet Health).`);
      } else {
        triggerAlert("success", `Real-time scan for ${item.ipOrCidr} complete: All ${scanResult.totalIPs} IP nodes are 100% clean.`);
      }

    } catch (err: any) {
      console.error("Error scanning single target:", err);
      triggerAlert("error", err.message || `Failed to re-scan ${item.ipOrCidr}.`);
    } finally {
      setScanningTargetId(null);
    }
  };

  const handleAddIP = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ipOrCidr.trim()) {
      triggerAlert("error", "Please provide a valid IP address or CIDR subnet block.");
      return;
    }

    setAddLoading(true);
    try {
      const cleanedInput = ipOrCidr.trim();
      
      // Perform a real-time check before adding
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: cleanedInput, simulate: false }) // Live RBL scan
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "Address parsing or scanning failed.");
      }

      const scanResult = await res.json();
      const firstResult = scanResult.results[0] || { status: "unknown", listedCount: 0, listings: {} };
      const blacklisted = scanResult.results.filter((r: any) => r.status === "listed");

      const tempId = `ip_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;

      const newIP: MonitoredIP = {
        id: tempId,
        ipOrCidr: cleanedInput,
        label: label.trim() || (cleanedInput.includes("/") ? `Subnet ${cleanedInput}` : `Host ${cleanedInput}`),
        status: scanResult.listedCount > 0 ? "listed" : "clean",
        listedCount: scanResult.listedCount,
        listings: firstResult.listings,
        totalIPs: scanResult.totalIPs,
        blacklistedIPs: blacklisted,
        simulate: false,
        lastChecked: new Date().toISOString(),
        createdBy: currentUser.uid,
        creatorEmail: currentUser.email
      };

      // 1. Update local storage and UI immediately
      const currentLocals = getLocalIPs().filter(item => item.id !== tempId);
      currentLocals.unshift(newIP);
      saveLocalIPs(currentLocals);
      setMonitoredIPs(prev => [newIP, ...prev.filter(i => i.id !== tempId)]);

      triggerAlert("success", `Added ${cleanedInput} (${scanResult.totalIPs} IP node${scanResult.totalIPs > 1 ? "s" : ""}) to real-time continuous monitoring.`);
      setIpOrCidr("");
      setLabel("");

      // 2. Send to Express server API
      try {
        await fetch("/api/monitored-ips", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(newIP)
        });
      } catch (apiErr) {
        console.warn("Server API add monitored IP error:", apiErr);
      }

      // 3. Write to Firestore if available
      try {
        const docRef = doc(db, "monitored_ips", tempId);
        const batch = writeBatch(db);
        batch.set(docRef, newIP);
        await batch.commit();
      } catch (fErr) {
        console.warn("Firestore add monitored IP error:", fErr);
      }

    } catch (err: any) {
      console.error("Error adding monitored IP:", err);
      triggerAlert("error", err.message || "Failed to add target to monitoring.");
    } finally {
      setAddLoading(false);
    }
  };

  const handleUpdateIP = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingIP) return;
    if (!editIpOrCidr.trim()) {
      triggerAlert("error", "Target IP address or subnet CIDR cannot be empty.");
      return;
    }
    setEditLoading(true);
    try {
      const hasAddressChanged = editIpOrCidr.trim() !== editingIP.ipOrCidr;
      
      let updatedFields: MonitoredIP = {
        ...editingIP,
        label: editLabel.trim() || `Target ${editIpOrCidr.trim()}`,
        ipOrCidr: editIpOrCidr.trim()
      };
      
      if (hasAddressChanged) {
        const res = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target: editIpOrCidr.trim(), simulate: false }) // Live RBL scan
        });
        
        if (res.ok) {
          const scanResult = await res.json();
          const firstResult = scanResult.results[0] || { status: "unknown", listedCount: 0, listings: {} };
          const blacklisted = scanResult.results.filter((r: any) => r.status === "listed");
          
          updatedFields.status = scanResult.listedCount > 0 ? "listed" : "clean";
          updatedFields.listedCount = scanResult.listedCount;
          updatedFields.listings = firstResult.listings;
          updatedFields.totalIPs = scanResult.totalIPs;
          updatedFields.blacklistedIPs = blacklisted;
          updatedFields.simulate = false;
          updatedFields.lastChecked = new Date().toISOString();
        } else {
          const errorData = await res.json();
          throw new Error(errorData.error || "Address parsing or scanning failed.");
        }
      }
      
      // Update local storage and UI
      const currentLocals = getLocalIPs().filter(i => i.id !== editingIP.id);
      currentLocals.unshift(updatedFields);
      saveLocalIPs(currentLocals);
      setMonitoredIPs(prev => prev.map(i => i.id === editingIP.id ? updatedFields : i));

      triggerAlert("success", `Successfully updated monitoring target.`);
      setEditingIP(null);

      // Send to Express server API
      try {
        await fetch(`/api/monitored-ips/${editingIP.id}`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(updatedFields)
        });
      } catch (apiErr) {
        console.warn("Server API update monitored IP error:", apiErr);
      }

      // Update Firestore
      try {
        const ipDocRef = doc(db, "monitored_ips", editingIP.id);
        const batch = writeBatch(db);
        batch.update(ipDocRef, updatedFields as any);
        await batch.commit();
      } catch (fErr) {
        console.warn("Firestore update error:", fErr);
      }

    } catch (err: any) {
      console.error("Error updating monitored IP:", err);
      triggerAlert("error", err.message || "Failed to update target.");
    } finally {
      setEditLoading(false);
    }
  };

  const handleConfirmDelete = async () => {
    if (!deletingIP) return;
    setDeleteLoading(true);
    try {
      // 1. Remove from local storage & state immediately
      const currentLocals = getLocalIPs().filter(ip => ip.id !== deletingIP.id);
      saveLocalIPs(currentLocals);
      setMonitoredIPs(prev => prev.filter(ip => ip.id !== deletingIP.id));

      triggerAlert("success", `Successfully stopped monitoring ${deletingIP.ipOrCidr}`);
      setDeletingIP(null);

      // 2. Call Express server API delete
      try {
        await fetch(`/api/monitored-ips/${deletingIP.id}`, { method: "DELETE" });
      } catch (apiErr) {
        console.warn("Server API delete monitored IP error:", apiErr);
      }

      // 3. Call Firestore delete
      try {
        const ipDocRef = doc(db, "monitored_ips", deletingIP.id);
        const batch = writeBatch(db);
        batch.delete(ipDocRef);
        await batch.commit();
      } catch (fErr) {
        console.warn("Firestore delete error:", fErr);
      }
    } catch (err) {
      console.error("Error deleting monitored IP:", err);
      triggerAlert("error", "Failed to remove target from monitoring.");
    } finally {
      setDeleteLoading(false);
    }
  };

  const getIPsForTarget = (item: MonitoredIP): { ip: string; status: "clean" | "listed"; listedCount: number; listings: any }[] => {
    const ipOrCidrVal = item.ipOrCidr || "";
    const blacklistedList = item.blacklistedIPs || [];
    
    if (ipOrCidrVal.includes("/")) {
      const parts = ipOrCidrVal.split("/");
      const ip = parts[0];
      const mask = parseInt(parts[1], 10);
      if (isNaN(mask) || mask < 0 || mask > 32) {
        return [{ ip, status: item.status === "listed" ? "listed" : "clean", listedCount: item.listedCount, listings: item.listings || {} }];
      }
      
      const ipParts = ip.split(".").map(Number);
      if (ipParts.length !== 4 || ipParts.some(isNaN)) {
        return [{ ip, status: item.status === "listed" ? "listed" : "clean", listedCount: item.listedCount, listings: item.listings || {} }];
      }
      
      const ipNum = ((ipParts[0] << 24) >>> 0) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
      const maskNum = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;
      const startIP = (ipNum & maskNum) >>> 0;
      const numIPs = Math.pow(2, 32 - mask);
      const limit = Math.min(numIPs, 256);
      
      const list = [];
      for (let i = 0; i < limit; i++) {
        const currentIPNum = (startIP + i) >>> 0;
        const p1 = (currentIPNum >>> 24) & 255;
        const p2 = (currentIPNum >>> 16) & 255;
        const p3 = (currentIPNum >>> 8) & 255;
        const p4 = currentIPNum & 255;
        const currentIp = `${p1}.${p2}.${p3}.${p4}`;
        
        const blacklistedMatch = blacklistedList.find((b: any) => b.ip === currentIp);
        if (blacklistedMatch) {
          list.push({
            ip: currentIp,
            status: "listed" as const,
            listedCount: blacklistedMatch.listedCount || 1,
            listings: blacklistedMatch.listings || {}
          });
        } else {
          list.push({
            ip: currentIp,
            status: "clean" as const,
            listedCount: 0,
            listings: {}
          });
        }
      }
      return list;
    } else if (ipOrCidrVal.includes(",") || ipOrCidrVal.includes(" ") || ipOrCidrVal.includes("\n")) {
      const ips = ipOrCidrVal.split(/[\s,]+/).map(i => i.trim()).filter(Boolean);
      return ips.map(currentIp => {
        const blacklistedMatch = blacklistedList.find((b: any) => b.ip === currentIp);
        if (blacklistedMatch) {
          return {
            ip: currentIp,
            status: "listed" as const,
            listedCount: blacklistedMatch.listedCount || 1,
            listings: blacklistedMatch.listings || {}
          };
        } else {
          return {
            ip: currentIp,
            status: "clean" as const,
            listedCount: item.ipOrCidr === currentIp && item.status === "listed" ? item.listedCount : 0,
            listings: item.ipOrCidr === currentIp ? (item.listings || {}) : {}
          };
        }
      });
    } else {
      return [{
        ip: ipOrCidrVal,
        status: item.status === "listed" ? "listed" : "clean",
        listedCount: item.listedCount,
        listings: item.listings || {}
      }];
    }
  };

  const handleCopyIP = (ip: string) => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(ip);
      } else {
        const textarea = document.createElement("textarea");
        textarea.value = ip;
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
      }
      setCopiedIp(ip);
      setTimeout(() => {
        setCopiedIp(null);
      }, 1500);
      triggerAlert("success", `Copied IP ${ip} to clipboard.`);
    } catch (err) {
      console.error("Failed to copy IP address:", err);
      triggerAlert("error", "Failed to copy IP address.");
    }
  };

  const handleExportSubnetCSV = (item: MonitoredIP, ipList: any[]) => {
    try {
      downloadSubnetMatrixCSV(item, ipList);
      triggerAlert("success", `Exported subnet report for ${item.ipOrCidr} successfully.`);
    } catch (err: any) {
      console.error("Failed to export subnet CSV:", err);
      triggerAlert("error", "Failed to download export file.");
    }
  };

  const handleScanAll = async () => {
    if (monitoredIPs.length === 0) {
      triggerAlert("info", "No monitored IPs available to scan.");
      return;
    }

    setScanAllLoading(true);
    triggerAlert("info", "Executing real-time DNSBL scanning check across all monitored subnets and hosts...");

    try {
      let changeCount = 0;
      const updatedList: MonitoredIP[] = [];

      for (let i = 0; i < monitoredIPs.length; i++) {
        const item = monitoredIPs[i];
        setScanProgress({ current: i + 1, total: monitoredIPs.length, target: item.ipOrCidr });

        try {
          const res = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target: item.ipOrCidr, simulate: false }) // Live RBL scan
          });

          if (res.ok) {
            const scanResult = await res.json();
            const blacklisted = scanResult.results.filter((r: any) => r.status === "listed");
            const newStatus = scanResult.listedCount > 0 ? "listed" : "clean";
            const newListedCount = scanResult.listedCount;
            const oldStatus = item.status;

            const updatedFields: MonitoredIP = {
              ...item,
              status: newStatus,
              listedCount: newListedCount,
              listings: scanResult.results[0]?.listings || {},
              totalIPs: scanResult.totalIPs,
              blacklistedIPs: blacklisted,
              simulate: false,
              lastChecked: new Date().toISOString()
            };

            updatedList.push(updatedFields);

            // Update Express server store
            try {
              await fetch(`/api/monitored-ips/${item.id}`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(updatedFields)
              });
            } catch (e) {}

            // Detect status changes
            if (oldStatus !== "unknown" && oldStatus !== newStatus) {
              changeCount++;
              const newNotification: AlertNotification = {
                id: `notif_${Date.now()}_${i}`,
                ip: item.ipOrCidr,
                oldStatus,
                newStatus,
                listedCount: newListedCount,
                timestamp: new Date().toISOString(),
                read: false,
                userId: item.createdBy
              };
              setNotifications(prev => [newNotification, ...prev]);
            }
          } else {
            updatedList.push(item);
          }
        } catch (targetErr) {
          console.error(`Error scanning target ${item.ipOrCidr}:`, targetErr);
          updatedList.push(item);
        }
      }

      setMonitoredIPs(updatedList);
      saveLocalIPs(updatedList);

      if (changeCount > 0) {
        triggerAlert("warning", `Monitoring audit complete: detected ${changeCount} blacklist reputation status change(s)!`);
      } else {
        triggerAlert("success", "Monitoring audit complete: All monitored subnets & nodes are evaluated in real time.");
      }

      fetchDailyReports();
    } catch (err) {
      console.error("Error scanning monitored IPs:", err);
      triggerAlert("error", "Scanning monitor execution failed.");
    } finally {
      setScanAllLoading(false);
      setScanProgress(null);
    }
  };

  const handleMarkNotificationsRead = async () => {
    const unread = notifications.filter(n => !n.read);
    if (unread.length === 0) return;

    try {
      const batch = writeBatch(db);
      unread.forEach(n => {
        const docRef = doc(db, "notifications", n.id);
        batch.update(docRef, { read: true });
      });
      await batch.commit();
    } catch (err) {
      console.warn("Firestore mark read error:", err);
    }
    
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
    saveLocalNotifs(notifications.map(n => ({ ...n, read: true })));
    triggerAlert("success", "Marked all status-change alert notifications as read.");
  };

  // Filter & Search IP list
  const filteredIPs = monitoredIPs.filter(item => {
    const matchesSearch = 
      (item.ipOrCidr || "").toLowerCase().includes(searchQuery.toLowerCase()) ||
      (item.label || "").toLowerCase().includes(searchQuery.toLowerCase()) ||
      (item.creatorEmail || "").toLowerCase().includes(searchQuery.toLowerCase());
    
    if (!matchesSearch) return false;

    if (filterStatus === "all") return true;
    if (filterStatus === "subnets") return (item.ipOrCidr || "").includes("/") || (item.ipOrCidr || "").includes("-");
    return item.status === filterStatus;
  });

  const unreadAlerts = notifications.filter(n => !n.read).length;

  // Aggregate Fleet Telemetry Stats
  let fleetTotalIPs = 0;
  let fleetListedIPs = 0;
  let fleetSubnetsCount = 0;
  let fleetCleanSubnetsCount = 0;
  let fleetFlaggedSubnetsCount = 0;

  monitoredIPs.forEach(item => {
    const stats = computeSubnetStats(item);
    fleetTotalIPs += stats.totalIPs;
    fleetListedIPs += stats.listedCount;
    if (stats.isSubnet) fleetSubnetsCount++;
    if (stats.status === "clean") fleetCleanSubnetsCount++;
    else if (stats.status === "listed") fleetFlaggedSubnetsCount++;
  });

  const fleetCleanIPs = Math.max(0, fleetTotalIPs - fleetListedIPs);
  const fleetHealthPercent = fleetTotalIPs > 0 ? Math.round((fleetCleanIPs / fleetTotalIPs) * 100) : 100;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Sub-navigation tabs */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-200 pb-3 gap-3">
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setActiveSubTab("hosts")}
            className={`px-4 py-2 text-xs font-black uppercase tracking-wider rounded-xl transition-all duration-200 flex items-center space-x-2 cursor-pointer ${
              activeSubTab === "hosts"
                ? "bg-red-600 text-white shadow-md shadow-red-600/20"
                : "text-slate-600 hover:text-slate-900 hover:bg-slate-100"
            }`}
          >
            <Globe className="w-4 h-4" />
            <span>Monitored Nodes & Subnets</span>
            <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold ${
              activeSubTab === "hosts" ? "bg-white/20 text-white" : "bg-slate-200 text-slate-700"
            }`}>
              {monitoredIPs.length}
            </span>
          </button>
          
          <button
            onClick={() => {
              setActiveSubTab("reports");
              fetchDailyReports();
            }}
            className={`px-4 py-2 text-xs font-black uppercase tracking-wider rounded-xl transition-all duration-200 flex items-center space-x-2 cursor-pointer ${
              activeSubTab === "reports"
                ? "bg-red-600 text-white shadow-md shadow-red-600/20"
                : "text-slate-600 hover:text-slate-900 hover:bg-slate-100"
            }`}
          >
            <FileText className="w-4 h-4" />
            <span>Daily Blacklist Reports</span>
            <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold ${
              activeSubTab === "reports" ? "bg-white/20 text-white" : "bg-slate-200 text-slate-700"
            }`}>
              {dailyReports.length}
            </span>
          </button>
        </div>

        {/* Live Daemon Status Badge */}
        <div className="flex items-center gap-2 text-xs text-slate-600 bg-white border border-slate-200 px-3.5 py-1.5 rounded-xl shadow-xs">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span className="font-extrabold uppercase text-[10px] tracking-wider text-slate-800">
            Real-Time Audit Daemon:
          </span>
          <span className="font-mono font-bold text-slate-600 text-[11px]">
            Active
          </span>
        </div>
      </div>

      {activeSubTab === "hosts" && (
        <div className="space-y-6">
          
          {/* Bento Metrics Bar for Real-time Subnet Reputation */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            
            {/* Metric 1: Fleet Health Meter */}
            <div className="bg-white rounded-2xl p-5 cyber-card flex flex-col justify-between min-h-[160px] border border-slate-200 shadow-sm relative overflow-hidden before:absolute before:top-0 before:left-0 before:right-0 before:h-1 before:bg-slate-900">
              <div className="flex justify-between items-start">
                <div className="bg-slate-100 rounded-lg p-2 border border-slate-200">
                  <Shield className="w-4 h-4 text-red-600" />
                </div>
                <span className={`text-[10px] px-2.5 py-0.5 rounded-lg font-black uppercase tracking-widest border ${
                  fleetHealthPercent >= 95 
                    ? "bg-emerald-50 text-emerald-800 border-emerald-200" 
                    : fleetHealthPercent >= 80 
                    ? "bg-amber-50 text-amber-800 border-amber-200" 
                    : "bg-rose-50 text-rose-800 border-rose-200"
                }`}>
                  {fleetHealthPercent}% Safe
                </span>
              </div>
              <div className="my-1">
                <span className={`text-3xl sm:text-4xl font-black font-mono block leading-none ${
                  fleetHealthPercent >= 95 ? "text-emerald-600" : fleetHealthPercent >= 80 ? "text-amber-600" : "text-rose-600"
                }`}>
                  {fleetHealthPercent}%
                </span>
                <span className="text-xs font-black text-slate-900 uppercase tracking-widest block mt-2">
                  Fleet Subnet Health
                </span>
              </div>
              <p className="text-[11px] text-slate-500 font-medium">
                {fleetCleanIPs} of {fleetTotalIPs} total addresses clean.
              </p>
            </div>

            {/* Metric 2: Total Monitored Space */}
            <div className="bg-white rounded-2xl p-5 cyber-card flex flex-col justify-between min-h-[160px] border border-slate-200 shadow-sm relative overflow-hidden before:absolute before:top-0 before:left-0 before:right-0 before:h-1 before:bg-slate-900">
              <div className="flex justify-between items-start">
                <div className="bg-slate-100 rounded-lg p-2 border border-slate-200">
                  <Layers className="w-4 h-4 text-slate-800" />
                </div>
                <span className="text-[10px] bg-slate-100 text-slate-700 px-2.5 py-0.5 rounded-lg font-black uppercase tracking-widest border border-slate-200">
                  {monitoredIPs.length} Targets
                </span>
              </div>
              <div className="my-1">
                <span className="text-3xl sm:text-4xl font-black text-slate-900 font-mono block leading-none">
                  {fleetTotalIPs}
                </span>
                <span className="text-xs font-black text-slate-900 uppercase tracking-widest block mt-2">
                  Total Monitored IPs
                </span>
              </div>
              <p className="text-[11px] text-slate-500 font-medium">
                Across {fleetSubnetsCount} CIDR subnet blocks & host nodes.
              </p>
            </div>

            {/* Metric 3: Active Blacklist Flagged Hosts */}
            <div className={`bg-white rounded-2xl p-5 cyber-card flex flex-col justify-between min-h-[160px] border border-slate-200 shadow-sm relative overflow-hidden before:absolute before:top-0 before:left-0 before:right-0 before:h-1 ${
              fleetListedIPs > 0 ? "before:bg-rose-600 border-l-4 border-l-rose-600" : "before:bg-emerald-500"
            }`}>
              <div className="flex justify-between items-start">
                <div className="bg-rose-50 rounded-lg p-2 border border-rose-200">
                  <ShieldAlert className="w-4 h-4 text-rose-600" />
                </div>
                {fleetListedIPs > 0 ? (
                  <span className="text-[10px] bg-rose-100 text-rose-800 px-2.5 py-0.5 rounded-lg font-black uppercase tracking-widest flex items-center gap-1 border border-rose-200">
                    <span className="w-2 h-2 rounded-full bg-rose-600 animate-ping" />
                    Threats Active
                  </span>
                ) : (
                  <span className="text-[10px] bg-emerald-100 text-emerald-800 px-2.5 py-0.5 rounded-lg font-black uppercase tracking-widest border border-emerald-200">
                    All Clean
                  </span>
                )}
              </div>
              <div className="my-1">
                <span className={`text-3xl sm:text-4xl font-black font-mono block leading-none ${
                  fleetListedIPs > 0 ? "text-rose-600" : "text-slate-900"
                }`}>
                  {fleetListedIPs}
                </span>
                <span className="text-xs font-black text-slate-900 uppercase tracking-widest block mt-2">
                  Listed Threat Nodes
                </span>
              </div>
              <p className="text-[11px] text-slate-500 font-medium">
                {fleetFlaggedSubnetsCount} target{fleetFlaggedSubnetsCount === 1 ? "" : "s"} require remediation.
              </p>
            </div>

            {/* Metric 4: Real-time Scan Trigger */}
            <div className="bg-white rounded-2xl p-5 cyber-card flex flex-col justify-between min-h-[160px] border border-slate-200 shadow-sm relative overflow-hidden before:absolute before:top-0 before:left-0 before:right-0 before:h-1 before:bg-red-600">
              <div className="flex justify-between items-start">
                <div className="bg-red-50 rounded-lg p-2 border border-red-200">
                  <Radio className="w-4 h-4 text-red-600" />
                </div>
                <span className="text-[10px] bg-red-50 text-red-700 px-2.5 py-0.5 rounded-lg font-black uppercase tracking-widest border border-red-200">
                  Real-Time Scan
                </span>
              </div>
              <div className="my-1">
                <button
                  onClick={handleScanAll}
                  disabled={scanAllLoading}
                  className="w-full bg-slate-900 hover:bg-black text-white px-4 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest shadow-sm flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 border border-slate-800 transition-all"
                >
                  {scanAllLoading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin text-red-400" />
                      <span>{scanProgress ? `Scanning ${scanProgress.current}/${scanProgress.total}` : "Auditing..."}</span>
                    </>
                  ) : (
                    <>
                      <RefreshCw className="w-4 h-4 text-red-400" />
                      <span>Audit All Subnets</span>
                    </>
                  )}
                </button>
              </div>
              <p className="text-[11px] text-slate-500 font-medium">
                Queries 62 authoritative DNSBL registries live.
              </p>
            </div>

          </div>

          {/* Quick Registration Form & Real-time Alert Feed */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            
            {/* Left column: Quick configuration form */}
            <div className="bg-white rounded-2xl p-6 cyber-card space-y-5 border border-slate-200 shadow-sm">
              <div>
                <h3 className="text-xs font-black text-slate-800 uppercase tracking-widest flex items-center gap-2">
                  <Server className="w-4 h-4 text-red-600" />
                  Register Monitoring Target / Subnet
                </h3>
                <p className="text-[11px] text-slate-500 font-medium mt-1">
                  Enter an IP address (e.g. <span className="font-mono font-bold text-slate-700">185.190.140.15</span>) or CIDR subnet block (e.g. <span className="font-mono font-bold text-slate-700">192.168.1.0/24</span>) to monitor.
                </p>
              </div>

              <form onSubmit={handleAddIP} className="space-y-4">
                <div className="space-y-1.5">
                  <label className="text-[10px] font-black text-slate-600 uppercase tracking-widest block">
                    IP Address or Subnet Block (CIDR)
                  </label>
                  <input
                    type="text"
                    required
                    value={ipOrCidr}
                    onChange={(e) => setIpOrCidr(e.target.value)}
                    placeholder="e.g. 185.190.140.15 or 1.1.1.0/24"
                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-red-500/10 focus:border-red-500 text-slate-900 font-mono font-bold transition-all placeholder:text-slate-400 placeholder:font-sans placeholder:font-normal"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] font-black text-slate-600 uppercase tracking-widest block">
                    Friendly Label / Subnet Description
                  </label>
                  <input
                    type="text"
                    value={label}
                    onChange={(e) => setLabel(e.target.value)}
                    placeholder="e.g. Primary Production Mail Subnet"
                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-red-500/10 focus:border-red-500 text-slate-900 font-bold transition-all placeholder:text-slate-400 placeholder:font-normal"
                  />
                </div>

                <button
                  type="submit"
                  disabled={addLoading}
                  className="w-full bg-red-600 hover:bg-red-700 text-white py-3 px-4 rounded-xl text-xs font-black uppercase tracking-widest shadow-md shadow-red-600/20 transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 border-none"
                >
                  {addLoading ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Scanning & Registering Subnet...
                    </>
                  ) : (
                    <>
                      <Plus className="w-4 h-4" />
                      Add to Real-Time Monitoring
                    </>
                  )}
                </button>
              </form>
            </div>

            {/* Right column: Blacklist Reputation Alerts and Notifications feed */}
            <div className="lg:col-span-2 bg-white rounded-2xl p-6 cyber-card space-y-4 border border-slate-200 shadow-sm">
              <div className="flex justify-between items-center border-b border-slate-100 pb-3">
                <div className="flex items-center gap-2">
                  <div className="relative">
                    <Bell className="w-4 h-4 text-slate-600" />
                    {unreadAlerts > 0 && (
                      <span className="absolute -top-1 -right-1 w-2 h-2 bg-rose-500 rounded-full animate-ping" />
                    )}
                  </div>
                  <h3 className="text-xs font-black text-slate-800 uppercase tracking-wider">
                    Real-Time Reputation Alert Feed
                  </h3>
                  {unreadAlerts > 0 && (
                    <span className="bg-rose-100 text-rose-800 text-[10px] px-2 py-0.5 rounded-full font-black">
                      {unreadAlerts} Unread
                    </span>
                  )}
                </div>
                
                {unreadAlerts > 0 && (
                  <button
                    onClick={handleMarkNotificationsRead}
                    className="text-[10px] text-red-600 hover:text-red-800 font-black uppercase tracking-wider cursor-pointer transition-colors"
                  >
                    Mark all read
                  </button>
                )}
              </div>

              <div className="max-h-52 overflow-y-auto space-y-2.5 pr-2">
                {notifications.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-10 text-center text-slate-400">
                    <BellOff className="w-6 h-6 text-slate-300 mb-1.5" />
                    <span className="text-[11px] font-black uppercase tracking-wider text-slate-600">
                      No status fluctuations detected
                    </span>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      Subnet & IP nodes are continuously monitored. Any DNSBL listings will trigger immediate alerts here.
                    </p>
                  </div>
                ) : (
                  notifications.map((notif) => {
                    const isUnread = !notif.read;
                    const isListed = notif.newStatus === "listed";

                    return (
                      <div
                        key={notif.id}
                        className={`p-3 rounded-xl border text-xs flex justify-between items-start gap-4 transition-all ${
                          isUnread 
                            ? "bg-rose-50/60 border-rose-200" 
                            : "bg-slate-50 border-slate-200"
                        }`}
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-slate-900">{notif.ip}</span>
                            {isListed ? (
                              <span className="bg-rose-100 text-rose-800 text-[9px] px-2 py-0.5 rounded-md border border-rose-200 font-black uppercase">
                                Reputation Degraded
                              </span>
                            ) : (
                              <span className="bg-emerald-100 text-emerald-800 text-[9px] px-2 py-0.5 rounded-md border border-emerald-200 font-black uppercase">
                                Reputation Clean
                              </span>
                            )}
                          </div>
                          <p className="text-[11px] text-slate-600 font-medium">
                            Subnet status shifted from <span className="uppercase font-bold text-slate-700">{notif.oldStatus}</span> to{" "}
                            <span className={`uppercase font-black ${isListed ? "text-rose-600" : "text-emerald-600"}`}>
                              {notif.newStatus}
                            </span>{" "}
                            ({notif.listedCount} listed RBL databases)
                          </p>
                          <span className="text-[10px] text-slate-400 block font-mono">
                            {new Date(notif.timestamp).toLocaleString()}
                          </span>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>

          </div>

          {/* Main Monitored Subnets & Hosts List */}
          <div className="bg-white rounded-2xl overflow-hidden cyber-card border border-slate-200 shadow-sm">
            
            {/* Table Header Controls */}
            <div className="p-5 border-b border-slate-200 flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-slate-50/70">
              <div>
                <h3 className="text-xs font-black text-slate-800 uppercase tracking-widest flex items-center gap-2">
                  <Activity className="w-4 h-4 text-red-600" />
                  Subnet & Host Real-Time Reputation Registry ({filteredIPs.length} Monitored Items)
                </h3>
                <p className="text-[11px] text-slate-500 font-medium mt-0.5">
                  Real-time status breakdown for individual IP hosts and entire CIDR subnet allocations.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto">
                <div className="relative flex-1 md:w-60">
                  <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search subnet, IP, label..."
                    className="w-full pl-9 pr-3.5 py-1.8 bg-white border border-slate-200 rounded-xl text-xs focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-red-500/10 focus:border-red-500 transition-all text-slate-900 font-bold placeholder:text-slate-400 placeholder:font-normal"
                  />
                </div>

                <select
                  value={filterStatus}
                  onChange={(e) => setFilterStatus(e.target.value as any)}
                  className="bg-white border border-slate-200 text-xs font-bold px-3 py-2 rounded-xl text-slate-700 focus:outline-hidden focus:ring-4 focus:ring-red-500/10 focus:border-red-500 cursor-pointer shadow-xs"
                >
                  <option value="all">All Targets</option>
                  <option value="subnets">Subnets Only (/24, etc.)</option>
                  <option value="clean">100% Clean Only</option>
                  <option value="listed">Threats / Listed Only</option>
                  <option value="unknown">Unknown / Pending</option>
                </select>

                <button
                  onClick={handleScanAll}
                  disabled={scanAllLoading}
                  className="bg-slate-900 hover:bg-black text-white px-3.5 py-2 rounded-xl text-xs font-black uppercase tracking-widest shadow-xs flex items-center gap-1.5 cursor-pointer disabled:opacity-50 border border-slate-800 transition-all"
                  title="Run Real-Time Audit on All Subnets"
                >
                  {scanAllLoading ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin text-red-400" />
                      <span>Auditing...</span>
                    </>
                  ) : (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 text-red-400" />
                      <span>Re-Audit All</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* IP List Table */}
            {loading ? (
              <div className="flex flex-col items-center justify-center py-16 text-slate-400 space-y-2">
                <Loader2 className="w-8 h-8 animate-spin text-red-600" />
                <span className="text-xs font-bold text-slate-600">Retrieving monitored subnet database...</span>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-slate-100/80 border-b border-slate-200 text-slate-600 font-black uppercase tracking-widest text-[10px]">
                      <th className="py-3.5 px-4">Subnet / Node Target</th>
                      <th className="py-3.5 px-4">Label & Description</th>
                      <th className="py-3.5 px-4">Real-Time Reputation Status</th>
                      <th className="py-3.5 px-4">Telemetry / Last Audit</th>
                      {isAdmin && <th className="py-3.5 px-4">Owner</th>}
                      <th className="py-3.5 px-4 text-center">Quick Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 font-semibold text-slate-700">
                    {filteredIPs.length === 0 ? (
                      <tr>
                        <td colSpan={isAdmin ? 6 : 5} className="text-center py-12 text-slate-400 font-medium bg-slate-50/50">
                          <Info className="w-8 h-8 mx-auto text-slate-300 mb-2" />
                          <span className="text-xs font-black text-slate-700 block uppercase tracking-wider">
                            No monitored targets match criteria
                          </span>
                          <p className="text-[11px] max-w-sm mx-auto mt-1 text-slate-500">
                            Use the form above to add an IP address or subnet block to establish permanent real-time reputation tracking.
                          </p>
                        </td>
                      </tr>
                    ) : (
                      filteredIPs.map((item) => {
                        const stats = computeSubnetStats(item);
                        const isScanningThis = scanningTargetId === item.id;

                        return (
                          <tr key={item.id} className="hover:bg-slate-50/80 transition-colors">
                            {/* Column 1: Subnet / Target Address */}
                            <td className="py-3.5 px-4">
                              <div className="space-y-1">
                                <div className="flex items-center gap-2">
                                  <span className="font-mono font-black text-slate-900 text-xs">
                                    {item.ipOrCidr}
                                  </span>
                                </div>
                                <div className="flex items-center gap-1.5 flex-wrap">
                                  <span className="bg-slate-100 text-slate-700 text-[9px] px-2 py-0.5 rounded-md font-bold border border-slate-200 uppercase">
                                    {stats.subnetType}
                                  </span>
                                  <span className="bg-slate-100 text-slate-700 text-[9px] px-2 py-0.5 rounded-md font-bold border border-slate-200">
                                    {stats.totalIPs} Host{stats.totalIPs > 1 ? "s" : ""}
                                  </span>
                                </div>
                              </div>
                            </td>

                            {/* Column 2: Label & Description */}
                            <td className="py-3.5 px-4">
                              <span className="text-slate-900 font-bold block text-xs">
                                {item.label || "Unnamed Subnet Target"}
                              </span>
                              <span className="text-[10px] text-slate-400 font-medium">
                                {stats.isSubnet ? "CIDR Subnet Allocation" : "Single Host Machine"}
                              </span>
                            </td>

                            {/* Column 3: Real-Time Reputation Status (The Core Feature!) */}
                            <td className="py-3.5 px-4">
                              <div className="space-y-2 min-w-[220px]">
                                {stats.status === "clean" ? (
                                  <div className="flex items-center justify-between">
                                    <span className="inline-flex items-center gap-1.5 text-emerald-800 bg-emerald-100 px-2.5 py-0.8 rounded-md border border-emerald-200 font-black text-[11px]">
                                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                                      100% Clean ({stats.cleanCount}/{stats.totalIPs})
                                    </span>
                                    <span className="text-[10px] font-black text-emerald-700 uppercase tracking-wider flex items-center gap-1">
                                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                                      Secure
                                    </span>
                                  </div>
                                ) : stats.status === "listed" ? (
                                  <div className="space-y-1">
                                    <div className="flex items-center justify-between">
                                      <span className="inline-flex items-center gap-1.5 text-rose-800 bg-rose-100 px-2.5 py-0.8 rounded-md border border-rose-200 font-black text-[11px]">
                                        <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />
                                        {stats.healthScore}% Subnet Health
                                      </span>
                                      <span className="text-[10px] font-black text-rose-700 uppercase tracking-wider flex items-center gap-1">
                                        <span className="w-1.5 h-1.5 rounded-full bg-rose-600 animate-ping" />
                                        {stats.listedCount} Threat{stats.listedCount > 1 ? "s" : ""}
                                      </span>
                                    </div>
                                    <div className="text-[10px] font-bold text-slate-500">
                                      {stats.listedCount} Listed / {stats.cleanCount} Clean Nodes
                                    </div>
                                  </div>
                                ) : (
                                  <span className="inline-flex items-center gap-1.5 text-slate-600 bg-slate-100 px-2.5 py-0.8 rounded-md border border-slate-200 font-bold text-[11px]">
                                    <Clock className="w-3.5 h-3.5 text-slate-400" />
                                    Pending Real-Time Scan
                                  </span>
                                )}

                                {/* Subnet Real-time Health Micro Bar */}
                                <div className="w-full bg-slate-200 h-1.5 rounded-full overflow-hidden flex">
                                  <div 
                                    className="bg-emerald-500 h-full transition-all duration-300"
                                    style={{ width: `${stats.healthScore}%` }}
                                  />
                                  {stats.listedCount > 0 && (
                                    <div 
                                      className="bg-rose-500 h-full transition-all duration-300"
                                      style={{ width: `${100 - stats.healthScore}%` }}
                                    />
                                  )}
                                </div>

                                {/* Flagged RBL Chips if any */}
                                {stats.flaggedRBLs.length > 0 && (
                                  <div className="flex flex-wrap gap-1 mt-1">
                                    {stats.flaggedRBLs.slice(0, 3).map((rblName, rblIdx) => (
                                      <span key={rblIdx} className="text-[9px] font-black bg-rose-50 text-rose-700 border border-rose-200 px-1.5 py-0.2 rounded uppercase">
                                        {rblName}
                                      </span>
                                    ))}
                                    {stats.flaggedRBLs.length > 3 && (
                                      <span className="text-[9px] font-black bg-slate-100 text-slate-600 px-1.5 py-0.2 rounded">
                                        +{stats.flaggedRBLs.length - 3} more
                                      </span>
                                    )}
                                  </div>
                                )}
                              </div>
                            </td>

                            {/* Column 4: Telemetry & Last Verified */}
                            <td className="py-3.5 px-4 text-slate-500 text-[11px] font-mono">
                              <span className="block font-bold text-slate-700">
                                {new Date(item.lastChecked || Date.now()).toLocaleTimeString()}
                              </span>
                              <span className="text-[10px] text-slate-400">
                                {new Date(item.lastChecked || Date.now()).toLocaleDateString()}
                              </span>
                            </td>

                            {/* Column 5: Owner (Admin only) */}
                            {isAdmin && (
                              <td className="py-3.5 px-4 font-mono text-[10px] text-slate-500">
                                {item.creatorEmail || "system"}
                              </td>
                            )}

                            {/* Column 6: Quick Actions */}
                            <td className="py-3.5 px-4">
                              <div className="flex justify-center items-center gap-1.5">
                                
                                {/* Quick Single Subnet Live Re-scan */}
                                <button
                                  onClick={() => handleScanSingleTarget(item)}
                                  disabled={isScanningThis || scanAllLoading}
                                  className="p-2 text-slate-600 hover:text-red-600 hover:bg-red-50 bg-white border border-slate-200 rounded-xl transition-all duration-200 cursor-pointer shadow-xs flex items-center justify-center disabled:opacity-50"
                                  title="Perform Instant Real-Time Subnet Audit"
                                >
                                  <RefreshCw className={`w-3.5 h-3.5 ${isScanningThis ? "animate-spin text-red-600" : ""}`} />
                                </button>

                                {/* View Subnet IP Matrix */}
                                <button
                                  onClick={() => {
                                    setViewingIP(item);
                                    setViewIpSearchQuery("");
                                    setViewIpStatusFilter("all");
                                    setViewIpCurrentPage(1);
                                  }}
                                  className="p-2 text-slate-600 hover:text-red-600 hover:bg-red-50 bg-white border border-slate-200 rounded-xl transition-all duration-200 cursor-pointer shadow-xs flex items-center justify-center"
                                  title="Inspect Subnet IP Allocation Matrix"
                                >
                                  <Eye className="w-3.5 h-3.5" />
                                </button>

                                {/* Edit Subnet Target */}
                                <button
                                  onClick={() => {
                                    setEditingIP(item);
                                    setEditLabel(item.label);
                                    setEditIpOrCidr(item.ipOrCidr);
                                  }}
                                  className="p-2 text-slate-600 hover:text-amber-600 hover:bg-amber-50 bg-white border border-slate-200 rounded-xl transition-all duration-200 cursor-pointer shadow-xs flex items-center justify-center"
                                  title="Edit Subnet Configuration"
                                >
                                  <Edit2 className="w-3.5 h-3.5" />
                                </button>

                                {/* Delete Target */}
                                <button
                                  onClick={() => setDeletingIP(item)}
                                  className="p-2 text-slate-600 hover:text-rose-600 hover:bg-rose-50 bg-white border border-slate-200 rounded-xl transition-all duration-200 cursor-pointer shadow-xs flex items-center justify-center"
                                  title="Stop Monitoring"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                </button>

                              </div>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Sub-tab: Daily Blacklist Reports */}
      {activeSubTab === "reports" && (
        <div className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 bg-white rounded-2xl p-6 cyber-card border border-slate-200 shadow-sm">
            <div>
              <h3 className="text-sm font-black text-slate-800 uppercase tracking-wider flex items-center gap-2">
                <FileText className="w-4 h-4 text-red-600" />
                Daily Blacklist Audit Reports
              </h3>
              <p className="text-xs text-slate-500 mt-1 max-w-2xl font-medium leading-relaxed">
                Access past consolidated daily blacklist audit reports. The background system performs regular daily checks on all subnets and single host IPs, aggregating RBL detections into daily reports.
              </p>
            </div>
            <div>
              <button
                onClick={handleGenerateDailyReport}
                disabled={generatingReport}
                className="w-full sm:w-auto px-5 py-3 text-xs font-black uppercase tracking-widest text-white bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded-xl shadow-md shadow-red-600/20 transition-all flex items-center justify-center gap-2 cursor-pointer border-none"
              >
                {generatingReport ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Compiling Today's Report...
                  </>
                ) : (
                  <>
                    <RefreshCw className="w-4 h-4" />
                    Compile Today's Report
                  </>
                )}
              </button>
            </div>
          </div>

          {reportsLoading ? (
            <div className="text-center py-24 bg-white rounded-2xl cyber-card border border-slate-200">
              <Loader2 className="w-8 h-8 animate-spin mx-auto text-red-600 mb-3" />
              <p className="text-xs font-black text-slate-700 uppercase tracking-wider">Retrieving Daily Report History...</p>
            </div>
          ) : dailyReports.length === 0 ? (
            <div className="text-center py-20 bg-white rounded-2xl cyber-card border border-slate-200 text-slate-400">
              <Calendar className="w-10 h-10 mx-auto text-slate-300 mb-2" />
              <h4 className="text-xs font-black text-slate-700 uppercase tracking-widest">No Reports Generated Yet</h4>
              <p className="text-[11px] max-w-sm mx-auto mt-1 font-medium text-slate-500">
                Trigger a manual compilation above or wait for the automatic background daemon to generate the next report.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {dailyReports.map((report) => {
                const totalListed = report.blacklistedIPsCount || 0;
                return (
                  <div
                    key={report.id}
                    className="bg-white rounded-2xl p-5 cyber-card hover:shadow-md transition-all duration-300 border border-slate-200 flex flex-col justify-between group"
                  >
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <Calendar className="w-4 h-4 text-red-600" />
                          <span className="text-xs font-black text-slate-900 tracking-wider">
                            {report.date}
                          </span>
                        </div>
                        {totalListed > 0 ? (
                          <span className="text-[10px] font-black text-rose-800 bg-rose-100 px-2.5 py-0.8 rounded-md border border-rose-200 uppercase tracking-wider">
                            {totalListed} Listed
                          </span>
                        ) : (
                          <span className="text-[10px] font-black text-emerald-800 bg-emerald-100 px-2.5 py-0.8 rounded-md border border-emerald-200 uppercase tracking-wider">
                            100% Clean
                          </span>
                        )}
                      </div>

                      <p className="text-[11px] text-slate-600 font-medium leading-relaxed">
                        {report.summary}
                      </p>

                      <div className="grid grid-cols-3 gap-2 bg-slate-50 p-3 rounded-xl border border-slate-200">
                        <div className="text-center">
                          <span className="block text-[10px] text-slate-400 uppercase tracking-widest font-bold">Total Monitored</span>
                          <span className="text-xs font-black text-slate-900">{report.totalMonitoredIPs}</span>
                        </div>
                        <div className="text-center">
                          <span className="block text-[10px] text-slate-400 uppercase tracking-widest font-bold">Targets</span>
                          <span className="text-xs font-black text-slate-900">{report.totalTargets}</span>
                        </div>
                        <div className="text-center">
                          <span className="block text-[10px] text-slate-400 uppercase tracking-widest font-bold">Clean Targets</span>
                          <span className="text-xs font-black text-slate-900">{report.cleanTargetsCount}</span>
                        </div>
                      </div>
                    </div>

                    <div className="mt-5 grid grid-cols-1 sm:grid-cols-3 gap-2">
                      <button
                        onClick={() => setSelectedReport(report)}
                        className="sm:col-span-1 bg-slate-900 hover:bg-black text-white text-xs py-2.5 px-3 rounded-xl font-black uppercase tracking-wider transition-all duration-200 flex items-center justify-center gap-1 cursor-pointer shadow-xs"
                      >
                        <span>Analyze</span>
                        <ChevronRight className="w-3.5 h-3.5" />
                      </button>

                      <button
                        onClick={() => {
                          try {
                            downloadDailyReportCSV(report);
                            triggerAlert("success", `Downloaded daily report CSV for ${report.date}`);
                          } catch (e) {
                            triggerAlert("error", "Failed to download daily report CSV");
                          }
                        }}
                        className="bg-white hover:bg-emerald-50 hover:text-emerald-700 border border-slate-200 hover:border-emerald-300 text-slate-700 text-xs py-2.5 px-3 rounded-xl font-bold uppercase tracking-wider transition-all duration-200 flex items-center justify-center gap-1.5 cursor-pointer shadow-2xs"
                        title="Download CSV"
                      >
                        <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-600" />
                        <span>CSV</span>
                      </button>

                      <button
                        onClick={() => {
                          try {
                            downloadDailyReportJSON(report);
                            triggerAlert("success", `Downloaded daily report JSON for ${report.date}`);
                          } catch (e) {
                            triggerAlert("error", "Failed to download daily report JSON");
                          }
                        }}
                        className="bg-white hover:bg-slate-100 hover:text-slate-900 border border-slate-200 text-slate-700 text-xs py-2.5 px-3 rounded-xl font-bold uppercase tracking-wider transition-all duration-200 flex items-center justify-center gap-1.5 cursor-pointer shadow-2xs"
                        title="Download JSON"
                      >
                        <FileText className="w-3.5 h-3.5 text-slate-600" />
                        <span>JSON</span>
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Delete Confirmation Modal */}
      <AnimatePresence>
        {deletingIP && (
          <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 z-50">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-white rounded-3xl w-full max-w-md overflow-hidden shadow-2xl flex flex-col border border-slate-200"
            >
              <div className="p-6 border-b border-slate-100 flex items-center space-x-3 bg-slate-50">
                <div className="p-2.5 bg-rose-100 rounded-xl text-rose-600">
                  <AlertTriangle className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-black text-slate-900 uppercase tracking-wider">
                    Stop Monitoring Subnet Target
                  </h3>
                  <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mt-0.5">
                    Confirm Target Removal
                  </p>
                </div>
              </div>

              <div className="p-6 space-y-3">
                <p className="text-xs text-slate-600 leading-relaxed font-medium">
                  Are you sure you want to stop monitoring <strong className="text-slate-900 font-mono">{deletingIP.ipOrCidr}</strong>? Continuous real-time reputation checking and daily report integrations for this subnet will be disabled immediately.
                </p>
              </div>

              <div className="p-5 border-t border-slate-100 bg-slate-50 flex justify-end gap-3">
                <button
                  onClick={() => setDeletingIP(null)}
                  disabled={deleteLoading}
                  className="px-5 py-2.5 bg-white border border-slate-200 text-slate-700 hover:bg-slate-50 rounded-xl text-xs font-black uppercase tracking-widest transition-all cursor-pointer disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  onClick={handleConfirmDelete}
                  disabled={deleteLoading}
                  className="px-5 py-2.5 bg-rose-600 hover:bg-rose-700 text-white rounded-xl text-xs font-black uppercase tracking-widest shadow-md shadow-rose-600/20 transition-all cursor-pointer flex items-center gap-1.5 border-none disabled:opacity-50"
                >
                  {deleteLoading ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      Deleting...
                    </>
                  ) : (
                    <>
                      <Trash2 className="w-3.5 h-3.5" />
                      Stop Monitoring
                    </>
                  )}
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Edit Target Modal */}
      <AnimatePresence>
        {editingIP && (
          <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 z-50">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-white rounded-3xl w-full max-w-md overflow-hidden shadow-2xl flex flex-col border border-slate-200"
            >
              <form onSubmit={handleUpdateIP}>
                <div className="p-6 border-b border-slate-100 flex items-center justify-between bg-slate-50">
                  <div className="flex items-center space-x-3">
                    <div className="p-2.5 bg-amber-100 rounded-xl text-amber-600">
                      <Edit2 className="w-5 h-5" />
                    </div>
                    <div>
                      <h3 className="text-sm font-black text-slate-900 uppercase tracking-wider">
                        Edit Monitoring Target
                      </h3>
                      <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mt-0.5">
                        Modify Subnet Configuration
                      </p>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setEditingIP(null)}
                    className="p-1.5 hover:bg-slate-100 rounded-lg text-slate-400 hover:text-slate-700 transition-colors cursor-pointer border-none bg-transparent"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>

                <div className="p-6 space-y-4">
                  <div className="space-y-1.5">
                    <label className="text-[10px] font-black text-slate-600 uppercase tracking-widest block">
                      Friendly Label / Subnet Name
                    </label>
                    <input
                      type="text"
                      required
                      value={editLabel}
                      onChange={(e) => setEditLabel(e.target.value)}
                      placeholder="e.g. Primary Production Mail Subnet"
                      className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-amber-500/10 focus:border-amber-500 text-slate-900 font-bold transition-all"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[10px] font-black text-slate-600 uppercase tracking-widest block">
                      IP Address or Subnet Block (CIDR)
                    </label>
                    <input
                      type="text"
                      required
                      value={editIpOrCidr}
                      onChange={(e) => setEditIpOrCidr(e.target.value)}
                      placeholder="e.g. 192.168.1.1 or 192.168.1.0/24"
                      className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-amber-500/10 focus:border-amber-500 text-slate-950 font-mono font-bold transition-all"
                    />
                    <p className="text-[10px] text-slate-400 font-medium">
                      Modifying the target address will trigger a live DNSBL reputation scan.
                    </p>
                  </div>
                </div>

                <div className="p-5 border-t border-slate-100 bg-slate-50 flex justify-end gap-3">
                  <button
                    type="button"
                    onClick={() => setEditingIP(null)}
                    disabled={editLoading}
                    className="px-5 py-2.5 bg-white border border-slate-200 text-slate-700 hover:bg-slate-50 rounded-xl text-xs font-black uppercase tracking-widest transition-all cursor-pointer disabled:opacity-50"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={editLoading}
                    className="px-5 py-2.5 bg-slate-900 hover:bg-black text-white rounded-xl text-xs font-black uppercase tracking-widest shadow-md transition-all cursor-pointer flex items-center gap-1.5 border-none disabled:opacity-50"
                  >
                    {editLoading ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        Saving & Scanning...
                      </>
                    ) : (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        Save Changes
                      </>
                    )}
                  </button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Subnet IP Allocation Matrix Inspector Modal */}
      <AnimatePresence>
        {viewingIP && (() => {
          const stats = computeSubnetStats(viewingIP);
          const expandedIPs = getIPsForTarget(viewingIP);
          const filteredViewIPs = expandedIPs.filter(ipItem => {
            const matchesSearch = ipItem.ip.toLowerCase().includes(viewIpSearchQuery.toLowerCase());
            const matchesStatus = viewIpStatusFilter === "all" || ipItem.status === viewIpStatusFilter;
            return matchesSearch && matchesStatus;
          });
          const totalPages = Math.ceil(filteredViewIPs.length / viewIpPageSize) || 1;
          const startIndex = (viewIpCurrentPage - 1) * viewIpPageSize;
          const paginatedViewIPs = filteredViewIPs.slice(startIndex, startIndex + viewIpPageSize);
          const cleanCount = expandedIPs.filter(ip => ip.status === "clean").length;
          const listedCount = expandedIPs.filter(ip => ip.status === "listed").length;

          return (
            <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 z-50">
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="bg-white rounded-3xl w-full max-w-4xl max-h-[90vh] overflow-hidden shadow-2xl flex flex-col border border-slate-200"
              >
                {/* Modal Header */}
                <div className="p-6 border-b border-slate-200 flex items-center justify-between bg-slate-50">
                  <div className="flex items-center space-x-3">
                    <div className="p-2.5 bg-red-100 rounded-xl text-red-600">
                      <Globe className="w-5 h-5" />
                    </div>
                    <div>
                      <h3 className="text-sm font-black text-slate-900 uppercase tracking-wider">
                        Subnet IP Allocation Dashboard
                      </h3>
                      <p className="text-[11px] text-slate-500 font-medium mt-0.5">
                        Target: <span className="font-mono font-bold text-slate-900">{viewingIP.ipOrCidr}</span> | Label: <span className="font-bold text-slate-800">{viewingIP.label}</span>
                      </p>
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-2">
                    <button
                      onClick={async () => {
                        setModalScanning(true);
                        await handleScanSingleTarget(viewingIP);
                        setModalScanning(false);
                      }}
                      disabled={modalScanning}
                      className="px-3 py-1.5 bg-slate-900 hover:bg-black text-white text-xs font-black uppercase tracking-wider rounded-xl transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 text-red-400 ${modalScanning ? "animate-spin" : ""}`} />
                      <span>{modalScanning ? "Scanning..." : "Re-Scan Subnet"}</span>
                    </button>

                    <button
                      onClick={() => setViewingIP(null)}
                      className="p-1.5 hover:bg-slate-200 rounded-lg text-slate-500 hover:text-slate-800 transition-colors cursor-pointer border-none bg-transparent"
                    >
                      <X className="w-5 h-5" />
                    </button>
                  </div>
                </div>

                <div className="p-6 overflow-y-auto space-y-5 flex-1">
                  {/* Real-time Subnet KPI Breakdown Cards */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <div className="bg-slate-50 p-4 rounded-2xl border border-slate-200 text-center">
                      <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest block">Total Address Space</span>
                      <span className="text-2xl font-black text-slate-900 font-mono block mt-1">{expandedIPs.length}</span>
                      <span className="text-[10px] text-slate-400 font-medium">Assigned Nodes</span>
                    </div>

                    <div className="bg-emerald-50/70 p-4 rounded-2xl border border-emerald-200/80 text-center">
                      <span className="text-[10px] font-black text-emerald-800 uppercase tracking-widest block">Clean Allocations</span>
                      <span className="text-2xl font-black text-emerald-600 font-mono block mt-1">{cleanCount}</span>
                      <span className="text-[10px] text-emerald-700 font-medium">100% Reputable</span>
                    </div>

                    <div className="bg-rose-50/70 p-4 rounded-2xl border border-rose-200/80 text-center">
                      <span className="text-[10px] font-black text-rose-800 uppercase tracking-widest block">Active Threat Listings</span>
                      <span className="text-2xl font-black text-rose-600 font-mono block mt-1">{listedCount}</span>
                      <span className="text-[10px] text-rose-700 font-medium">DNSBL Flagged</span>
                    </div>

                    <div className="bg-slate-50 p-4 rounded-2xl border border-slate-200 text-center">
                      <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest block">Subnet Health Score</span>
                      <span className={`text-2xl font-black font-mono block mt-1 ${
                        stats.healthScore >= 95 ? "text-emerald-600" : stats.healthScore >= 80 ? "text-amber-600" : "text-rose-600"
                      }`}>
                        {stats.healthScore}%
                      </span>
                      <span className="text-[10px] text-slate-400 font-medium">Overall Integrity</span>
                    </div>
                  </div>

                  {/* Filter & Export Controls */}
                  <div className="flex flex-col sm:flex-row gap-3 justify-between items-center bg-slate-50 p-4 rounded-2xl border border-slate-200">
                    <div className="relative flex-1 w-full">
                      <Search className="w-3.5 h-3.5 absolute left-3 top-3.5 text-slate-400" />
                      <input
                        type="text"
                        value={viewIpSearchQuery}
                        onChange={(e) => {
                          setViewIpSearchQuery(e.target.value);
                          setViewIpCurrentPage(1);
                        }}
                        placeholder="Filter IP address in subnet..."
                        className="w-full pl-9 pr-3.5 py-2.5 bg-white border border-slate-200 rounded-xl text-xs focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-red-500/10 focus:border-red-500 transition-all text-slate-900 font-mono font-bold placeholder:text-slate-400"
                      />
                    </div>

                    <div className="flex gap-2 w-full sm:w-auto">
                      <select
                        value={viewIpStatusFilter}
                        onChange={(e) => {
                          setViewIpStatusFilter(e.target.value as any);
                          setViewIpCurrentPage(1);
                        }}
                        className="bg-white border border-slate-200 text-xs font-bold px-3 py-2.5 rounded-xl text-slate-700 focus:outline-hidden focus:ring-4 focus:ring-red-500/10 focus:border-red-500 cursor-pointer flex-1 sm:flex-initial"
                      >
                        <option value="all">All ({expandedIPs.length})</option>
                        <option value="clean">Clean ({cleanCount})</option>
                        <option value="listed">Listed Only ({listedCount})</option>
                      </select>

                      <button
                        onClick={() => handleExportSubnetCSV(viewingIP, filteredViewIPs)}
                        className="bg-slate-900 hover:bg-black text-white px-4 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest shadow-xs flex items-center justify-center gap-1.5 cursor-pointer border border-slate-800 transition-all"
                        title="Export Subnet Report to CSV"
                      >
                        <Download className="w-3.5 h-3.5 text-red-400" />
                        <span>Export CSV</span>
                      </button>
                    </div>
                  </div>

                  {/* IPs Allocation Matrix Table */}
                  <div className="border border-slate-200 rounded-2xl overflow-hidden shadow-xs">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="bg-slate-100 border-b border-slate-200 text-[10px] font-black uppercase text-slate-600 tracking-wider">
                          <th className="py-3 px-4">Node IP Address</th>
                          <th className="py-3 px-4">Reputation Status</th>
                          <th className="py-3 px-4">Blacklist Registrations</th>
                          <th className="py-3 px-4 text-center">Copy</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 font-semibold text-slate-700">
                        {paginatedViewIPs.length === 0 ? (
                          <tr>
                            <td colSpan={4} className="text-center py-8 text-slate-400 font-bold uppercase tracking-wider bg-slate-50/50">
                              No IP addresses match your filter criteria
                            </td>
                          </tr>
                        ) : (
                          paginatedViewIPs.map((ipItem, idx) => {
                            const activeDbs = Object.entries(ipItem.listings || {})
                              .filter(([_, value]: any) => value && value.listed)
                              .map(([key, value]: any) => value.name || key);

                            return (
                              <tr key={idx} className="hover:bg-slate-50/70 transition-colors">
                                <td className="py-3 px-4 font-mono font-bold text-slate-900">
                                  {ipItem.ip}
                                </td>
                                <td className="py-3 px-4">
                                  {ipItem.status === "clean" ? (
                                    <span className="inline-flex items-center gap-1 text-emerald-800 bg-emerald-100 px-2.5 py-0.5 rounded-full border border-emerald-200 font-black text-[10px] uppercase">
                                      <ShieldCheck className="w-3 h-3 text-emerald-600" />
                                      Clean
                                    </span>
                                  ) : (
                                    <span className="inline-flex items-center gap-1 text-rose-800 bg-rose-100 px-2.5 py-0.5 rounded-full border border-rose-200 font-black text-[10px] uppercase">
                                      <ShieldAlert className="w-3 h-3 text-rose-600" />
                                      Listed ({ipItem.listedCount})
                                    </span>
                                  )}
                                </td>
                                <td className="py-3 px-4">
                                  {activeDbs.length > 0 ? (
                                    <div className="flex flex-wrap gap-1 max-w-xs">
                                      {activeDbs.map((dbName, dbIdx) => (
                                        <span key={dbIdx} className="text-[9px] font-black bg-rose-100 border border-rose-200 text-rose-800 px-1.5 py-0.5 rounded uppercase">
                                          {dbName}
                                        </span>
                                      ))}
                                    </div>
                                  ) : (
                                    <span className="text-slate-400 font-medium italic">No listings recorded</span>
                                  )}
                                </td>
                                <td className="py-3 px-4 text-center">
                                  <button
                                    onClick={() => handleCopyIP(ipItem.ip)}
                                    className="p-1 hover:bg-slate-200 rounded-lg text-slate-500 hover:text-slate-800 transition-colors inline-flex items-center justify-center border-none bg-transparent cursor-pointer"
                                    title="Copy IP Address"
                                  >
                                    {copiedIp === ipItem.ip ? (
                                      <Check className="w-3.5 h-3.5 text-emerald-600" />
                                    ) : (
                                      <Copy className="w-3.5 h-3.5" />
                                    )}
                                  </button>
                                </td>
                              </tr>
                            );
                          })
                        )}
                      </tbody>
                    </table>
                  </div>

                  {/* Pagination Controls */}
                  {totalPages > 1 && (
                    <div className="flex items-center justify-between border-t border-slate-200 pt-4">
                      <span className="text-[10px] font-bold text-slate-500 uppercase">
                        Showing {startIndex + 1} to {Math.min(startIndex + viewIpPageSize, filteredViewIPs.length)} of {filteredViewIPs.length} addresses
                      </span>
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => setViewIpCurrentPage(prev => Math.max(prev - 1, 1))}
                          disabled={viewIpCurrentPage === 1}
                          className="p-1.5 border border-slate-200 hover:bg-slate-100 text-slate-600 rounded-lg disabled:opacity-40 transition-colors cursor-pointer flex items-center justify-center"
                        >
                          <ChevronLeft className="w-4 h-4" />
                        </button>
                        <span className="text-xs font-bold text-slate-700 px-2">
                          Page {viewIpCurrentPage} of {totalPages}
                        </span>
                        <button
                          onClick={() => setViewIpCurrentPage(prev => Math.min(prev + 1, totalPages))}
                          disabled={viewIpCurrentPage === totalPages}
                          className="p-1.5 border border-slate-200 hover:bg-slate-100 text-slate-600 rounded-lg disabled:opacity-40 transition-colors cursor-pointer flex items-center justify-center"
                        >
                          <ChevronRight className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                <div className="p-5 border-t border-slate-200 bg-slate-50 flex justify-end">
                  <button
                    onClick={() => setViewingIP(null)}
                    className="px-5 py-2.5 bg-slate-900 hover:bg-black text-white rounded-xl text-xs font-black uppercase tracking-widest shadow-sm transition-all cursor-pointer border-none"
                  >
                    Close Subnet Matrix
                  </button>
                </div>
              </motion.div>
            </div>
          );
        })()}
      </AnimatePresence>

      {/* Daily Report Detail Modal */}
      <AnimatePresence>
        {selectedReport && (
          <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 z-50">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-white rounded-3xl w-full max-w-4xl max-h-[90vh] overflow-hidden shadow-2xl flex flex-col border border-slate-200"
            >
              <div className="p-6 border-b border-slate-200 flex items-center justify-between bg-slate-50">
                <div className="flex items-center space-x-3">
                  <div className="p-2.5 bg-red-100 rounded-xl text-red-600">
                    <FileText className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-black text-slate-900 uppercase tracking-wider">
                      Daily Audit Report: {selectedReport.date}
                    </h3>
                    <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mt-0.5">
                      Compiled: {new Date(selectedReport.timestamp).toLocaleString()}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedReport(null)}
                  className="p-1.5 hover:bg-slate-200 rounded-lg text-slate-500 hover:text-slate-800 transition-colors cursor-pointer border-none bg-transparent"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="p-6 overflow-y-auto space-y-5 flex-1">
                {/* Summary Metrics */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="bg-slate-50 p-4 rounded-2xl border border-slate-200 text-center">
                    <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest block">Monitored Space</span>
                    <span className="text-xl font-black text-slate-900 font-mono block mt-1">{selectedReport.totalMonitoredIPs}</span>
                  </div>
                  <div className="bg-slate-50 p-4 rounded-2xl border border-slate-200 text-center">
                    <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest block">Subnet Targets</span>
                    <span className="text-xl font-black text-slate-900 font-mono block mt-1">{selectedReport.totalTargets}</span>
                  </div>
                  <div className="bg-emerald-50/70 p-4 rounded-2xl border border-emerald-200/80 text-center">
                    <span className="text-[10px] font-black text-emerald-800 uppercase tracking-widest block">Clean Targets</span>
                    <span className="text-xl font-black text-emerald-600 font-mono block mt-1">{selectedReport.cleanTargetsCount}</span>
                  </div>
                  <div className="bg-rose-50/70 p-4 rounded-2xl border border-rose-200/80 text-center">
                    <span className="text-[10px] font-black text-rose-800 uppercase tracking-widest block">Blacklisted Nodes</span>
                    <span className="text-xl font-black text-rose-600 font-mono block mt-1">{selectedReport.blacklistedIPsCount || 0}</span>
                  </div>
                </div>

                <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200">
                  <h4 className="text-xs font-black text-slate-800 uppercase tracking-wider mb-1">Executive Summary</h4>
                  <p className="text-xs text-slate-600 font-medium leading-relaxed">{selectedReport.summary}</p>
                </div>

                {/* Blacklisted Nodes Detail */}
                <div className="space-y-3">
                  <h4 className="text-xs font-black text-slate-800 uppercase tracking-wider">
                    Flagged Threat Nodes Breakdown ({selectedReport.blacklistedIPs?.length || 0})
                  </h4>

                  {(!selectedReport.blacklistedIPs || selectedReport.blacklistedIPs.length === 0) ? (
                    <div className="p-8 text-center bg-emerald-50/60 rounded-2xl border border-emerald-200 text-emerald-800">
                      <CheckCircle2 className="w-8 h-8 mx-auto text-emerald-600 mb-1" />
                      <span className="text-xs font-black uppercase tracking-wider">100% Clean Audit Status</span>
                      <p className="text-[11px] text-emerald-700 mt-0.5">No IP hosts in any monitored subnet were blacklisted on this day.</p>
                    </div>
                  ) : (
                    <div className="border border-slate-200 rounded-2xl overflow-hidden">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="bg-slate-100 border-b border-slate-200 text-[10px] font-black uppercase text-slate-600 tracking-wider">
                            <th className="py-3 px-4">Flagged IP</th>
                            <th className="py-3 px-4">Parent Subnet / Label</th>
                            <th className="py-3 px-4">RBL Database Flagged</th>
                            <th className="py-3 px-4">Location / ISP</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-200">
                          {selectedReport.blacklistedIPs.map((bItem, bIdx) => {
                            const dbs = Object.entries(bItem.listings || {})
                              .filter(([_, v]: any) => v && v.listed)
                              .map(([k, _]) => k);

                            return (
                              <tr key={bIdx} className="hover:bg-slate-50">
                                <td className="py-3 px-4 font-mono font-bold text-rose-600">{bItem.ip}</td>
                                <td className="py-3 px-4 font-medium text-slate-800">
                                  <span className="block font-bold">{bItem.parentLabel}</span>
                                  <span className="font-mono text-[10px] text-slate-400">{bItem.parentTarget}</span>
                                </td>
                                <td className="py-3 px-4">
                                  <div className="flex flex-wrap gap-1">
                                    {dbs.map((dbName, idx) => (
                                      <span key={idx} className="text-[9px] font-black bg-rose-100 text-rose-800 px-1.5 py-0.5 rounded uppercase border border-rose-200">
                                        {dbName}
                                      </span>
                                    ))}
                                  </div>
                                </td>
                                <td className="py-3 px-4 text-slate-500 font-medium">
                                  {bItem.location ? `${bItem.location.city || ""}, ${bItem.location.countryCode || ""}` : "Unknown"}
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </div>

              <div className="p-5 border-t border-slate-200 bg-slate-50 flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => {
                      try {
                        downloadDailyReportCSV(selectedReport);
                        triggerAlert("success", `Downloaded daily report CSV for ${selectedReport.date}`);
                      } catch (e) {
                        triggerAlert("error", "Failed to download CSV");
                      }
                    }}
                    className="px-4 py-2.5 bg-white hover:bg-emerald-50 hover:text-emerald-700 border border-slate-300 hover:border-emerald-300 text-slate-700 rounded-xl text-xs font-bold uppercase tracking-wider shadow-2xs transition-all flex items-center gap-1.5 cursor-pointer"
                  >
                    <FileSpreadsheet className="w-4 h-4 text-emerald-600" />
                    <span>Export CSV</span>
                  </button>

                  <button
                    onClick={() => {
                      try {
                        downloadDailyReportJSON(selectedReport);
                        triggerAlert("success", `Downloaded daily report JSON for ${selectedReport.date}`);
                      } catch (e) {
                        triggerAlert("error", "Failed to download JSON");
                      }
                    }}
                    className="px-4 py-2.5 bg-white hover:bg-slate-100 hover:text-slate-900 border border-slate-300 text-slate-700 rounded-xl text-xs font-bold uppercase tracking-wider shadow-2xs transition-all flex items-center gap-1.5 cursor-pointer"
                  >
                    <FileText className="w-4 h-4 text-slate-600" />
                    <span>Export JSON</span>
                  </button>
                </div>

                <button
                  onClick={() => setSelectedReport(null)}
                  className="px-5 py-2.5 bg-slate-900 hover:bg-black text-white rounded-xl text-xs font-black uppercase tracking-widest shadow-sm transition-all cursor-pointer border-none"
                >
                  Close Report
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

    </div>
  );
};
