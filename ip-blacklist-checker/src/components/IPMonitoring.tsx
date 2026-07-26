import React, { useEffect, useState } from "react";
import { db } from "../firebase";
import { collection, query, where, getDocs, addDoc, deleteDoc, doc, writeBatch, updateDoc } from "firebase/firestore";
import { MonitoredIP, UserProfile, AlertNotification, DailyReport } from "../types";
import { ShieldCheck, ShieldAlert, Plus, Trash2, Search, Loader2, Play, RefreshCw, Bell, BellOff, Info, Check, Filter, FileText, Calendar, ChevronRight, X, Globe, BarChart2, CheckCircle2, Edit2, Eye, Copy, Download, ChevronLeft } from "lucide-react";
import { motion, AnimatePresence } from "motion/react";

interface IPMonitoringProps {
  currentUser: UserProfile;
  triggerAlert: (type: "success" | "error" | "info" | "warning", message: string) => void;
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

  // Filter/Search states
  const [searchQuery, setSearchQuery] = useState("");
  const [filterStatus, setFilterStatus] = useState<"all" | "clean" | "listed" | "unknown">("all");

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

      // Load local storage first
      getLocalIPs().forEach(item => combinedIPs.set(item.id, item));
      getLocalNotifs().forEach(item => combinedNotifs.set(item.id, item));

      // Fetch from Express server API
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

      notifList.sort((a, b) => b.timestamp.localeCompare(a.timestamp));

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

  const handleAddIP = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ipOrCidr.trim()) {
      triggerAlert("error", "Please provide a valid IP address or CIDR subnet block.");
      return;
    }

    setAddLoading(true);
    try {
      const cleanedInput = ipOrCidr.trim();
      
      // Perform a check before adding
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
      const blacklisted = scanResult.results.filter((r: any) => r.status === 'listed');

      const tempId = `ip_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;

      const newIP: MonitoredIP = {
        id: tempId,
        ipOrCidr: cleanedInput,
        label: label.trim() || `Host ${cleanedInput}`,
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
      currentLocals.push(newIP);
      saveLocalIPs(currentLocals);
      setMonitoredIPs(prev => [newIP, ...prev.filter(i => i.id !== tempId)]);

      triggerAlert("success", `Added ${cleanedInput} to continuous monitoring.`);
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

    } catch (err: any) {
      console.error("Error adding monitored IP:", err);
      triggerAlert("error", err.message || "Failed to add IP to monitoring.");
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
      
      let updatedFields: any = {
        ...editingIP,
        label: editLabel.trim() || `Host ${editIpOrCidr.trim()}`,
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
          const blacklisted = scanResult.results.filter((r: any) => r.status === 'listed');
          
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
      currentLocals.push(updatedFields);
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
    } catch (err) {
      console.error("Error deleting monitored IP:", err);
      triggerAlert("error", "Failed to remove IP from monitoring.");
    } finally {
      setDeleteLoading(false);
    }
  };

  const getIPsForTarget = (item: MonitoredIP): { ip: string; status: "clean" | "listed"; listedCount: number; listings: any }[] => {
    const ipOrCidrVal = item.ipOrCidr;
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
            listedCount: blacklistedMatch.listedCount || 0,
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
            listedCount: blacklistedMatch.listedCount || 0,
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
    const headers = ["IP Address", "Status", "Listed Count", "Listed Providers"];
    
    const rows = ipList.map(item => {
      const activeBlacklists = Object.entries(item.listings)
        .filter(([_, value]: any) => value && value.listed)
        .map(([key, _]) => key)
        .join("; ");

      return [
        item.ip,
        item.status.toUpperCase(),
        item.listedCount,
        activeBlacklists || "None"
      ];
    });

    const csvContent = [
      headers.join(","),
      ...rows.map(row => row.map(val => `"${String(val).replace(/"/g, '""')}"`).join(","))
    ].join("\n");

    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `subnet_ips_${item.ipOrCidr.replace(/[\/.-]/g, "_")}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleScanAll = async () => {
    if (monitoredIPs.length === 0) {
      triggerAlert("info", "No monitored IPs available to scan.");
      return;
    }

    setScanAllLoading(true);
    triggerAlert("info", "Executing real-time DNSBL scanning check across monitored subnets...");

    try {
      let changeCount = 0;
      const batch = writeBatch(db);

      // We'll scan each monitored target and check if reputation has changed
      for (const item of monitoredIPs) {
        const res = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target: item.ipOrCidr, simulate: false }) // Live RBL scan
        });

        if (res.ok) {
          const scanResult = await res.json();
          const blacklisted = scanResult.results.filter((r: any) => r.status === 'listed');
          
          const newStatus = scanResult.listedCount > 0 ? "listed" : "clean";
          const newListedCount = scanResult.listedCount;
          const oldStatus = item.status;

          // Update Monitored IP document in Firestore
          const ipDocRef = doc(db, "monitored_ips", item.id);
          batch.update(ipDocRef, {
            status: newStatus,
            listedCount: newListedCount,
            listings: scanResult.results[0]?.listings || {},
            totalIPs: scanResult.totalIPs,
            blacklistedIPs: blacklisted,
            simulate: false, // update to false so daemon respects it
            lastChecked: new Date().toISOString()
          });

          // Detect status changes and log/create notifications!
          if (oldStatus !== "unknown" && oldStatus !== newStatus) {
            changeCount++;
            
            // Create a status change notification document
            const newNotification = {
              ip: item.ipOrCidr,
              oldStatus,
              newStatus,
              listedCount: newListedCount,
              timestamp: new Date().toISOString(),
              read: false,
              userId: item.createdBy
            };
            
            const notifDocRef = doc(collection(db, "notifications"));
            batch.set(notifDocRef, newNotification);
          }
        }
      }

      await batch.commit();

      if (changeCount > 0) {
        triggerAlert("warning", `Monitoring update complete: detected ${changeCount} blacklist reputation changes!`);
      } else {
        triggerAlert("success", "Monitoring update complete: All IP node reputations are stable.");
      }

      fetchMonitoredData();
    } catch (err) {
      console.error("Error scanning monitored IPs:", err);
      triggerAlert("error", "Scanning monitor execution failed.");
    } finally {
      setScanAllLoading(false);
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
      
      setNotifications(prev => prev.map(n => ({ ...n, read: true })));
      triggerAlert("success", "Marked all status-change alert notifications as read.");
    } catch (err) {
      console.error("Error updating notifications:", err);
    }
  };

  // Filter & Search IP list
  const filteredIPs = monitoredIPs.filter(item => {
    const matchesSearch = 
      item.ipOrCidr.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.creatorEmail.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesStatus = 
      filterStatus === "all" || 
      item.status === filterStatus;

    return matchesSearch && matchesStatus;
  });

  const unreadAlerts = notifications.filter(n => !n.read).length;

  return (
    <div className="space-y-6">
      {/* Sub-navigation tabs */}
      <div className="flex items-center justify-between border-b border-slate-200 pb-3">
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setActiveSubTab("hosts")}
            className={`px-4 py-2 text-xs font-black uppercase tracking-wider rounded-lg transition-all duration-200 flex items-center space-x-1.5 ${
              activeSubTab === "hosts"
                ? "bg-red-500/10 text-red-500 border border-red-500/20"
                : "text-slate-500 hover:text-slate-800 hover:bg-slate-50"
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>Monitored Nodes & Subnets</span>
          </button>
          <button
            onClick={() => {
              setActiveSubTab("reports");
              fetchDailyReports();
            }}
            className={`px-4 py-2 text-xs font-black uppercase tracking-wider rounded-lg transition-all duration-200 flex items-center space-x-1.5 ${
              activeSubTab === "reports"
                ? "bg-red-500/10 text-red-500 border border-red-500/20"
                : "text-slate-500 hover:text-slate-800 hover:bg-slate-50"
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Daily Blacklist Reports</span>
          </button>
        </div>
      </div>

      {activeSubTab === "hosts" && (
        <div className="space-y-6">
          {/* Overview stats and alert feed */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            
            {/* Left column: Quick configuration form */}
            <div className="bg-white rounded-2xl p-6 cyber-card space-y-5 transition-all duration-300">
          <div>
            <h3 className="text-xs font-black text-slate-700 uppercase tracking-widest">
              Register Monitoring Target
            </h3>
            <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mt-1">
              Provide the host IP address or subnet block to establish permanent blocklist auditing.
            </p>
          </div>

          <form onSubmit={handleAddIP} className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                IP Address or Subnet Block
              </label>
              <input
                type="text"
                required
                value={ipOrCidr}
                onChange={(e) => setIpOrCidr(e.target.value)}
                placeholder="e.g. 185.190.140.15 or 1.1.1.0/24"
                className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-red-500/10 focus:border-red-500/80 text-slate-900 font-bold transition-all placeholder:text-slate-400 placeholder:font-normal"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                Friendly Label / Description
              </label>
              <input
                type="text"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="e.g. Primary Mail Server Office"
                className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-red-500/10 focus:border-red-500/80 text-slate-900 font-bold transition-all placeholder:text-slate-400 placeholder:font-normal"
              />
            </div>

            <button
              type="submit"
              disabled={addLoading}
              className="w-full bg-gradient-to-r from-red-650 to-red-800 hover:from-red-600 hover:to-red-750 text-white py-3 px-4 rounded-xl text-xs font-black uppercase tracking-widest shadow-[0_4px_12px_rgba(220,38,38,0.2)] transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 border border-white/5"
            >
              {addLoading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  Analyzing Node...
                </>
              ) : (
                <>
                  <Plus className="w-4 h-4 text-white" />
                  Add to Monitored List
                </>
              )}
            </button>
          </form>
        </div>

        {/* Right column: Blacklist Reputation Alerts and Notifications feed */}
        <div className="lg:col-span-2 bg-white rounded-2xl p-6 cyber-card space-y-5">
          <div className="flex justify-between items-center border-b border-slate-100 pb-3">
            <div className="flex items-center gap-2">
              <div className="relative">
                <Bell className="w-4 h-4 text-slate-500 animate-pulse" />
                {unreadAlerts > 0 && (
                  <span className="absolute -top-1 -right-1 w-2 h-2 bg-rose-500 rounded-full animate-ping" />
                )}
              </div>
              <h3 className="text-xs font-extrabold text-slate-700 uppercase tracking-wider">
                Monitoring Status Alert Feed
              </h3>
            </div>
            
            {unreadAlerts > 0 && (
              <button
                onClick={handleMarkNotificationsRead}
                className="text-[9px] text-red-500 hover:text-red-700 font-extrabold uppercase tracking-wider cursor-pointer transition-colors"
              >
                Mark all read
              </button>
            )}
          </div>

          <div className="max-h-48 overflow-y-auto space-y-2.5 pr-2">
            {notifications.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-10 text-center text-slate-400">
                <BellOff className="w-6 h-6 text-slate-300 mb-1.5" />
                <span className="text-[10px] font-extrabold uppercase tracking-wider">No status changes detected yet</span>
                <p className="text-[10px] text-slate-400">Continuous check cycles will notify you here of reputation fluctuations.</p>
              </div>
            ) : (
              notifications.map((notif) => {
                const isUnread = !notif.read;
                const isListed = notif.newStatus === "listed";

                return (
                  <div
                    key={notif.id}
                    className={`p-3 rounded-lg border text-xs flex justify-between items-start gap-4 transition-all ${
                      isUnread 
                        ? "bg-red-500/5 border-red-500/25" 
                        : "bg-slate-50/50 border-slate-150"
                    }`}
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-slate-950">{notif.ip}</span>
                        {isListed ? (
                          <span className="bg-rose-50 text-rose-700 text-[9px] px-1.5 py-0.2 rounded border border-rose-100 font-bold uppercase">
                            Reputation Degraded
                          </span>
                        ) : (
                          <span className="bg-emerald-50 text-emerald-700 text-[9px] px-1.5 py-0.2 rounded border border-emerald-100 font-bold uppercase">
                            Reputation Clean
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-slate-600 font-medium">
                        Reputation shifted from <span className="uppercase font-bold">{notif.oldStatus}</span> to{" "}
                        <span className={`uppercase font-bold ${isListed ? "text-rose-600" : "text-emerald-600"}`}>
                          {notif.newStatus}
                        </span>{" "}
                        ({notif.listedCount} listed RBL databases)
                      </p>
                      <span className="text-[9px] text-slate-400 block font-semibold">
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

      {/* Main monitored list */}
      <div className="bg-white rounded-2xl overflow-hidden cyber-card">
        
        {/* Table Header Controls */}
        <div className="p-5 border-b border-slate-200 flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-slate-50/50">
          <div>
            <h3 className="text-xs font-black text-slate-700 uppercase tracking-widest">
              Continuous Monitored Hosts ({filteredIPs.length} nodes)
            </h3>
            <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mt-1">
              Automated reputation checking daemon. Users have visibility over assigned assets.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto">
            <div className="relative flex-1 md:w-60">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search label, target IP..."
                className="w-full pl-9 pr-3.5 py-1.8 bg-white border border-slate-200 rounded-xl text-xs focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-red-500/10 focus:border-red-500/80 transition-all text-slate-900 font-bold placeholder:text-slate-400 placeholder:font-normal"
              />
            </div>

            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value as any)}
              className="bg-white border border-slate-200 text-xs font-bold px-3 py-1.8 rounded-xl text-slate-700 focus:outline-hidden focus:ring-4 focus:ring-red-500/10 focus:border-red-500/80 cursor-pointer"
            >
              <option value="all">All Reputations</option>
              <option value="clean">Clean Only</option>
              <option value="listed">Listed Only</option>
              <option value="unknown">Unknown</option>
            </select>

            <button
              onClick={handleScanAll}
              disabled={scanAllLoading}
              className="bg-black hover:bg-zinc-900 text-white px-4 py-1.8 rounded-xl text-xs font-black uppercase tracking-widest shadow-sm flex items-center gap-1.5 cursor-pointer disabled:opacity-50 border border-zinc-800 transition-all"
            >
              {scanAllLoading ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin text-red-500" />
                  Scanning...
                </>
              ) : (
                <>
                  <RefreshCw className="w-3.5 h-3.5 text-red-500" />
                  Scan All
                </>
              )}
            </button>
          </div>
        </div>

        {/* IP List Table */}
        {loading ? (
          <div className="flex flex-col items-center justify-center py-16 text-slate-400 space-y-2">
            <Loader2 className="w-8 h-8 animate-spin text-red-600" />
            <span className="text-xs font-semibold">Loading monitored database...</span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 font-extrabold uppercase tracking-widest text-[10px]">
                  <th className="py-3.5 px-4">Node Target Address</th>
                  <th className="py-3.5 px-4">Description / Friendly Name</th>
                  <th className="py-3.5 px-4">RBL Reputation Status</th>
                  <th className="py-3.5 px-4">Continuous Check Log</th>
                  {isAdmin && <th className="py-3.5 px-4">Created By</th>}
                  <th className="py-3.5 px-4 text-center">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-150 font-semibold text-slate-700">
                {filteredIPs.length === 0 ? (
                  <tr>
                    <td colSpan={isAdmin ? 6 : 5} className="text-center py-12 text-slate-400 font-medium bg-slate-50/50">
                      <Info className="w-8 h-8 mx-auto text-slate-300 mb-2" />
                      <span className="text-xs font-bold text-slate-600 block uppercase tracking-wider">No monitored host nodes match criteria</span>
                      <p className="text-[11px] max-w-sm mx-auto mt-0.5">Use the configuration form above to inject active targets to the real-time monitoring list.</p>
                    </td>
                  </tr>
                ) : (
                  filteredIPs.map((item) => {
                    return (
                      <tr key={item.id} className="hover:bg-slate-50/80 transition-colors">
                        <td className="py-3.5 px-4 font-mono font-bold text-slate-900">
                          {item.ipOrCidr}
                        </td>
                        <td className="py-3.5 px-4 text-slate-600 font-bold">
                          {item.label}
                        </td>
                        <td className="py-3.5 px-4">
                          {item.status === "clean" ? (
                            <span className="inline-flex items-center gap-1 text-emerald-700 bg-emerald-50 px-2.5 py-0.5 rounded-full border border-emerald-150 font-bold text-[11px]">
                              <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                              Clean
                            </span>
                          ) : item.status === "listed" ? (
                            <span className="inline-flex items-center gap-1 text-rose-700 bg-rose-50 px-2.5 py-0.5 rounded-full border border-rose-150 font-bold text-[11px]">
                              <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />
                              Listed ({item.listedCount})
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-slate-500 bg-slate-100 px-2.5 py-0.5 rounded-full border border-slate-200 font-bold text-[11px]">
                              Unknown Status
                            </span>
                          )}
                        </td>
                        <td className="py-3.5 px-4 text-slate-400 text-[11px] font-mono">
                          Last Checked: {new Date(item.lastChecked).toLocaleString()}
                        </td>
                        {isAdmin && (
                          <td className="py-3.5 px-4 font-mono text-[10px] text-slate-500">
                            {item.creatorEmail}
                          </td>
                        )}
                        <td className="py-3.5 px-4">
                          <div className="flex justify-center items-center gap-2">
                            {/* View IP List Icon */}
                            <button
                              onClick={() => {
                                setViewingIP(item);
                                setViewIpSearchQuery("");
                                setViewIpStatusFilter("all");
                                setViewIpCurrentPage(1);
                              }}
                              className="p-1.8 text-slate-500 hover:text-red-600 hover:bg-red-500/10 hover:border-red-500/20 bg-white border border-slate-150 rounded-xl transition-all duration-200 cursor-pointer shadow-sm flex items-center justify-center"
                              title="View IP List"
                            >
                              <Eye className="w-4 h-4" />
                            </button>

                            {/* Edit Icon */}
                            <button
                              onClick={() => {
                                setEditingIP(item);
                                setEditLabel(item.label);
                                setEditIpOrCidr(item.ipOrCidr);
                              }}
                              className="p-1.8 text-slate-500 hover:text-amber-600 hover:bg-amber-500/10 hover:border-amber-500/20 bg-white border border-slate-150 rounded-xl transition-all duration-200 cursor-pointer shadow-sm flex items-center justify-center"
                              title="Edit Target"
                            >
                              <Edit2 className="w-4 h-4" />
                            </button>

                            {/* Delete Icon */}
                            <button
                              onClick={() => {
                                setDeletingIP(item);
                              }}
                              className="p-1.8 text-slate-500 hover:text-rose-600 hover:bg-rose-500/10 hover:border-rose-500/20 bg-white border border-slate-150 rounded-xl transition-all duration-200 cursor-pointer shadow-sm flex items-center justify-center"
                              title="Delete Target"
                            >
                              <Trash2 className="w-4 h-4" />
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

  {activeSubTab === "reports" && (
      <div className="space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 bg-white rounded-2xl p-6 cyber-card">
          <div>
            <h3 className="text-sm font-black text-slate-800 uppercase tracking-wider flex items-center gap-2">
              <FileText className="w-4 h-4 text-red-500" />
              Daily Reputation Audit Reports
            </h3>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl font-semibold">
              Access past daily consolidated blacklist scan reports. The background system performs regular daily checks on all /24 subnets and single host IPs, then aggregates RBL detections into immutable daily reports.
            </p>
          </div>
          <div>
            <button
              onClick={handleGenerateDailyReport}
              disabled={generatingReport}
              className="w-full sm:w-auto px-5 py-3 text-xs font-black uppercase tracking-widest text-white bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded-xl shadow-md hover:shadow-red-500/20 shadow-red-500/10 transition-all flex items-center justify-center gap-2 cursor-pointer border-none"
            >
              {generatingReport ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Compiling Report...
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
          <div className="text-center py-24 bg-white rounded-2xl cyber-card">
            <Loader2 className="w-8 h-8 animate-spin mx-auto text-red-500 mb-3" />
            <p className="text-xs font-black text-slate-600 uppercase tracking-wider">Retrieving Daily Report History...</p>
          </div>
        ) : dailyReports.length === 0 ? (
          <div className="text-center py-20 bg-white rounded-2xl cyber-card text-slate-400">
            <Calendar className="w-10 h-10 mx-auto text-slate-300 mb-2" />
            <h4 className="text-xs font-black text-slate-600 uppercase tracking-widest">No Reports Generated Yet</h4>
            <p className="text-[11px] max-w-sm mx-auto mt-1 font-semibold">
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
                  className="bg-white rounded-2xl p-5 cyber-card hover:shadow-lg transition-all duration-300 border border-slate-100 flex flex-col justify-between group"
                >
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <Calendar className="w-4 h-4 text-red-500" />
                        <span className="text-xs font-black text-slate-900 tracking-wider">
                          {report.date}
                        </span>
                      </div>
                      {totalListed > 0 ? (
                        <span className="text-[10px] font-black text-rose-700 bg-rose-50 px-2 py-0.5 rounded border border-rose-150 uppercase tracking-wider">
                          {totalListed} Listed
                        </span>
                      ) : (
                        <span className="text-[10px] font-black text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-150 uppercase tracking-wider">
                          Clean
                        </span>
                      )}
                    </div>

                    <p className="text-[11px] text-slate-500 font-bold leading-relaxed">
                      {report.summary}
                    </p>

                    <div className="grid grid-cols-3 gap-2 bg-slate-50 p-3 rounded-xl border border-slate-100">
                      <div className="text-center">
                        <span className="block text-[10px] text-slate-400 uppercase tracking-widest font-bold">Total Monitored</span>
                        <span className="text-xs font-black text-slate-900">{report.totalMonitoredIPs}</span>
                      </div>
                      <div className="text-center">
                        <span className="block text-[10px] text-slate-400 uppercase tracking-widest font-bold">Groups</span>
                        <span className="text-xs font-black text-slate-900">{report.totalTargets}</span>
                      </div>
                      <div className="text-center">
                        <span className="block text-[10px] text-slate-400 uppercase tracking-widest font-bold">Cleaned</span>
                        <span className="text-xs font-black text-slate-900">{report.cleanTargetsCount}</span>
                      </div>
                    </div>
                  </div>

                  <button
                    onClick={() => setSelectedReport(report)}
                    className="mt-5 w-full bg-slate-50 hover:bg-red-50 hover:text-red-600 border border-slate-150 hover:border-red-200 text-slate-700 text-xs py-2 rounded-xl font-black uppercase tracking-wider transition-all duration-200 flex items-center justify-center gap-1 cursor-pointer"
                  >
                    <span>Analyze Detail Report</span>
                    <ChevronRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
                  </button>
                </div>
              );
            })}
          </div>
        )}

        {/* Report Detail Modal */}
        <AnimatePresence>
          {selectedReport && (
            <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 z-50">
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="bg-white rounded-3xl w-full max-w-3xl max-h-[85vh] overflow-hidden shadow-2xl flex flex-col border border-slate-150"
              >
                <div className="p-6 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
                  <div className="flex items-center space-x-3">
                    <div className="p-2.5 bg-red-500/10 rounded-xl text-red-500">
                      <FileText className="w-5 h-5" />
                    </div>
                    <div>
                      <h3 className="text-sm font-black text-slate-800 uppercase tracking-wider">
                        Consolidated Audit Detail
                      </h3>
                      <span className="text-[10px] text-slate-400 font-bold uppercase tracking-widest flex items-center gap-1.5 mt-0.5">
                        <Calendar className="w-3.5 h-3.5 text-slate-300" />
                        Audit Timestamp: {new Date(selectedReport.timestamp).toLocaleString()}
                      </span>
                    </div>
                  </div>
                  <button
                    onClick={() => setSelectedReport(null)}
                    className="p-1.5 hover:bg-slate-100 rounded-lg text-slate-400 hover:text-slate-700 transition-colors cursor-pointer border-none bg-transparent"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>

                <div className="p-6 overflow-y-auto space-y-6">
                  {/* Status metrics bar */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                    <div className="bg-slate-50 p-4 rounded-2xl border border-slate-100">
                      <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">Total Audited IPs</span>
                      <span className="text-lg font-black text-slate-900 block mt-1">{selectedReport.totalMonitoredIPs}</span>
                    </div>
                    <div className="bg-slate-50 p-4 rounded-2xl border border-slate-100">
                      <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">Monitoring Targets</span>
                      <span className="text-lg font-black text-slate-900 block mt-1">{selectedReport.totalTargets}</span>
                    </div>
                    <div className="bg-slate-50 p-4 rounded-2xl border border-slate-100">
                      <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">Clean Groups</span>
                      <span className="text-lg font-black text-emerald-600 block mt-1">{selectedReport.cleanTargetsCount}</span>
                    </div>
                    <div className="bg-slate-50 p-4 rounded-2xl border border-slate-100">
                      <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">Listed Host nodes</span>
                      <span className={`text-lg font-black block mt-1 ${selectedReport.blacklistedIPsCount > 0 ? "text-rose-600" : "text-emerald-600"}`}>{selectedReport.blacklistedIPsCount}</span>
                    </div>
                  </div>

                  {/* Summary text */}
                  <div className="bg-red-500/5 rounded-2xl p-4 border border-red-500/10">
                    <p className="text-xs text-red-950 font-bold leading-relaxed flex items-start gap-2">
                      <Info className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
                      {selectedReport.summary}
                    </p>
                  </div>

                  {/* Blacklist detail table */}
                  <div className="space-y-3">
                    <h4 className="text-[10px] font-black text-slate-700 uppercase tracking-widest">
                      Blacklisted IP Listings Breakdown
                    </h4>

                    {selectedReport.blacklistedIPs.length === 0 ? (
                      <div className="text-center py-8 bg-slate-50 rounded-2xl border border-slate-100 text-slate-400">
                        <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-1.5" />
                        <p className="text-xs font-black text-slate-600 uppercase tracking-wider">Perfect Clean Reputation</p>
                        <p className="text-[10px] mt-0.5">No IP hosts in any monitored subnet were blacklisted on this day.</p>
                      </div>
                    ) : (
                      <div className="border border-slate-150 rounded-2xl overflow-hidden shadow-xs">
                        <table className="w-full text-left text-xs border-collapse">
                          <thead>
                            <tr className="bg-slate-50 border-b border-slate-150 text-[10px] font-black uppercase text-slate-400 tracking-wider">
                              <th className="py-3 px-4">Listed IP Address</th>
                              <th className="py-3 px-4">Parent Group</th>
                              <th className="py-3 px-4">RBL Databases</th>
                              <th className="py-3 px-4">Geographic Source</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-100 font-semibold text-slate-700">
                            {selectedReport.blacklistedIPs.map((b, bIdx) => {
                              const activeDbs = Object.entries(b.listings || {})
                                .filter(([_, value]: any) => value.listed)
                                .map(([key, _]) => key);

                              return (
                                <tr key={bIdx} className="hover:bg-slate-50/50 transition-colors">
                                  <td className="py-3 px-4 font-mono font-bold text-slate-900">
                                    {b.ip}
                                  </td>
                                  <td className="py-3 px-4">
                                    <span className="font-sans font-bold text-slate-800 block">{b.parentLabel}</span>
                                    <span className="font-mono text-[10px] text-slate-400 block mt-0.5">{b.parentTarget}</span>
                                  </td>
                                  <td className="py-3 px-4">
                                    <div className="flex flex-wrap gap-1">
                                      {activeDbs.map((dbName, dbIdx) => (
                                        <span key={dbIdx} className="text-[9px] font-black bg-rose-50 border border-rose-100 text-rose-700 px-1.5 py-0.5 rounded">
                                          {dbName}
                                        </span>
                                      ))}
                                    </div>
                                  </td>
                                  <td className="py-3 px-4 text-[11px] text-slate-500">
                                    {b.location ? (
                                      <span>
                                        {b.location.city || b.location.region || "Unknown City"}, {b.location.countryCode || b.location.country || "Unknown Country"}
                                      </span>
                                    ) : (
                                      <span className="text-slate-300">No Location Cache</span>
                                    )}
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

                <div className="p-5 border-t border-slate-100 bg-slate-50/50 flex justify-end">
                  <button
                    onClick={() => setSelectedReport(null)}
                    className="px-5 py-2.5 bg-slate-800 hover:bg-slate-900 border-none text-white rounded-xl text-xs font-black uppercase tracking-widest shadow-sm transition-all cursor-pointer"
                  >
                    Close Detailed Audit
                  </button>
                </div>
              </motion.div>
            </div>
          )}
        </AnimatePresence>
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
            className="bg-white rounded-3xl w-full max-w-md overflow-hidden shadow-2xl flex flex-col border border-slate-150"
          >
            <div className="p-6 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
              <div className="flex items-center space-x-3">
                <div className="p-2.5 bg-rose-500/10 rounded-xl text-rose-500">
                  <Trash2 className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-black text-slate-800 uppercase tracking-wider">
                    Stop Monitoring Target
                  </h3>
                  <p className="text-[10px] text-slate-400 font-bold uppercase tracking-widest mt-0.5">
                    Confirm Permanent Deletion
                  </p>
                </div>
              </div>
              <button
                onClick={() => setDeletingIP(null)}
                className="p-1.5 hover:bg-slate-100 rounded-lg text-slate-400 hover:text-slate-700 transition-colors cursor-pointer border-none bg-transparent"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div className="bg-rose-500/5 rounded-2xl p-4 border border-rose-500/10">
                <p className="text-xs text-rose-950 font-bold leading-relaxed flex items-start gap-2">
                  <Info className="w-4 h-4 text-rose-500 shrink-0 mt-0.5" />
                  Are you sure you want to stop monitoring this host or subnet? Continuous reputation checking, status history, and daily reports integrations for this node target will be disabled immediately.
                </p>
              </div>

              <div className="text-xs space-y-1.5">
                <div className="flex justify-between border-b border-slate-100 pb-2">
                  <span className="text-slate-400 font-bold uppercase">Target Address:</span>
                  <span className="font-mono font-bold text-slate-900">{deletingIP.ipOrCidr}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400 font-bold uppercase">Friendly Label:</span>
                  <span className="font-bold text-slate-800">{deletingIP.label}</span>
                </div>
              </div>
            </div>

            <div className="p-5 border-t border-slate-100 bg-slate-50/50 flex justify-end gap-3">
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
                className="px-5 py-2.5 bg-rose-600 hover:bg-rose-700 text-white rounded-xl text-xs font-black uppercase tracking-widest shadow-md shadow-rose-500/10 hover:shadow-rose-500/20 transition-all cursor-pointer flex items-center gap-1.5 border-none disabled:opacity-50"
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
            className="bg-white rounded-3xl w-full max-w-md overflow-hidden shadow-2xl flex flex-col border border-slate-150"
          >
            <form onSubmit={handleUpdateIP}>
              <div className="p-6 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
                <div className="flex items-center space-x-3">
                  <div className="p-2.5 bg-amber-500/10 rounded-xl text-amber-500">
                    <Edit2 className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-black text-slate-800 uppercase tracking-wider">
                      Edit Monitoring Target
                    </h3>
                    <p className="text-[10px] text-slate-400 font-bold uppercase tracking-widest mt-0.5">
                      Modify node configuration
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
                  <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                    Friendly Label / Description
                  </label>
                  <input
                    type="text"
                    required
                    value={editLabel}
                    onChange={(e) => setEditLabel(e.target.value)}
                    placeholder="e.g. Primary Mail Server"
                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-amber-500/10 focus:border-amber-500/80 text-slate-900 font-bold transition-all"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                    IP Address or Subnet Block
                  </label>
                  <input
                    type="text"
                    required
                    value={editIpOrCidr}
                    onChange={(e) => setEditIpOrCidr(e.target.value)}
                    placeholder="e.g. 192.168.1.1 or 192.168.1.0/24"
                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2.5 text-xs focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-amber-500/10 focus:border-amber-500/80 text-slate-950 font-bold transition-all"
                  />
                  <p className="text-[9px] text-slate-400 font-bold uppercase tracking-wide">
                    Changing the target IP/subnet will automatically trigger a fresh RBL reputation scan.
                  </p>
                </div>
              </div>

              <div className="p-5 border-t border-slate-100 bg-slate-50/50 flex justify-end gap-3">
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
                  className="px-5 py-2.5 bg-black hover:bg-zinc-900 text-white rounded-xl text-xs font-black uppercase tracking-widest shadow-md hover:shadow-slate-500/10 transition-all cursor-pointer flex items-center gap-1.5 border-none disabled:opacity-50"
                >
                  {editLoading ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      Saving...
                    </>
                  ) : (
                    <>
                      <Check className="w-3.5 h-3.5 text-red-500" />
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

    {/* View Subnet IP List Modal */}
    <AnimatePresence>
      {viewingIP && (() => {
        const expandedIPs = getIPsForTarget(viewingIP);
        const filteredViewIPs = expandedIPs.filter(ipItem => {
          const matchesSearch = ipItem.ip.toLowerCase().includes(viewIpSearchQuery.toLowerCase());
          const matchesStatus = viewIpStatusFilter === "all" || ipItem.status === viewIpStatusFilter;
          return matchesSearch && matchesStatus;
        });
        const totalPages = Math.ceil(filteredViewIPs.length / viewIpPageSize) || 1;
        const startIndex = (viewIpCurrentPage - 1) * viewIpPageSize;
        const paginatedViewIPs = filteredViewIPs.slice(startIndex, startIndex + viewIpPageSize);
        const cleanCount = expandedIPs.filter(ip => ip.status === 'clean').length;
        const listedCount = expandedIPs.filter(ip => ip.status === 'listed').length;

        return (
          <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 z-50">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-white rounded-3xl w-full max-w-3xl max-h-[85vh] overflow-hidden shadow-2xl flex flex-col border border-slate-150"
            >
              <div className="p-6 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
                <div className="flex items-center space-x-3">
                  <div className="p-2.5 bg-red-500/10 rounded-xl text-red-500 animate-pulse">
                    <Globe className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-black text-slate-800 uppercase tracking-wider">
                      Subnet IP Allocation Dashboard
                    </h3>
                    <p className="text-[10px] text-slate-400 font-bold uppercase tracking-widest mt-0.5">
                      Target: {viewingIP.ipOrCidr} | Label: {viewingIP.label}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setViewingIP(null)}
                  className="p-1.5 hover:bg-slate-100 rounded-lg text-slate-400 hover:text-slate-700 transition-colors cursor-pointer border-none bg-transparent"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="p-6 overflow-y-auto space-y-6 flex-1">
                {/* Metrics Row */}
                <div className="grid grid-cols-3 gap-4">
                  <div className="bg-slate-50 p-4 rounded-2xl border border-slate-100 text-center">
                    <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">Total Address Space</span>
                    <span className="text-lg font-black text-slate-900 block mt-1">{expandedIPs.length}</span>
                  </div>
                  <div className="bg-slate-50 p-4 rounded-2xl border border-slate-100 text-center">
                    <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest block text-emerald-600">Clean IP Allocations</span>
                    <span className="text-lg font-black text-emerald-600 block mt-1">{cleanCount}</span>
                  </div>
                  <div className="bg-slate-50 p-4 rounded-2xl border border-slate-100 text-center">
                    <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest block text-rose-600">Active Listings</span>
                    <span className="text-lg font-black text-rose-600 block mt-1">{listedCount}</span>
                  </div>
                </div>

                {/* Filter controls */}
                <div className="flex flex-col sm:flex-row gap-3 justify-between items-center bg-slate-50 p-4 rounded-2xl border border-slate-100">
                  <div className="relative flex-1 w-full">
                    <Search className="w-3.5 h-3.5 absolute left-3 top-3.5 text-slate-400" />
                    <input
                      type="text"
                      value={viewIpSearchQuery}
                      onChange={(e) => {
                        setViewIpSearchQuery(e.target.value);
                        setViewIpCurrentPage(1);
                      }}
                      placeholder="Filter IP address..."
                      className="w-full pl-9 pr-3.5 py-2.5 bg-white border border-slate-200 rounded-xl text-xs focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-red-500/10 focus:border-red-500/80 transition-all text-slate-900 font-bold placeholder:text-slate-400"
                    />
                  </div>

                  <div className="flex gap-2 w-full sm:w-auto">
                    <select
                      value={viewIpStatusFilter}
                      onChange={(e) => {
                        setViewIpStatusFilter(e.target.value as any);
                        setViewIpCurrentPage(1);
                      }}
                      className="bg-white border border-slate-200 text-xs font-bold px-3 py-2.5 rounded-xl text-slate-700 focus:outline-hidden focus:ring-4 focus:ring-red-500/10 focus:border-red-500/80 cursor-pointer flex-1 sm:flex-initial"
                    >
                      <option value="all">All Statuses</option>
                      <option value="clean">Clean Only</option>
                      <option value="listed">Listed Only</option>
                    </select>

                    <button
                      onClick={() => handleExportSubnetCSV(viewingIP, filteredViewIPs)}
                      className="bg-black hover:bg-zinc-900 text-white px-4 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest shadow-sm flex items-center justify-center gap-1.5 cursor-pointer border border-zinc-850 transition-all"
                      title="Export to CSV"
                    >
                      <Download className="w-3.5 h-3.5 text-red-500" />
                      <span>Export</span>
                    </button>
                  </div>
                </div>

                {/* IPs Table */}
                <div className="border border-slate-150 rounded-2xl overflow-hidden shadow-xs">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="bg-slate-50 border-b border-slate-150 text-[10px] font-black uppercase text-slate-400 tracking-wider">
                        <th className="py-3 px-4">Node Address</th>
                        <th className="py-3 px-4">Reputation Status</th>
                        <th className="py-3 px-4">RBL Listings</th>
                        <th className="py-3 px-4 text-center">Copy</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 font-semibold text-slate-700">
                      {paginatedViewIPs.length === 0 ? (
                        <tr>
                          <td colSpan={4} className="text-center py-8 text-slate-400 font-bold uppercase tracking-wider bg-slate-50/30">
                            No IP addresses match your filter criteria
                          </td>
                        </tr>
                      ) : (
                        paginatedViewIPs.map((ipItem, idx) => {
                          const activeDbs = Object.entries(ipItem.listings || {})
                            .filter(([_, value]: any) => value.listed)
                            .map(([key, _]) => key);

                          return (
                            <tr key={idx} className="hover:bg-slate-50/50 transition-colors">
                              <td className="py-3 px-4 font-mono font-bold text-slate-900">
                                {ipItem.ip}
                              </td>
                              <td className="py-3 px-4">
                                {ipItem.status === "clean" ? (
                                  <span className="inline-flex items-center gap-1 text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-100 font-bold text-[10px] uppercase">
                                    Clean
                                  </span>
                                ) : (
                                  <span className="inline-flex items-center gap-1 text-rose-700 bg-rose-50 px-2 py-0.5 rounded-full border border-rose-100 font-bold text-[10px] uppercase">
                                    Listed ({ipItem.listedCount})
                                  </span>
                                )}
                              </td>
                              <td className="py-3 px-4">
                                {activeDbs.length > 0 ? (
                                  <div className="flex flex-wrap gap-1 max-w-xs">
                                    {activeDbs.map((dbName, dbIdx) => (
                                      <span key={dbIdx} className="text-[9px] font-black bg-rose-50 border border-rose-100 text-rose-700 px-1.5 py-0.2 rounded uppercase">
                                        {dbName}
                                      </span>
                                    ))}
                                  </div>
                                ) : (
                                  <span className="text-slate-400 font-normal italic">None</span>
                                )}
                              </td>
                              <td className="py-3 px-4 text-center">
                                <button
                                  onClick={() => handleCopyIP(ipItem.ip)}
                                  className="p-1 hover:bg-slate-100 rounded-lg text-slate-400 hover:text-slate-700 transition-colors inline-flex items-center justify-center border-none bg-transparent cursor-pointer"
                                  title="Copy IP Address"
                                >
                                  {copiedIp === ipItem.ip ? (
                                    <Check className="w-3.5 h-3.5 text-emerald-500" />
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
                  <div className="flex items-center justify-between border-t border-slate-100 pt-4">
                    <span className="text-[10px] font-bold text-slate-400 uppercase">
                      Showing {startIndex + 1} to {Math.min(startIndex + viewIpPageSize, filteredViewIPs.length)} of {filteredViewIPs.length} addresses
                    </span>
                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => setViewIpCurrentPage(prev => Math.max(prev - 1, 1))}
                        disabled={viewIpCurrentPage === 1}
                        className="p-1.5 border border-slate-200 hover:bg-slate-50 text-slate-600 rounded-lg disabled:opacity-40 transition-colors cursor-pointer flex items-center justify-center"
                      >
                        <ChevronLeft className="w-4 h-4" />
                      </button>
                      <span className="text-xs font-bold text-slate-700 px-2">
                        Page {viewIpCurrentPage} of {totalPages}
                      </span>
                      <button
                        onClick={() => setViewIpCurrentPage(prev => Math.min(prev + 1, totalPages))}
                        disabled={viewIpCurrentPage === totalPages}
                        className="p-1.5 border border-slate-200 hover:bg-slate-50 text-slate-600 rounded-lg disabled:opacity-40 transition-colors cursor-pointer flex items-center justify-center"
                      >
                        <ChevronRight className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                )}
              </div>

              <div className="p-5 border-t border-slate-100 bg-slate-50/50 flex justify-end">
                <button
                  onClick={() => setViewingIP(null)}
                  className="px-5 py-2.5 bg-slate-900 hover:bg-slate-950 text-white rounded-xl text-xs font-black uppercase tracking-widest shadow-sm transition-all cursor-pointer border-none"
                >
                  Close Dashboard
                </button>
              </div>
            </motion.div>
          </div>
        );
      })()}
    </AnimatePresence>
  </div>
);
};
