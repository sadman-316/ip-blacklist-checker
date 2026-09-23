import React, { useState, useEffect } from 'react';
import { 
  Mail, 
  Send, 
  Clock, 
  CheckCircle2, 
  AlertCircle, 
  XCircle, 
  ExternalLink, 
  Search, 
  RefreshCw, 
  Trash2, 
  Building2, 
  FileText, 
  ShieldCheck, 
  Filter,
  Plus,
  Loader2,
  Copy,
  Check
} from 'lucide-react';
import { DelistRequest, UserProfile } from '../types';

interface DelistRequestsTrackerProps {
  currentUser: UserProfile;
  triggerAlert: (type: 'success' | 'error' | 'info' | 'warning', message: string) => void;
  onOpenNewAppealModal?: (targetIP?: string) => void;
}

export function DelistRequestsTracker({
  currentUser,
  triggerAlert,
  onOpenNewAppealModal
}: DelistRequestsTrackerProps) {
  const [requests, setRequests] = useState<DelistRequest[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [statusFilter, setStatusFilter] = useState<'all' | 'pending' | 'submitted' | 'under_review' | 'delisted' | 'rejected'>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [viewingRequest, setViewingRequest] = useState<DelistRequest | null>(null);
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [quickIP, setQuickIP] = useState<string>('');

  // Fetch removal requests from backend
  const fetchRequests = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/delist/requests');
      if (res.ok) {
        const data = await res.json();
        setRequests(data.requests || []);
      }
    } catch (err) {
      console.warn('Failed to load delist requests:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRequests();
  }, []);

  // Update request status
  const handleUpdateStatus = async (id: string, newStatus: DelistRequest['status']) => {
    try {
      const res = await fetch(`/api/delist/requests/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      if (res.ok) {
        setRequests(prev => prev.map(r => r.id === id ? { ...r, status: newStatus } : r));
        triggerAlert('success', `Updated status to ${newStatus.replace('_', ' ').toUpperCase()}`);
      }
    } catch (err) {
      triggerAlert('error', 'Failed to update request status.');
    }
  };

  // Delete a request
  const handleDeleteRequest = async (id: string) => {
    if (!confirm('Are you sure you want to remove this delist request record?')) return;
    try {
      const res = await fetch(`/api/delist/requests/${id}`, { method: 'DELETE' });
      if (res.ok) {
        setRequests(prev => prev.filter(r => r.id !== id));
        triggerAlert('success', 'Delist request record removed.');
      }
    } catch (err) {
      triggerAlert('error', 'Failed to delete record.');
    }
  };

  // Quick re-verify IP listing status
  const handleReverifyStatus = async (req: DelistRequest) => {
    setVerifyingId(req.id);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: req.ip })
      });
      if (res.ok) {
        const scanData = await res.json();
        const ipResult = scanData.results?.[0];
        if (ipResult) {
          const providerEntry = ipResult.listings?.[req.providerId];
          const isListed = providerEntry?.listed || providerEntry?.status === 'LISTED';
          
          if (!isListed) {
            await handleUpdateStatus(req.id, 'delisted');
            triggerAlert('success', `GREAT NEWS! ${req.ip} is NO LONGER LISTED on ${req.providerName}!`);
          } else {
            triggerAlert('info', `${req.ip} is still listed on ${req.providerName}. Appeal remains under review.`);
          }
        }
      }
    } catch (err) {
      triggerAlert('error', 'Failed to re-verify status with DNSBL.');
    } finally {
      setVerifyingId(null);
    }
  };

  // Copy appeal text
  const handleCopyAppeal = (req: DelistRequest) => {
    navigator.clipboard.writeText(`${req.subject}\n\n${req.message}`);
    setCopiedId(req.id);
    triggerAlert('success', 'Appeal letter copied to clipboard!');
    setTimeout(() => setCopiedId(null), 2500);
  };

  // Filter requests
  const filteredRequests = requests.filter(r => {
    if (statusFilter !== 'all' && r.status !== statusFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        r.ip.toLowerCase().includes(q) ||
        r.providerName.toLowerCase().includes(q) ||
        r.companyName.toLowerCase().includes(q) ||
        r.senderEmail.toLowerCase().includes(q)
      );
    }
    return true;
  });

  // Stats calculation
  const totalCount = requests.length;
  const pendingCount = requests.filter(r => r.status === 'pending' || r.status === 'submitted').length;
  const underReviewCount = requests.filter(r => r.status === 'under_review').length;
  const delistedCount = requests.filter(r => r.status === 'delisted').length;

  return (
    <div className="space-y-6" id="delist-requests-tracker">
      
      {/* Top Banner & Header */}
      <div className="bg-slate-900 text-white p-6 rounded-2xl shadow-sm border border-slate-800 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-red-600/20 border border-red-500/30 flex items-center justify-center text-red-500">
              <Mail className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-black uppercase tracking-wider text-white">
                Blacklist Delisting & Removal Tracker
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Track formal delisting appeals sent to Spamhaus, Barracuda, UCEPROTECT, and global security desks
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5 w-full sm:w-auto">
          <button
            onClick={fetchRequests}
            disabled={loading}
            className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold rounded-xl text-xs flex items-center gap-1.5 transition-all cursor-pointer"
            title="Refresh requests"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>

          {onOpenNewAppealModal && (
            <button
              onClick={() => onOpenNewAppealModal()}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white font-extrabold rounded-xl text-xs flex items-center gap-1.5 transition-all cursor-pointer shadow-xs"
            >
              <Plus className="w-4 h-4" />
              <span>Draft New Removal Appeal</span>
            </button>
          )}
        </div>
      </div>

      {/* Quick Add IP to Delist Section */}
      <div className="bg-gradient-to-r from-red-950/40 via-slate-900 to-slate-900 border border-red-500/30 rounded-2xl p-5 shadow-sm">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-red-500/20 border border-red-500/30 text-red-400 text-[10px] font-black uppercase tracking-wider">
                Instant Delist Action
              </span>
              <span className="text-[11px] text-slate-400 font-bold">Add any IP to delist</span>
            </div>
            <h3 className="text-base font-black text-white mt-1.5">
              Add IP Address to Request Delisting & Removal
            </h3>
            <p className="text-xs text-slate-300 mt-0.5 max-w-xl">
              Type or paste any listed IP address below to immediately draft, customize, and dispatch an official delisting appeal to Spamhaus, Barracuda, UCEPROTECT, and other RBL security desks.
            </p>
          </div>

          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5 w-full lg:w-auto shrink-0">
            <div className="relative">
              <input
                type="text"
                value={quickIP}
                onChange={(e) => setQuickIP(e.target.value.trim())}
                placeholder="Enter IP (e.g. 103.150.12.5)"
                className="w-full sm:w-64 px-3.5 py-2.5 bg-slate-950/90 border border-slate-700 rounded-xl text-xs font-mono font-bold text-white placeholder:text-slate-500 focus:outline-hidden focus:border-red-500 focus:ring-2 focus:ring-red-500/20"
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    if (onOpenNewAppealModal) onOpenNewAppealModal(quickIP);
                  }
                }}
              />
            </div>
            <button
              type="button"
              onClick={() => {
                if (onOpenNewAppealModal) {
                  onOpenNewAppealModal(quickIP);
                }
              }}
              className="px-4 py-2.5 bg-red-600 hover:bg-red-700 text-white font-black rounded-xl text-xs flex items-center justify-center gap-1.5 transition-all cursor-pointer shadow-xs whitespace-nowrap"
            >
              <Mail className="w-4 h-4" />
              <span>Draft Delist Appeal</span>
            </button>
          </div>
        </div>
      </div>

      {/* KPI Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 sm:gap-4">
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-2xs">
          <span className="text-[10px] font-black uppercase tracking-wider text-slate-400 block">Total Appeals Logged</span>
          <span className="text-2xl sm:text-3xl font-black font-mono text-slate-900 mt-1 block">{totalCount}</span>
          <span className="text-[11px] text-slate-500 mt-1 block">Across all monitored IPs</span>
        </div>

        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-2xs">
          <span className="text-[10px] font-black uppercase tracking-wider text-amber-600 block">Pending Review</span>
          <span className="text-2xl sm:text-3xl font-black font-mono text-amber-600 mt-1 block">{pendingCount}</span>
          <span className="text-[11px] text-slate-500 mt-1 block">Awaiting provider response</span>
        </div>

        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-2xs">
          <span className="text-[10px] font-black uppercase tracking-wider text-blue-600 block">Under Review</span>
          <span className="text-2xl sm:text-3xl font-black font-mono text-blue-600 mt-1 block">{underReviewCount}</span>
          <span className="text-[11px] text-slate-500 mt-1 block">In ticket queue</span>
        </div>

        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-2xs">
          <span className="text-[10px] font-black uppercase tracking-wider text-emerald-600 block">Successfully Delisted</span>
          <span className="text-2xl sm:text-3xl font-black font-mono text-emerald-600 mt-1 block">{delistedCount}</span>
          <span className="text-[11px] text-slate-500 mt-1 block">IP removed & clean</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-white p-4 rounded-2xl border border-slate-200 shadow-2xs flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3.5 top-3 text-slate-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by IP, provider name, company, or email..."
            className="w-full pl-10 pr-4 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold text-slate-900 focus:outline-hidden focus:ring-2 focus:ring-red-500/20"
          />
        </div>

        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 md:pb-0 text-xs font-bold">
          <span className="text-[10px] font-black uppercase tracking-wider text-slate-400 mr-1 hidden sm:inline">Status:</span>
          {[
            { id: 'all', label: 'All' },
            { id: 'pending', label: 'Pending' },
            { id: 'under_review', label: 'Under Review' },
            { id: 'delisted', label: 'Delisted' },
            { id: 'rejected', label: 'Rejected' }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setStatusFilter(tab.id as any)}
              className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer whitespace-nowrap text-xs ${
                statusFilter === tab.id 
                  ? 'bg-slate-900 text-white shadow-2xs' 
                  : 'bg-slate-100 hover:bg-slate-200 text-slate-600'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Requests Table */}
      <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-2xs">
        {loading ? (
          <div className="p-12 text-center text-slate-500">
            <Loader2 className="w-8 h-8 animate-spin mx-auto text-red-600 mb-3" />
            <p className="font-bold text-xs">Loading delisting removal tracker...</p>
          </div>
        ) : filteredRequests.length === 0 ? (
          <div className="p-12 text-center space-y-3">
            <div className="w-12 h-12 rounded-full bg-slate-100 flex items-center justify-center mx-auto text-slate-400">
              <Mail className="w-6 h-6" />
            </div>
            <h3 className="font-black text-slate-800 text-sm">No Delisting Appeals Found</h3>
            <p className="text-xs text-slate-500 max-w-sm mx-auto">
              When an IP address is blacklisted, you can submit a removal appeal directly from the Network Scan screen or by clicking "Draft New Removal Appeal".
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-100/80 border-b border-slate-200 text-slate-600 font-black uppercase tracking-wider text-[10px]">
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Target IP</th>
                  <th className="py-3 px-4">Blacklist Provider</th>
                  <th className="py-3 px-4">Company & Sender</th>
                  <th className="py-3 px-4">Reason Category</th>
                  <th className="py-3 px-4">Submitted At</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-150 font-medium text-slate-800">
                {filteredRequests.map((req) => {
                  const isVerifying = verifyingId === req.id;
                  return (
                    <tr key={req.id} className="hover:bg-slate-50 transition-colors">
                      
                      {/* Status Dropdown/Badge */}
                      <td className="py-3 px-4">
                        <select
                          value={req.status}
                          onChange={(e) => handleUpdateStatus(req.id, e.target.value as any)}
                          className={`text-[10px] font-black uppercase px-2.5 py-1 rounded-lg cursor-pointer border focus:outline-hidden ${
                            req.status === 'delisted' ? 'bg-emerald-100 border-emerald-300 text-emerald-800' :
                            req.status === 'under_review' ? 'bg-blue-100 border-blue-300 text-blue-800' :
                            req.status === 'rejected' ? 'bg-rose-100 border-rose-300 text-rose-800' :
                            'bg-amber-100 border-amber-300 text-amber-800'
                          }`}
                        >
                          <option value="pending">Pending</option>
                          <option value="submitted">Submitted</option>
                          <option value="under_review">Under Review</option>
                          <option value="delisted">Delisted (Clean)</option>
                          <option value="rejected">Rejected</option>
                        </select>
                      </td>

                      {/* IP */}
                      <td className="py-3 px-4">
                        <span className="font-mono font-bold text-slate-900">{req.ip}</span>
                      </td>

                      {/* Provider */}
                      <td className="py-3 px-4">
                        <span className="font-bold text-slate-900 block">{req.providerName}</span>
                        <span className="text-[10px] text-slate-400 font-mono block truncate max-w-xs">
                          {req.recipientEmail || 'Portal Submission'}
                        </span>
                      </td>

                      {/* Company & Sender */}
                      <td className="py-3 px-4">
                        <span className="font-bold text-slate-900 block">{req.companyName}</span>
                        <span className="text-[10px] text-slate-500 block">{req.senderName} ({req.senderEmail})</span>
                      </td>

                      {/* Reason */}
                      <td className="py-3 px-4">
                        <span className="bg-slate-100 text-slate-700 px-2 py-0.5 rounded text-[10px] font-bold block truncate max-w-xs">
                          {req.reasonCategory}
                        </span>
                      </td>

                      {/* Date */}
                      <td className="py-3 px-4 text-slate-500 font-mono text-[11px]">
                        {new Date(req.submittedAt).toLocaleDateString()}
                        <span className="block text-[10px] text-slate-400">
                          {new Date(req.submittedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </span>
                      </td>

                      {/* Action buttons */}
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          
                          {/* Re-verify IP button */}
                          <button
                            onClick={() => handleReverifyStatus(req)}
                            disabled={isVerifying}
                            className="p-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-[10px] font-bold transition-all cursor-pointer"
                            title="Re-check if this IP is still listed on this provider"
                          >
                            <RefreshCw className={`w-3.5 h-3.5 ${isVerifying ? 'animate-spin text-red-600' : ''}`} />
                          </button>

                          {/* View Letter button */}
                          <button
                            onClick={() => setViewingRequest(req)}
                            className="px-2.5 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-800 rounded-lg text-[10px] font-black uppercase transition-all cursor-pointer flex items-center gap-1"
                            title="View appeal text"
                          >
                            <FileText className="w-3 h-3" />
                            <span>View</span>
                          </button>

                          {/* Portal link */}
                          {req.delistUrl && (
                            <a
                              href={req.delistUrl}
                              target="_blank"
                              rel="noreferrer"
                              className="p-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg transition-all"
                              title="Open official removal portal"
                            >
                              <ExternalLink className="w-3.5 h-3.5" />
                            </a>
                          )}

                          {/* Delete button */}
                          <button
                            onClick={() => handleDeleteRequest(req.id)}
                            className="p-1.5 bg-slate-100 hover:bg-rose-100 text-slate-400 hover:text-rose-600 rounded-lg transition-all cursor-pointer"
                            title="Delete record"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>

                        </div>
                      </td>

                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal: View Full Appeal Letter */}
      {viewingRequest && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/75 backdrop-blur-xs animate-fade-in">
          <div className="bg-white rounded-2xl max-w-2xl w-full border border-slate-200 shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
            <div className="bg-slate-900 text-white p-4 flex justify-between items-center">
              <div>
                <h3 className="text-sm font-black uppercase tracking-wider">
                  Delisting Appeal - {viewingRequest.ip}
                </h3>
                <p className="text-[11px] text-slate-400 font-mono">
                  Sent to {viewingRequest.providerName} ({viewingRequest.recipientEmail || 'Portal'})
                </p>
              </div>
              <button
                onClick={() => setViewingRequest(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg"
              >
                ✕
              </button>
            </div>

            <div className="p-5 overflow-y-auto space-y-4 text-xs">
              <div className="bg-slate-50 p-3 rounded-xl border border-slate-200 space-y-1">
                <span className="text-[10px] font-black uppercase text-slate-400 block">Subject</span>
                <span className="font-mono font-bold text-slate-900 block">{viewingRequest.subject}</span>
              </div>

              <div className="space-y-1">
                <span className="text-[10px] font-black uppercase text-slate-400 block">Message Body</span>
                <pre className="p-4 bg-slate-50 border border-slate-200 rounded-xl font-mono text-slate-800 text-xs whitespace-pre-wrap leading-relaxed">
                  {viewingRequest.message}
                </pre>
              </div>
            </div>

            <div className="p-4 bg-slate-50 border-t border-slate-200 flex justify-between items-center">
              <button
                onClick={() => handleCopyAppeal(viewingRequest)}
                className="px-3.5 py-2 bg-slate-200 hover:bg-slate-300 text-slate-800 font-bold rounded-xl text-xs flex items-center gap-1.5 transition-all cursor-pointer"
              >
                {copiedId === viewingRequest.id ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedId === viewingRequest.id ? 'Copied' : 'Copy Full Letter'}</span>
              </button>

              <button
                onClick={() => setViewingRequest(null)}
                className="px-4 py-2 bg-slate-900 text-white font-bold rounded-xl text-xs cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
