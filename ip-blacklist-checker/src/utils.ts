import { IPScanResult, SubnetScanReport, DailyReport, MonitoredIP } from "./types";

/**
 * Universal safe file downloader for browser environments
 */
export function triggerFileDownload(content: string, filename: string, mimeType: string) {
  try {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.style.display = "none";
    document.body.appendChild(link);
    link.click();
    setTimeout(() => {
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    }, 1000);
  } catch (err) {
    console.error("Failed to trigger file download:", err);
  }
}

function getListedProvidersLabel(listings: Record<string, any> | undefined): string {
  if (!listings) return "None";
  const active = Object.entries(listings)
    .filter(([_, value]: any) => value && value.listed)
    .map(([key, value]: any) => {
      const name = value?.name || key;
      const db = value?.database ? ` (${value.database})` : "";
      return `${name}${db}`;
    });
  return active.length > 0 ? active.join("; ") : "None";
}

function escapeCsvCell(val: unknown): string {
  return `"${String(val ?? "").replace(/"/g, '""')}"`;
}

function escapeHtml(val: unknown): string {
  return String(val ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Download CSV report for SubnetScanReport (with prominent [LISTED] markers & top flagged summary)
export function downloadCSVReport(report: SubnetScanReport) {
  const results = report.results || [];
  const listedResults = results.filter(r => r.status === "listed" || (r.listedCount || 0) > 0);
  const cleanResults = results.filter(r => r.status !== "listed" && (r.listedCount || 0) === 0);

  const headers = [
    "Mark / Flag",
    "IP Address",
    "Status",
    "Listed Count",
    "Listed On (Blacklists)",
    "PTR / Hostname",
    "ISP / Organization",
    "Location",
    "Action Status",
    "Notes",
    "Timestamp"
  ];

  const buildRow = (r: IPScanResult) => {
    const isListed = r.status === "listed" || (r.listedCount || 0) > 0;
    const mark = isListed ? "🔴 [LISTED]" : "✓ Clean";
    const statusLabel = isListed ? "LISTED - ACTION REQUIRED" : (r.status || "clean").toUpperCase();
    const activeBlacklists = getListedProvidersLabel(r.listings);
    const ptr = r.ptr || r.location?.ptr || r.hostname || r.location?.hostname || "N/A";
    const isp = r.isp || r.location?.isp || r.org || r.location?.org || "Unknown";
    const location = r.location?.country
      ? `${r.location.city ? `${r.location.city}, ` : ""}${r.location.country}`
      : r.country || "Unknown";

    return [
      mark,
      r.ip,
      statusLabel,
      r.listedCount || 0,
      activeBlacklists,
      ptr,
      isp,
      location,
      r.actionStatus?.toUpperCase() || (isListed ? "UNRESOLVED" : "N/A"),
      r.notes || "",
      r.timestamp || report.timestamp || new Date().toISOString()
    ];
  };

  const csvLines: string[] = [];

  // Summary Banner
  csvLines.push(["BLACKLIST BLOCK SCAN REPORT", `Target: ${report.target}`, `Total IPs: ${results.length}`, `Listed IPs: ${listedResults.length}`, `Clean IPs: ${cleanResults.length}`, `Exported: ${new Date().toISOString()}`].map(escapeCsvCell).join(","));
  csvLines.push("");

  // For multi-IP / block scans, put a dedicated Flagged / Listed IPs Summary section at the very top of the sheet
  if (results.length > 1) {
    csvLines.push([">>> FLAGGED / LISTED IPs SUMMARY (BLACKLISTED ONLY) <<<"].map(escapeCsvCell).join(","));
    csvLines.push(headers.map(escapeCsvCell).join(","));
    if (listedResults.length > 0) {
      listedResults.forEach(r => {
        csvLines.push(buildRow(r).map(escapeCsvCell).join(","));
      });
    } else {
      csvLines.push(["✅ [ALL CLEAN]", "No blacklisted IPs found in this subnet block", "CLEAN", "0", "None", "", "", "", "", "", ""].map(escapeCsvCell).join(","));
    }
    csvLines.push("");
    csvLines.push([`>>> COMPLETE FULL BLOCK IP LIST (${results.length} IPs — LISTED IPs MARKED) <<<`].map(escapeCsvCell).join(","));
  }

  csvLines.push(headers.map(escapeCsvCell).join(","));
  results.forEach(r => {
    csvLines.push(buildRow(r).map(escapeCsvCell).join(","));
  });

  const csvContent = "\uFEFF" + csvLines.join("\n");
  const sanitizedTarget = (report.target || "scan").replace(/[\/.:\s-]/g, "_");
  triggerFileDownload(csvContent, `blacklist_report_${sanitizedTarget}.csv`, "text/csv;charset=utf-8;");
}

// Download Color-Highlighted Excel Sheet (.xls) for SubnetScanReport
export function downloadExcelReport(report: SubnetScanReport) {
  const results = report.results || [];
  const listedResults = results.filter(r => r.status === "listed" || (r.listedCount || 0) > 0);
  const cleanResults = results.filter(r => r.status !== "listed" && (r.listedCount || 0) === 0);

  const renderRow = (r: IPScanResult) => {
    const isListed = r.status === "listed" || (r.listedCount || 0) > 0;
    const rowBg = isListed ? "#fee2e2" : "#ffffff";
    const rowColor = isListed ? "#991b1b" : "#1e293b";
    const markBg = isListed ? "#dc2626" : "#ecfdf5";
    const markColor = isListed ? "#ffffff" : "#047857";
    const markText = isListed ? "LISTED [FLAGGED]" : "CLEAN";
    const activeBlacklists = getListedProvidersLabel(r.listings);
    const ptr = r.ptr || r.location?.ptr || r.hostname || r.location?.hostname || "N/A";
    const isp = r.isp || r.location?.isp || r.org || r.location?.org || "Unknown";
    const location = r.location?.country
      ? `${r.location.city ? `${r.location.city}, ` : ""}${r.location.country}`
      : r.country || "Unknown";

    return `<tr style="background-color:${rowBg}; color:${rowColor}; ${isListed ? "font-weight:bold;" : ""}">
      <td style="background-color:${markBg}; color:${markColor}; font-weight:bold; text-align:center;">${markText}</td>
      <td style="font-family:monospace; font-weight:bold;">${escapeHtml(r.ip)}</td>
      <td style="text-align:center; font-weight:bold;">${isListed ? "LISTED" : "CLEAN"}</td>
      <td style="text-align:center;">${r.listedCount || 0}</td>
      <td>${escapeHtml(activeBlacklists)}</td>
      <td>${escapeHtml(ptr)}</td>
      <td>${escapeHtml(isp)}</td>
      <td>${escapeHtml(location)}</td>
      <td>${escapeHtml(r.actionStatus?.toUpperCase() || (isListed ? "UNRESOLVED" : "N/A"))}</td>
      <td>${escapeHtml(r.notes || "")}</td>
      <td>${escapeHtml(r.timestamp || report.timestamp || "")}</td>
    </tr>`;
  };

  const tableHeader = `<tr style="background-color:#0f172a; color:#ffffff; font-weight:bold;">
    <th>Mark / Flag</th>
    <th>IP Address</th>
    <th>Status</th>
    <th>Listed Count</th>
    <th>Listed On (Blacklists)</th>
    <th>PTR / Hostname</th>
    <th>ISP / Organization</th>
    <th>Location</th>
    <th>Action Status</th>
    <th>Notes</th>
    <th>Timestamp</th>
  </tr>`;

  const html = `<!DOCTYPE html>
<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel">
<head><meta charset="utf-8" /></head>
<body style="font-family:Arial,sans-serif;">
  <table border="1" cellspacing="0" cellpadding="6" style="border-collapse:collapse; width:100%; font-size:12px;">
    <tr>
      <th colspan="11" style="background-color:#0f172a; color:#ffffff; font-size:15px; text-align:left; padding:10px;">
        SUBNET BLACKLIST AUDIT SHEET — Target: ${escapeHtml(report.target)} | Total IPs: ${results.length} | Listed: ${listedResults.length} | Clean: ${cleanResults.length}
      </th>
    </tr>
    ${results.length > 1 ? `
    <tr><td colspan="11" style="background-color:#fef2f2; color:#991b1b; font-weight:bold; padding:8px;">FLAGGED / LISTED IPs SUMMARY (${listedResults.length} Listed)</td></tr>
    ${tableHeader}
    ${listedResults.length > 0 ? listedResults.map(renderRow).join("") : `<tr><td colspan="11" style="background-color:#ecfdf5; color:#047857; font-weight:bold;">All scanned IPs are 100% clean.</td></tr>`}
    <tr><td colspan="11" style="height:12px;"></td></tr>
    <tr><td colspan="11" style="background-color:#f1f5f9; color:#0f172a; font-weight:bold; padding:8px;">COMPLETE BLOCK MATRIX (${results.length} IPs — Listed IPs Highlighted in Red)</td></tr>
    ` : ""}
    ${tableHeader}
    ${results.map(renderRow).join("")}
  </table>
</body>
</html>`;

  const sanitizedTarget = (report.target || "scan").replace(/[\/.:\s-]/g, "_");
  triggerFileDownload("\uFEFF" + html, `blacklist_sheet_${sanitizedTarget}.xls`, "application/vnd.ms-excel;charset=utf-8;");
}

// Download JSON report for SubnetScanReport
export function downloadJSONReport(report: SubnetScanReport) {
  const jsonContent = JSON.stringify(report, null, 2);
  const sanitizedTarget = (report.target || "scan").replace(/[\/.:\s-]/g, "_");
  triggerFileDownload(jsonContent, `blacklist_report_${sanitizedTarget}.json`, "application/json");
}

// Download Subnet IP Allocation Matrix CSV (with prominent [LISTED] markers & top flagged summary)
export function downloadSubnetMatrixCSV(item: MonitoredIP, ipList: any[]) {
  const listedIPs = ipList.filter(ipItem => ipItem.status === "listed" || (ipItem.listedCount || 0) > 0);
  const cleanIPs = ipList.filter(ipItem => ipItem.status !== "listed" && (ipItem.listedCount || 0) === 0);

  const headers = ["Mark / Flag", "IP Address", "Status", "Listed Count", "Listed Providers", "Timestamp"];

  const buildRow = (ipItem: any) => {
    const isListed = ipItem.status === "listed" || (ipItem.listedCount || 0) > 0;
    const mark = isListed ? "🔴 [LISTED]" : "✓ Clean";
    const statusLabel = isListed ? "LISTED - ACTION REQUIRED" : "CLEAN";
    const activeBlacklists = getListedProvidersLabel(ipItem.listings);

    return [
      mark,
      ipItem.ip,
      statusLabel,
      ipItem.listedCount || 0,
      activeBlacklists,
      new Date().toISOString()
    ];
  };

  const csvLines: string[] = [];
  csvLines.push([
    "SUBNET ALLOCATION MATRIX REPORT",
    `Target: ${item.ipOrCidr}`,
    `Label: ${item.label || "N/A"}`,
    `Total IPs: ${ipList.length}`,
    `Listed IPs: ${listedIPs.length}`,
    `Clean IPs: ${cleanIPs.length}`
  ].map(escapeCsvCell).join(","));
  csvLines.push("");

  if (ipList.length > 1) {
    csvLines.push([">>> FLAGGED / LISTED IPs SUMMARY (BLACKLISTED ONLY) <<<"].map(escapeCsvCell).join(","));
    csvLines.push(headers.map(escapeCsvCell).join(","));
    if (listedIPs.length > 0) {
      listedIPs.forEach(ipItem => {
        csvLines.push(buildRow(ipItem).map(escapeCsvCell).join(","));
      });
    } else {
      csvLines.push(["✅ [ALL CLEAN]", "No blacklisted IPs found in this block", "CLEAN", "0", "None", ""].map(escapeCsvCell).join(","));
    }
    csvLines.push("");
    csvLines.push([`>>> COMPLETE FULL BLOCK IP LIST (${ipList.length} IPs — LISTED IPs MARKED) <<<`].map(escapeCsvCell).join(","));
  }

  csvLines.push(headers.map(escapeCsvCell).join(","));
  ipList.forEach(ipItem => {
    csvLines.push(buildRow(ipItem).map(escapeCsvCell).join(","));
  });

  const csvContent = "\uFEFF" + csvLines.join("\n");
  const sanitized = (item.ipOrCidr || "subnet").replace(/[\/.:\s-]/g, "_");
  triggerFileDownload(csvContent, `subnet_matrix_${sanitized}.csv`, "text/csv;charset=utf-8;");
}

// Download Color-Highlighted Excel Sheet (.xls) for Monitored Subnet Matrix
export function downloadSubnetMatrixExcel(item: MonitoredIP, ipList: any[]) {
  const listedIPs = ipList.filter(ipItem => ipItem.status === "listed" || (ipItem.listedCount || 0) > 0);
  const cleanIPs = ipList.filter(ipItem => ipItem.status !== "listed" && (ipItem.listedCount || 0) === 0);

  const renderRow = (ipItem: any) => {
    const isListed = ipItem.status === "listed" || (ipItem.listedCount || 0) > 0;
    const rowBg = isListed ? "#fee2e2" : "#ffffff";
    const rowColor = isListed ? "#991b1b" : "#1e293b";
    const markBg = isListed ? "#dc2626" : "#ecfdf5";
    const markColor = isListed ? "#ffffff" : "#047857";
    const markText = isListed ? "LISTED [FLAGGED]" : "CLEAN";
    const activeBlacklists = getListedProvidersLabel(ipItem.listings);

    return `<tr style="background-color:${rowBg}; color:${rowColor}; ${isListed ? "font-weight:bold;" : ""}">
      <td style="background-color:${markBg}; color:${markColor}; font-weight:bold; text-align:center;">${markText}</td>
      <td style="font-family:monospace; font-weight:bold;">${escapeHtml(ipItem.ip)}</td>
      <td style="text-align:center; font-weight:bold;">${isListed ? "LISTED" : "CLEAN"}</td>
      <td style="text-align:center;">${ipItem.listedCount || 0}</td>
      <td>${escapeHtml(activeBlacklists)}</td>
      <td>${escapeHtml(new Date().toISOString())}</td>
    </tr>`;
  };

  const tableHeader = `<tr style="background-color:#0f172a; color:#ffffff; font-weight:bold;">
    <th>Mark / Flag</th>
    <th>IP Address</th>
    <th>Status</th>
    <th>Listed Count</th>
    <th>Listed Providers</th>
    <th>Timestamp</th>
  </tr>`;

  const html = `<!DOCTYPE html>
<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel">
<head><meta charset="utf-8" /></head>
<body style="font-family:Arial,sans-serif;">
  <table border="1" cellspacing="0" cellpadding="6" style="border-collapse:collapse; width:100%; font-size:12px;">
    <tr>
      <th colspan="6" style="background-color:#0f172a; color:#ffffff; font-size:15px; text-align:left; padding:10px;">
        MONITORED SUBNET SHEET — ${escapeHtml(item.ipOrCidr)} (${escapeHtml(item.label)}) | Total: ${ipList.length} | Listed: ${listedIPs.length} | Clean: ${cleanIPs.length}
      </th>
    </tr>
    ${ipList.length > 1 ? `
    <tr><td colspan="6" style="background-color:#fef2f2; color:#991b1b; font-weight:bold; padding:8px;">FLAGGED / LISTED IPs SUMMARY (${listedIPs.length} Listed)</td></tr>
    ${tableHeader}
    ${listedIPs.length > 0 ? listedIPs.map(renderRow).join("") : `<tr><td colspan="6" style="background-color:#ecfdf5; color:#047857; font-weight:bold;">No blacklisted IPs found in this subnet block.</td></tr>`}
    <tr><td colspan="6" style="height:12px;"></td></tr>
    <tr><td colspan="6" style="background-color:#f1f5f9; color:#0f172a; font-weight:bold; padding:8px;">COMPLETE SUBNET MATRIX (${ipList.length} IPs — Listed IPs Highlighted in Red)</td></tr>
    ` : ""}
    ${tableHeader}
    ${ipList.map(renderRow).join("")}
  </table>
</body>
</html>`;

  const sanitized = (item.ipOrCidr || "subnet").replace(/[\/.:\s-]/g, "_");
  triggerFileDownload("\uFEFF" + html, `subnet_sheet_${sanitized}.xls`, "application/vnd.ms-excel;charset=utf-8;");
}

// Download Daily Audit Report CSV
export function downloadDailyReportCSV(report: DailyReport) {
  const headers = ["Flagged IP", "Parent Subnet", "Parent Label", "Listed Databases", "Location / ISP", "Report Date"];
  
  const rows = (report.blacklistedIPs || []).map(bItem => {
    const dbs = Object.entries(bItem.listings || {})
      .filter(([_, v]: any) => v && v.listed)
      .map(([k, _]) => k)
      .join("; ");

    const loc = bItem.location ? `${bItem.location.city || ""}, ${bItem.location.countryCode || ""}` : "Unknown";

    return [
      bItem.ip,
      bItem.parentTarget || "N/A",
      bItem.parentLabel || "N/A",
      dbs || "None",
      loc,
      report.date
    ];
  });

  if (rows.length === 0) {
    rows.push(["None", "N/A", "N/A", "100% Clean", "N/A", report.date]);
  }

  const csvContent = "\uFEFF" + [
    headers.join(","),
    ...rows.map(row => row.map(val => `"${String(val).replace(/"/g, '""')}"`).join(","))
  ].join("\n");

  const sanitizedDate = (report.date || "audit").replace(/[\/.:\s-]/g, "_");
  triggerFileDownload(csvContent, `daily_audit_report_${sanitizedDate}.csv`, "text/csv;charset=utf-8;");
}

// Download Daily Audit Report JSON
export function downloadDailyReportJSON(report: DailyReport) {
  const jsonContent = JSON.stringify(report, null, 2);
  const sanitizedDate = (report.date || "audit").replace(/[\/.:\s-]/g, "_");
  triggerFileDownload(jsonContent, `daily_audit_report_${sanitizedDate}.json`, "application/json");
}
