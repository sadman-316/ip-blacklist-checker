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

// Download CSV report for SubnetScanReport
export function downloadCSVReport(report: SubnetScanReport) {
  const headers = ["IP Address", "Status", "Listed Count", "ISP", "Location", "Listed On", "Action Status", "Notes", "Timestamp"];
  
  const rows = report.results.map(r => {
    const activeBlacklists = Object.entries(r.listings || {})
      .filter(([_, value]) => value && value.listed)
      .map(([key, _]) => key)
      .join("; ");

    return [
      r.ip,
      (r.status || "clean").toUpperCase(),
      r.listedCount || 0,
      r.location?.isp || "Unknown",
      r.location?.country ? `${r.location.city || ""}, ${r.location.country}` : "Unknown",
      activeBlacklists || "None",
      r.actionStatus?.toUpperCase() || "N/A",
      r.notes || "",
      r.timestamp || new Date().toISOString()
    ];
  });

  const csvContent = "\uFEFF" + [
    headers.join(","),
    ...rows.map(row => row.map(val => `"${String(val).replace(/"/g, '""')}"`).join(","))
  ].join("\n");

  const sanitizedTarget = (report.target || "scan").replace(/[\/.:\s-]/g, "_");
  triggerFileDownload(csvContent, `blacklist_report_${sanitizedTarget}.csv`, "text/csv;charset=utf-8;");
}

// Download JSON report for SubnetScanReport
export function downloadJSONReport(report: SubnetScanReport) {
  const jsonContent = JSON.stringify(report, null, 2);
  const sanitizedTarget = (report.target || "scan").replace(/[\/.:\s-]/g, "_");
  triggerFileDownload(jsonContent, `blacklist_report_${sanitizedTarget}.json`, "application/json");
}

// Download Subnet IP Allocation Matrix CSV
export function downloadSubnetMatrixCSV(item: MonitoredIP, ipList: any[]) {
  const headers = ["IP Address", "Status", "Listed Count", "Listed Providers", "Timestamp"];
  
  const rows = ipList.map(ipItem => {
    const activeBlacklists = Object.entries(ipItem.listings || {})
      .filter(([_, value]: any) => value && value.listed)
      .map(([key, _]) => key)
      .join("; ");

    return [
      ipItem.ip,
      (ipItem.status || "clean").toUpperCase(),
      ipItem.listedCount || 0,
      activeBlacklists || "None",
      new Date().toISOString()
    ];
  });

  const csvContent = "\uFEFF" + [
    headers.join(","),
    ...rows.map(row => row.map(val => `"${String(val).replace(/"/g, '""')}"`).join(","))
  ].join("\n");

  const sanitized = (item.ipOrCidr || "subnet").replace(/[\/.:\s-]/g, "_");
  triggerFileDownload(csvContent, `subnet_matrix_${sanitized}.csv`, "text/csv;charset=utf-8;");
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

