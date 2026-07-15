import { IPScanResult, SubnetScanReport } from "./types";

// Download CSV report
export function downloadCSVReport(report: SubnetScanReport) {
  const headers = ["IP Address", "Status", "Listed Count", "ISP", "Location", "Listed On", "Action Status", "Notes", "Timestamp"];
  
  const rows = report.results.map(r => {
    const activeBlacklists = Object.entries(r.listings)
      .filter(([_, value]) => value.listed)
      .map(([key, _]) => key)
      .join("; ");

    return [
      r.ip,
      r.status.toUpperCase(),
      r.listedCount,
      r.location?.isp || "Unknown",
      r.location?.country ? `${r.location.city}, ${r.location.country}` : "Unknown",
      activeBlacklists || "None",
      r.actionStatus?.toUpperCase() || "N/A",
      r.notes || "",
      r.timestamp
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
  link.setAttribute("download", `blacklist_report_${report.target.replace(/[\/.-]/g, "_")}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

// Download JSON report
export function downloadJSONReport(report: SubnetScanReport) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.setAttribute("href", url);
  link.setAttribute("download", `blacklist_report_${report.target.replace(/[\/.-]/g, "_")}.json`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}
