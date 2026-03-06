"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import Navbar from "@/components/Navbar";
import ProtectedRoute from "@/components/ProtectedRoute";
import { getAuditLogs } from "@/lib/api";

interface AuditEntry {
  id: number;
  user_id: number;
  user_email: string;
  action: string;
  resource_type: string;
  resource_id: number | null;
  details: string | null;
  ip_address: string | null;
  created_at: string;
}

const ACTION_COLORS: Record<string, string> = {
  upload: "badge-info",
  mask: "badge-success",
  download: "badge-neutral",
  vault_access: "badge-warning",
  reverse_tokens: "badge-danger",
};

const ACTION_ICONS: Record<string, string> = {
  upload: "⬆",
  mask: "🔒",
  download: "⬇",
  vault_access: "🔑",
  reverse_tokens: "🔓",
};

function AuditContent() {
  const [logs, setLogs] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");

  useEffect(() => {
    getAuditLogs()
      .then(setLogs)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const filtered = filter
    ? logs.filter(
        (l) =>
          l.action === filter ||
          l.user_email.toLowerCase().includes(filter.toLowerCase())
      )
    : logs;

  if (loading) {
    return (
      <div style={{ display: "flex", justifyContent: "center", padding: 80 }}>
        <div className="loader" />
      </div>
    );
  }

  return (
    <div className="page-container" style={{ maxWidth: 1100 }}>
      <div className="page-header">
        <Link
          href="/dashboard"
          style={{
            color: "var(--text-muted)",
            textDecoration: "none",
            fontSize: "0.85rem",
            fontWeight: 600,
            marginBottom: 12,
            display: "inline-flex",
            alignItems: "center",
            gap: 4,
          }}
        >
          ← Back to Dashboard
        </Link>
        <h1 className="page-title">📋 Audit Logs</h1>
        <p className="page-subtitle">
          Security audit trail — {logs.length} event{logs.length !== 1 ? "s" : ""} recorded.
        </p>
      </div>

      {/* Filters */}
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: 8,
          marginBottom: 24,
        }}
      >
        {["", "upload", "mask", "download", "vault_access", "reverse_tokens"].map(
          (action) => (
            <button
              key={action}
              className={filter === action ? "btn-primary" : "btn-secondary"}
              style={{ fontSize: "0.8rem", padding: "6px 14px" }}
              onClick={() => setFilter(action)}
            >
              {action
                ? `${ACTION_ICONS[action] || ""} ${action.replace(/_/g, " ")}`
                : "All"}
            </button>
          )
        )}
      </div>

      {/* Logs Table */}
      {filtered.length === 0 ? (
        <div
          className="glass-card"
          style={{ padding: 60, textAlign: "center", color: "var(--text-muted)" }}
        >
          <div style={{ fontSize: "2rem", marginBottom: 12 }}>📋</div>
          <p>No audit log entries found.</p>
        </div>
      ) : (
        <div className="glass-card" style={{ overflow: "hidden" }}>
          <div style={{ overflowX: "auto" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Timestamp</th>
                  <th>User</th>
                  <th>Action</th>
                  <th>Resource</th>
                  <th>IP</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((log) => {
                  let parsedDetails: Record<string, unknown> | null = null;
                  try {
                    if (log.details) parsedDetails = JSON.parse(log.details);
                  } catch {
                    /* ignore */
                  }

                  return (
                    <tr key={log.id}>
                      <td
                        style={{
                          color: "var(--text-muted)",
                          fontFamily: "var(--font-mono)",
                          fontSize: "0.8rem",
                        }}
                      >
                        {log.id}
                      </td>
                      <td style={{ fontSize: "0.8rem", whiteSpace: "nowrap" }}>
                        {new Date(log.created_at).toLocaleDateString("en-IN", {
                          day: "2-digit",
                          month: "short",
                          year: "numeric",
                          hour: "2-digit",
                          minute: "2-digit",
                          second: "2-digit",
                        })}
                      </td>
                      <td style={{ fontSize: "0.85rem", fontWeight: 600 }}>
                        {log.user_email}
                      </td>
                      <td>
                        <span
                          className={`badge ${ACTION_COLORS[log.action] || "badge-neutral"}`}
                        >
                          {ACTION_ICONS[log.action] || ""}{" "}
                          {log.action.replace(/_/g, " ")}
                        </span>
                      </td>
                      <td>
                        {log.resource_id ? (
                          <Link
                            href={`/files/${log.resource_id}`}
                            style={{
                              color: "var(--accent-primary-light)",
                              textDecoration: "none",
                              fontWeight: 600,
                              fontSize: "0.85rem",
                            }}
                          >
                            {log.resource_type} #{log.resource_id}
                          </Link>
                        ) : (
                          <span style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>
                            {log.resource_type}
                          </span>
                        )}
                      </td>
                      <td
                        style={{
                          fontSize: "0.8rem",
                          fontFamily: "var(--font-mono)",
                          color: "var(--text-muted)",
                        }}
                      >
                        {log.ip_address || "—"}
                      </td>
                      <td style={{ fontSize: "0.8rem", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis" }}>
                        {parsedDetails
                          ? Object.entries(parsedDetails)
                              .map(([k, v]) => `${k}: ${v}`)
                              .join(", ")
                          : "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export default function AuditPage() {
  return (
    <ProtectedRoute adminOnly>
      <Navbar />
      <AuditContent />
    </ProtectedRoute>
  );
}
