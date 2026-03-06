"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import Navbar from "@/components/Navbar";
import ProtectedRoute from "@/components/ProtectedRoute";
import { getDashboardStats, listFiles } from "@/lib/api";
import { useAuth } from "@/lib/auth";

interface Stats {
  total_files: number;
  files_processed: number;
  total_pii_found: number;
  avg_risk_score: number;
}

interface FileItem {
  id: number;
  original_filename: string;
  file_type: string;
  status: string;
  uploaded_by: number;
  created_at: string;
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { cls: string; label: string }> = {
    uploaded: { cls: "badge-info", label: "Uploaded" },
    processing: { cls: "badge-warning", label: "Processing" },
    completed: { cls: "badge-success", label: "Completed" },
    failed: { cls: "badge-danger", label: "Failed" },
  };
  const s = map[status] || { cls: "badge-neutral", label: status };
  return <span className={`badge ${s.cls}`}>{s.label}</span>;
}

function StatCard({
  label,
  value,
  icon,
  color,
  delay,
}: {
  label: string;
  value: string | number;
  icon: string;
  color: string;
  delay: number;
}) {
  return (
    <div
      className="glass-card animate-fadeIn"
      style={{
        padding: 24,
        animationDelay: `${delay}ms`,
        position: "relative",
        overflow: "hidden",
      }}
    >
      <div
        style={{
          position: "absolute",
          top: -20,
          right: -20,
          width: 80,
          height: 80,
          borderRadius: "50%",
          background: color,
          opacity: 0.08,
        }}
      />
      <div
        style={{
          fontSize: "1.6rem",
          marginBottom: 8,
        }}
      >
        {icon}
      </div>
      <div
        style={{
          fontSize: "2rem",
          fontWeight: 800,
          color: "var(--text-primary)",
          lineHeight: 1,
          marginBottom: 6,
        }}
      >
        {value}
      </div>
      <div
        style={{
          fontSize: "0.8rem",
          fontWeight: 600,
          color: "var(--text-muted)",
          textTransform: "uppercase",
          letterSpacing: "0.05em",
        }}
      >
        {label}
      </div>
    </div>
  );
}

function DashboardContent() {
  const { user } = useAuth();
  const [stats, setStats] = useState<Stats | null>(null);
  const [files, setFiles] = useState<FileItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([getDashboardStats(), listFiles()])
      .then(([s, f]) => {
        setStats(s);
        setFiles(f.files || []);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div
        style={{
          display: "flex",
          justifyContent: "center",
          padding: 80,
        }}
      >
        <div className="loader" />
      </div>
    );
  }

  return (
    <div className="page-container">
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-subtitle">
            Welcome back, {user?.name}. Here&apos;s your privacy compliance overview.
          </p>
        </div>
        {user?.role === "admin" && (
          <Link href="/upload" className="btn-primary" style={{ textDecoration: "none" }}>
            ⬆ Upload File
          </Link>
        )}
      </div>

      {/* Stats Grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
          gap: 20,
          marginBottom: 40,
        }}
      >
        <StatCard
          label="Total Files"
          value={stats?.total_files ?? 0}
          icon="📁"
          color="var(--accent-primary)"
          delay={0}
        />
        <StatCard
          label="Files Processed"
          value={stats?.files_processed ?? 0}
          icon="✅"
          color="var(--success)"
          delay={100}
        />
        <StatCard
          label="PII Detected"
          value={stats?.total_pii_found ?? 0}
          icon="🔍"
          color="var(--warning)"
          delay={200}
        />
        <StatCard
          label="Avg Risk Score"
          value={stats?.avg_risk_score?.toFixed(1) ?? "0.0"}
          icon="⚠️"
          color="var(--danger)"
          delay={300}
        />
      </div>

      {/* Files Table */}
      <div className="glass-card" style={{ overflow: "hidden" }}>
        <div
          style={{
            padding: "20px 24px",
            borderBottom: "1px solid var(--border)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <h2
            style={{
              fontSize: "1.1rem",
              fontWeight: 700,
              color: "var(--text-primary)",
            }}
          >
            Recent Files
          </h2>
          <span
            style={{
              fontSize: "0.8rem",
              color: "var(--text-muted)",
            }}
          >
            {files.length} file{files.length !== 1 ? "s" : ""}
          </span>
        </div>

        {files.length === 0 ? (
          <div
            style={{
              padding: 60,
              textAlign: "center",
              color: "var(--text-muted)",
            }}
          >
            <div style={{ fontSize: "2rem", marginBottom: 12 }}>📄</div>
            <p>No files uploaded yet.</p>
            {user?.role === "admin" && (
              <Link
                href="/upload"
                className="btn-primary"
                style={{
                  marginTop: 16,
                  display: "inline-flex",
                  textDecoration: "none",
                }}
              >
                Upload your first file
              </Link>
            )}
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>File Name</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Uploaded</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {files.map((file) => (
                  <tr key={file.id}>
                    <td style={{ fontWeight: 600, color: "var(--text-primary)" }}>
                      {file.original_filename}
                    </td>
                    <td>
                      <span className="badge badge-neutral">
                        .{file.file_type}
                      </span>
                    </td>
                    <td>
                      <StatusBadge status={file.status} />
                    </td>
                    <td>
                      {new Date(file.created_at).toLocaleDateString("en-IN", {
                        day: "2-digit",
                        month: "short",
                        year: "numeric",
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </td>
                    <td>
                      <Link
                        href={`/files/${file.id}`}
                        style={{
                          color: "var(--accent-primary-light)",
                          textDecoration: "none",
                          fontWeight: 600,
                          fontSize: "0.85rem",
                        }}
                      >
                        View →
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default function DashboardPage() {
  return (
    <ProtectedRoute>
      <Navbar />
      <DashboardContent />
    </ProtectedRoute>
  );
}
