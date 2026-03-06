"use client";

import { useEffect, useState, use } from "react";
import Link from "next/link";
import Navbar from "@/components/Navbar";
import ProtectedRoute from "@/components/ProtectedRoute";
import { getVault, reverseTokens } from "@/lib/api";

interface TokenItem {
  id: number;
  token: string;
  pii_type: string;
  file_id: number;
  created_at: string;
}

function VaultContent({ fileId }: { fileId: number }) {
  const [tokens, setTokens] = useState<TokenItem[]>([]);
  const [reversed, setReversed] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [reversing, setReversing] = useState(false);
  const [showReversed, setShowReversed] = useState(false);
  const [error, setError] = useState("");
  const [searchQuery, setSearchQuery] = useState("");

  useEffect(() => {
    getVault(fileId)
      .then(setTokens)
      .catch(() => setError("Failed to load vault"))
      .finally(() => setLoading(false));
  }, [fileId]);

  const handleReverse = async () => {
    setReversing(true);
    setError("");
    try {
      const data = await reverseTokens(fileId);
      setReversed(data.mappings);
      setShowReversed(true);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Reversal failed");
    } finally {
      setReversing(false);
    }
  };

  const filteredTokens = tokens.filter((t) => {
    const query = searchQuery.toLowerCase();
    const tokenMatch = t.token.toLowerCase().includes(query);
    const typeMatch = t.pii_type.toLowerCase().includes(query);
    const originalMatch = showReversed && reversed[t.token] 
      ? reversed[t.token].toLowerCase().includes(query)
      : false;
    return tokenMatch || typeMatch || originalMatch;
  });

  const uniquePiiTypes = new Set(tokens.map((t) => t.pii_type)).size;

  if (loading) {
    return (
      <div style={{ display: "flex", justifyContent: "center", padding: 80 }}>
        <div className="loader" />
      </div>
    );
  }

  return (
    <div className="page-container" style={{ maxWidth: 1100 }}>
      {/* Header */}
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", flexWrap: "wrap", gap: 16 }}>
        <div>
          <Link
            href={`/files/${fileId}`}
            style={{
              color: "var(--text-muted)",
              textDecoration: "none",
              fontSize: "0.85rem",
              fontWeight: 600,
              marginBottom: 12,
              display: "inline-flex",
              alignItems: "center",
              gap: 4,
              transition: "color 0.2s"
            }}
            onMouseOver={(e) => e.currentTarget.style.color = "var(--text-primary)"}
            onMouseOut={(e) => e.currentTarget.style.color = "var(--text-muted)"}
          >
            ← Back to File Overview
          </Link>
          <h1 className="page-title" style={{ fontSize: "2.2rem" }}>🔑 Secure Token Vault</h1>
          <p className="page-subtitle">
            Manage encrypted token mappings for file #{fileId}
          </p>
        </div>
      </div>

      {error && (
        <div
          className="animate-fadeIn"
          style={{
            padding: "16px",
            borderRadius: "var(--radius-lg)",
            background: "rgba(239,68,68,0.1)",
            border: "1px solid rgba(239,68,68,0.3)",
            color: "var(--danger)",
            fontSize: "0.95rem",
            fontWeight: 500,
            marginBottom: 24,
            display: "flex",
            alignItems: "center",
            gap: 12
          }}
        >
          <span style={{ fontSize: "1.2rem" }}>⚠️</span>
          {error}
        </div>
      )}

      {/* Stats Dashboard */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 20, marginBottom: 32 }}>
        <div className="glass-card animate-fadeIn" style={{ padding: 24, borderLeft: "4px solid var(--accent-primary)" }}>
          <div className="input-label" style={{ marginBottom: 4 }}>Total Tokens Stored</div>
          <div style={{ fontSize: "2rem", fontWeight: 700, color: "var(--text-primary)" }}>
            {tokens.length}
          </div>
        </div>
        <div className="glass-card animate-fadeIn" style={{ padding: 24, borderLeft: "4px solid var(--accent-secondary)", animationDelay: "0.1s" }}>
          <div className="input-label" style={{ marginBottom: 4 }}>Unique PII Types</div>
          <div style={{ fontSize: "2rem", fontWeight: 700, color: "var(--text-primary)" }}>
            {uniquePiiTypes}
          </div>
        </div>
        <div className="glass-card animate-fadeIn" style={{ padding: 24, borderLeft: `4px solid ${showReversed ? "var(--warning)" : "var(--success)"}`, animationDelay: "0.2s" }}>
          <div className="input-label" style={{ marginBottom: 4 }}>Vault Status</div>
          <div style={{ fontSize: "1.4rem", fontWeight: 600, color: showReversed ? "var(--warning)" : "var(--success)", display: "flex", alignItems: "center", gap: 8, marginTop: 6 }}>
            {showReversed ? "🔓 Decrypted" : "🔒 Encrypted"}
          </div>
        </div>
      </div>

      {/* Action Bar */}
      <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "center", gap: 16, marginBottom: 24 }}>
        <button
          className={showReversed ? "btn-secondary" : "btn-primary"}
          style={{ minWidth: 220 }}
          onClick={() => {
            if (showReversed) {
              setShowReversed(false);
            } else {
              handleReverse();
            }
          }}
          disabled={reversing}
        >
          {reversing ? (
            <>
              <div className="loader" style={{ width: 16, height: 16, borderWidth: 2 }} />
              Decrypting Vault...
            </>
          ) : showReversed ? (
            <>🔒 Re-Encrypt Details</>
          ) : (
            <>🔓 Reveal Original Values</>
          )}
        </button>

        <div style={{ position: "relative", flexGrow: 1, maxWidth: 400 }}>
          <span style={{ position: "absolute", left: 14, top: "50%", transform: "translateY(-50%)", color: "var(--text-muted)" }}>
            🔍
          </span>
          <input
            type="text"
            className="input-field"
            placeholder="Search tokens, types, or values..."
            style={{ paddingLeft: 40, borderRadius: "var(--radius-lg)" }}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </div>

      {/* Tokens Table */}
      {tokens.length === 0 ? (
        <div
          className="glass-card animate-fadeIn"
          style={{ padding: "80px 40px", textAlign: "center", color: "var(--text-muted)" }}
        >
          <div style={{ fontSize: "3rem", marginBottom: 16, opacity: 0.8 }}>📭</div>
          <h3 style={{ fontSize: "1.2rem", fontWeight: 600, color: "var(--text-primary)", marginBottom: 8 }}>Empty Vault</h3>
          <p>No token mappings were found for this file.</p>
        </div>
      ) : (
        <div className="glass-card animate-slideIn">
          {filteredTokens.length === 0 ? (
             <div style={{ padding: 60, textAlign: "center", color: "var(--text-muted)" }}>
               <div style={{ fontSize: "2rem", marginBottom: 12 }}>🕵️</div>
               <p>No tokens matched your search query "{searchQuery}".</p>
             </div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th style={{ width: 60 }}>#</th>
                    <th>Encrypted Token</th>
                    <th>PII Classification</th>
                    {showReversed && <th>Original Value</th>}
                    <th>Logged At</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredTokens.map((t, idx) => (
                    <tr key={t.id} className="animate-fadeIn" style={{ animationDelay: `${idx * 0.03}s` }}>
                      <td style={{ color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: "0.85rem" }}>
                        {idx + 1}
                      </td>
                      <td>
                        <code
                          style={{
                            background: "rgba(99,102,241,0.08)",
                            color: "var(--accent-primary-light)",
                            padding: "6px 12px",
                            borderRadius: 6,
                            fontSize: "0.85rem",
                            fontWeight: 600,
                            fontFamily: "var(--font-mono)",
                            border: "1px solid rgba(99,102,241,0.2)"
                          }}
                        >
                          {t.token}
                        </code>
                      </td>
                      <td>
                        <span className="badge badge-neutral" style={{ letterSpacing: "0.02em" }}>{t.pii_type}</span>
                      </td>
                      {showReversed && (
                        <td
                          style={{
                            fontWeight: 600,
                            color: "var(--warning)",
                            fontFamily: "var(--font-mono)",
                            fontSize: "0.9rem",
                            background: "rgba(245, 158, 11, 0.03)"
                          }}
                        >
                          {reversed[t.token] || "—"}
                        </td>
                      )}
                      <td style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
                        {new Date(t.created_at).toLocaleDateString("en-IN", {
                          day: "2-digit",
                          month: "short",
                          hour: "2-digit",
                          minute: "2-digit",
                        })}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function VaultPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return (
    <ProtectedRoute adminOnly>
      <Navbar />
      <VaultContent fileId={parseInt(id)} />
    </ProtectedRoute>
  );
}
