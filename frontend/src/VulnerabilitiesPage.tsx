import { useEffect, useMemo, useState } from 'react'
import type { Vulnerability } from './types'
import { getAnalysis } from './api'
import './VulnerabilitiesPage.css'

type SortKey = 'package' | 'cve_id' | 'cvss' | 'epss' | 'kev' | 'severity'
type SortDir = 'asc' | 'desc'

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
}

function severityTier(v: Vulnerability): string {
  if (v.severity) return v.severity
  if (v.cvss == null) return 'unknown'
  if (v.cvss >= 9) return 'critical'
  if (v.cvss >= 7) return 'high'
  if (v.cvss >= 4) return 'medium'
  return 'low'
}

function compare(a: Vulnerability, b: Vulnerability, key: SortKey): number {
  switch (key) {
    case 'package':
      return a.package.localeCompare(b.package)
    case 'cve_id':
      return a.cve_id.localeCompare(b.cve_id)
    case 'cvss':
      return (a.cvss ?? -1) - (b.cvss ?? -1)
    case 'epss':
      return (a.epss ?? -1) - (b.epss ?? -1)
    case 'kev':
      return Number(a.kev) - Number(b.kev)
    case 'severity':
      return (SEVERITY_RANK[severityTier(a)] ?? 0) - (SEVERITY_RANK[severityTier(b)] ?? 0)
  }
}

interface Props {
  projectId: string
}

export default function VulnerabilitiesPage({ projectId }: Props) {
  const [vulns, setVulns] = useState<Vulnerability[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  // Default: highest real-world risk first. CVSS desc until bridge-centrality
  // ("connections") lands with the graph layer.
  const [sortKey, setSortKey] = useState<SortKey>('cvss')
  const [sortDir, setSortDir] = useState<SortDir>('desc')

  useEffect(() => {
    if (!projectId) {
      setLoading(false)
      return
    }
    setLoading(true)
    setError(null)
    getAnalysis(projectId)
      .then((data) => setVulns(data.vulnerabilities))
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [projectId])

  const sorted = useMemo(() => {
    const list = [...vulns].sort((a, b) => compare(a, b, sortKey))
    return sortDir === 'asc' ? list : list.reverse()
  }, [vulns, sortKey, sortDir])

  function toggleSort(key: SortKey) {
    if (key === sortKey) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortKey(key)
      setSortDir('desc')
    }
  }

  function arrow(key: SortKey) {
    if (key !== sortKey) return ''
    return sortDir === 'asc' ? ' ▲' : ' ▼'
  }

  if (loading) return <div className="vulns-state">Loading vulnerabilities…</div>
  if (error) return <div className="vulns-state vulns-error">{error}</div>
  if (!vulns.length)
    return <div className="vulns-state">No known vulnerabilities found. 🎉</div>

  return (
    <div className="vulns-page">
      <div className="vulns-header">
        <h2>Vulnerabilities</h2>
        <span className="vulns-count">{vulns.length} confirmed CVEs</span>
      </div>

      <table className="vulns-table">
        <thead>
          <tr>
            <th onClick={() => toggleSort('package')}>Package{arrow('package')}</th>
            <th>Version</th>
            <th onClick={() => toggleSort('cve_id')}>CVE{arrow('cve_id')}</th>
            <th onClick={() => toggleSort('cvss')} className="num">CVSS{arrow('cvss')}</th>
            <th onClick={() => toggleSort('epss')} className="num">EPSS{arrow('epss')}</th>
            <th onClick={() => toggleSort('kev')}>KEV{arrow('kev')}</th>
            <th onClick={() => toggleSort('severity')}>Severity{arrow('severity')}</th>
            <th>Fixed in</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((v) => {
            const tier = severityTier(v)
            return (
              <tr key={`${v.cve_id}-${v.package}-${v.version}`}>
                <td className="mono">{v.package}</td>
                <td className="mono dim">{v.version}</td>
                <td>
                  {v.osv_url ? (
                    <a href={v.osv_url} target="_blank" rel="noreferrer" className="mono">
                      {v.cve_id}
                    </a>
                  ) : (
                    <span className="mono">{v.cve_id}</span>
                  )}
                </td>
                <td className="num">{v.cvss != null ? v.cvss.toFixed(1) : '—'}</td>
                <td className="num">
                  {v.epss != null ? `${(v.epss * 100).toFixed(1)}%` : '—'}
                </td>
                <td>{v.kev ? <span className="badge badge-kev">KEV</span> : ''}</td>
                <td>
                  <span className={`badge badge-${tier}`}>{tier}</span>
                </td>
                <td className="mono dim">{v.fixed_version ?? '—'}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
