import { useEffect, useState } from 'react'
import { api } from '../api/client'

export default function Plugins() {
  const [plugins, setPlugins] = useState([])
  const [loading, setLoading] = useState(true)
  const [reloading, setReloading] = useState(false)

  function load() {
    setLoading(true)
    api.plugins.list()
      .then(r => setPlugins(r.plugins || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(load, [])

  async function reload() {
    setReloading(true)
    try {
      const r = await api.plugins.reload()
      setPlugins(r.plugins || [])
    } catch (e) {
      alert('Reload failed: ' + e.message)
    } finally {
      setReloading(false)
    }
  }

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-base font-bold text-gray-100">Plugins</h1>
          <p className="text-xs text-gray-500 mt-0.5">
            Loaded from <code className="text-gray-600">/app/plugins</code>
          </p>
        </div>
        <button onClick={reload} disabled={reloading} className="btn-primary text-xs">
          {reloading ? 'Reloading...' : 'Reload All'}
        </button>
      </div>

      {/* How to add a plugin */}
      <div className="card p-4 mb-6 border-indigo-800/50 bg-indigo-950/20">
        <h2 className="text-xs font-semibold text-indigo-300 mb-2">How to add a plugin</h2>
        <ol className="text-xs text-gray-400 space-y-1 list-decimal list-inside">
          <li>Create a Python file that imports and subclasses <code className="text-indigo-400">BasePlugin</code></li>
          <li>Set <code className="text-indigo-400">PLUGIN_NAME</code>, <code className="text-indigo-400">SUPPORTED_EXTENSIONS</code>, and implement <code className="text-indigo-400">parse()</code></li>
          <li>Copy your file into the plugins volume: <code className="text-gray-500">kubectl cp myplugin.py processor-pod:/app/plugins/myplugin/myplugin_plugin.py</code></li>
          <li>Click "Reload All" above</li>
        </ol>
      </div>

      {loading ? (
        <div className="text-gray-500 text-sm">Loading plugins...</div>
      ) : plugins.length === 0 ? (
        <div className="card p-8 text-center text-gray-500 text-sm">No plugins loaded.</div>
      ) : (
        <div className="space-y-3">
          {plugins.map(p => (
            <div key={p.name} className="card p-4">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-sm font-semibold text-gray-100">{p.name}</h2>
                    <span className="badge bg-gray-700 text-gray-400">v{p.version}</span>
                    <span className="badge bg-green-900/40 text-green-400">active</span>
                  </div>
                  <p className="text-xs text-gray-500 mt-1">
                    Artifact type: <code className="text-indigo-400">{p.default_artifact_type}</code>
                  </p>
                </div>
                <div className="text-right">
                  <div className="flex flex-wrap gap-1 justify-end">
                    {p.supported_extensions?.map(ext => (
                      <span key={ext} className="badge bg-gray-700 text-gray-300 font-mono">{ext}</span>
                    ))}
                    {p.handled_filenames?.map(fn => (
                      <span key={fn} className="badge bg-gray-700 text-gray-300 font-mono">{fn}</span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
