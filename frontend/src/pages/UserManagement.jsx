import { useState, useEffect } from 'react'
import { Users, Plus, Trash2, Pencil, Key, Shield, ShieldCheck, Loader2, Check, X, UserCircle, AlertTriangle } from 'lucide-react'
import { api } from '../api/client'

/* ── Helpers ──────────────────────────────────────────────────────────────── */

function currentUser() {
  try { return JSON.parse(localStorage.getItem('fo_user')) } catch { return null }
}

function fmtDate(iso) {
  if (!iso) return '-'
  return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

/* ── Modal shell ──────────────────────────────────────────────────────────── */

function Modal({ open, onClose, title, children }) {
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30" onClick={onClose}>
      <div className="card p-5 w-full max-w-md mx-4 space-y-4" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-brand-text">{title}</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600"><X size={16} /></button>
        </div>
        {children}
      </div>
    </div>
  )
}

/* ── Role badge ───────────────────────────────────────────────────────────── */

function RoleBadge({ role }) {
  if (role === 'admin') {
    return (
      <span className="badge bg-purple-100 text-purple-700 gap-1">
        <ShieldCheck size={11} /> admin
      </span>
    )
  }
  return (
    <span className="badge bg-blue-100 text-blue-700 gap-1">
      <Shield size={11} /> analyst
    </span>
  )
}

/* ══════════════════════════════════════════════════════════════════════════ */

export default function UserManagement() {
  const me = currentUser()

  /* ── State ── */
  const [users, setUsers]       = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState('')

  // Create user
  const [showCreate, setShowCreate]   = useState(false)
  const [createForm, setCreateForm]   = useState({ username: '', password: '', role: 'analyst' })
  const [creating, setCreating]       = useState(false)
  const [createErr, setCreateErr]     = useState('')

  // Edit role
  const [editTarget, setEditTarget]     = useState(null) // { username, role }
  const [editRole, setEditRole]         = useState('analyst')
  const [editingSave, setEditingSave]   = useState(false)
  const [editErr, setEditErr]           = useState('')

  // Reset password
  const [resetTarget, setResetTarget]     = useState(null) // username
  const [resetPw, setResetPw]             = useState('')
  const [resetting, setResetting]         = useState(false)
  const [resetErr, setResetErr]           = useState('')

  // Change own password
  const [ownPw, setOwnPw]         = useState({ old_password: '', new_password: '', confirm: '' })
  const [changingPw, setChangingPw] = useState(false)
  const [pwMsg, setPwMsg]           = useState({ ok: false, text: '' })

  /* ── Load users ── */
  useEffect(() => {
    if (me?.role !== 'admin') { setLoading(false); return }
    loadUsers()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  async function loadUsers() {
    setLoading(true)
    setError('')
    try {
      const data = await api.auth.listUsers()
      setUsers(data.users || [])
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  /* ── Create user ── */
  async function handleCreate(e) {
    e.preventDefault()
    setCreating(true)
    setCreateErr('')
    try {
      await api.auth.createUser(createForm)
      setShowCreate(false)
      setCreateForm({ username: '', password: '', role: 'analyst' })
      await loadUsers()
    } catch (err) {
      setCreateErr(err.message)
    } finally {
      setCreating(false)
    }
  }

  /* ── Edit role ── */
  function openEditRole(u) {
    setEditTarget(u)
    setEditRole(u.role)
    setEditErr('')
  }

  async function handleEditRole(e) {
    e.preventDefault()
    setEditingSave(true)
    setEditErr('')
    try {
      await api.auth.updateUser(editTarget.username, { role: editRole })
      setEditTarget(null)
      await loadUsers()
    } catch (err) {
      setEditErr(err.message)
    } finally {
      setEditingSave(false)
    }
  }

  /* ── Reset password ── */
  async function handleResetPw(e) {
    e.preventDefault()
    setResetting(true)
    setResetErr('')
    try {
      await api.auth.updateUser(resetTarget, { password: resetPw })
      setResetTarget(null)
      setResetPw('')
    } catch (err) {
      setResetErr(err.message)
    } finally {
      setResetting(false)
    }
  }

  /* ── Delete user ── */
  async function handleDelete(username) {
    if (!confirm(`Delete user "${username}"? This cannot be undone.`)) return
    try {
      await api.auth.deleteUser(username)
      await loadUsers()
    } catch (err) {
      setError(err.message)
    }
  }

  /* ── Change own password ── */
  async function handleChangePw(e) {
    e.preventDefault()
    if (ownPw.new_password !== ownPw.confirm) {
      setPwMsg({ ok: false, text: 'New passwords do not match.' })
      return
    }
    setChangingPw(true)
    setPwMsg({ ok: false, text: '' })
    try {
      await api.auth.changePassword({
        old_password: ownPw.old_password,
        new_password: ownPw.new_password,
      })
      setOwnPw({ old_password: '', new_password: '', confirm: '' })
      setPwMsg({ ok: true, text: 'Password changed successfully.' })
      setTimeout(() => setPwMsg({ ok: false, text: '' }), 4000)
    } catch (err) {
      setPwMsg({ ok: false, text: err.message })
    } finally {
      setChangingPw(false)
    }
  }

  /* ── Access gate ── */
  if (me?.role !== 'admin') {
    return (
      <div className="p-6 max-w-2xl mx-auto">
        <div className="card p-8 flex flex-col items-center gap-3 text-center">
          <AlertTriangle size={28} className="text-amber-500" />
          <h2 className="font-semibold text-brand-text">Admin access required</h2>
          <p className="text-sm text-gray-500">
            You must be an administrator to manage users. Contact your admin if you need elevated permissions.
          </p>
        </div>

        {/* Non-admins can still change their own password */}
        <section className="card p-5 space-y-4 mt-6">
          <div className="flex items-center gap-2">
            <Key size={15} className="text-amber-500" />
            <h2 className="font-semibold text-brand-text">Change My Password</h2>
          </div>
          {renderChangePasswordForm()}
        </section>
      </div>
    )
  }

  /* ── Render helpers ── */
  function renderChangePasswordForm() {
    return (
      <form onSubmit={handleChangePw} className="space-y-3">
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Current Password</label>
          <input
            type="password"
            className="input text-xs"
            placeholder="Enter current password"
            value={ownPw.old_password}
            onChange={e => setOwnPw(f => ({ ...f, old_password: e.target.value }))}
            required
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">
            New Password <span className="text-gray-400 font-normal">(min. 8 characters)</span>
          </label>
          <input
            type="password"
            className="input text-xs"
            placeholder="Enter new password (min. 8 characters)"
            value={ownPw.new_password}
            onChange={e => setOwnPw(f => ({ ...f, new_password: e.target.value }))}
            minLength={8}
            required
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Confirm New Password</label>
          <input
            type="password"
            className="input text-xs"
            placeholder="Confirm new password"
            value={ownPw.confirm}
            onChange={e => setOwnPw(f => ({ ...f, confirm: e.target.value }))}
            required
          />
        </div>

        {pwMsg.text && (
          <p className={`text-xs rounded-lg px-3 py-2 flex items-center gap-1.5 ${
            pwMsg.ok
              ? 'text-green-700 bg-green-50 border border-green-200'
              : 'text-red-600 bg-red-50 border border-red-200'
          }`}>
            {pwMsg.ok ? <Check size={12} /> : <X size={12} />} {pwMsg.text}
          </p>
        )}

        <button type="submit" disabled={changingPw} className="btn-primary text-xs">
          {changingPw ? <Loader2 size={13} className="animate-spin" /> : <Key size={13} />}
          Change Password
        </button>
      </form>
    )
  }

  /* ── Main render ── */
  return (
    <div className="p-6 max-w-4xl mx-auto">

      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-2.5 mb-1">
          <Users size={20} className="text-brand-accent" />
          <h1 className="text-xl font-bold text-brand-text">User Management</h1>
        </div>
        <p className="text-sm text-gray-500">Create, edit, and remove platform users.</p>
      </div>

      {/* User list */}
      <section className="card">
        <div className="flex items-center justify-between px-5 py-3 border-b border-gray-100">
          <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">Users</span>
          <button onClick={() => { setShowCreate(true); setCreateErr('') }} className="btn-primary text-xs">
            <Plus size={13} /> New User
          </button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center gap-2 text-gray-400 py-12">
            <Loader2 size={14} className="animate-spin" /> Loading users...
          </div>
        ) : error ? (
          <div className="text-xs text-red-600 bg-red-50 border-t border-red-100 px-5 py-4 flex items-center gap-1.5">
            <AlertTriangle size={12} /> {error}
          </div>
        ) : users.length === 0 ? (
          <div className="text-sm text-gray-400 text-center py-12">No users found.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-100">
                  <th className="px-5 py-2.5 font-medium">Username</th>
                  <th className="px-5 py-2.5 font-medium">Role</th>
                  <th className="px-5 py-2.5 font-medium">Created</th>
                  <th className="px-5 py-2.5 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {users.map(u => (
                  <tr key={u.username} className="hover:bg-gray-50/50 transition-colors">
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2">
                        <UserCircle size={16} className="text-gray-400" />
                        <span className="font-medium text-brand-text">{u.username}</span>
                        {u.username === me?.username && (
                          <span className="text-[10px] text-gray-400 bg-gray-100 rounded-full px-1.5 py-0.5">you</span>
                        )}
                      </div>
                    </td>
                    <td className="px-5 py-3"><RoleBadge role={u.role} /></td>
                    <td className="px-5 py-3 text-gray-500 text-xs">{fmtDate(u.created_at)}</td>
                    <td className="px-5 py-3">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => openEditRole(u)}
                          className="btn-ghost text-xs py-1 px-2"
                          title="Edit role"
                        >
                          <Pencil size={12} />
                        </button>
                        <button
                          onClick={() => { setResetTarget(u.username); setResetPw(''); setResetErr('') }}
                          className="btn-ghost text-xs py-1 px-2"
                          title="Reset password"
                        >
                          <Key size={12} />
                        </button>
                        <button
                          onClick={() => handleDelete(u.username)}
                          disabled={u.username === me?.username}
                          className="btn-ghost text-xs py-1 px-2 text-red-500 hover:text-red-700 disabled:opacity-30"
                          title={u.username === me?.username ? 'Cannot delete yourself' : 'Delete user'}
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Change own password */}
      <section className="card p-5 space-y-4 mt-6">
        <div className="flex items-center gap-2">
          <Key size={15} className="text-amber-500" />
          <h2 className="font-semibold text-brand-text">Change My Password</h2>
        </div>
        <p className="text-xs text-gray-500">Update your own account password.</p>
        {renderChangePasswordForm()}
      </section>

      {/* ── Create User Modal ── */}
      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Create User">
        <form onSubmit={handleCreate} className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Username</label>
            <input
              className="input text-xs"
              placeholder="e.g. jdoe"
              value={createForm.username}
              onChange={e => setCreateForm(f => ({ ...f, username: e.target.value }))}
              required
              autoFocus
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Password</label>
            <input
              type="password"
              className="input text-xs"
              placeholder="Temporary password"
              value={createForm.password}
              onChange={e => setCreateForm(f => ({ ...f, password: e.target.value }))}
              required
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Role</label>
            <select
              className="input text-xs"
              value={createForm.role}
              onChange={e => setCreateForm(f => ({ ...f, role: e.target.value }))}
            >
              <option value="analyst">Analyst</option>
              <option value="admin">Admin</option>
            </select>
          </div>

          {createErr && (
            <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
              <AlertTriangle size={12} /> {createErr}
            </p>
          )}

          <div className="flex items-center gap-2 pt-1">
            <button type="submit" disabled={creating} className="btn-primary text-xs">
              {creating ? <Loader2 size={13} className="animate-spin" /> : <Plus size={13} />}
              Create User
            </button>
            <button type="button" onClick={() => setShowCreate(false)} className="btn-ghost text-xs">
              Cancel
            </button>
          </div>
        </form>
      </Modal>

      {/* ── Edit Role Modal ── */}
      <Modal open={!!editTarget} onClose={() => setEditTarget(null)} title={`Edit Role — ${editTarget?.username}`}>
        <form onSubmit={handleEditRole} className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Role</label>
            <select
              className="input text-xs"
              value={editRole}
              onChange={e => setEditRole(e.target.value)}
            >
              <option value="analyst">Analyst</option>
              <option value="admin">Admin</option>
            </select>
          </div>

          {editErr && (
            <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
              <AlertTriangle size={12} /> {editErr}
            </p>
          )}

          <div className="flex items-center gap-2 pt-1">
            <button type="submit" disabled={editingSave} className="btn-primary text-xs">
              {editingSave ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
              Save
            </button>
            <button type="button" onClick={() => setEditTarget(null)} className="btn-ghost text-xs">
              Cancel
            </button>
          </div>
        </form>
      </Modal>

      {/* ── Reset Password Modal ── */}
      <Modal open={!!resetTarget} onClose={() => setResetTarget(null)} title={`Reset Password — ${resetTarget}`}>
        <form onSubmit={handleResetPw} className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">New Password</label>
            <input
              type="password"
              className="input text-xs"
              placeholder="Enter new password"
              value={resetPw}
              onChange={e => setResetPw(e.target.value)}
              required
              autoFocus
            />
          </div>

          {resetErr && (
            <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
              <AlertTriangle size={12} /> {resetErr}
            </p>
          )}

          <div className="flex items-center gap-2 pt-1">
            <button type="submit" disabled={resetting} className="btn-primary text-xs">
              {resetting ? <Loader2 size={13} className="animate-spin" /> : <Key size={13} />}
              Reset Password
            </button>
            <button type="button" onClick={() => setResetTarget(null)} className="btn-ghost text-xs">
              Cancel
            </button>
          </div>
        </form>
      </Modal>
    </div>
  )
}
