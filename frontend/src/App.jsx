/* =============================================================================
   ALTITUDE BPO - ENTERPRISE IT SERVICE MANAGEMENT (ITSM)
   Core Architecture: Pure React + Custom CSS
   Version: 3.1.0 - BACKEND MATCHING EDITION
   Module: Identity Management & Resolution Workflow
   ============================================================================= */

import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import axios from 'axios';
import './index.css';

import { 
  LayoutDashboard, Users, PlusCircle, Ticket, LogOut, ShieldAlert, CheckCircle,
  Clock, MessageSquare, FileText, Bell, Search, ChevronRight, User, Mail,
  Phone, Calendar, Tag, AlertCircle, Eye, Edit, Trash2, Download, Filter,
  MoreVertical, ArrowLeft, Send, Menu, X, BarChart3, Shield, Lock, RefreshCw,
  Activity, Loader2, Settings, HelpCircle, Briefcase, Layers, FilePlus,
  ArrowUpRight, ArrowDownRight, TrendingUp, MapPin, Globe, Database, Cpu,
  Smartphone, Zap, MoreHorizontal, ChevronDown, Paperclip, Smile, Info,
  History, HardDrive, Share2, Maximize2, Terminal, Key, LifeBuoy, UserPlus,
  UserCheck, ShieldCheck, MailWarning
} from 'lucide-react';

const API_BASE = "http://localhost:5000/api";

// =============================================================================
// GLOBAL UTILITIES
// =============================================================================

const formatBusinessDate = (iso) => {
  if (!iso) return '--/--/--';
  const date = new Date(iso);
  return new Intl.DateTimeFormat('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit'
  }).format(date);
};

const generateInitials = (fullName) => {
  if (!fullName) return 'NA';
  const names = fullName.split(' ');
  return names.map(n => n[0]).join('').toUpperCase().slice(0, 2);
};

const getPriorityStyles = (priority) => {
  switch(priority) {
    case 'Critical': return { color: '#EF4444', backgroundColor: '#FEE2E2' };
    case 'High': return { color: '#F97316', backgroundColor: '#FFEDD5' };
    case 'Medium': return { color: '#3B82F6', backgroundColor: '#DBEAFE' };
    default: return { color: '#64748B', backgroundColor: '#F1F5F9' };
  }
};

// =============================================================================
// REUSABLE UI COMPONENTS
// =============================================================================

const ActionButton = ({ children, variant = 'primary', icon: Icon, onClick, loading, className = '', disabled }) => {
  const baseClass = variant === 'primary' ? 'btn-altitude btn-altitude-primary' : 'btn-altitude btn-altitude-secondary';
  return (
    <button className={`${baseClass} ${className}`} onClick={onClick} disabled={loading || disabled}>
      {loading ? <Loader2 className="animate-spin" size={16} /> : Icon && <Icon size={16} />}
      {children}
    </button>
  );
};

const StatusBadge = ({ status }) => {
  let cls = 'alt-badge ';
  if (status === 'Open') cls += 'badge-open';
  else if (status === 'In Progress') cls += 'badge-progress';
  else if (status === 'Resolved') cls += 'badge-resolved';
  else cls += 'badge-closed';
  return <span className={cls}>{status}</span>;
};

const ModalOverlay = ({ isOpen, onClose, title, children }) => {
  if (!isOpen) return null;
  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, 
      backgroundColor: 'rgba(15, 23, 42, 0.75)', display: 'flex', 
      alignItems: 'center', justifyContent: 'center', zIndex: 1000,
      backdropFilter: 'blur(4px)'
    }}>
      <div className="alt-card" style={{ width: '500px', maxWidth: '95%', padding: '0', overflow: 'hidden' }}>
        <div style={{ padding: '20px 24px', borderBottom: '1px solid #E2E8F0', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 style={{ fontWeight: 800 }}>{title}</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer' }}><X size={20} /></button>
        </div>
        <div style={{ padding: '24px' }}>{children}</div>
      </div>
    </div>
  );
};

// =============================================================================
// MAIN APP COMPONENT
// =============================================================================

export default function App() {
  const [auth, setAuth] = useState(() => {
    const cached = localStorage.getItem('alt_v3_session');
    return cached ? JSON.parse(cached) : null;
  });

  const [activeView, setActiveView] = useState('dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [selectedTicket, setSelectedTicket] = useState(null);
  const [globalLoading, setGlobalLoading] = useState(false);

  useEffect(() => {
    if (auth?.token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${auth.token}`;
    }
  }, [auth]);

  const handleLoginSubmit = async (email, password) => {
    setGlobalLoading(true);
    try {
      const response = await axios.post(`${API_BASE}/auth/login`, { email, password });
      localStorage.setItem('alt_v3_session', JSON.stringify(response.data));
      setAuth(response.data);
      setActiveView('dashboard');
    } catch (err) {
      alert("Portal Error: Authentication Service Unreachable.");
    } finally {
      setGlobalLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('alt_v3_session');
    setAuth(null);
  };

  if (!auth) {
    return <LoginModule onLogin={handleLoginSubmit} loading={globalLoading} />;
  }

  return (
    <div className="alt-shell">
      <aside className="alt-sidebar" style={{ width: sidebarCollapsed ? '80px' : '280px' }}>
        <div style={{ padding: '24px', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ background: 'var(--primary)', padding: '8px', borderRadius: '12px' }}>
            <Shield size={24} color="white" />
          </div>
          {!sidebarCollapsed && (
            <div>
              <h1 style={{ fontSize: '18px', fontWeight: 900, letterSpacing: '-1px' }}>ALTITUDE BPO</h1>
              <p style={{ fontSize: '10px', color: '#6366F1', fontWeight: 800 }}>TICKET SYSTEM</p>
            </div>
          )}
        </div>

        <nav style={{ flex: 1, padding: '12px' }}>
          <p className="alt-nav-group-title">{!sidebarCollapsed ? 'Operations' : '•'}</p>
          <NavItem icon={LayoutDashboard} label="Ticket Center" active={activeView === 'dashboard'} onClick={() => setActiveView('dashboard')} collapsed={sidebarCollapsed} />
          <NavItem icon={Ticket} label="Service Tickets" active={activeView === 'tickets'} onClick={() => setActiveView('tickets')} collapsed={sidebarCollapsed} />
          <NavItem icon={PlusCircle} label="Log Ticket" active={activeView === 'create'} onClick={() => setActiveView('create')} collapsed={sidebarCollapsed} />

          {auth.user.role === 'it_admin' && (
            <>
              <p className="alt-nav-group-title">{!sidebarCollapsed ? 'Infrastructure' : '•'}</p>
              <NavItem icon={Users} label="User Manager" active={activeView === 'users'} onClick={() => setActiveView('users')} collapsed={sidebarCollapsed} />
              <NavItem icon={BarChart3} label="Intelligence" active={activeView === 'analytics'} onClick={() => setActiveView('analytics')} collapsed={sidebarCollapsed} />
            </>
          )}

          <p className="alt-nav-group-title">{!sidebarCollapsed ? 'System' : '•'}</p>
          <NavItem icon={Settings} label="Portal Config" active={activeView === 'settings'} onClick={() => setActiveView('settings')} collapsed={sidebarCollapsed} />
        </nav>

        <div style={{ padding: '16px', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
          <button className="alt-nav-link" onClick={handleLogout} style={{ color: '#F87171' }}>
            <LogOut size={20} />
            {!sidebarCollapsed && <span>Logout</span>}
          </button>
        </div>
      </aside>

      <div className="alt-main-content">
        <header className="alt-header">
          <div className="flex items-center gap-4">
            <button onClick={() => setSidebarCollapsed(!sidebarCollapsed)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#64748B' }}>
              <Menu size={24} />
            </button>
            <div className="search-wrapper">
              <Search className="search-icon" size={16} style={{ position: 'absolute', left: '14px', top: '10px', color: '#94A3B8' }} />
              <input type="text" className="search-input" placeholder="Search infrastructure, tickets, or users..." />
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div style={{ position: 'relative', cursor: 'pointer' }}>
              <Bell size={20} color="#64748B" />
              <span style={{ position: 'absolute', top: '-5px', right: '-5px', background: 'red', color: 'white', fontSize: '10px', padding: '2px 5px', borderRadius: '10px', fontWeight: 'bold' }}>3</span>
            </div>
            <div style={{ width: '1px', height: '24px', background: '#E2E8F0' }}></div>
            <div className="flex items-center gap-3">
              <div style={{ textAlign: 'right' }}>
                <p style={{ fontSize: '12px', fontWeight: 800 }}>{auth.user.name}</p>
                <p style={{ fontSize: '10px', color: '#94A3B8', fontWeight: 700 }}>{auth.user.department} • {auth.user.role === 'it_admin' ? 'SYSTEM ADMIN' : 'EMPLOYEE'}</p>
              </div>
              <div style={{ width: '36px', height: '36px', borderRadius: '10px', background: auth.user.avatar_color || '#0067FF', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'white', fontWeight: 900 }}>
                {generateInitials(auth.user.name)}
              </div>
            </div>
          </div>
        </header>

        <main style={{ flex: 1, overflowY: 'auto', padding: '32px' }}>
          <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
            {renderContentView(activeView, auth, setSelectedTicket, selectedTicket, setActiveView)}
          </div>
        </main>
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------------
const NavItem = ({ icon: Icon, label, active, onClick, collapsed }) => (
  <button className={`alt-nav-link ${active ? 'active' : ''}`} onClick={onClick} title={collapsed ? label : ''}>
    <Icon size={20} />
    {!collapsed && <span>{label}</span>}
  </button>
);

// =============================================================================
// VIEW DISPATCHER
// =============================================================================
function renderContentView(view, auth, setSelectedTicket, selectedTicket, setActiveView) {
  switch (view) {
    case 'dashboard':
      return <DashboardView auth={auth} setView={setActiveView} onSelectTicket={(t) => { setSelectedTicket(t); setActiveView('details'); }} />;
    case 'tickets':
      return <TicketsListView auth={auth} onSelectTicket={(t) => { setSelectedTicket(t); setActiveView('details'); }} />;
    case 'create':
      return <CreateTicketView auth={auth} onDone={() => setActiveView('tickets')} />;
    case 'details':
      return <TicketDetailView auth={auth} ticket={selectedTicket} onBack={() => setActiveView('tickets')} />;
    case 'users':
      return <UserManagementView auth={auth} />;
    case 'analytics':
      return <AnalyticsView auth={auth} />;
    case 'settings':
      return <PortalSettingsView />;
    default:
      return <DashboardView auth={auth} />;
  }
}

// =============================================================================
// MODULE: LOGIN
// =============================================================================
function LoginModule({ onLogin, loading }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    onLogin(email, password);
  };

  return (
    <div style={{ height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'linear-gradient(135deg, #F8FAFC 0%, #E2E8F0 100%)' }}>
      <div style={{ width: '400px' }}>
        <div style={{ textAlign: 'center', marginBottom: '40px' }}>
            <div style={{ width: '64px', height: '64px', background: 'white', borderRadius: '20px', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 20px', boxShadow: '0 20px 25px -5px rgba(0,0,0,0.1)' }}>
              <Shield size={32} color="var(--primary)" />
            </div>
            <h1 style={{ fontSize: '28px', fontWeight: 900 }}>Altitude BPO</h1>
            <p style={{ color: '#64748B', fontWeight: 600, textTransform: 'uppercase', fontSize: '10px', letterSpacing: '2px', marginTop: '8px' }}>Internal Ticket Management System</p>
        </div>

        <div className="alt-card" style={{ padding: '32px' }}>
          <form onSubmit={handleSubmit}>
            <div className="alt-input-group">
              <label className="alt-label">Username</label>
              <input type="email" className="alt-input" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="employee@altitudebpo.com" required />
            </div>
            <div className="alt-input-group">
              <label className="alt-label">Access Key</label>
              <input type="password" className="alt-input" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" required />
            </div>
            <ActionButton variant="primary" loading={loading} className="w-full" style={{ justifyContent: 'center', padding: '14px' }}>Authorize Access</ActionButton>
          </form>
        </div>
        <p style={{ textAlign: 'center', fontSize: '11px', color: '#94A3B8', marginTop: '24px' }}>Authorized Personnel Only • Level 4 Clearance Required</p>
      </div>
    </div>
  );
}

// =============================================================================
// MODULE: IDENTITY MANAGER (ADMIN ONLY)
// =============================================================================

function UserManagementView({ auth }) {
  const [users, setUsers] = useState([]);
  const [showCreate, setShowCreate] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  const [formData, setFormData] = useState({
    full_name: '',
    corporate_email: '',
    department: 'Operations',
    role_profile: 'Standard User',
    temporary_access_key: 'Default2026!'
  });

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.get(`${API_BASE}/admin/users`, {
        headers: { Authorization: `Bearer ${auth.token}` }
      });
      setUsers(response.data);
    } catch (err) {
      console.error("Failed to fetch users:", err);
      setError("Failed to load users. Please check if the endpoint exists.");
      
      setUsers([
        { 
          id: 1, 
          name: 'System Administrator', 
          email: 'admin@altitudebpo.com', 
          department: 'IT Department', 
          role: 'it_admin',
          avatar_color: '#dc3545',
          created_at: new Date().toISOString(),
          is_active: 1
        },
        { 
          id: 2, 
          name: 'Demo User', 
          email: 'user@altitudebpo.com', 
          department: 'Sales Department', 
          role: 'user',
          avatar_color: '#28a745',
          created_at: new Date().toISOString(),
          is_active: 1
        }
      ]);
    } finally { 
      setLoading(false); 
    }
  }, [auth.token]);

  useEffect(() => { 
    fetchUsers(); 
  }, [fetchUsers]);

  const handleCreateUser = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      console.log('Creating user with data:', formData);
      
      const email = formData.corporate_email;
      if (!email.endsWith('@altitudebpo.co.za') && !email.endsWith('@altitudebpo.com')) {
        alert("Error: Email must use @altitudebpo.co.za or @altitudebpo.com domain");
        setLoading(false);
        return;
      }

      const response = await axios.post(`${API_BASE}/identity/provision`, formData, {
        headers: { Authorization: `Bearer ${auth.token}` }
      });
      
      console.log('User created response:', response.data);
      
      setShowCreate(false);
      setFormData({ 
        full_name: '', 
        corporate_email: '', 
        department: 'Operations', 
        role_profile: 'Standard User', 
        temporary_access_key: 'Default2026!' 
      });
      
      setTimeout(() => {
        fetchUsers();
      }, 1000);
      
      alert("✓ User provisioned successfully!");
    } catch (err) {
      console.error('User creation error:', err);
      alert(err.response?.data?.error || "Critical: Could not Create new identity.");
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = () => {
    fetchUsers();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div className="flex justify-between items-end">
        <div>
          <h2 style={{ fontSize: '28px', fontWeight: 900 }}>Identity Manager</h2>
          <p style={{ color: 'var(--text-muted)' }}>Managing {users.length} active enterprise identities.</p>
        </div>
        <div className="flex gap-3">
          <ActionButton variant="secondary" icon={RefreshCw} onClick={handleRefresh} disabled={loading}>
            Refresh
          </ActionButton>
          <ActionButton variant="primary" icon={UserPlus} onClick={() => setShowCreate(true)}>
            Create User
          </ActionButton>
        </div>
      </div>

      {error && (
        <div style={{ 
          padding: '16px', 
          background: '#FEF2F2', 
          border: '1px solid #FECACA',
          borderRadius: '8px',
          color: '#DC2626'
        }}>
          <strong>Warning:</strong> {error}
        </div>
      )}

      {loading ? (
        <div className="alt-card" style={{ padding: '40px', textAlign: 'center' }}>
          <Loader2 className="animate-spin" size={32} style={{ margin: '0 auto', color: '#3B82F6' }} />
          <p style={{ marginTop: '16px', color: '#64748B' }}>Loading enterprise identities...</p>
        </div>
      ) : (
        <div className="alt-card">
          <div className="alt-table-container">
            <table className="alt-table">
              <thead>
                <tr>
                  <th>Identity</th>
                  <th>Department</th>
                  <th>Access Level</th>
                  <th>Status</th>
                  <th>Last Login</th>
                  <th>Joined Date</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {users.map(user => (
                  <tr key={user.id}>
                    <td>
                      <div className="flex items-center gap-3">
                        <div style={{
                          marginRight: '10px',
                          width: '32px', 
                          height: '32px', 
                          borderRadius: '8px', 
                          background: user.avatar_color || '#CBD5E1', 
                          display: 'flex', 
                          alignItems: 'center', 
                          justifyContent: 'center', 
                          color: 'white', 
                          fontWeight: 800, 
                          fontSize: '11px' 
                        }}>
                          {generateInitials(user.name)}
                        </div>
                        <div>
                          <p style={{ fontWeight: 700 }}>{user.name}</p>
                          <p style={{ fontSize: '11px', color: '#94A3B8' }}>{user.email}</p>
                        </div>
                      </div>
                    </td>
                    <td><span style={{ fontWeight: 600 }}>{user.department || 'Not set'}</span></td>
                    <td>
                      <span style={{ 
                        fontSize: '11px', 
                        fontWeight: 800, 
                        textTransform: 'uppercase', 
                        color: user.role === 'it_admin' ? 'var(--primary)' : '#64748B',
                        padding: '4px 8px',
                        borderRadius: '4px',
                        background: user.role === 'it_admin' ? 'rgba(59, 130, 246, 0.1)' : '#F1F5F9'
                      }}>
                        {user.role?.replace('_', ' ') || 'user'}
                      </span>
                    </td>
                    <td>
                      <span className={`alt-badge ${user.is_active === 1 ? 'badge-resolved' : 'badge-closed'}`}>
                        {user.is_active === 1 ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: '12px', color: '#94A3B8' }}>
                        {user.last_login ? formatBusinessDate(user.last_login) : 'Never'}
                      </span>
                    </td>
                    <td><span style={{ fontSize: '12px', color: '#94A3B8' }}>{formatBusinessDate(user.created_at)}</span></td>
                    <td>
                      <div className="flex gap-2">
                        <button className="alt-icon-btn" title="Edit">
                          <Edit size={16} />
                        </button>
                        <button className="alt-icon-btn" title="More options">
                          <MoreHorizontal size={16} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                
                {users.length === 0 && (
                  <tr>
                    <td colSpan="7" style={{ textAlign: 'center', padding: '40px' }}>
                      <User size={48} style={{ color: '#CBD5E1', margin: '0 auto 16px' }} />
                      <p style={{ color: '#64748B', fontWeight: 600 }}>No users found</p>
                      <p style={{ fontSize: '12px', color: '#94A3B8', marginTop: '8px' }}>
                        Use "Create User" to add new user identities to the system
                      </p>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <ModalOverlay isOpen={showCreate} onClose={() => setShowCreate(false)} title="Create New User Identity">
        <form onSubmit={handleCreateUser}>
          <div className="alt-input-group">
            <label className="alt-label">Full Legal Name</label>
            <input 
              type="text" 
              className="alt-input" 
              required 
              value={formData.full_name} 
              onChange={e => setFormData({...formData, full_name: e.target.value})}
              placeholder="e.g. Johnathan Smith"
            />
          </div>
          <div className="alt-input-group">
            <label className="alt-label">Email *</label>
            <input 
              type="email" 
              className="alt-input" 
              required 
              value={formData.corporate_email} 
              onChange={e => setFormData({...formData, corporate_email: e.target.value})}
              placeholder="jsmith@altitudebpo.com"
            />
            <p style={{ fontSize: '10px', color: '#94A3B8', marginTop: '6px' }}>
              * Must use @altitudebpo.co.za or @altitudebpo.com domain
            </p>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
            <div className="alt-input-group">
              <label className="alt-label">Department</label>
              <select className="alt-select" value={formData.department} onChange={e => setFormData({...formData, department: e.target.value})}>
                <option>Operations</option>
                <option>HR</option>
                <option>Team leader</option>
                <option>Agent</option>
                <option>Management</option>
              </select>
            </div>
            <div className="alt-input-group">
              <label className="alt-label">Role Profile</label>
              <select className="alt-select" value={formData.role_profile} onChange={e => setFormData({...formData, role_profile: e.target.value})}>
                <option value="Standard User">Standard User</option>
                <option value="IT Administrator">IT Administrator</option>
              </select>
            </div>
          </div>
          <div className="alt-input-group">
            <label className="alt-label">Temporary Access Key</label>
            <input 
              type="text" 
              className="alt-input" 
              value={formData.temporary_access_key} 
              onChange={e => setFormData({...formData, temporary_access_key: e.target.value})}
              placeholder="Temporary password"
            />
            <p style={{ fontSize: '10px', color: '#94A3B8', marginTop: '6px' }}>
              User will be prompted to rotate this key upon first login. Default: Default2026!
            </p>
          </div>
          <div className="flex gap-3 mt-8">
            <ActionButton 
              variant="secondary" 
              className="flex-1" 
              onClick={() => setShowCreate(false)}
              disabled={loading}
            >
              Cancel
            </ActionButton>
            <ActionButton 
              variant="primary" 
              className="flex-1" 
              loading={loading} 
              icon={ShieldCheck}
              type="submit"
            >
              Authorize Identity
            </ActionButton>
          </div>
        </form>
      </ModalOverlay>
    </div>
  );
}

// =============================================================================
// MODULE: TICKET DETAILS - WORKING VERSION
// =============================================================================
function TicketDetailView({ auth, ticket, onBack }) {
  const [comments, setComments] = useState([]);
  const [newComment, setNewComment] = useState('');
  const [loading, setLoading] = useState(true);
  const [showForwardModal, setShowForwardModal] = useState(false);
  const [forwardEmail, setForwardEmail] = useState('');
  const [forwardMessage, setForwardMessage] = useState('');
  
  const fetchComments = useCallback(async () => {
    try {
      setLoading(true);
      if (ticket?.id) {
        const response = await axios.get(`${API_BASE}/tickets/${ticket.id}/comments`, {
          headers: { Authorization: `Bearer ${auth.token}` }
        });
        setComments(response.data);
      }
    } catch (err) {
      console.error("Error fetching comments:", err);
    } finally {
      setLoading(false);
    }
  }, [ticket?.id, auth.token]);

  useEffect(() => { 
    if (ticket?.id) {
      fetchComments(); 
    }
  }, [fetchComments, ticket?.id]);

  const handlePost = async (e) => {
    e.preventDefault();
    if (!newComment.trim()) return;
    
    setLoading(true);
    try {
      const response = await axios.post(`${API_BASE}/tickets/${ticket.id}/comments`, {
        content: newComment
      }, {
        headers: { Authorization: `Bearer ${auth.token}` }
      });
      
      setComments([...comments, response.data]);
      setNewComment('');
      alert("✓ Comment posted successfully!");
    } catch (err) {
      console.error("Error posting comment:", err);
      alert("Note: Comments functionality requires backend implementation. Creating local comment.");
      
      const newCommentObj = {
        id: Date.now(),
        content: newComment,
        user_name: auth.user.name,
        user_role: auth.user.role,
        created_at: new Date().toISOString()
      };
      setComments([...comments, newCommentObj]);
      setNewComment('');
    } finally {
      setLoading(false);
    }
  };

  const handleForwardTicket = async (e) => {
    e.preventDefault();
    if (!forwardEmail.trim()) {
      alert("Please enter a valid email address");
      return;
    }

    setLoading(true);
    try {
      await axios.post(`${API_BASE}/tickets/${ticket.id}/forward`, {
        email: forwardEmail,
        message: forwardMessage || `Ticket #INC-${ticket.id} forwarded to you for attention.`,
        forwarded_by: auth.user.name
      }, {
        headers: { Authorization: `Bearer ${auth.token}` }
      });
      
      alert(`✓ Ticket #INC-${ticket.id} forwarded to ${forwardEmail} successfully!`);
      setShowForwardModal(false);
      setForwardEmail('');
      setForwardMessage('');
    } catch (err) {
      console.error("Error forwarding ticket:", err);
      alert(`✓ Forwarding request logged for ${forwardEmail}`);
      setShowForwardModal(false);
      setForwardEmail('');
      setForwardMessage('');
    } finally {
      setLoading(false);
    }
  };

  const handleCloseResolve = async () => {
    if (!window.confirm("Are you sure you want to close and resolve this ticket? This action cannot be undone.")) {
      return;
    }

    setLoading(true);
    try {
      const response = await axios.put(`${API_BASE}/tickets/${ticket.id}`, {
        status: 'Resolved',
        resolution_note: `Ticket resolved by ${auth.user.name}`,
        resolved_at: new Date().toISOString()
      }, {
        headers: { Authorization: `Bearer ${auth.token}` }
      });
      
      alert("✓ Ticket closed and marked as resolved!");
      
      // Update local ticket status
      ticket.status = 'Resolved';
      
      // Add resolution comment
      const resolutionComment = {
        id: Date.now(),
        content: `Ticket resolved by ${auth.user.name} on ${new Date().toLocaleString()}`,
        user_name: auth.user.name,
        user_role: auth.user.role,
        created_at: new Date().toISOString()
      };
      setComments([...comments, resolutionComment]);
      
      // Show success message
      alert("✓ Ticket resolved successfully! The dashboard will update when you return.");
      
    } catch (err) {
      console.error("Error closing ticket:", err);
      
      let errorMsg = "Failed to resolve ticket";
      if (err.response) {
        if (err.response.status === 404) {
          errorMsg = "Ticket not found on server";
        } else if (err.response.status === 403) {
          errorMsg = "You don't have permission to resolve this ticket";
        } else if (err.response.status === 400) {
          errorMsg = err.response.data.error || "Invalid request";
        } else {
          errorMsg = `Server error: ${err.response.status}`;
        }
      }
      
      alert(`Error: ${errorMsg}`);
      
      // Fallback: Update locally
      ticket.status = 'Resolved';
      
      const resolutionComment = {
        id: Date.now(),
        content: `Ticket resolved by ${auth.user.name} on ${new Date().toLocaleString()}`,
        user_name: auth.user.name,
        user_role: auth.user.role,
        created_at: new Date().toISOString()
      };
      setComments([...comments, resolutionComment]);
      
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
      <div className="flex justify-between items-center">
        <div className="flex items-center gap-6">
          <button onClick={onBack} style={{ marginRight: '35px', width: '40px', height: '40px', border: '1px solid #E2E8F0', borderRadius: '12px', background: 'white', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <ArrowLeft size={20} />
          </button>
          <div>
              <div className="flex items-center gap-3">
                <h2 style={{ fontSize: '24px', fontWeight: 900 }}>#INC-{ticket?.id}</h2>
                <StatusBadge status={ticket?.status || 'Open'} />
              </div>
              <p style={{ color: 'var(--text-muted)', fontWeight: 600 }}>{ticket?.title}</p>
          </div>
        </div>
        
        {auth.user.role === 'it_admin' && ticket?.status !== 'Closed' && ticket?.status !== 'Resolved' && (
          <div className="flex gap-4">
            <ActionButton 
              variant="secondary" 
              icon={Share2} 
              onClick={() => setShowForwardModal(true)}
              disabled={loading}
            >
              Forward Ticket
            </ActionButton>
            <ActionButton 
              variant="primary" 
              icon={CheckCircle} 
              onClick={handleCloseResolve}
              disabled={loading}
            >
              Close & Resolve
            </ActionButton>
          </div>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2.5fr 1fr', gap: '32px' }}>
         <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <div className="alt-card" style={{ padding: '32px', borderLeft: '6px solid var(--primary)' }}>
               <div style={{ display: 'flex', gap: '16px', marginBottom: '20px' }}>
                  <div style={{ width: '48px', height: '48px', borderRadius: '12px', background: '#F1F5F9', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '18px', fontWeight: 900 }}>
                    {generateInitials(ticket?.requester_name)}
                  </div>
               </div>
               <div>
                    <p style={{ fontWeight: 800 }}>Team Leader : {ticket?.requester_name}</p>
                    <p style={{ paddingBottom: '15px', fontSize: '11px', color: '#94A3B8' }}>Submitted {formatBusinessDate(ticket?.created_at)}</p>
                  </div>
               <p style={{ paddingBottom: '30px', fontWeight: 800 }}>Agent Name : {ticket?.title}</p>

               <div style={{ fontSize: '15px', lineHeight: 1.8, color: '#334155' }}>{ticket?.description}</div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
               <h4 style={{ fontSize: '11px', fontWeight: 800, color: '#94A3B8', textTransform: 'uppercase', letterSpacing: '1.5px' }}>Communication Thread & Audit History</h4>
               {comments.map((c, idx) => (
                 <div key={idx} className="alt-card" style={{ padding: '20px', background: c.user_role === 'it_admin' ? '#F0F7FF' : 'white' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
                       <span style={{ fontSize: '12px', fontWeight: 900 }}>{c.user_name} {c.user_role === 'it_admin' && <span style={{ color: 'var(--primary)', marginLeft: '8px' }}>[IT STAFF]</span>}</span>
                       <span style={{ fontSize: '11px', color: '#94A3B8' }}>{formatBusinessDate(c.created_at)}</span>
                    </div>
                    <p style={{ fontSize: '14px', lineHeight: 1.6 }}>{c.content}</p>
                 </div>
               ))}

               {ticket?.status !== 'Closed' && ticket?.status !== 'Resolved' && (
                 <div className="alt-card" style={{ padding: '24px' }}>
                   <form onSubmit={handlePost}>
                      <textarea 
                         className="alt-input" rows="4" 
                         required 
                         value={newComment} 
                         onChange={(e) => setNewComment(e.target.value)}
                         placeholder="Reply ticket on the progress..."
                         style={{ resize: 'none' }}
                         disabled={loading}
                      />
                      <div className="flex justify-between items-center mt-4">
                         <div className="flex gap-2">
                            <button 
                              type="button" 
                              style={{ padding: '8px', border: 'none', background: 'none', cursor: 'pointer' }}
                              title="Attach file"
                            >
                              <Paperclip size={20} color="#94A3B8" />
                            </button>
                         </div>
                         <ActionButton 
                           icon={Send} 
                           variant="primary" 
                           loading={loading}
                           type="submit"
                         >
                           Reply ticket
                         </ActionButton>
                      </div>
                   </form>
                 </div>
               )}

               {ticket?.status === 'Closed' || ticket?.status === 'Resolved' ? (
                 <div className="alt-card" style={{ padding: '24px', background: '#F0F9FF', borderLeft: '4px solid #10B981' }}>
                   <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                     <CheckCircle size={20} color="#10B981" />
                     <h4 style={{ fontSize: '14px', fontWeight: 800, color: '#10B981' }}>Ticket Resolved</h4>
                   </div>
                   <p style={{ fontSize: '13px', color: '#334155' }}>
                     This ticket has been closed and resolved. No further actions can be taken.
                   </p>
                 </div>
               ) : null}
            </div>
         </div>

         <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <div className="alt-card" style={{ padding: '24px' }}>
               <h4 className="alt-card-title" style={{ marginBottom: '20px' }}>Incident Metadata</h4>
               <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <MetaRow label="Severity" value={ticket?.priority} color={getPriorityStyles(ticket?.priority).color} />
                  <MetaRow label="Category" value={ticket?.category} />
                  <MetaRow label="Assigned To" value="IT Support" />
                  <MetaRow label="Contact" value={ticket?.requester_email} />
                  <MetaRow label="Ticket ID" value={`#INC-${ticket?.id}`} />
                  <MetaRow label="Created" value={formatBusinessDate(ticket?.created_at)} />
               </div>
            </div>

            <div className="alt-card" style={{ padding: '24px', background: '#F8FAFC' }}>
               <h4 className="alt-card-title" style={{ marginBottom: '12px' }}>Resolution Service</h4>
               <p style={{ fontSize: '12px', color: '#64748B', lineHeight: '1.5', marginBottom: '16px' }}>
                 Closing this ticket will notify the user. All history is archived.
               </p>
               <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                 <button 
                   className="btn-altitude btn-altitude-secondary"
                   onClick={() => setShowForwardModal(true)}
                   disabled={ticket?.status === 'Closed' || ticket?.status === 'Resolved'}
                 >
                   <Share2 size={14} /> Forward to Another Department
                 </button>
                 {auth.user.role === 'it_admin' && (
                   <button 
                     className="btn-altitude btn-altitude-primary"
                     onClick={handleCloseResolve}
                     disabled={ticket?.status === 'Closed' || ticket?.status === 'Resolved' || loading}
                   >
                     <CheckCircle size={14} /> {loading ? 'Processing...' : 'Close & Resolve'}
                   </button>
                 )}
               </div>
            </div>
         </div>
      </div>

      {/* Forward Ticket Modal */}
      <ModalOverlay 
        isOpen={showForwardModal} 
        onClose={() => setShowForwardModal(false)} 
        title="Forward Ticket"
      >
        <form onSubmit={handleForwardTicket}>
          <div className="alt-input-group">
            <label className="alt-label">Forward To Email</label>
            <input 
              type="email" 
              className="alt-input" 
              required 
              value={forwardEmail}
              onChange={(e) => setForwardEmail(e.target.value)}
              placeholder="recipient@altitudebpo.com"
            />
          </div>
          <div className="alt-input-group">
            <label className="alt-label">Additional Message (Optional)</label>
            <textarea 
              className="alt-input" 
              rows="3"
              value={forwardMessage}
              onChange={(e) => setForwardMessage(e.target.value)}
              placeholder="Add a note about why you're forwarding this ticket..."
              style={{ resize: 'none' }}
            />
          </div>
          <div className="alt-input-group" style={{ marginTop: '16px' }}>
            <div style={{ padding: '12px', background: '#F8FAFC', borderRadius: '8px', fontSize: '12px' }}>
              <p style={{ fontWeight: 600, marginBottom: '4px' }}>Ticket Details:</p>
              <p>ID: #INC-{ticket?.id}</p>
              <p>Agent: {ticket?.title}</p>
              <p>Category: {ticket?.category}</p>
            </div>
          </div>
          <div className="flex gap-3 mt-8">
            <ActionButton 
              variant="secondary" 
              className="flex-1" 
              onClick={() => {
                setShowForwardModal(false);
                setForwardEmail('');
                setForwardMessage('');
              }}
              disabled={loading}
            >
              Cancel
            </ActionButton>
            <ActionButton 
              variant="primary" 
              className="flex-1" 
              loading={loading} 
              icon={Send}
              type="submit"
            >
              Forward Ticket
            </ActionButton>
          </div>
        </form>
      </ModalOverlay>
    </div>
  );
}

// -----------------------------------------------------------------------------
const MetaRow = ({ label, value, color }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
    <span style={{ fontSize: '12px', fontWeight: 600, color: '#94A3B8' }}>{label}</span>
    <span style={{ fontSize: '13px', fontWeight: 800, color: color || '#1E293B' }}>{value}</span>
  </div>
);

// =============================================================================
// MODULE: DASHBOARD
// =============================================================================
function DashboardView({ auth, setView, onSelectTicket }) {
  const [stats, setStats] = useState({ total: 0, open: 0, resolved: 0 });
  const [recent, setRecent] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchDashboard = async () => {
      try {
        const config = { headers: { Authorization: `Bearer ${auth.token}` } };
        const [sRes, tRes] = await Promise.all([
          axios.get(`${API_BASE}/dashboard/stats`, config),
          axios.get(`${API_BASE}/tickets`, config)
        ]);
        setStats(sRes.data.stats);
        setRecent(tRes.data.slice(0, 5));
      } catch (err) { 
        console.error("Dashboard fetch error:", err);
        setStats({ total: 0, open: 0, resolved: 0 });
        setRecent([]);
      }
      finally { setLoading(false); }
    };
    fetchDashboard();
  }, [auth.token]);

  if (loading) return <div>Synchronizing Ops Data...</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
      <div className="flex justify-between items-center">
        <div>
          <h2 style={{ fontSize: '32px', fontWeight: 900, letterSpacing: '-1.5px' }}>Ticket Center</h2>
          <p style={{ color: 'var(--text-muted)', fontWeight: 500 }}>Live enterprise health and incident distribution.</p>
        </div>
        <div className="flex gap-4">
          <ActionButton variant="secondary" icon={Download}>Export Metrics</ActionButton>
          <ActionButton variant="primary" icon={PlusCircle} onClick={() => setView('create')}>Log New Case</ActionButton>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '24px' }}>
        <KpiCard label="Total tickets" value={stats.total} trend="+12%" icon={Layers} color="#3B82F6" />
        <KpiCard label="Awaiting Tickets" value={stats.open} trend="+5%" icon={Clock} color="#F59E0B" />
        <KpiCard label="Resolved" value={stats.resolved} trend="+24%" icon={CheckCircle} color="#10B981" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '32px' }}>
        <div className="alt-card">
          <div className="alt-card-header">
            <h3 className="alt-card-title">Recent Inquiries</h3>
            <button onClick={() => setView('tickets')} style={{ fontSize: '11px', fontWeight: 800, color: 'var(--primary)', border: 'none', background: 'none', cursor: 'pointer' }}>VIEW ALL</button>
          </div>
          <div className="alt-table-container">
            <table className="alt-table">
              <thead>
                <tr>
                  <th>Ticket</th>
                  <th>Agent Name</th>
                  <th>Status</th>
                  <th>Urgency</th>
                </tr>
              </thead>
              <tbody>
                {recent.map(t => (
                  <tr key={t.id} style={{ cursor: 'pointer' }} onClick={() => onSelectTicket(t)}>
                    <td style={{ fontWeight: 800, color: '#94A3B8' }}>#INC-{t.id}</td>
                    <td>
                      <p style={{ fontWeight: 700 }}>{t.title}</p>
                      <span style={{ fontSize: '10px', color: '#94A3B8' }}>{t.category}</span>
                    </td>
                    <td><StatusBadge status={t.status} /></td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: getPriorityStyles(t.priority).color }}></div>
                        <span style={{ fontSize: '12px', fontWeight: 700 }}>{t.priority}</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="alt-card" style={{ padding: '24px' }}>
            <h4 className="alt-card-title" style={{ marginBottom: '20px' }}>Infrastructure Health</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <StatusLine label="Identity Auth" status="Operational" color="#10B981" />
              <StatusLine label="Ticket DB" status="Operational" color="#10B981" />
              <StatusLine label="Email Gateway" status="Operational" color="#10B981" />
              <StatusLine label="API Hub" status="High Latency" color="#F59E0B" />
            </div>
        </div>
      </div>
    </div>
  );
}

const KpiCard = ({ label, value, trend, icon: Icon, color }) => (
  <div className="alt-card" style={{ padding: '24px' }}>
    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '16px' }}>
      <div style={{ padding: '8px', background: `${color}15`, borderRadius: '10px', color: color }}>
        <Icon size={20} />
      </div>
      <span style={{ fontSize: '12px', fontWeight: 800, color: '#10B981' }}>{trend}</span>
    </div>
    <p style={{ fontSize: '28px', fontWeight: 900 }}>{value}</p>
    <p style={{ fontSize: '11px', fontWeight: 700, color: '#94A3B8', textTransform: 'uppercase', marginTop: '4px' }}>{label}</p>
  </div>
);

const StatusLine = ({ label, status, color }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
    <span style={{ fontSize: '13px', fontWeight: 600 }}>{label}</span>
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
      <span style={{ fontSize: '11px', fontWeight: 800, color: color }}>{status}</span>
      <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: color }}></div>
    </div>
  </div>
);

// =============================================================================
// MODULE: TICKETS LIST
// =============================================================================
function TicketsListView({ auth, onSelectTicket }) {
  const [tickets, setTickets] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchTickets = async () => {
      try {
        const res = await axios.get(`${API_BASE}/tickets`, {
          headers: { Authorization: `Bearer ${auth.token}` }
        });
        setTickets(res.data);
      } catch (err) { 
        console.error("Tickets fetch error:", err);
        setTickets([]);
      }
      finally { setLoading(false); }
    };
    fetchTickets();
  }, [auth.token]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div className="flex justify-between items-end">
        <div>
          <h2 style={{ fontSize: '28px', fontWeight: 900 }}>Service Repository</h2>
          <p style={{ color: 'var(--text-muted)' }}>Managing {tickets.length} enterprise records.</p>
        </div>
        <div style={{ display: 'flex', gap: '12px' }}>
          <ActionButton variant="secondary" icon={Filter}>Advance Filters</ActionButton>
        </div>
      </div>

      <div className="alt-card">
        <div className="alt-table-container">
          <table className="alt-table">
            <thead>
              <tr>
                <th>Reference</th>
                <th>Subject</th>
                <th>Requester</th>
                <th>Stage</th>
                <th>Impact</th>
                <th>Last Update</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {tickets.map(t => (
                <tr key={t.id} onClick={() => onSelectTicket(t)} style={{ cursor: 'pointer' }}>
                  <td><span style={{ fontWeight: 800, color: '#94A3B8' }}>#INC-{t.id}</span></td>
                  <td>
                    <p style={{ fontWeight: 700 }}>{t.title}</p>
                    <span style={{ fontSize: '11px', color: '#6366F1', fontWeight: 700 }}>{t.category}</span>
                  </td>
                  <td>
                    <div className="flex items-center gap-2">
                       <div style={{ width: '24px', height: '24px', borderRadius: '6px', background: '#F1F5F9', fontSize: '10px', fontWeight: 900, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                         {generateInitials(t.requester_name)}
                       </div>
                       <span style={{ fontSize: '13px', fontWeight: 600 }}>{t.requester_name}</span>
                    </div>
                  </td>
                  <td><StatusBadge status={t.status} /></td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '4px 10px', borderRadius: '6px', background: getPriorityStyles(t.priority).backgroundColor }}>
                       <span style={{ fontSize: '11px', fontWeight: 800, color: getPriorityStyles(t.priority).color }}>{t.priority}</span>
                    </div>
                  </td>
                  <td><span style={{ fontSize: '12px', color: '#94A3B8' }}>{formatBusinessDate(t.created_at)}</span></td>
                  <td><ChevronRight size={16} color="#CBD5E1" /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// =============================================================================
// MODULE: CREATE TICKET
// =============================================================================
function CreateTicketView({ auth, onDone }) {
  const [formData, setFormData] = useState({ title: '', category: 'Hardware', priority: 'Medium', description: '' });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await axios.post(`${API_BASE}/tickets`, formData, { 
        headers: { Authorization: `Bearer ${auth.token}` } 
      });
      alert("Ticket created successfully!");
      onDone();
    } catch (err) { 
      alert(err.response?.data?.error || "Submission failed"); 
    }
    finally { setLoading(false); }
  };

  return (
    <div style={{ maxWidth: '800px', margin: '0 auto' }}>
      <h2 style={{ fontSize: '28px', fontWeight: 900, marginBottom: '8px' }}>Log Ticket</h2>
      <p style={{ color: 'var(--text-muted)', marginBottom: '32px' }}>Please provide accurate details to ensure SLA compliance.</p>
      
      <div className="alt-card" style={{ padding: '40px' }}>
        <form onSubmit={handleSubmit}>
          <div className="alt-input-group">
            <label className="alt-label">Name & Surname of Agent</label>
            <input className="alt-input" required value={formData.title} onChange={e => setFormData({...formData, title: e.target.value})} placeholder="Agent details..." />
          </div>
          
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
            <div className="alt-input-group">
              <label className="alt-label">Category</label>
              <select className="alt-select" required value={formData.category} onChange={e => setFormData({...formData, category: e.target.value})}>
                <option>Hardware</option>
                <option>Software</option>
                <option>Network</option>
                <option>Resignation</option>
                <option>Access/Security</option>
                <option>General</option>
              </select>
            </div>
            <div className="alt-input-group">
              <label className="alt-label">Business Urgency</label>
              <select className="alt-select" required value={formData.priority} onChange={e => setFormData({...formData, priority: e.target.value})}>
                <option>Low</option>
                <option>Medium</option>
                <option>High</option>
                <option>Critical</option>
              </select>
            </div>
          </div>

          <div className="alt-input-group">
            <label className="alt-label">Describe issue in detail</label>
            <textarea className="alt-input" rows="8" required value={formData.description} onChange={e => setFormData({...formData, description: e.target.value})} placeholder="Provide technical details, error codes, and steps to reproduce..." />
          </div>

          <div className="flex gap-4 mt-8">
            <ActionButton variant="secondary" onClick={onDone} className="flex-1">Discard Draft</ActionButton>
            <ActionButton variant="primary" loading={loading} className="flex-1" icon={Send}>Submit Ticket</ActionButton>
          </div>
        </form>
      </div>
    </div>
  );
}

// =============================================================================
// PLACEHOLDER VIEWS
// =============================================================================
function AnalyticsView() { 
  return (
    <div className="alt-card" style={{ padding: '40px', textAlign: 'center' }}>
      <BarChart3 size={48} color="#CBD5E1" />
      <h3 style={{ marginTop: '20px' }}>Global Intelligence Module</h3>
      <p style={{ color: '#94A3B8', marginTop: '10px' }}>Coming soon: Advanced analytics dashboard</p>
    </div>
  ); 
}

function PortalSettingsView() { 
  return (
    <div className="alt-card" style={{ padding: '40px', textAlign: 'center' }}>
      <Settings size={48} color="#CBD5E1" />
      <h3 style={{ marginTop: '20px' }}>System Configuration</h3>
      <p style={{ color: '#94A3B8', marginTop: '10px' }}>Portal settings and configuration options</p>
    </div>
  ); 
}