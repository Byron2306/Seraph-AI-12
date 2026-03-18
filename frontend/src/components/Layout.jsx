import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { 
  LayoutDashboard, 
  Shield, 
  Bell, 
  AlertTriangle, 
  LogOut, 
  ChevronRight,
  Cpu,
  Activity,
  Network,
  Crosshair,
  Radar,
  FileText,
  Monitor,
  ShieldAlert,
  Settings,
  Zap,
  Clock,
  ScrollText,
  Database,
  Container,
  Lock,
  GitBranch,
  Brain,
  Workflow,
  Key,
  ShieldCheck,
  Box,
  Globe,
  BarChart3,
  Terminal,
  Radio,
  Map,
  Mail,
  Chrome,
  Server,
  Cloud,
  Route,
  Eye,
  Fingerprint,
  Smartphone,
  Link
} from 'lucide-react';
import { Button } from './ui/button';

const Layout = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  // Seraph AI Logo URL
  const logoUrl = "https://customer-assets.emergentagent.com/job_securityshield-17/artifacts/4jbqdhyd_ChatGPT%20Image%20Feb%2010%2C%202026%2C%2009_07_51%20AM.png";

  const navItems = [
    { path: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
    { path: '/unified-agent', icon: Cpu, label: 'Unified Agent' },
    { path: '/command-center', icon: ShieldAlert, label: 'Command Center' },
    { path: '/advanced', icon: Cpu, label: 'Advanced Services' },
    { path: '/heatmap', icon: Map, label: 'Threat Heatmap' },
    { path: '/ai-threats', icon: Brain, label: 'AI Threats (AATL)' },
    { path: '/cli-sessions', icon: Brain, label: 'AI Detection' },
    { path: '/threats', icon: AlertTriangle, label: 'Threats' },
    { path: '/alerts', icon: Bell, label: 'Alerts' },
    { path: '/vns-alerts', icon: Mail, label: 'VNS Alerts' },
    { path: '/quarantine', icon: ShieldAlert, label: 'Quarantine' },
    { path: '/response', icon: Zap, label: 'Auto Response' },
    { path: '/timeline', icon: Clock, label: 'Timeline' },
    { path: '/network', icon: Network, label: 'Network Map' },
    { path: '/hunting', icon: Crosshair, label: 'Threat Hunting' },
    { path: '/honeypots', icon: Radar, label: 'Honeypots' },
    { path: '/threat-intel', icon: Database, label: 'Threat Intel' },
    { path: '/correlation', icon: GitBranch, label: 'Correlation' },
    { path: '/ransomware', icon: ShieldAlert, label: 'Ransomware' },
    { path: '/containers', icon: Container, label: 'Containers' },
    { path: '/cspm', icon: Cloud, label: 'Cloud Security' },
    { path: '/attack-paths', icon: Route, label: 'Attack Paths' },
    { path: '/deception', icon: Eye, label: 'Deception' },
    { path: '/kernel-sensors', icon: Cpu, label: 'Kernel Sensors' },
    { path: '/secure-boot', icon: ShieldCheck, label: 'Secure Boot' },
    { path: '/identity', icon: Fingerprint, label: 'Identity' },
    { path: '/vpn', icon: Lock, label: 'VPN' },
    { path: '/edr', icon: Brain, label: 'EDR' },
    { path: '/soar', icon: Workflow, label: 'SOAR' },
    { path: '/honey-tokens', icon: Key, label: 'Honey Tokens' },
    { path: '/zero-trust', icon: ShieldCheck, label: 'Zero Trust' },
    { path: '/ml-prediction', icon: Brain, label: 'ML Prediction' },
    { path: '/sandbox', icon: Box, label: 'Sandbox' },
    { path: '/browser-isolation', icon: Globe, label: 'Browser Isolation' },
    { path: '/email-protection', icon: Mail, label: 'Email Protection' },
    { path: '/email-gateway', icon: Server, label: 'Email Gateway' },
    { path: '/mobile-security', icon: Smartphone, label: 'Mobile Security' },
    { path: '/mdm', icon: Link, label: 'MDM Connectors' },
    { path: '/browser-extension', icon: Chrome, label: 'Browser Extension' },
    { path: '/kibana', icon: BarChart3, label: 'Kibana' },
    { path: '/reports', icon: FileText, label: 'Reports' },
    { path: '/audit', icon: ScrollText, label: 'Audit Logs' },
    { path: '/tenants', icon: Globe, label: 'Tenants' },
    { path: '/setup-guide', icon: Server, label: 'Setup Guide' },
    { path: '/settings', icon: Settings, label: 'Settings' },
  ];

  return (
    <div className="min-h-screen flex" style={{ backgroundColor: '#0C1020' }}>
      {/* Sidebar */}
      <aside className="w-64 flex flex-col" style={{ backgroundColor: '#121833', borderRight: '2px solid rgba(253, 230, 138, 0.2)' }}>
        {/* Logo */}
        <div className="p-6" style={{ borderBottom: '2px solid rgba(253, 230, 138, 0.2)' }}>
          <div className="flex items-center gap-4">
            <div className="w-16 h-16 rounded-xl overflow-hidden" style={{ 
              background: 'linear-gradient(135deg, rgba(253, 230, 138, 0.3), rgba(56, 189, 248, 0.2))',
              boxShadow: '0 0 30px rgba(253, 230, 138, 0.4), inset 0 0 20px rgba(56, 189, 248, 0.1)',
              border: '2px solid rgba(253, 230, 138, 0.4)'
            }}>
              <img src={logoUrl} alt="Seraph AI" className="w-full h-full object-cover" />
            </div>
            <div>
              <h1 className="font-mono font-bold text-xl tracking-wider" style={{ color: '#FDE68A', textShadow: '0 0 15px rgba(253, 230, 138, 0.4)' }}>SERAPH AI</h1>
              <p className="text-xs" style={{ color: '#A5F3FC' }}>Seraphic Watch</p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-3 space-y-0.5 overflow-y-auto">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-4 py-2.5 rounded-lg transition-all duration-200 group ${
                  isActive
                    ? 'seraph-nav-active'
                    : 'seraph-nav-item'
                }`
              }
              style={({ isActive }) => isActive ? {
                backgroundColor: 'rgba(56, 189, 248, 0.1)',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                color: '#38BDF8'
              } : {
                color: '#A5F3FC',
                border: '1px solid transparent'
              }}
            >
              {({ isActive }) => (
                <>
                  <item.icon className="w-4 h-4" style={{ color: isActive ? '#38BDF8' : '#A5F3FC' }} />
                  <span className="font-medium text-sm" style={{ color: isActive ? '#E0E7FF' : '#A5F3FC' }}>{item.label}</span>
                  {isActive && (
                    <ChevronRight className="w-4 h-4 ml-auto" style={{ color: '#38BDF8' }} />
                  )}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        {/* System Status */}
        <div className="p-4" style={{ borderTop: '2px solid rgba(253, 230, 138, 0.2)' }}>
          <div className="rounded-xl p-4" style={{ backgroundColor: 'rgba(253, 230, 138, 0.08)', border: '1px solid rgba(253, 230, 138, 0.2)' }}>
            <div className="flex items-center gap-2 mb-2">
              <Activity className="w-5 h-5" style={{ color: '#FDE68A' }} />
              <span className="text-sm font-medium" style={{ color: '#FDE68A' }}>Seraphic Status</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full animate-pulse" style={{ backgroundColor: '#FDE68A', boxShadow: '0 0 15px #FDE68A' }} />
              <span className="text-sm font-mono font-bold" style={{ color: '#FDE68A' }}>WATCHING</span>
            </div>
          </div>
        </div>

        {/* User Section */}
        <div className="p-4" style={{ borderTop: '2px solid rgba(253, 230, 138, 0.2)' }}>
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ backgroundColor: 'rgba(253, 230, 138, 0.15)', border: '2px solid rgba(253, 230, 138, 0.4)' }}>
              <span className="text-lg font-mono font-bold" style={{ color: '#FDE68A' }}>
                {user?.name?.charAt(0)?.toUpperCase() || 'U'}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-white truncate">{user?.name}</p>
              <p className="text-xs truncate" style={{ color: '#A5F3FC' }}>{user?.role}</p>
            </div>
          </div>
          <Button
            onClick={handleLogout}
            variant="ghost"
            className="w-full justify-start text-slate-400 hover:text-red-400 hover:bg-red-500/10"
            data-testid="logout-btn"
          >
            <LogOut className="w-4 h-4 mr-2" />
            Logout
          </Button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto" style={{ backgroundColor: '#0C1020' }}>
        <Outlet />
      </main>
    </div>
  );
};

export default Layout;
