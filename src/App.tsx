import { useAuth } from '@/lib/auth';
import { Login } from '@/pages/Login';
import { Dashboard } from '@/pages/Dashboard';
import { Shield } from 'lucide-react';

export default function App() {
  const { user } = useAuth();
  if (!user) {
    return (
      <div className="login-page">
        <div className="login-card">
          <div className="login-header">
            <div className="logo">
              <Shield color="#38bdf8" size={32} />
              <h1>LogSentinel</h1>
            </div>
            <p>Security Monitoring &amp; Incident Detection</p>
          </div>
          <Login />
        </div>
      </div>
    );
  }
  return <Dashboard />;
}
