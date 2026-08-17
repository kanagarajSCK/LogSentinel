import { useState, type FormEvent } from 'react';
import { useAuth } from '@/lib/auth';
import { Loader2, AlertCircle, ShieldAlert, LogIn } from 'lucide-react';

export function Login() {
  const { login, loading, error, blocked } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!username || !password) return;
    await login(username, password);
    setPassword('');
  }

  return (
    <div>
      {error && (
        <div className={blocked ? 'alert alert-error' : 'alert alert-warning'}>
          {blocked ? <ShieldAlert size={16} style={{ verticalAlign: 'middle', marginRight: 6 }} /> : <AlertCircle size={16} style={{ verticalAlign: 'middle', marginRight: 6 }} />}
          {error}
        </div>
      )}
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="username">Username</label>
          <input
            id="username"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Enter username"
            autoComplete="username"
            autoFocus
            disabled={loading}
          />
        </div>
        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter password"
            autoComplete="current-password"
            disabled={loading}
          />
        </div>
        <button type="submit" className="btn btn-primary btn-block" disabled={loading || !username || !password}>
          {loading ? <Loader2 size={16} className="spin" /> : <LogIn size={16} />}
          {loading ? 'Authenticating...' : 'Sign In'}
        </button>
      </form>

      <div className="demo-credentials">
        <h4>Demo Accounts</h4>
        <ul>
          <li><strong>admin</strong> / admin123</li>
          <li><strong>analyst</strong> / analyst123</li>
          <li><strong>jsmith</strong> / password123</li>
        </ul>
      </div>
    </div>
  );
}
