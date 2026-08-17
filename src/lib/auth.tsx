import { createContext, useContext, useState, useEffect, type ReactNode } from 'react';
import type { AppUser } from '@/types';
import { callEdgeFunction } from '@/lib/supabase';

interface AuthContextValue {
  user: AppUser | null;
  loading: boolean;
  error: string | null;
  blocked: boolean;
  login: (username: string, password: string) => Promise<{ success: boolean; incidentId?: string }>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

const STORAGE_KEY = 'logsentinel_session';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AppUser | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [blocked, setBlocked] = useState(false);

  useEffect(() => {
    const saved = sessionStorage.getItem(STORAGE_KEY);
    if (saved) {
      try {
        setUser(JSON.parse(saved));
      } catch {
        sessionStorage.removeItem(STORAGE_KEY);
      }
    }
  }, []);

  async function login(username: string, password: string) {
    setLoading(true);
    setError(null);
    setBlocked(false);
    try {
      const requestId = `req-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
      const result = await callEdgeFunction<{ success: boolean; error?: string; blocked?: boolean; user?: AppUser; incident_id?: string }>('auth-verify', {
        username,
        password,
        source_ip: '127.0.0.1',
        user_agent: navigator.userAgent,
        request_id: requestId,
      });
      if (result.success && result.user) {
        const appUser = result.user;
        setUser(appUser);
        sessionStorage.setItem(STORAGE_KEY, JSON.stringify(appUser));
        return { success: true, incidentId: result.incident_id };
      }
      setError(result.error || 'Login failed');
      return { success: false };
    } catch (err) {
      const e = err as Error & { blocked?: boolean };
      if (e.blocked) {
        setBlocked(true);
        setError(e.message);
      } else {
        setError(e.message || 'Authentication service unavailable');
      }
      return { success: false };
    } finally {
      setLoading(false);
    }
  }

  function logout() {
    setUser(null);
    sessionStorage.removeItem(STORAGE_KEY);
  }

  return (
    <AuthContext.Provider value={{ user, loading, error, blocked, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
