import { useState } from 'react';
import { Loader2, ShieldCheck, Hammer, KeyRound, UserCheck, Target } from 'lucide-react';

interface DemoPanelProps {
  onRun: (scenario: string) => Promise<void>;
}

export function DemoPanel({ onRun }: DemoPanelProps) {
  const [running, setRunning] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<string | null>(null);

  async function run(scenario: string) {
    setRunning(scenario);
    setLastResult(null);
    try {
      await onRun(scenario);
      setLastResult(`${scenario} events generated successfully. Check the Overview and Incidents tabs.`);
    } catch {
      setLastResult('Failed to generate events. Please try again.');
    } finally {
      setRunning(null);
    }
  }

  const scenarios = [
    {
      key: 'normal_login',
      title: 'Normal Failed Login',
      desc: 'Generates a single failed login event. Represents a user mistyping their password. No incident will be created.',
      icon: ShieldCheck,
      color: '#22c55e',
    },
    {
      key: 'brute_force',
      title: 'Brute-Force Attack',
      desc: 'Simulates 10 rapid failed login attempts against a single account from one IP. Triggers a HIGH severity brute-force incident.',
      icon: Hammer,
      color: '#ef4444',
    },
    {
      key: 'credential_attack',
      title: 'Credential Stuffing',
      desc: 'Simulates failed logins across multiple usernames from a single IP. Triggers a CRITICAL severity credential attack incident.',
      icon: KeyRound,
      color: '#dc2626',
    },
    {
      key: 'account_compromise',
      title: 'Account Compromise',
      desc: 'Simulates repeated failures followed by a successful login. Triggers a CRITICAL severity account compromise incident.',
      icon: UserCheck,
      color: '#f59e0b',
    },
    {
      key: 'account_targeting',
      title: 'Account Targeting',
      desc: 'Simulates multiple failed logins against one username from different IPs. Triggers a MEDIUM severity targeting incident.',
      icon: Target,
      color: '#f59e0b',
    },
  ];

  return (
    <div>
      <div className="alert alert-info">
        This panel generates simulated security events for testing the detection engine and incident workflow.
        Generated events flow through the same pipeline as real login attempts.
      </div>

      {lastResult && <div className="alert alert-info" style={{ marginTop: 12 }}>{lastResult}</div>}

      <div className="demo-grid" style={{ marginTop: 20 }}>
        {scenarios.map((scenario) => {
          const Icon = scenario.icon;
          return (
            <div className="demo-card" key={scenario.key}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                <div style={{
                  width: 36, height: 36, borderRadius: 8,
                  background: `${scenario.color}1a`, color: scenario.color,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  <Icon size={20} />
                </div>
                <h4>{scenario.title}</h4>
              </div>
              <p>{scenario.desc}</p>
              <button
                className="btn btn-primary demo-btn"
                onClick={() => run(scenario.key)}
                disabled={running !== null}
              >
                {running === scenario.key ? <Loader2 size={16} className="spin" /> : null}
                {running === scenario.key ? 'Generating...' : 'Generate Events'}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
