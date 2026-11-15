import { useState, type FC, type FormEvent } from 'react';
import { Eye, EyeOff, ShieldCheck, UserRound } from 'lucide-react';

export interface PrincipalIdentity {
  name: string;
  role: string;
  kind: string;
  hostId?: string;
}

interface LoginGateProps {
  onAuthenticated: (identity: PrincipalIdentity) => void;
  notice?: string | null;
}

export const LoginGate: FC<LoginGateProps> = ({ onAuthenticated, notice }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!username.trim() || !password || isSubmitting) return;

    setIsSubmitting(true);
    setError(null);
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password }),
        cache: 'no-store'
      });
      const body = await response.json().catch(() => null) as Partial<PrincipalIdentity> & { reason?: string } | null;
      if (response.status === 401) {
        setError('Username atau password tidak cocok. Periksa kembali lalu coba lagi.');
        return;
      }
      if (response.status === 503) {
        setError(body?.reason || 'Akun admin belum disiapkan. Konfigurasikan username/password admin di environment lokal dan jalankan ulang aplikasi.');
        return;
      }
      if (!response.ok) {
        setError(body?.reason || 'Server gagal memverifikasi akun. Coba lagi beberapa saat.');
        return;
      }
      if (typeof body?.name !== 'string' || typeof body?.role !== 'string') {
        setError('Respons identitas dari server tidak valid.');
        return;
      }
      setPassword('');
      onAuthenticated({ name: body.name, role: body.role, kind: typeof body.kind === 'string' ? body.kind : 'session' });
    } catch {
      setError('Tidak dapat terhubung ke server PASOPATI. Pastikan aplikasi berjalan dan coba lagi.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <main className="hud-grid flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-md pasopati-fade-up">
        <div className="mb-8 flex items-center justify-center gap-3">
          <img src="/pasopati-mark.png" alt="" className="h-14 w-14 rounded-xl border border-[#2a3140] object-cover" />
          <div>
            <div className="text-2xl font-black tracking-[0.16em] text-rose-500">PASOPATI</div>
            <div className="mt-1 font-mono text-[10px] uppercase tracking-[0.14em] text-slate-500">
              Endpoint Audit Command Center
            </div>
          </div>
        </div>

        <section className="rounded-2xl border border-[#2a3140] bg-[#11151d]/95 p-6 shadow-2xl shadow-black/40 sm:p-8">
          <div className="mb-6 flex items-start gap-3">
            <span className="rounded-xl border border-rose-800/50 bg-rose-950/40 p-2.5 text-rose-300">
              <ShieldCheck className="h-5 w-5" />
            </span>
            <div>
              <h1 className="text-xl font-bold text-slate-100">Masuk ke PASOPATI</h1>
              <p className="mt-1 text-sm leading-relaxed text-slate-400">
                Masuk dengan username dan password akun yang terdaftar. Hak akses ditentukan oleh server.
              </p>
            </div>
          </div>

          {(notice || error) && (
            <div role="alert" className={`mb-4 rounded-lg border px-3 py-2.5 text-xs leading-relaxed ${error ? 'border-rose-800/60 bg-rose-950/30 text-rose-200' : 'border-amber-800/60 bg-amber-950/25 text-amber-200'}`}>
              {error || notice}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-slate-300">Username</span>
              <span className="relative block">
                <UserRound className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  value={username}
                  onChange={event => { setUsername(event.target.value); setError(null); }}
                  autoComplete="username"
                  autoCapitalize="none"
                  spellCheck={false}
                  required
                  autoFocus
                  maxLength={40}
                  placeholder="username"
                  aria-label="Username PASOPATI"
                  className="w-full rounded-lg border border-slate-700 bg-[#0b0e14] py-3 pl-10 pr-3 text-sm text-slate-100 outline-none transition focus:border-rose-500 focus:ring-2 focus:ring-rose-500/15"
                />
              </span>
            </label>

            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-slate-300">Password</span>
              <span className="relative block">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={event => { setPassword(event.target.value); setError(null); }}
                  autoComplete="current-password"
                  required
                  maxLength={256}
                  placeholder="Masukkan password"
                  aria-label="Password PASOPATI"
                  className="w-full rounded-lg border border-slate-700 bg-[#0b0e14] py-3 pl-3 pr-11 text-sm text-slate-100 outline-none transition focus:border-rose-500 focus:ring-2 focus:ring-rose-500/15"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(value => !value)}
                  aria-label={showPassword ? 'Sembunyikan password' : 'Tampilkan password'}
                  className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md p-2 text-slate-500 hover:bg-white/5 hover:text-slate-200"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </span>
            </label>

            <button
              type="submit"
              disabled={isSubmitting || !username.trim() || !password}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-rose-600 px-4 py-3 text-sm font-bold text-white shadow-lg shadow-rose-950/40 transition hover:bg-rose-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {isSubmitting ? 'Memverifikasi…' : 'Masuk'}
            </button>
          </form>

          <div className="mt-6 space-y-2 border-t border-slate-800 pt-4 text-xs leading-relaxed text-slate-500">
            <p>Password disimpan sebagai hash di server. Sesi login memakai cookie HttpOnly dan berakhir otomatis setelah 12 jam.</p>
            <p>API key dan HMAC tetap digunakan untuk integrasi agen/backend, bukan sebagai kredensial login ke dashboard.</p>
          </div>
        </section>
        <p className="mt-4 text-center font-mono text-[10px] text-slate-600">AUTENTIKASI &amp; IZIN AKSES DIKELOLA SERVER</p>
      </div>
    </main>
  );
};
