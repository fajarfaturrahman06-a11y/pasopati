import { useState, type FC, type FormEvent } from 'react';
import { Check, Copy, Eye, EyeOff, ShieldCheck, UserRound, X } from 'lucide-react';

interface OperatorTestAccessProps {
  onClose: () => void;
}

interface CreatedViewer {
  username: string;
  password: string;
}

export const OperatorTestAccess: FC<OperatorTestAccessProps> = ({ onClose }) => {
  const [username, setUsername] = useState(() => `viewer-uji-${Date.now().toString().slice(-6)}`);
  const [password, setPassword] = useState('');
  const [created, setCreated] = useState<CreatedViewer | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [copyMessage, setCopyMessage] = useState<string | null>(null);

  const createViewer = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const accountName = username.trim();
    if (!accountName || !password || isSubmitting) return;

    setIsSubmitting(true);
    setError(null);
    setCreated(null);
    setCopyMessage(null);
    try {
      const response = await fetch('/api/auth/users', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: accountName, password })
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          setError('Server menolak pembuatan akun. Pastikan sesi yang aktif adalah administrator.');
        } else if (response.status === 409) {
          setError('Username sudah digunakan. Ubah username akun uji lalu coba lagi.');
        } else {
          setError(typeof body?.reason === 'string' ? body.reason : 'Akun viewer gagal dibuat.');
        }
        return;
      }
      setCreated({ username: String(body.username || accountName), password });
    } catch {
      setError('Tidak dapat terhubung ke server PASOPATI. Coba lagi setelah koneksi pulih.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const copyCredentials = async () => {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(`Username: ${created.username}\nPassword: ${created.password}`);
      setCopyMessage('Username dan password disalin ke clipboard.');
    } catch {
      setShowPassword(true);
      setCopyMessage('Salin kredensial dari kolom di bawah.');
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/75 px-4 py-6 backdrop-blur-sm" role="presentation">
      <section
        role="dialog"
        aria-modal="true"
        aria-labelledby="operator-test-title"
        className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-2xl border border-[#303746] bg-[#11151d] p-5 shadow-2xl shadow-black/60 sm:p-7"
      >
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <span className="rounded-xl border border-cyan-800/50 bg-cyan-950/30 p-2.5 text-cyan-300">
              <UserRound className="h-5 w-5" />
            </span>
            <div>
              <h2 id="operator-test-title" className="text-lg font-bold text-slate-100">Buat akun viewer untuk uji</h2>
              <p className="mt-1 text-xs leading-relaxed text-slate-400">Akun disimpan di server dengan role <strong className="text-cyan-300">viewer</strong>; izin tetap diperiksa backend.</p>
            </div>
          </div>
          <button type="button" onClick={onClose} className="rounded-md p-2 text-slate-500 hover:bg-white/5 hover:text-white" aria-label="Tutup">
            <X className="h-4 w-4" />
          </button>
        </div>

        {!created ? (
          <form onSubmit={createViewer} className="mt-6 space-y-4">
            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-slate-300">Username viewer</span>
              <input
                value={username}
                onChange={event => setUsername(event.target.value)}
                minLength={3}
                maxLength={40}
                pattern="[A-Za-z0-9._-]{3,40}"
                autoComplete="username"
                required
                autoFocus
                className="w-full rounded-lg border border-slate-700 bg-[#0b0e14] px-3 py-2.5 text-sm text-slate-100 outline-none focus:border-cyan-500"
                placeholder="contoh: viewer-uji"
              />
            </label>
            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-slate-300">Password viewer</span>
              <input
                type="password"
                value={password}
                onChange={event => setPassword(event.target.value)}
                minLength={12}
                maxLength={256}
                autoComplete="new-password"
                required
                className="w-full rounded-lg border border-slate-700 bg-[#0b0e14] px-3 py-2.5 text-sm text-slate-100 outline-none focus:border-cyan-500"
                placeholder="Minimal 12 karakter"
              />
            </label>
            <div className="rounded-lg border border-slate-800 bg-black/20 p-3 text-xs leading-relaxed text-slate-400">
              Password di-hash dan disimpan di database server. Akun ini hanya role viewer: dapat membaca data, tetapi operasi admin tetap ditolak.
            </div>
            {error && <p role="alert" className="rounded-lg border border-rose-800/60 bg-rose-950/30 px-3 py-2.5 text-xs text-rose-200">{error}</p>}
            <div className="flex justify-end gap-2">
              <button type="button" onClick={onClose} className="rounded-lg border border-slate-700 px-4 py-2 text-xs font-semibold text-slate-300 hover:bg-white/5">Batal</button>
              <button type="submit" disabled={isSubmitting || !username.trim() || password.length < 12} className="rounded-lg bg-cyan-700 px-4 py-2 text-xs font-bold text-white hover:bg-cyan-600 disabled:cursor-not-allowed disabled:opacity-50">
                {isSubmitting ? 'Membuat akun…' : 'Buat akun viewer'}
              </button>
            </div>
          </form>
        ) : (
          <div className="mt-6 space-y-4">
            <div className="flex items-start gap-3 rounded-lg border border-emerald-800/60 bg-emerald-950/20 p-3 text-xs leading-relaxed text-emerald-200">
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
              <span>Akun <strong>{created.username}</strong> berhasil dibuat sebagai <strong>viewer</strong>. Password ini hanya ditampilkan di sesi form ini.</span>
            </div>
            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-slate-300">Username</span>
              <input readOnly value={created.username} className="w-full rounded-lg border border-slate-700 bg-[#0b0e14] px-3 py-3 text-sm text-slate-200 outline-none" />
            </label>
            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-slate-300">Password</span>
              <span className="relative block">
                <input
                  type={showPassword ? 'text' : 'password'}
                  readOnly
                  autoComplete="off"
                  value={created.password}
                  className="w-full rounded-lg border border-slate-700 bg-[#0b0e14] px-3 py-3 pr-12 font-mono text-xs text-slate-200 outline-none"
                />
                <button type="button" onClick={() => setShowPassword(value => !value)} aria-label={showPassword ? 'Sembunyikan password viewer' : 'Tampilkan password viewer'} className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md p-2 text-slate-500 hover:bg-white/5 hover:text-slate-200">
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </span>
            </label>
            <button type="button" onClick={copyCredentials} className="flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-700 px-4 py-2.5 text-xs font-bold text-white hover:bg-cyan-600">
              {copyMessage?.startsWith('Username dan') ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
              {copyMessage?.startsWith('Username dan') ? 'Tersalin' : 'Salin username & password'}
            </button>
            {copyMessage && <p role="status" className="rounded-lg border border-slate-800 bg-black/20 p-3 text-xs leading-relaxed text-slate-300">{copyMessage}</p>}
            <div className="rounded-lg border border-amber-800/50 bg-amber-950/20 p-3 text-xs leading-relaxed text-amber-100">
              Untuk tes: simpan kredensial viewer, tutup panel, tekan <strong>Keluar</strong>, lalu masuk lagi memakai akun viewer ini.
            </div>
            <div className="flex justify-end">
              <button type="button" onClick={onClose} className="rounded-lg border border-slate-700 px-4 py-2 text-xs font-semibold text-slate-300 hover:bg-white/5">Selesai</button>
            </div>
          </div>
        )}
      </section>
    </div>
  );
};
