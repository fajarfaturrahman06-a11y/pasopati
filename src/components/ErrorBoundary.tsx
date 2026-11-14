import React from 'react';

interface ErrorBoundaryProps {
  children: React.ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('[PASOPATI] UI ErrorBoundary caught error:', error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#070a10] text-slate-100 flex items-center justify-center p-6">
          <div className="max-w-xl w-full bg-slate-900 border border-rose-800 rounded-lg p-6 text-center">
            <h1 className="text-lg font-bold font-mono text-rose-300">SISTEM PASOPATI MENGALAMI ERROR</h1>
            <p className="text-xs text-slate-400 mt-2 font-mono">
              {this.state.error?.message || 'Unknown UI error'}
            </p>
            <button
              onClick={() => window.location.reload()}
              className="mt-6 px-4 py-2 rounded-md text-xs font-bold font-mono bg-rose-600 hover:bg-rose-500 text-white border border-rose-400"
            >
              RELOAD INTERFACE
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
