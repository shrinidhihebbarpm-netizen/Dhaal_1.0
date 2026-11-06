import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface ErrorBoundaryProps {
  viewName: string;
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class ViewErrorBoundary extends Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Log full diagnostic details server-side/console only; do not leak to public UI
    console.error(
      `[Dhaal View Error Boundary] Error in ${this.props.viewName}:`,
      error,
      errorInfo
    );
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="editorial-panel p-6 sm:p-8 space-y-4 my-4 border border-[#d42020] dark:border-[#ef4444]">
          <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.1em] text-[#d42020] dark:text-[#ef4444] font-bold">
            <AlertTriangle className="w-4 h-4" />
            <span>{this.props.viewName} Shield Intercepted an Error</span>
          </div>
          <h2 className="font-display italic text-2xl font-semibold text-[#1a1a1a] dark:text-[#f2f0eb]">
            This section encountered an unexpected issue.
          </h2>
          <p className="text-xs sm:text-sm text-[#6b6b6b] dark:text-[#9ca3af] leading-relaxed max-w-xl">
            The rest of Dhaal remains fully operational. You can switch to other
            views or click reload below to reinitialize this console without
            losing your saved telemetry.
          </p>
          <div className="pt-2 flex items-center gap-3">
            <button
              type="button"
              onClick={this.handleReset}
              className="px-4 py-2.5 bg-[#1a1a1a] dark:bg-[#f2f0eb] hover:bg-[#333333] dark:hover:bg-white text-white dark:text-[#0f1115] font-mono text-xs uppercase tracking-[0.1em] font-bold flex items-center gap-2 cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Retry {this.props.viewName}</span>
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
