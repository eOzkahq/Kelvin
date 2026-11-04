import { Component, type ErrorInfo, type ReactNode } from "react";
import { Button } from "./Button";
import { Card } from "./Card";

export interface ErrorBoundaryProps {
  children: ReactNode;
  fallback?: ReactNode;
  onReset?: () => void;
  title?: string;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  public state: ErrorBoundaryState = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    if (process.env.NODE_ENV !== "production") {
      // Safely log in development only
      // eslint-disable-next-line no-console
      console.error("ErrorBoundary caught an unhandled rendering error:", error, errorInfo);
    }
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  public render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="flex min-h-[300px] w-full items-center justify-center p-6" role="alert">
          <Card className="max-w-md w-full border-red-900/50 bg-zinc-900/90 p-6 text-center shadow-xl">
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-red-950/60 text-red-400 border border-red-800 text-xl font-bold">
              ⚠️
            </div>
            <h2 className="text-lg font-semibold text-zinc-100">
              {this.props.title || "Something went wrong in this view"}
            </h2>
            <p className="mt-2 text-xs text-zinc-400">
              An unexpected client error occurred while rendering this component. The rest of the
              application remains fully operational.
            </p>
            {this.state.error?.message && (
              <div className="mt-3 overflow-x-auto rounded bg-zinc-950 p-2 text-left font-mono text-[11px] text-red-400 border border-zinc-800">
                {this.state.error.message}
              </div>
            )}
            <div className="mt-5 flex items-center justify-center gap-3">
              <Button variant="secondary" onClick={this.handleReset}>
                Try Again
              </Button>
              <Button variant="primary" onClick={() => (window.location.href = "/")}>
                Go to Dashboard
              </Button>
            </div>
          </Card>
        </div>
      );
    }

    return this.props.children;
  }
}
