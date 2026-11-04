import React from "react";
import { Link } from "react-router-dom";
import { Button, Card } from "../../components/ui";

export const NotFoundPage: React.FC = () => {
  return (
    <div className="flex min-h-[60vh] items-center justify-center p-6 text-center">
      <Card className="max-w-md w-full border-zinc-800 bg-zinc-900/80 p-8 shadow-2xl">
        <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-cyan-950/60 border border-cyan-800 text-2xl font-bold text-cyan-400">
          404
        </div>
        <h1 className="text-xl font-bold tracking-tight text-zinc-100">Page Not Found</h1>
        <p className="mt-2 text-xs text-zinc-400 leading-relaxed">
          The security asset, report, or configuration page you requested does not exist or has been
          relocated to another workspace.
        </p>
        <div className="mt-6 flex justify-center gap-3">
          <Link to="/">
            <Button variant="primary">Return to Dashboard</Button>
          </Link>
          <Link to="/assessments">
            <Button variant="secondary">View Assessments</Button>
          </Link>
        </div>
      </Card>
    </div>
  );
};

export default NotFoundPage;
