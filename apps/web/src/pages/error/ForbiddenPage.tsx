import React from "react";
import { Link } from "react-router-dom";
import { Button, Card } from "../../components/ui";

export const ForbiddenPage: React.FC = () => {
  return (
    <div className="flex min-h-[60vh] items-center justify-center p-6 text-center">
      <Card className="max-w-md w-full border-amber-900/40 bg-zinc-900/80 p-8 shadow-2xl">
        <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-amber-950/60 border border-amber-800 text-2xl font-bold text-amber-400">
          403
        </div>
        <h1 className="text-xl font-bold tracking-tight text-zinc-100">Access Restricted</h1>
        <p className="mt-2 text-xs text-zinc-400 leading-relaxed">
          Your current account role does not possess the RBAC authorization required to view or
          modify this resource. Contact your Organization Administrator to adjust your role privileges.
        </p>
        <div className="mt-6 flex justify-center gap-3">
          <Link to="/">
            <Button variant="primary">Return to Dashboard</Button>
          </Link>
          <Link to="/profile">
            <Button variant="secondary">View My Permissions</Button>
          </Link>
        </div>
      </Card>
    </div>
  );
};

export default ForbiddenPage;
