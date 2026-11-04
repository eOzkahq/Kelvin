import React from "react";
import { Link } from "react-router-dom";
import { Button, Card } from "../../components/ui";

export const UnauthorizedPage: React.FC = () => {
  return (
    <div className="flex min-h-[60vh] items-center justify-center p-6 text-center">
      <Card className="max-w-md w-full border-red-900/40 bg-zinc-900/80 p-8 shadow-2xl">
        <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-red-950/60 border border-red-800 text-2xl font-bold text-red-400">
          401
        </div>
        <h1 className="text-xl font-bold tracking-tight text-zinc-100">Session Expired</h1>
        <p className="mt-2 text-xs text-zinc-400 leading-relaxed">
          Your authentication token has expired or is invalid. Please sign in again with your corporate
          SSO or credentials to continue.
        </p>
        <div className="mt-6 flex justify-center gap-3">
          <Link to="/login">
            <Button variant="primary">Sign In</Button>
          </Link>
        </div>
      </Card>
    </div>
  );
};

export default UnauthorizedPage;
