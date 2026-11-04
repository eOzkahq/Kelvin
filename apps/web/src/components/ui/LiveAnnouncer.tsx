import React, { useState, useEffect } from "react";
import { liveAnnouncer } from "../../features/a11y";

export const LiveAnnouncer: React.FC = () => {
  const [politeMessage, setPoliteMessage] = useState("");
  const [assertiveMessage, setAssertiveMessage] = useState("");

  useEffect(() => {
    return liveAnnouncer.subscribe((message, politeness) => {
      if (politeness === "assertive") {
        setAssertiveMessage(message);
      } else {
        setPoliteMessage(message);
      }
    });
  }, []);

  return (
    <div className="sr-only" aria-hidden="false">
      <div
        role="status"
        aria-live="polite"
        aria-atomic="true"
        data-testid="live-announcer-polite"
      >
        {politeMessage}
      </div>
      <div
        role="alert"
        aria-live="assertive"
        aria-atomic="true"
        data-testid="live-announcer-assertive"
      >
        {assertiveMessage}
      </div>
    </div>
  );
};
