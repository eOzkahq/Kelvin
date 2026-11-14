import { useEffect, useRef, useState } from "react";

export const CustomCursor = () => {
  const dotRef = useRef<HTMLDivElement>(null);
  const ringRef = useRef<HTMLDivElement>(null);
  const ringOuterRef = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(false);
  const [isTouch, setIsTouch] = useState(true);

  useEffect(() => {
    const checkTouch = () => {
      return (
        "ontouchstart" in window ||
        navigator.maxTouchPoints > 0 ||
        (window.matchMedia && window.matchMedia("(max-width: 900px)").matches)
      );
    };
    setIsTouch(checkTouch());
  }, []);

  useEffect(() => {
    if (isTouch) return;

    const handleMouseMove = (e: MouseEvent) => {
      if (!visible) {
        setVisible(true);
      }
      const mx = e.clientX;
      const my = e.clientY;

      if (dotRef.current) {
        dotRef.current.style.transform = `translate3d(${mx}px, ${my}px, 0) translate(-50%, -50%)`;
      }
      if (ringRef.current) {
        ringRef.current.style.transform = `translate3d(${mx}px, ${my}px, 0) translate(-50%, -50%)`;
      }
      if (ringOuterRef.current) {
        ringOuterRef.current.style.transform = `translate3d(${mx}px, ${my}px, 0) translate(-50%, -50%)`;
      }
    };

    window.addEventListener("mousemove", handleMouseMove, { passive: true });

    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
    };
  }, [isTouch, visible]);

  if (isTouch || !visible) return null;

  return (
    <>
      <div id="cursor-dot" ref={dotRef} className="active" aria-hidden="true" />
      <div id="cursor-ring" ref={ringRef} className="active" aria-hidden="true" />
      <div id="cursor-ring-outer" ref={ringOuterRef} className="active" aria-hidden="true" />
    </>
  );
};
