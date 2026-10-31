/**
 * MagnificationDock Component
 *
 * A macOS-inspired dock component with fluid magnification effects,
 * spring physics, and tooltips. Tailored to Dhaal's Editorial AI Security
 * aesthetic (Light & Dark modes).
 */

import React, {
  Children,
  cloneElement,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';

export type SpringOptions = {
  mass?: number;
  stiffness?: number;
  damping?: number;
};

export type DockItemData = {
  id?: string;
  icon: React.ReactNode;
  label: React.ReactNode;
  onClick: () => void;
  isActive?: boolean;
  className?: string;
};

export type DockProps = {
  items: DockItemData[];
  className?: string;
  distance?: number;
  panelHeight?: number;
  baseItemSize?: number;
  dockHeight?: number;
  magnification?: number;
  spring?: SpringOptions;
};

function useSpringValue(
  target: number,
  spring: SpringOptions,
  minBound = 24,
  maxBound = 160
) {
  const [value, setValue] = useState(target);
  const stateRef = useRef({ current: target, velocity: 0, target });
  stateRef.current.target = target;

  const mass = Math.max(0.05, spring.mass ?? 0.1);
  const stiffness = spring.stiffness ?? 150;
  const damping = spring.damping ?? 12;

  useEffect(() => {
    let rafId: number;
    let lastTime = performance.now();

    const step = (now: number) => {
      const totalDt = Math.min(Math.max((now - lastTime) / 1000, 0.001), 0.032);
      lastTime = now;

      const s = stateRef.current;
      // Sub-step integration at 1ms intervals for unconditional stability with low mass
      const subStepDt = 0.001;
      let remaining = totalDt;

      while (remaining > 0) {
        const dt = Math.min(remaining, subStepDt);
        const displacement = s.current - s.target;
        const springForce = -stiffness * displacement;
        const dampingForce = -damping * s.velocity;
        const acceleration = (springForce + dampingForce) / mass;

        s.velocity += acceleration * dt;
        s.current += s.velocity * dt;
        remaining -= dt;
      }

      s.current = Math.max(minBound, Math.min(maxBound, s.current));

      if (Math.abs(s.velocity) < 0.08 && Math.abs(s.target - s.current) < 0.15) {
        s.current = s.target;
        s.velocity = 0;
        setValue(s.target);
        return;
      }

      setValue(s.current);
      rafId = requestAnimationFrame(step);
    };

    rafId = requestAnimationFrame(step);
    return () => cancelAnimationFrame(rafId);
  }, [target, mass, stiffness, damping, minBound, maxBound]);

  return value;
}

type DockItemProps = {
  id?: string;
  className?: string;
  children: React.ReactNode;
  onClick?: () => void;
  isActive?: boolean;
  mouseX: number;
  spring: SpringOptions;
  distance: number;
  baseItemSize: number;
  magnification: number;
};

function DockItem({
  id,
  children,
  className = '',
  onClick,
  isActive = false,
  mouseX,
  spring,
  distance,
  magnification,
  baseItemSize,
}: DockItemProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [isHovered, setIsHovered] = useState(false);

  const targetSize = useMemo(() => {
    if (!Number.isFinite(mouseX) || !ref.current) {
      return baseItemSize;
    }
    const rect = ref.current.getBoundingClientRect();
    const itemCenterX = rect.x + rect.width / 2;
    const mouseDistance = mouseX - itemCenterX;
    const absDist = Math.abs(mouseDistance);
    if (absDist >= distance) {
      return baseItemSize;
    }
    const ratio = 1 - absDist / distance;
    return baseItemSize + (magnification - baseItemSize) * ratio;
  }, [mouseX, distance, magnification, baseItemSize]);

  const size = useSpringValue(
    targetSize,
    spring,
    baseItemSize,
    magnification
  );

  return (
    <div
      ref={ref}
      id={id}
      style={{
        width: `${size}px`,
        height: `${size}px`,
      }}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      onFocus={() => setIsHovered(true)}
      onBlur={() => setIsHovered(false)}
      onClick={onClick}
      className={`relative inline-flex items-center justify-center rounded-full border shadow-lg cursor-pointer transition-colors ${
        isActive
          ? 'bg-[#1a1a1a] dark:bg-[#f2f0eb] text-white dark:text-[#0f1115] border-[#d42020] dark:border-[#ff5c5c] ring-2 ring-[#d42020]/40 dark:ring-[#ff5c5c]/40'
          : 'bg-white dark:bg-[#161920] text-[#1a1a1a] dark:text-[#f2f0eb] border-[#ddd] dark:border-[#262b36] hover:border-[#1a1a1a] dark:hover:border-[#f2f0eb]'
      } ${className}`}
      tabIndex={0}
      role="button"
      aria-pressed={isActive}
      aria-haspopup="true"
    >
      {Children.map(children, (child) =>
        React.isValidElement(child)
          ? cloneElement(
              child as React.ReactElement<{ isHovered?: boolean }>,
              { isHovered }
            )
          : child
      )}
      {isActive && (
        <span
          aria-hidden="true"
          className="absolute -bottom-1.5 left-1/2 -translate-x-1/2 w-1.5 h-1.5 rounded-full bg-[#d42020] dark:bg-[#ff5c5c]"
        />
      )}
    </div>
  );
}

type DockLabelProps = {
  className?: string;
  children: React.ReactNode;
  isHovered?: boolean;
};

function DockLabel({ children, className = '', isHovered }: DockLabelProps) {
  if (!isHovered) return null;

  return (
    <div
      className={`${className} absolute -top-10 left-1/2 -translate-x-1/2 -translate-y-1 w-fit whitespace-pre rounded-md border border-[#ddd] dark:border-[#262b36] bg-[#1a1a1a] dark:bg-[#f2f0eb] px-2.5 py-1 font-mono text-[11px] uppercase tracking-[0.08em] text-white dark:text-[#0f1115] font-bold shadow-md pointer-events-none transition-all duration-150`}
      role="tooltip"
    >
      {children}
    </div>
  );
}

type DockIconProps = {
  className?: string;
  children: React.ReactNode;
  isHovered?: boolean;
};

function DockIcon({ children, className = '' }: DockIconProps) {
  return (
    <div className={`flex items-center justify-center ${className}`}>
      {children}
    </div>
  );
}

export function MagnificationDock({
  items,
  className = '',
  spring = { mass: 0.1, stiffness: 150, damping: 12 },
  magnification = 72,
  distance = 200,
  panelHeight = 68,
  dockHeight = 256,
  baseItemSize = 50,
}: DockProps) {
  const [mouseX, setMouseX] = useState<number>(Infinity);
  const [isDockHovered, setIsDockHovered] = useState(false);

  const maxHeight = useMemo(
    () => Math.max(dockHeight, magnification + magnification / 2 + 4),
    [dockHeight, magnification]
  );
  const targetHeight = isDockHovered ? Math.min(maxHeight, 108) : panelHeight;
  const height = useSpringValue(targetHeight, spring, panelHeight, 120);

  return (
    <div
      style={{ height: `${height}px`, scrollbarWidth: 'none' }}
      className="flex max-w-full items-end justify-center pointer-events-none"
    >
      <div
        onMouseMove={({ clientX }) => {
          setIsDockHovered(true);
          setMouseX(clientX);
        }}
        onMouseLeave={() => {
          setIsDockHovered(false);
          setMouseX(Infinity);
        }}
        className={`${className} pointer-events-auto flex items-end w-fit gap-3.5 rounded-3xl border border-[#ddd] dark:border-[#262b36] bg-[#f8f7f4]/95 dark:bg-[#161920]/95 backdrop-blur-md pb-2.5 px-5 shadow-2xl`}
        style={{ height: `${panelHeight}px` }}
        role="toolbar"
        aria-label="Dhaal Navigation Dock"
      >
        {items.map((item, index) => (
          <DockItem
            key={index}
            id={item.id}
            onClick={item.onClick}
            isActive={item.isActive}
            className={item.className}
            mouseX={mouseX}
            spring={spring}
            distance={distance}
            magnification={magnification}
            baseItemSize={baseItemSize}
          >
            <DockIcon>{item.icon}</DockIcon>
            <DockLabel>{item.label}</DockLabel>
          </DockItem>
        ))}
      </div>
    </div>
  );
}

export default MagnificationDock;
