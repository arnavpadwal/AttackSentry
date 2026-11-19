export default function LoadingSkeleton({ rows = 3, className = '' }: { rows?: number; className?: string }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }} className={className}>
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="animate-shimmer"
          style={{
            height:       i === 0 ? 48 : 40,
            borderRadius: 8,
            opacity:      1 - i * 0.15,
          }}
        />
      ))}
    </div>
  );
}
