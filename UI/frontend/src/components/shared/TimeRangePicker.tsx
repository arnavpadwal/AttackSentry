import { TIME_RANGES } from '@/config/constants';

interface TimeRangePickerProps {
  value: string;
  onChange: (range: string) => void;
}

export default function TimeRangePicker({ value, onChange }: TimeRangePickerProps) {
  return (
    <div className="inline-flex gap-1 rounded-[10px] border border-[var(--color-surface-border)] bg-white p-1">
      {TIME_RANGES.map((r) => (
        <button
          key={r.value}
          onClick={() => onChange(r.value)}
          className="rounded-md transition-all font-medium"
          style={{
            padding: '6px 14px',
            fontSize: 13,
            backgroundColor: value === r.value ? 'var(--color-p-deep)' : 'transparent',
            color: value === r.value ? '#fff' : 'var(--color-text-secondary)',
          }}
          onMouseEnter={(e) => {
            if (value !== r.value) e.currentTarget.style.backgroundColor = 'var(--color-p-bg)';
          }}
          onMouseLeave={(e) => {
            if (value !== r.value) e.currentTarget.style.backgroundColor = 'transparent';
          }}
        >
          {r.value}
        </button>
      ))}
    </div>
  );
}
