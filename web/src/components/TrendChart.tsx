import { useEffect, useId, useRef, useState } from "react";
import type { TrendPoint } from "../api/types";
import { fmtMonthDay, fmtNumber } from "../lib/format";
import Icon from "./Icon";

const SERIES = [
  { key: "critical", label: "CRITICAL" },
  { key: "high", label: "HIGH" },
  { key: "medium", label: "MEDIUM" },
  { key: "low", label: "LOW" },
] as const;

const PAD = { l: 40, r: 14, t: 12, b: 28 };

/** Smallest round axis top >= max whose 4 gridlines land on round numbers (e.g. 104 -> 120, 37 -> 40, 3 -> 4). */
export function niceMax(max: number, ticks = 4): number {
  if (max <= 0) return ticks;
  const raw = max / ticks;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10].map((m) => m * mag).find((s) => s >= raw)!;
  return Math.max(ticks, Math.ceil(step) * ticks);
}

/**
 * Open findings per day by severity (the dashboard's 30 points, 4 series) as inline SVG.
 * Screen readers get the <title>/<desc> summary; "표로 보기" switches to the same numbers as a table.
 */
export default function TrendChart({ data, height = 232 }: { data: TrendPoint[]; height?: number }) {
  const id = useId();
  const box = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(640);
  const [hover, setHover] = useState<number | null>(null);
  const [asTable, setAsTable] = useState(false);

  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setWidth(Math.max(280, Math.round(e.contentRect.width))));
    ro.observe(el);
    return () => ro.disconnect();
  }, [asTable]);

  const n = data.length;
  const last = data[n - 1];
  const top = niceMax(Math.max(0, ...data.flatMap((d) => SERIES.map((s) => d[s.key]))));
  const iw = width - PAD.l - PAD.r;
  const ih = height - PAD.t - PAD.b;
  const x = (i: number) => PAD.l + (n <= 1 ? iw / 2 : (i * iw) / (n - 1));
  const y = (v: number) => PAD.t + ih - (v / top) * ih;
  const ticks = [0, 1, 2, 3, 4].map((i) => (top * i) / 4);
  const labelIdx = n > 1 ? [0, Math.round((n - 1) / 3), Math.round((2 * (n - 1)) / 3), n - 1] : [0];
  const summary = last
    ? `${fmtMonthDay(data[0].date)}부터 ${fmtMonthDay(last.date)}까지 ${n}일. 마지막 날 열린 결과: ` +
      SERIES.map((s) => `${s.label} ${last[s.key]}건`).join(", ") + "."
    : "";

  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    const px = e.clientX - r.left;
    setHover(n <= 1 ? 0 : Math.min(n - 1, Math.max(0, Math.round(((px - PAD.l) / iw) * (n - 1)))));
  };

  return (
    <div className="trend">
      <div className="trend-top">
        <ul className="trend-legend" aria-label="범례">
          {SERIES.map((s) => (
            <li key={s.key}>
              <span className={`trend-swatch line-${s.key}`} aria-hidden="true" />
              {s.label}
              {last && <b className="num">{fmtNumber(last[s.key])}</b>}
            </li>
          ))}
        </ul>
        <button type="button" className="btn btn-ghost btn-sm" onClick={() => setAsTable((v) => !v)} aria-pressed={asTable}>
          <Icon name={asTable ? "chart" : "table"} size={14} />
          {asTable ? "차트로 보기" : "표로 보기"}
        </button>
      </div>

      {asTable ? (
        <div className="table-wrap table-scroll" style={{ maxHeight: height + 20, overflow: "auto" }}>
          <table className="table table-dense">
            <caption className="sr-only">최근 {n}일 심각도별 열린 결과</caption>
            <thead>
              <tr><th scope="col">날짜</th>{SERIES.map((s) => <th key={s.key} scope="col" style={{ textAlign: "right" }}>{s.label}</th>)}</tr>
            </thead>
            <tbody>
              {[...data].reverse().map((d) => (
                <tr key={d.date}>
                  <th scope="row" className="num">{d.date}</th>
                  {SERIES.map((s) => <td key={s.key} className="num" style={{ textAlign: "right" }}>{fmtNumber(d[s.key])}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="trend-plot" ref={box}>
          <svg width={width} height={height} role="img" aria-labelledby={`${id}-t ${id}-d`} onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
            <title id={`${id}-t`}>최근 {n}일 심각도별 열린 결과 추세</title>
            <desc id={`${id}-d`}>{summary}</desc>
            <g className="trend-grid" aria-hidden="true">
              {ticks.map((t) => (
                <g key={t}>
                  <line x1={PAD.l} x2={width - PAD.r} y1={y(t)} y2={y(t)} />
                  <text x={PAD.l - 8} y={y(t)} dy="0.32em" textAnchor="end">{fmtNumber(Math.round(t))}</text>
                </g>
              ))}
              {labelIdx.map((i) => (
                <text key={i} x={x(i)} y={height - 8} textAnchor={i === 0 ? "start" : i === n - 1 ? "end" : "middle"}>{fmtMonthDay(data[i].date)}</text>
              ))}
            </g>
            {SERIES.map((s) => (
              <polyline key={s.key} className={`trend-line line-${s.key}`} fill="none"
                points={data.map((d, i) => `${x(i).toFixed(1)},${y(d[s.key]).toFixed(1)}`).join(" ")} />
            ))}
            {hover !== null && (
              <g aria-hidden="true">
                <line className="trend-cursor" x1={x(hover)} x2={x(hover)} y1={PAD.t} y2={PAD.t + ih} />
                {SERIES.map((s) => <circle key={s.key} className={`trend-dot line-${s.key}`} cx={x(hover)} cy={y(data[hover][s.key])} r={3.5} />)}
              </g>
            )}
          </svg>
          {hover !== null && (
            <div className="trend-tip" aria-hidden="true"
              style={{ left: Math.min(x(hover) + 12, width - 150), top: PAD.t }}>
              <div className="trend-tip-date">{data[hover].date}</div>
              {SERIES.map((s) => (
                <div key={s.key} className="trend-tip-row">
                  <span className={`trend-swatch line-${s.key}`} />{s.label}<b className="num">{fmtNumber(data[hover][s.key])}</b>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
