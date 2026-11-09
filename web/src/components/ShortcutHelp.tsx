import { SHORTCUTS, keyCaps } from "../lib/hotkeys";
import Dialog from "./Dialog";

export default function ShortcutHelp({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Dialog open={open} onClose={onClose} title="단축키" size="sm"
      description="입력 칸 밖에서 누르세요. 두 글자 단축키는 차례로 누릅니다.">
      <dl className="shortcuts">
        {SHORTCUTS.map((s) => (
          <div key={s.keys} className="shortcut-row">
            <dt>{s.label}</dt>
            <dd>
              {keyCaps(s.keys).map((k, i) => (
                <span key={i}>{i > 0 && <span className="kbd-then">다음</span>}<kbd>{k}</kbd></span>
              ))}
            </dd>
          </div>
        ))}
      </dl>
    </Dialog>
  );
}
