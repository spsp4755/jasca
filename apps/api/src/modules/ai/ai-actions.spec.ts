import { AiActionType, buildAiPrompt } from './ai-actions';
import { AiService } from './ai.service';

describe('buildAiPrompt', () => {
    it.each(Object.values(AiActionType))(
        'adds common Korean safety and report rules for %s',
        (action) => {
            const prompt = buildAiPrompt(action, '관리자 지정 프롬프트');

            expect(prompt).toContain('관리자 지정 프롬프트');
            expect(prompt).toContain('반드시 한국어로만 작성');
            expect(prompt).toContain('근거 없는 수치, CVE, URL, 참조 정보');
            expect(prompt).toContain('내부 추론 과정');
            expect(prompt).toContain('발견 없음');
            expect(prompt).toContain('확인 필요');
            expect(prompt).toContain('스캐너별로 구분');
            expect(prompt).toContain('## 요약');
            expect(prompt).toContain('## 주요 발견 사항');
            expect(prompt).toContain('## 권장 조치');
            expect(prompt).toContain('## 확인 필요 사항');
        },
    );

    it.each([
        AiActionType.SCAN_ANALYSIS,
        AiActionType.SCAN_CHANGE_ANALYSIS,
        AiActionType.REPORT_GENERATION,
    ])('adds a prioritized six-column findings table for %s', (action) => {
        const prompt = buildAiPrompt(action, '기본 프롬프트');

        expect(prompt).toContain('| ID | 이름 | 심각도 | 대상 | 상세 위치 | 참조 정보 |');
        expect(prompt).toContain('Critical, High 순으로 우선');
        expect(prompt).toContain('최대 20건');
        expect(prompt).toContain('전체 건수, 표기 건수, 생략 건수');
    });

    it('adds common rules to an administrator custom prompt at execution time', async () => {
        const prisma = {
            systemSettings: {
                findUnique: jest.fn().mockResolvedValue({
                    value: { [AiActionType.SCAN_ANALYSIS]: '관리자 지정 스캔 지침' },
                }),
            },
        };
        const service = new AiService(prisma as any);

        const prompt = await service.getPromptForAction(AiActionType.SCAN_ANALYSIS);

        expect(prompt).toContain('관리자 지정 스캔 지침');
        expect(prompt).toContain('근거 없는 수치, CVE, URL, 참조 정보');
        expect(prompt).toContain('| ID | 이름 | 심각도 | 대상 | 상세 위치 | 참조 정보 |');
    });
});
