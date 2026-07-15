import { ForbiddenException } from '@nestjs/common';
import {
    AiExportService,
    buildAiExportReport,
    stripAiExportReasoning,
} from './ai-export.service';

const savedExecution = {
    id: 'execution-1',
    userId: 'user-1',
    action: 'scan.analysis',
    actionLabel: '스캔 결과 분석',
    provider: 'openai',
    model: 'security-model',
    inputTokens: 120,
    outputTokens: 80,
    durationMs: 2450,
    status: 'SUCCESS',
    error: null,
    context: {
        target: 'registry.example.test/team/api:latest',
        critical: 2,
    },
    result: [
        '<think>internal chain of thought</think>',
        '<thinking>hidden analysis</thinking>',
        '<reasoning>hidden reasoning</reasoning>',
        '```thinking',
        'hidden markdown thinking',
        '```',
        'Reasoning:',
        'hidden prefixed reasoning',
        '',
        '## 상세 분석',
        '치명적 취약점 두 건이 확인되었습니다.',
        '',
        '## 우선 조치',
        '- 외부 노출 서비스를 먼저 패치합니다.',
        '- 수정 후 이미지를 다시 스캔합니다.',
    ].join('\n'),
    createdAt: new Date('2026-07-15T03:00:00.000Z'),
};

describe('AI execution exports', () => {
    it('removes model reasoning while preserving the final answer', () => {
        const cleaned = stripAiExportReasoning(savedExecution.result);

        expect(cleaned).toContain('치명적 취약점 두 건이 확인되었습니다.');
        expect(cleaned).not.toMatch(/internal chain|hidden analysis|hidden reasoning|hidden markdown|hidden prefixed/i);
        expect(cleaned).not.toMatch(/<\/?(?:think|thinking|reasoning)>|```thinking/i);
    });

    it('builds every section of the shared Korean report template', () => {
        const report = buildAiExportReport(savedExecution);

        expect(report.title).toBe('스캔 결과 분석 AI 분석 보고서');
        expect(report.metadata).toEqual(expect.arrayContaining([
            { label: '실행 ID', value: 'execution-1' },
            { label: '모델', value: 'security-model' },
        ]));
        expect(report.summary).toContain('치명적 취약점 두 건');
        expect(report.detailedAnalysis).toContain('## 상세 분석');
        expect(report.prioritizedRemediation).toEqual([
            '외부 노출 서비스를 먼저 패치합니다.',
            '수정 후 이미지를 다시 스캔합니다.',
        ]);
        expect(report.evidence.join('\n')).toContain('registry.example.test/team/api:latest');
    });

    it.each([
        ['pdf', 'application/pdf', '%PDF'],
        ['docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'PK'],
    ] as const)('exports an owned execution as %s', async (format, contentType, signature) => {
        const prisma = {
            aiExecution: {
                findUnique: jest.fn().mockResolvedValue(savedExecution),
            },
            user: {
                findUnique: jest.fn(),
            },
        } as any;
        const service = new AiExportService(prisma);

        const exported = await service.exportExecution('execution-1', format, {
            id: 'user-1',
            roles: ['DEVELOPER'],
        });

        expect(exported.contentType).toBe(contentType);
        expect(exported.fileName).toMatch(new RegExp(`^ai-report-scan-analysis-20260715\\.${format}$`));
        expect(exported.content.subarray(0, signature.length).toString()).toBe(signature);
    });

    it('rejects exporting another user\'s saved execution', async () => {
        const prisma = {
            aiExecution: {
                findUnique: jest.fn().mockResolvedValue(savedExecution),
            },
            user: {
                findUnique: jest.fn(),
            },
        } as any;
        const service = new AiExportService(prisma);

        await expect(service.exportExecution('execution-1', 'pdf', {
            id: 'user-2',
            roles: ['DEVELOPER'],
        })).rejects.toBeInstanceOf(ForbiddenException);
    });
});
