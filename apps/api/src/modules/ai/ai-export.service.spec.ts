import { ForbiddenException } from '@nestjs/common';
import * as fs from 'fs';
import * as PDFDocument from 'pdfkit';
import { inflateRawSync } from 'zlib';
import {
    AiExportService,
    AiExportExecution,
    buildAiExportReport,
    resolveKoreanFontPath,
    stripAiExportReasoning,
} from './ai-export.service';

const storedFindings = Array.from({ length: 25 }, (_, index) => ({
    cveId: `CVE-2026-${String(index + 1).padStart(4, '0')}`,
    severity: index < 8 ? 'MEDIUM' : index < 18 ? 'HIGH' : 'CRITICAL',
    pkgName: `package-${index + 1}`,
    installedVersion: '1.0.0',
    fixedVersion: '1.0.1',
    title: `테스트 취약점 ${index + 1}`,
}));

const savedExecution = {
    id: 'execution-1',
    userId: 'user-1',
    organizationId: 'org-1',
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
        scanId: 'scan-1',
        scanner: 'Trivy',
        location: 'registry.example.test/team/api:latest',
        reference: 'sha256:abc123',
        target: 'registry.example.test/team/api:latest',
        summary: {
            totalVulns: 30,
            critical: 7,
            high: 10,
            medium: 8,
            low: 5,
            unknown: 0,
        },
        topVulnerabilities: storedFindings,
        licenseIssues: [{
            name: 'GNU Affero General Public License',
            spdxId: 'AGPL-3.0-only',
            classification: 'FORBIDDEN',
            packages: 1,
        }],
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

function createExportService(execution: AiExportExecution = savedExecution) {
    const prisma = {
        aiExecution: {
            findUnique: jest.fn().mockResolvedValue(execution),
        },
        scanResult: {
            findUnique: jest.fn().mockResolvedValue(null),
        },
        user: {
            findUnique: jest.fn(),
        },
    } as any;

    return { prisma, service: new AiExportService(prisma) };
}

describe('AI execution exports', () => {
    afterEach(() => jest.restoreAllMocks());

    it('removes model reasoning while preserving the final answer', () => {
        const cleaned = stripAiExportReasoning(savedExecution.result);

        expect(cleaned).toContain('치명적 취약점 두 건이 확인되었습니다.');
        expect(cleaned).not.toMatch(/internal chain|hidden analysis|hidden reasoning|hidden markdown|hidden prefixed/i);
        expect(cleaned).not.toMatch(/<\/?(?:think|thinking|reasoning)>|```thinking/i);
    });

    it('builds every section of the shared Korean report template', () => {
        const report = buildAiExportReport(savedExecution) as any;

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
        expect(report.statistics).toEqual(expect.objectContaining({
            total: 31,
            included: 20,
            omitted: 11,
            critical: 8,
            high: 10,
        }));
        expect(report.findings).toHaveLength(20);
        expect(report.findings[0]).toEqual(expect.objectContaining({
            id: 'CVE-2026-0019',
            severity: 'CRITICAL',
        }));
        expect(report.scope).toBe('summary');
        expect(report.partial).toBe(false);
    });

    it.each([
        ['pdf', 'application/pdf', '%PDF'],
        ['docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'PK'],
    ] as const)('exports an owned execution as %s', async (format, contentType, signature) => {
        const { service } = createExportService();

        const exported = await (service as any).exportExecution('execution-1', format, {
            id: 'user-1',
            roles: ['DEVELOPER'],
            isApiToken: false,
        }, 'summary');

        expect(exported.contentType).toBe(contentType);
        expect(exported.fileName).toMatch(new RegExp(`^ai-report-scan-analysis-20260715\\.${format}$`));
        expect(exported.content.subarray(0, signature.length).toString()).toBe(signature);
        expect(exported.content.length).toBeGreaterThan(1_000);
    });

    it('renders a real six-column DOCX table with Korean text and no reasoning', async () => {
        const { service } = createExportService();

        const exported = await (service as any).exportExecution('execution-1', 'docx', {
            id: 'user-1',
            roles: ['DEVELOPER'],
            isApiToken: false,
        }, 'summary');
        const documentXml = readZipEntry(exported.content, 'word/document.xml');

        expect(documentXml).toContain('<w:tbl>');
        expect(documentXml).toContain('발견 항목');
        expect(documentXml).toContain('취약점/정책 이름');
        expect(documentXml).toContain('상세 위치');
        expect(documentXml).toContain('참조 정보');
        expect(documentXml).not.toMatch(/hidden reasoning|<reasoning>/i);
        expect(documentXml.match(/<w:gridCol/g)).toHaveLength(6);
    });

    it('loads every original scan finding for full exports', async () => {
        const { prisma, service } = createExportService();
        const vulnerabilities = Array.from({ length: 28 }, (_, index) => ({
            pkgName: `full-package-${index + 1}`,
            pkgVersion: '2.0.0',
            fixedVersion: '2.0.1',
            pkgPath: `/app/full-${index + 1}`,
            vulnerability: {
                cveId: `CVE-FULL-${index + 1}`,
                title: `전체 취약점 ${index + 1}`,
                severity: index < 2 ? 'CRITICAL' : 'MEDIUM',
                references: [`https://example.test/CVE-FULL-${index + 1}`],
            },
        }));
        prisma.scanResult.findUnique.mockResolvedValue({
            id: 'scan-1',
            imageRef: 'registry.example.test/team/api:latest',
            imageDigest: 'sha256:abc123',
            artifactName: null,
            sourceType: 'TRIVY_JSON',
            summary: { totalVulns: 28, critical: 2, high: 0, medium: 26, low: 0, unknown: 0 },
            vulnerabilities,
            packageLicenses: [{
                pkgName: 'licensed-package',
                pkgVersion: '3.0.0',
                pkgPath: '/app/license',
                licenseName: 'AGPL-3.0-only',
                license: {
                    name: 'GNU Affero General Public License',
                    spdxId: 'AGPL-3.0-only',
                    classification: 'FORBIDDEN',
                    url: 'https://spdx.org/licenses/AGPL-3.0-only.html',
                },
            }],
        });
        const textSpy = jest.spyOn((PDFDocument as any).prototype, 'text');

        const exported = await (service as any).exportExecution('execution-1', 'pdf', {
            id: 'user-1',
            roles: ['DEVELOPER'],
            isApiToken: false,
        }, 'full');
        const renderedText = textSpy.mock.calls.map(call => String(call[0]));
        const pageCount = (exported.content.toString('latin1').match(/\/Type \/Page\b/g) || []).length;

        expect(prisma.scanResult.findUnique).toHaveBeenCalledWith(expect.objectContaining({
            where: { id: 'scan-1' },
        }));
        expect(renderedText).toContain('CVE-FULL-28');
        expect(renderedText).toContain('AGPL-3.0-only');
        expect(renderedText.filter(text => text === 'ID').length).toBeGreaterThan(1);
        expect(renderedText).toContain('발견 항목');
        expect(pageCount).toBeGreaterThan(1);
        expect(renderedText.join('\n')).not.toMatch(/hidden reasoning|<reasoning>/i);
        textSpy.mockRestore();
    });

    it('falls back to stored findings and marks a deleted scan full export as partial', async () => {
        const { service } = createExportService();
        const textSpy = jest.spyOn((PDFDocument as any).prototype, 'text');

        await (service as any).exportExecution('execution-1', 'pdf', {
            id: 'user-1',
            roles: ['DEVELOPER'],
            isApiToken: false,
        }, 'full');
        const renderedText = textSpy.mock.calls.map(call => String(call[0]));

        expect(renderedText).toContain('CVE-2026-0001');
        expect(renderedText.join('\n')).toContain('원본 스캔이 삭제되어 저장된 항목만 포함한 일부 보고서입니다.');
        textSpy.mockRestore();
    });

    it('accepts the Linux Noto CJK TTC path', async () => {
        const linuxFont = '/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc';
        const existsSpy = jest.spyOn(fs, 'existsSync').mockImplementation(candidate => candidate === linuxFont);

        expect(resolveKoreanFontPath()).toBe(linuxFont);

        existsSpy.mockRestore();
    });

    it('returns an actionable Korean error when every Korean font candidate is absent', async () => {
        const existsSpy = jest.spyOn(fs, 'existsSync').mockReturnValue(false);

        expect(() => resolveKoreanFontPath()).toThrow(
            '한글 PDF 글꼴을 찾을 수 없습니다. 컨테이너에 fonts-noto-cjk를 설치하세요.',
        );

        existsSpy.mockRestore();
    });

    it('rejects exporting another user\'s saved execution', async () => {
        const { service } = createExportService();

        await expect(service.exportExecution('execution-1', 'pdf', {
            id: 'user-2',
            roles: ['DEVELOPER'],
            isApiToken: false,
        })).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('allows ORG_ADMIN export from the execution organization snapshot without a user lookup', async () => {
        const { prisma, service } = createExportService({
            ...savedExecution,
            userId: 'api-token:token-1',
        });

        await expect(service.exportExecution('execution-1', 'docx', {
            id: 'org-admin-1',
            organizationId: 'org-1',
            roles: ['ORG_ADMIN'],
            isApiToken: false,
        })).resolves.toEqual(expect.objectContaining({
            contentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        }));
        expect(prisma.user.findUnique).not.toHaveBeenCalled();
    });

    it('uses the user lookup fallback only for a legacy execution without an organization snapshot', async () => {
        const { prisma, service } = createExportService({
            ...savedExecution,
            organizationId: null,
        });
        prisma.user.findUnique.mockResolvedValue({ organizationId: 'org-1' });

        await expect(service.exportExecution('execution-1', 'docx', {
            id: 'org-admin-1',
            organizationId: 'org-1',
            roles: ['ORG_ADMIN'],
            isApiToken: false,
        })).resolves.toEqual(expect.objectContaining({ content: expect.any(Buffer) }));
        expect(prisma.user.findUnique).toHaveBeenCalledWith({
            where: { id: savedExecution.userId },
            select: { organizationId: true },
        });
    });

    it('does not use the legacy fallback when an execution has another organization snapshot', async () => {
        const { prisma, service } = createExportService();

        await expect(service.exportExecution('execution-1', 'pdf', {
            id: 'org-admin-2',
            organizationId: 'org-2',
            roles: ['ORG_ADMIN'],
            isApiToken: false,
        })).rejects.toBeInstanceOf(ForbiddenException);
        expect(prisma.user.findUnique).not.toHaveBeenCalled();
    });

    it('keeps API token owner and SYSTEM_ADMIN export access', async () => {
        const tokenExecution = {
            ...savedExecution,
            userId: 'api-token:token-1',
        };
        const tokenService = createExportService(tokenExecution).service;
        const systemService = createExportService(tokenExecution).service;

        await expect(tokenService.exportExecution('execution-1', 'docx', {
            id: 'api-token:token-1',
            organizationId: 'org-1',
            roles: [],
            isApiToken: true,
        })).resolves.toEqual(expect.objectContaining({ content: expect.any(Buffer) }));
        await expect(systemService.exportExecution('execution-1', 'docx', {
            id: 'system-admin-1',
            roles: ['SYSTEM_ADMIN'],
            isApiToken: false,
        })).resolves.toEqual(expect.objectContaining({ content: expect.any(Buffer) }));
    });
});

function readZipEntry(buffer: Buffer, entryName: string): string {
    const endSignature = 0x06054b50;
    let endOffset = buffer.length - 22;
    while (endOffset >= 0 && buffer.readUInt32LE(endOffset) !== endSignature) endOffset -= 1;
    if (endOffset < 0) throw new Error('ZIP end record not found');

    let offset = buffer.readUInt32LE(endOffset + 16);
    while (buffer.readUInt32LE(offset) === 0x02014b50) {
        const compression = buffer.readUInt16LE(offset + 10);
        const compressedSize = buffer.readUInt32LE(offset + 20);
        const nameLength = buffer.readUInt16LE(offset + 28);
        const extraLength = buffer.readUInt16LE(offset + 30);
        const commentLength = buffer.readUInt16LE(offset + 32);
        const localOffset = buffer.readUInt32LE(offset + 42);
        const name = buffer.subarray(offset + 46, offset + 46 + nameLength).toString('utf8');
        if (name === entryName) {
            const localNameLength = buffer.readUInt16LE(localOffset + 26);
            const localExtraLength = buffer.readUInt16LE(localOffset + 28);
            const dataOffset = localOffset + 30 + localNameLength + localExtraLength;
            const data = buffer.subarray(dataOffset, dataOffset + compressedSize);
            if (compression !== 8) return data.toString('utf8');
            return inflateRawSync(data).toString('utf8');
        }
        offset += 46 + nameLength + extraLength + commentLength;
    }
    throw new Error(`ZIP entry not found: ${entryName}`);
}
