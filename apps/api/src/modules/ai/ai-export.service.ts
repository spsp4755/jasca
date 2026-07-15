import { ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import {
    AlignmentType,
    Document,
    HeadingLevel,
    Packer,
    Paragraph,
    TextRun,
} from 'docx';
import * as fs from 'fs';
import * as path from 'path';
import * as PDFDocument from 'pdfkit';
import { PrismaService } from '../../prisma/prisma.service';
import { AiExecutionAccessActor, canAccessAiExecution } from './ai-execution-access';

export type AiExportFormat = 'pdf' | 'docx';

export type AiExportActor = AiExecutionAccessActor;

export interface AiExportExecution {
    id: string;
    userId: string | null;
    organizationId: string | null;
    action: string;
    actionLabel: string | null;
    provider: string | null;
    model: string | null;
    inputTokens: number;
    outputTokens: number;
    durationMs: number;
    status: string;
    error: string | null;
    context: unknown;
    result: string | null;
    createdAt: Date;
}

export interface AiExportReport {
    title: string;
    metadata: Array<{ label: string; value: string }>;
    summary: string;
    detailedAnalysis: string;
    prioritizedRemediation: string[];
    evidence: string[];
}

export interface AiExecutionExport {
    content: Buffer;
    contentType: string;
    fileName: string;
}

const REASONING_TAGS = ['think', 'thinking', 'analysis', 'reasoning'];
const REMEDIATION_HEADING = /(?:우선|조치|개선|권고|대응|해결|remediation|recommendation|action)/i;

export function stripAiExportReasoning(content: string): string {
    if (!content) return content;

    let cleaned = content;
    for (const tag of REASONING_TAGS) {
        cleaned = stripXmlReasoningTag(cleaned, tag);
    }

    cleaned = cleaned.replace(
        /^```[ \t]*(?:think(?:ing)?|analysis|reasoning)[ \t]*\r?\n[\s\S]*?^```[ \t]*$/gim,
        '',
    );
    cleaned = cleaned.replace(
        /(?:^|\r?\n)[ \t]*(?:Thinking|Thought|Reasoning)[ \t]*:[\s\S]*?(?=\r?\n[ \t]*\r?\n|\r?\n#{1,6}[ \t]|$)/gi,
        '',
    );

    return cleaned.replace(/\n{3,}/g, '\n\n').trim();
}

export function buildAiExportReport(execution: AiExportExecution): AiExportReport {
    const cleanedResult = stripAiExportReasoning(execution.result || '');
    const actionLabel = execution.actionLabel || execution.action;
    const evidence = buildEvidence(execution);

    return {
        title: `${actionLabel} AI 분석 보고서`,
        metadata: [
            { label: '실행 ID', value: execution.id },
            { label: '생성 일시', value: formatKoreanDate(execution.createdAt) },
            { label: 'AI 작업', value: `${actionLabel} (${execution.action})` },
            { label: '상태', value: formatStatus(execution.status) },
            { label: '제공자', value: execution.provider || '-' },
            { label: '모델', value: execution.model || '-' },
            { label: '토큰', value: `입력 ${execution.inputTokens.toLocaleString('ko-KR')} / 출력 ${execution.outputTokens.toLocaleString('ko-KR')}` },
            { label: '처리 시간', value: `${(execution.durationMs / 1000).toFixed(2)}초` },
        ],
        summary: summarizeResult(cleanedResult, execution.error),
        detailedAnalysis: cleanedResult || execution.error || '저장된 상세 분석 결과가 없습니다.',
        prioritizedRemediation: extractPrioritizedRemediation(cleanedResult),
        evidence,
    };
}

@Injectable()
export class AiExportService {
    constructor(private readonly prisma: PrismaService) {}

    async exportExecution(
        executionId: string,
        format: AiExportFormat,
        actor: AiExportActor,
    ): Promise<AiExecutionExport> {
        const execution = await this.prisma.aiExecution.findUnique({
            where: { id: executionId },
        });

        if (!execution) {
            throw new NotFoundException('AI execution not found');
        }

        await this.assertCanExport(execution, actor);
        const report = buildAiExportReport(execution);
        const content = format === 'pdf'
            ? await renderPdf(report)
            : await renderDocx(report);

        return {
            content,
            contentType: format === 'pdf'
                ? 'application/pdf'
                : 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            fileName: buildFileName(execution, format),
        };
    }

    private async assertCanExport(execution: AiExportExecution, actor: AiExportActor): Promise<void> {
        const allowed = await canAccessAiExecution(execution, actor, userId => (
            this.prisma.user.findUnique({
                where: { id: userId },
                select: { organizationId: true },
            })
        ));
        if (allowed) return;

        throw new ForbiddenException('You cannot export this AI execution');
    }
}

function stripXmlReasoningTag(text: string, tag: string): string {
    const openPrefix = `<${tag}`;
    const closeTag = `</${tag}>`;
    let result = text;

    for (;;) {
        const lower = result.toLowerCase();
        const closeIndex = lower.indexOf(closeTag);
        if (closeIndex === -1) break;

        const openIndex = findOpeningTagBefore(lower, openPrefix, closeIndex);
        const removeFrom = openIndex === -1 ? 0 : openIndex;
        result = result.slice(0, removeFrom) + result.slice(closeIndex + closeTag.length);
    }

    const lower = result.toLowerCase();
    const danglingOpen = findOpeningTagBefore(lower, openPrefix, lower.length);
    return danglingOpen === -1 ? result : result.slice(0, danglingOpen);
}

function findOpeningTagBefore(text: string, openPrefix: string, beforeIndex: number): number {
    let searchFrom = beforeIndex;
    for (;;) {
        const index = text.lastIndexOf(openPrefix, searchFrom - 1);
        if (index === -1) return -1;

        const next = text[index + openPrefix.length];
        if (next === '>' || /\s/.test(next || '')) {
            return index;
        }
        searchFrom = index;
    }
}

function summarizeResult(content: string, error: string | null): string {
    const meaningfulLine = content
        .split(/\r?\n/)
        .map(line => line.trim())
        .find(line => line && !/^#{1,6}\s/.test(line) && !/^[-*+]\s/.test(line));
    const summary = stripInlineMarkdown(meaningfulLine || error || '저장된 분석 요약이 없습니다.');
    return summary.length > 240 ? `${summary.slice(0, 240)}...` : summary;
}

function extractPrioritizedRemediation(content: string): string[] {
    const lines = content.split(/\r?\n/);
    const remediation: string[] = [];
    let inRemediationSection = false;

    for (const rawLine of lines) {
        const line = rawLine.trim();
        const heading = /^#{1,6}\s+(.+)$/.exec(line);
        if (heading) {
            inRemediationSection = REMEDIATION_HEADING.test(heading[1]);
            continue;
        }
        if (!inRemediationSection) continue;

        const item = /^(?:[-*+]\s+|\d+[.)]\s+)(.+)$/.exec(line);
        if (item?.[1]) {
            remediation.push(stripInlineMarkdown(item[1]));
        }
    }

    return remediation.length > 0
        ? remediation.slice(0, 20)
        : ['상세 분석 결과를 검토하고 담당자, 우선순위, 완료 기한을 지정하십시오.'];
}

function buildEvidence(execution: AiExportExecution): string[] {
    const evidence: string[] = [];
    if (execution.context !== null && execution.context !== undefined) {
        try {
            evidence.push(`저장된 입력 컨텍스트\n${JSON.stringify(execution.context, null, 2)}`);
        } catch {
            evidence.push(`저장된 입력 컨텍스트\n${String(execution.context)}`);
        }
    } else {
        evidence.push('저장된 입력 컨텍스트가 없습니다.');
    }
    if (execution.error) {
        evidence.push(`실행 오류\n${execution.error}`);
    }
    return evidence;
}

function formatKoreanDate(date: Date): string {
    return new Intl.DateTimeFormat('ko-KR', {
        dateStyle: 'long',
        timeStyle: 'medium',
        timeZone: 'Asia/Seoul',
    }).format(date);
}

function formatStatus(status: string): string {
    return ({ SUCCESS: '성공', ERROR: '오류', TIMEOUT: '시간 초과' } as Record<string, string>)[status] || status;
}

function buildFileName(execution: AiExportExecution, format: AiExportFormat): string {
    const action = execution.action
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '') || 'analysis';
    const date = execution.createdAt.toISOString().slice(0, 10).replace(/-/g, '');
    return `ai-report-${action}-${date}.${format}`;
}

async function renderPdf(report: AiExportReport): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
        const doc = new PDFDocument({
            size: 'A4',
            margin: 48,
            bufferPages: true,
            info: { Title: report.title, Author: 'JASCA' },
        });
        const chunks: Buffer[] = [];

        doc.on('data', chunk => chunks.push(Buffer.from(chunk)));
        doc.on('error', reject);
        doc.on('end', () => resolve(Buffer.concat(chunks)));

        const fontPath = resolveKoreanFontPath();
        doc.registerFont('Korean', fontPath);
        doc.font('Korean');

        doc.fillColor('#0f172a').fontSize(22).text(report.title, { align: 'center' });
        doc.moveDown(0.5);
        doc.fillColor('#64748b').fontSize(9).text('JASCA AI SECURITY REPORT', { align: 'center', characterSpacing: 1.2 });
        doc.moveDown(1.5);

        addPdfSectionHeading(doc, '메타데이터');
        for (const item of report.metadata) {
            doc.fillColor('#475569').fontSize(9).text(`${item.label}  `, { continued: true });
            doc.fillColor('#0f172a').text(item.value);
            doc.moveDown(0.25);
        }

        addPdfSectionHeading(doc, '요약');
        addPdfBody(doc, report.summary);

        addPdfSectionHeading(doc, '상세 분석');
        addPdfMarkdown(doc, report.detailedAnalysis);

        addPdfSectionHeading(doc, '우선순위 개선 조치');
        report.prioritizedRemediation.forEach((item, index) => {
            addPdfBody(doc, `${index + 1}. ${item}`);
        });

        addPdfSectionHeading(doc, '근거');
        report.evidence.forEach(item => addPdfBody(doc, item));

        const range = doc.bufferedPageRange();
        for (let page = range.start; page < range.start + range.count; page += 1) {
            doc.switchToPage(page);
            doc.fillColor('#94a3b8').fontSize(8).text(
                `${page + 1} / ${range.count}`,
                48,
                doc.page.height - 32,
                { align: 'center', width: doc.page.width - 96 },
            );
        }
        doc.end();
    });
}

function addPdfSectionHeading(doc: PDFKit.PDFDocument, title: string): void {
    doc.moveDown(1.1);
    doc.fillColor('#1d4ed8').fontSize(14).text(title);
    doc.moveDown(0.35);
    doc.strokeColor('#bfdbfe').lineWidth(1).moveTo(48, doc.y).lineTo(doc.page.width - 48, doc.y).stroke();
    doc.moveDown(0.55);
}

function addPdfBody(doc: PDFKit.PDFDocument, text: string): void {
    doc.fillColor('#1e293b').fontSize(10).text(text, { lineGap: 3 });
    doc.moveDown(0.45);
}

function addPdfMarkdown(doc: PDFKit.PDFDocument, markdown: string): void {
    for (const rawLine of markdown.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line) {
            doc.moveDown(0.35);
            continue;
        }
        const heading = /^#{1,6}\s+(.+)$/.exec(line);
        if (heading) {
            doc.fillColor('#334155').fontSize(11).text(stripInlineMarkdown(heading[1]));
            doc.moveDown(0.25);
            continue;
        }
        const bullet = /^(?:[-*+]\s+|\d+[.)]\s+)(.+)$/.exec(line);
        addPdfBody(doc, bullet ? `• ${stripInlineMarkdown(bullet[1])}` : stripInlineMarkdown(line));
    }
}

async function renderDocx(report: AiExportReport): Promise<Buffer> {
    const children: Paragraph[] = [
        new Paragraph({
            alignment: AlignmentType.CENTER,
            spacing: { after: 120 },
            children: [new TextRun({ text: report.title, bold: true, size: 34, font: 'Malgun Gothic' })],
        }),
        new Paragraph({
            alignment: AlignmentType.CENTER,
            spacing: { after: 360 },
            children: [new TextRun({ text: 'JASCA AI SECURITY REPORT', color: '64748B', size: 18, font: 'Arial' })],
        }),
        docxHeading('메타데이터'),
        ...report.metadata.map(item => new Paragraph({
            spacing: { after: 80 },
            children: [
                new TextRun({ text: `${item.label}  `, bold: true, color: '475569', font: 'Malgun Gothic' }),
                new TextRun({ text: item.value, color: '0F172A', font: 'Malgun Gothic' }),
            ],
        })),
        docxHeading('요약'),
        docxBody(report.summary),
        docxHeading('상세 분석'),
        ...docxMarkdown(report.detailedAnalysis),
        docxHeading('우선순위 개선 조치'),
        ...report.prioritizedRemediation.map((item, index) => docxBody(`${index + 1}. ${item}`)),
        docxHeading('근거'),
        ...report.evidence.flatMap(item => item.split(/\r?\n/).map(line => docxBody(line))),
    ];
    const document = new Document({
        creator: 'JASCA',
        title: report.title,
        description: 'JASCA AI 분석 결과 보고서',
        sections: [{ children }],
    });

    return Buffer.from(await Packer.toBuffer(document));
}

function docxHeading(text: string): Paragraph {
    return new Paragraph({
        heading: HeadingLevel.HEADING_1,
        spacing: { before: 320, after: 160 },
        children: [new TextRun({ text, bold: true, color: '1D4ED8', size: 28, font: 'Malgun Gothic' })],
    });
}

function docxBody(text: string): Paragraph {
    return new Paragraph({
        spacing: { after: 120, line: 320 },
        children: [new TextRun({ text, color: '1E293B', size: 20, font: 'Malgun Gothic' })],
    });
}

function docxMarkdown(markdown: string): Paragraph[] {
    return markdown
        .split(/\r?\n/)
        .filter(line => line.trim().length > 0)
        .map(rawLine => {
            const line = rawLine.trim();
            const heading = /^#{1,6}\s+(.+)$/.exec(line);
            if (heading) {
                return new Paragraph({
                    heading: HeadingLevel.HEADING_2,
                    spacing: { before: 180, after: 100 },
                    children: [new TextRun({ text: stripInlineMarkdown(heading[1]), bold: true, color: '334155', font: 'Malgun Gothic' })],
                });
            }
            const bullet = /^(?:[-*+]\s+|\d+[.)]\s+)(.+)$/.exec(line);
            return docxBody(bullet ? `• ${stripInlineMarkdown(bullet[1])}` : stripInlineMarkdown(line));
        });
}

function stripInlineMarkdown(text: string): string {
    return text
        .replace(/!\[([^\]]*)\]\([^)]*\)/g, '$1')
        .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '$1 ($2)')
        .replace(/[*_~`]/g, '')
        .trim();
}

function resolveKoreanFontPath(): string {
    const candidates = [
        path.join(process.cwd(), 'dist/assets/fonts/NotoSansKR.otf'),
        path.join(process.cwd(), 'src/assets/fonts/NotoSansKR.otf'),
        path.join(process.cwd(), 'dist/assets/fonts/NotoSansKR-Regular.ttf'),
        path.join(process.cwd(), 'src/assets/fonts/NotoSansKR-Regular.ttf'),
    ];
    const fontPath = candidates.find(candidate => fs.existsSync(candidate));
    if (!fontPath) {
        throw new Error('Korean PDF font asset not found');
    }
    return fontPath;
}
