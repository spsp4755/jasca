import { ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import {
    AlignmentType,
    Document,
    HeadingLevel,
    Packer,
    Paragraph,
    Table,
    TableCell,
    TableRow,
    TextRun,
    WidthType,
} from 'docx';
import * as fs from 'fs';
import * as path from 'path';
import * as PDFDocument from 'pdfkit';
import { assertProjectAccess, RequestUserRole } from '../../common/authz/access-control';
import { PrismaService } from '../../prisma/prisma.service';
import { AiExecutionAccessActor, canAccessAiExecution } from './ai-execution-access';

export type AiExportFormat = 'pdf' | 'docx';
export type AiExportScope = 'summary' | 'full';

export interface AiExportActor extends AiExecutionAccessActor {
    scopedRoles?: RequestUserRole[];
    permissions?: string[];
}

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
    scope: AiExportScope;
    partial: boolean;
    statistics: AiExportStatistics;
    findings: AiExportFinding[];
    prioritizedRemediation: string[];
    evidence: string[];
}

export interface AiExportStatistics {
    total: number;
    included: number;
    omitted: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
}

export interface AiExportFinding {
    id: string;
    name: string;
    severity: string;
    target: string;
    location: string;
    reference: string;
    affectedCount?: number;
}

type AiExportFindingColumn = Exclude<keyof AiExportFinding, 'affectedCount'>;

interface BuildReportOptions {
    scope?: AiExportScope;
    partial?: boolean;
    findings?: AiExportFinding[];
    statistics?: Omit<AiExportStatistics, 'included' | 'omitted'>;
}

export interface AiExecutionExport {
    content: Buffer;
    contentType: string;
    fileName: string;
}

const REASONING_TAGS = ['think', 'thinking', 'analysis', 'reasoning'];
const REMEDIATION_HEADING = /(?:우선|조치|개선|권고|대응|해결|remediation|recommendation|action)/i;
const PARTIAL_NOTICE = '원본 스캔이 삭제되어 저장된 항목만 포함한 일부 보고서입니다.';
const SUMMARY_FINDING_LIMIT = 20;
const SEVERITY_ORDER: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    UNKNOWN: 4,
};

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

export function buildAiExportReport(
    execution: AiExportExecution,
    options: BuildReportOptions = {},
): AiExportReport {
    const cleanedResult = stripAiExportReasoning(execution.result || '');
    const cleanedError = stripAiExportReasoning(execution.error || '');
    const actionLabel = cleanText(execution.actionLabel || execution.action);
    const evidence = buildEvidence(execution);
    const context = asRecord(execution.context);
    const scope = options.scope || 'summary';
    const partial = options.partial === true;
    const availableFindings = options.findings || normalizeStoredFindings(context);
    const findings = [...availableFindings]
        .sort((left, right) => severityRank(left.severity) - severityRank(right.severity))
        .slice(0, scope === 'summary' ? SUMMARY_FINDING_LIMIT : undefined);
    const baseStatistics = options.statistics || buildStoredStatistics(context, availableFindings);
    const included = findings.reduce((total, finding) => total + findingAffectedCount(finding), 0);
    const statistics: AiExportStatistics = {
        ...baseStatistics,
        included,
        omitted: Math.max(0, baseStatistics.total - included),
    };
    const metadata = [
        { label: '실행 ID', value: execution.id },
        { label: '생성 일시', value: formatKoreanDate(execution.createdAt) },
        { label: 'AI 작업', value: `${actionLabel} (${execution.action})` },
        { label: '분석 범위', value: scope === 'summary' ? '요약 (상위 20건)' : '전체 항목' },
        { label: '상태', value: formatStatus(execution.status) },
        { label: '제공자', value: cleanText(execution.provider) || '-' },
        { label: '모델', value: cleanText(execution.model) || '-' },
        { label: '토큰', value: `입력 ${execution.inputTokens.toLocaleString('ko-KR')} / 출력 ${execution.outputTokens.toLocaleString('ko-KR')}` },
        { label: '처리 시간', value: `${(execution.durationMs / 1000).toFixed(2)}초` },
    ];
    addContextMetadata(metadata, context);
    if (partial) metadata.push({ label: '데이터 상태', value: '일부 데이터 (원본 스캔 삭제)' });

    return {
        title: `${actionLabel} AI 분석 보고서`,
        metadata,
        summary: summarizeResult(cleanedResult, cleanedError || null),
        detailedAnalysis: cleanedResult || cleanedError || '저장된 상세 분석 결과가 없습니다.',
        scope,
        partial,
        statistics,
        findings,
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
        scope: AiExportScope = 'summary',
    ): Promise<AiExecutionExport> {
        const execution = await this.prisma.aiExecution.findUnique({
            where: { id: executionId },
        });

        if (!execution) {
            throw new NotFoundException('AI execution not found');
        }

        await this.assertCanExport(execution, actor);
        const report = await this.buildReport(execution, scope, actor);
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

    private async buildReport(
        execution: AiExportExecution,
        scope: AiExportScope,
        actor: AiExportActor,
    ): Promise<AiExportReport> {
        if (scope !== 'full') return buildAiExportReport(execution, { scope });

        const scanId = stringValue(asRecord(execution.context).scanId);
        if (!scanId) return buildAiExportReport(execution, { scope, partial: true });

        const scan = await this.prisma.scanResult.findUnique({
            where: { id: scanId },
            select: {
                project: {
                    select: {
                        id: true,
                        organizationId: true,
                    },
                },
                imageRef: true,
                imageDigest: true,
                artifactName: true,
                vulnerabilities: {
                    select: {
                        pkgName: true,
                        pkgVersion: true,
                        fixedVersion: true,
                        pkgPath: true,
                        vulnerability: {
                            select: {
                                cveId: true,
                                title: true,
                                severity: true,
                                references: true,
                            },
                        },
                    },
                },
                packageLicenses: {
                    select: {
                        licenseName: true,
                        pkgName: true,
                        pkgVersion: true,
                        pkgPath: true,
                        license: {
                            select: {
                                name: true,
                                spdxId: true,
                                classification: true,
                                url: true,
                            },
                        },
                    },
                },
            },
        });
        if (!scan) return buildAiExportReport(execution, { scope, partial: true });

        assertProjectAccess({
            id: actor.id,
            organizationId: actor.organizationId,
            roles: actor.scopedRoles ?? actor.roles.map(role => ({ role })),
            isApiToken: actor.isApiToken,
            permissions: actor.permissions,
        }, scan.project);

        const findings = normalizeScanFindings(scan);
        return buildAiExportReport(execution, {
            scope,
            findings,
            statistics: countFindings(findings),
        });
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

type UnknownRecord = Record<string, unknown>;

function asRecord(value: unknown): UnknownRecord {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
        ? value as UnknownRecord
        : {};
}

function recordArray(value: unknown): UnknownRecord[] {
    return Array.isArray(value) ? value.map(asRecord) : [];
}

function stringValue(value: unknown): string {
    if (typeof value === 'string') return value.trim();
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
    return '';
}

function cleanText(value: unknown): string {
    return stripAiExportReasoning(stringValue(value));
}

function numberValue(value: unknown): number {
    return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function firstValue(...values: unknown[]): string {
    for (const value of values) {
        const text = cleanText(value);
        if (text) return text;
    }
    return '';
}

function referenceValue(value: unknown): string {
    return Array.isArray(value)
        ? value.map(cleanText).filter(Boolean).join(', ')
        : cleanText(value);
}

function severityRank(severity: string): number {
    return SEVERITY_ORDER[normalizeSeverity(severity)] ?? SEVERITY_ORDER.UNKNOWN;
}

function normalizeSeverity(value: unknown): string {
    const severity = stringValue(value).toUpperCase();
    return Object.prototype.hasOwnProperty.call(SEVERITY_ORDER, severity) ? severity : 'UNKNOWN';
}

function licenseSeverity(classification: unknown): string {
    return ({
        FORBIDDEN: 'CRITICAL',
        RESTRICTED: 'HIGH',
        RECIPROCAL: 'MEDIUM',
        NOTICE: 'LOW',
        PERMISSIVE: 'LOW',
        UNENCUMBERED: 'LOW',
    } as Record<string, string>)[stringValue(classification).toUpperCase()] || 'UNKNOWN';
}

function packageTarget(row: UnknownRecord, fallback: string): string {
    const name = firstValue(row.target, row.pkgName, fallback) || '-';
    const version = firstValue(row.installedVersion, row.pkgVersion);
    return version ? `${name}@${version}` : name;
}

function normalizeStoredFindings(context: UnknownRecord): AiExportFinding[] {
    const fallbackTarget = firstValue(context.target, context.reference);
    const fallbackLocation = firstValue(context.location, context.scanLocation);
    const fallbackReference = firstValue(context.reference);
    const vulnerabilities = [
        ...recordArray(context.findings),
        ...recordArray(context.topVulnerabilities),
        ...recordArray(context.vulnerabilities),
    ].map(row => ({
        id: firstValue(row.cveId, row.ruleId, row.id, row.spdxId, row.name) || '-',
        name: firstValue(row.title, row.name, row.policyName, row.cveId, row.ruleId) || '-',
        severity: normalizeSeverity(row.severity),
        target: packageTarget(row, fallbackTarget),
        location: firstValue(row.location, row.pkgPath, fallbackLocation) || '-',
        reference: firstValue(
            row.reference,
            referenceValue(row.references),
            row.fixedVersion ? `수정 버전: ${stringValue(row.fixedVersion)}` : '',
            fallbackReference,
        ) || '-',
        affectedCount: positiveCount(row.affectedCount),
    }));
    const licenses = normalizeStoredLicenses(context);
    const unique = new Map<string, AiExportFinding>();
    for (const finding of [...vulnerabilities, ...licenses]) {
        unique.set(`${finding.id}|${finding.target}|${finding.location}`, finding);
    }
    return [...unique.values()];
}

function normalizeStoredLicenses(context: UnknownRecord): AiExportFinding[] {
    const fallbackLocation = firstValue(context.location, context.scanLocation);
    const fallbackReference = firstValue(context.reference);
    return [
        ...recordArray(context.licenseIssues),
        ...recordArray(context.licenses),
    ].map(row => {
        const packageCount = positiveCount(row.packages || row.packageCount);
        return {
            id: firstValue(row.spdxId, row.licenseName, row.id, row.name) || '-',
            name: firstValue(row.name, row.licenseName, row.spdxId) || '-',
            severity: normalizeSeverity(row.severity) === 'UNKNOWN'
                ? licenseSeverity(row.classification)
                : normalizeSeverity(row.severity),
            target: packageTarget(row, packageCount ? `${packageCount}개 패키지` : firstValue(context.target)),
            location: firstValue(row.location, row.pkgPath, fallbackLocation) || '-',
            reference: firstValue(row.reference, row.url, row.spdxId, fallbackReference) || '-',
            affectedCount: packageCount,
        };
    });
}

function buildStoredStatistics(
    context: UnknownRecord,
    findings: AiExportFinding[],
): Omit<AiExportStatistics, 'included' | 'omitted'> {
    const summary = Object.keys(asRecord(context.summary)).length > 0
        ? asRecord(context.summary)
        : context;
    const vulnerabilityTotal = numberValue(summary.totalVulns || summary.total);
    if (!vulnerabilityTotal) return countFindings(findings);

    const licenseStatistics = countFindings(normalizeStoredLicenses(context));
    return {
        total: vulnerabilityTotal + licenseStatistics.total,
        critical: numberValue(summary.critical) + licenseStatistics.critical,
        high: numberValue(summary.high) + licenseStatistics.high,
        medium: numberValue(summary.medium) + licenseStatistics.medium,
        low: numberValue(summary.low) + licenseStatistics.low,
        unknown: numberValue(summary.unknown) + licenseStatistics.unknown,
    };
}

function countFindings(
    findings: AiExportFinding[],
): Omit<AiExportStatistics, 'included' | 'omitted'> {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    let total = 0;
    for (const finding of findings) {
        const key = normalizeSeverity(finding.severity).toLowerCase() as keyof typeof counts;
        const affectedCount = findingAffectedCount(finding);
        counts[key] += affectedCount;
        total += affectedCount;
    }
    return { total, ...counts };
}

function positiveCount(value: unknown): number | undefined {
    const count = numberValue(value);
    return count > 0 ? Math.floor(count) : undefined;
}

function findingAffectedCount(finding: AiExportFinding): number {
    return positiveCount(finding.affectedCount) || 1;
}

function normalizeScanFindings(scan: {
    imageRef: string;
    imageDigest: string | null;
    artifactName: string | null;
    vulnerabilities: Array<{
        pkgName: string;
        pkgVersion: string;
        fixedVersion: string | null;
        pkgPath: string | null;
        vulnerability: {
            cveId: string;
            title: string | null;
            severity: string;
            references: string[];
        };
    }>;
    packageLicenses: Array<{
        licenseName: string;
        pkgName: string;
        pkgVersion: string;
        pkgPath: string | null;
        license: {
            name: string;
            spdxId: string;
            classification: string;
            url: string | null;
        } | null;
    }>;
}): AiExportFinding[] {
    const fallbackLocation = scan.artifactName || scan.imageRef;
    const vulnerabilities = scan.vulnerabilities.map(row => ({
        id: cleanText(row.vulnerability.cveId) || '-',
        name: cleanText(row.vulnerability.title || row.vulnerability.cveId) || '-',
        severity: normalizeSeverity(row.vulnerability.severity),
        target: `${cleanText(row.pkgName)}@${cleanText(row.pkgVersion)}`,
        location: cleanText(row.pkgPath || fallbackLocation) || '-',
        reference: [
            row.fixedVersion ? `수정 버전: ${cleanText(row.fixedVersion)}` : '',
            row.vulnerability.references.map(cleanText).filter(Boolean).join(', '),
        ].filter(Boolean).join(' | ') || cleanText(scan.imageDigest) || '-',
    }));
    const licenses = scan.packageLicenses.map(row => ({
        id: cleanText(row.license?.spdxId || row.licenseName) || '-',
        name: cleanText(row.license?.name || row.licenseName) || '-',
        severity: licenseSeverity(row.license?.classification),
        target: `${cleanText(row.pkgName)}@${cleanText(row.pkgVersion)}`,
        location: cleanText(row.pkgPath || fallbackLocation) || '-',
        reference: cleanText(row.license?.url || row.license?.spdxId || scan.imageDigest) || '-',
    }));
    return [...vulnerabilities, ...licenses];
}

function addContextMetadata(
    metadata: Array<{ label: string; value: string }>,
    context: UnknownRecord,
): void {
    const values = [
        ['스캔 ID', context.scanId],
        ['스캐너', context.scanner],
        ['대상 위치', context.location || context.scanLocation],
        ['참조 정보', context.reference],
    ] as const;
    for (const [label, value] of values) {
        const text = cleanText(value);
        if (text) metadata.push({ label, value: text });
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
        if (index === 0) return -1;
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
            evidence.push(`저장된 입력 컨텍스트\n${JSON.stringify(execution.context, (key, value) => (
                REASONING_TAGS.includes(key.toLowerCase())
                    ? undefined
                    : typeof value === 'string' ? stripAiExportReasoning(value) : value
            ), 2)}`);
        } catch {
            evidence.push(`저장된 입력 컨텍스트\n${stripAiExportReasoning(String(execution.context))}`);
        }
    } else {
        evidence.push('저장된 입력 컨텍스트가 없습니다.');
    }
    if (execution.error) {
        evidence.push(`실행 오류\n${stripAiExportReasoning(execution.error)}`);
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
        doc.registerFont(
            'Korean',
            fontPath,
            fontPath.toLowerCase().endsWith('.ttc') ? 'NotoSansCJKkr-Regular' : undefined,
        );
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
        if (report.partial) addPdfBody(doc, PARTIAL_NOTICE);

        addPdfSectionHeading(doc, '심각도 통계');
        addPdfBody(doc, statisticsText(report.statistics));

        addPdfSectionHeading(doc, '발견 항목');
        addPdfBody(doc, findingCountText(report.statistics));
        addPdfFindingTable(doc, report.findings);

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

const PDF_TABLE_COLUMNS: Array<{
    key: AiExportFindingColumn;
    label: string;
    width: number;
}> = [
    { key: 'id', label: 'ID', width: 65 },
    { key: 'name', label: '취약점/정책 이름', width: 105 },
    { key: 'severity', label: '심각도', width: 48 },
    { key: 'target', label: '대상', width: 85 },
    { key: 'location', label: '상세 위치', width: 96 },
    { key: 'reference', label: '참조 정보', width: 100 },
];
const PDF_MAX_ROW_HEIGHT = 120;
const PDF_CELL_CHUNK_SIZE = 120;

function addPdfFindingTable(doc: PDFKit.PDFDocument, findings: AiExportFinding[]): void {
    const left = 48;
    const pageBottom = doc.page.height - 48;
    const headerHeight = 28;

    const drawHeader = () => {
        const y = doc.y;
        doc.save().fillColor('#dbeafe').rect(left, y, PDF_TABLE_COLUMNS.reduce((sum, column) => sum + column.width, 0), headerHeight).fill().restore();
        let x = left;
        for (const column of PDF_TABLE_COLUMNS) {
            doc.fillColor('#1e3a8a').fontSize(7).text(column.label, x + 4, y + 7, {
                width: column.width - 8,
                height: headerHeight - 8,
                ellipsis: true,
            });
            x += column.width;
        }
        doc.y = y + headerHeight;
    };

    if (doc.y + headerHeight > pageBottom) doc.addPage();
    drawHeader();
    for (const finding of findings) {
        doc.fontSize(7);
        const cellChunks = PDF_TABLE_COLUMNS.map(column => (
            splitPdfCell(doc, finding[column.key], column.width - 8)
        ));
        const continuationRows = Math.max(...cellChunks.map(chunks => chunks.length));

        for (let rowIndex = 0; rowIndex < continuationRows; rowIndex += 1) {
            const values = cellChunks.map(chunks => chunks[rowIndex] || '');
            const rowHeight = Math.max(24, ...values.map((value, index) => (
                pdfCellHeight(doc, value, PDF_TABLE_COLUMNS[index].width - 8)
            )));
            if (doc.y + rowHeight > pageBottom) {
                doc.addPage();
                drawHeader();
            }

            const y = doc.y;
            let x = left;
            doc.save().strokeColor('#cbd5e1').lineWidth(0.5);
            for (let index = 0; index < PDF_TABLE_COLUMNS.length; index += 1) {
                const column = PDF_TABLE_COLUMNS[index];
                doc.rect(x, y, column.width, rowHeight).stroke();
                doc.fillColor('#1e293b').fontSize(7).text(values[index], x + 4, y + 4, {
                    width: column.width - 8,
                    height: rowHeight - 8,
                    lineGap: 1,
                });
                x += column.width;
            }
            doc.restore();
            doc.y = y + rowHeight;
        }
    }
    doc.moveDown(0.5);
}

function splitPdfCell(doc: PDFKit.PDFDocument, value: string, width: number): string[] {
    const characters = Array.from(value);
    if (characters.length === 0) return [''];

    const chunks: string[] = [];
    let offset = 0;
    while (offset < characters.length) {
        let length = Math.min(PDF_CELL_CHUNK_SIZE, characters.length - offset);
        let chunk = characters.slice(offset, offset + length).join('');
        while (length > 1 && pdfCellHeight(doc, chunk, width) > PDF_MAX_ROW_HEIGHT) {
            length = Math.max(1, Math.floor(length / 2));
            chunk = characters.slice(offset, offset + length).join('');
        }
        chunks.push(chunk);
        offset += length;
    }
    return chunks;
}

function pdfCellHeight(doc: PDFKit.PDFDocument, value: string, width: number): number {
    return doc.heightOfString(value, { width, lineGap: 1 }) + 8;
}

async function renderDocx(report: AiExportReport): Promise<Buffer> {
    const children = [
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
        ...(report.partial ? [docxBody(PARTIAL_NOTICE)] : []),
        docxHeading('심각도 통계'),
        docxBody(statisticsText(report.statistics)),
        docxHeading('발견 항목'),
        docxBody(findingCountText(report.statistics)),
        docxFindingTable(report.findings),
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

function statisticsText(statistics: AiExportStatistics): string {
    return [
        `전체 ${statistics.total}건`,
        `Critical ${statistics.critical}건`,
        `High ${statistics.high}건`,
        `Medium ${statistics.medium}건`,
        `Low ${statistics.low}건`,
        `Unknown ${statistics.unknown}건`,
    ].join(' | ');
}

function findingCountText(statistics: AiExportStatistics): string {
    return `전체 ${statistics.total}건 중 ${statistics.included}건 포함, ${statistics.omitted}건 생략`;
}

function docxFindingTable(findings: AiExportFinding[]): Table {
    const columns: Array<{ key: AiExportFindingColumn; label: string }> = [
        { key: 'id', label: 'ID' },
        { key: 'name', label: '취약점/정책 이름' },
        { key: 'severity', label: '심각도' },
        { key: 'target', label: '대상' },
        { key: 'location', label: '상세 위치' },
        { key: 'reference', label: '참조 정보' },
    ];
    const cell = (text: string, bold = false) => new TableCell({
        children: [new Paragraph({
            spacing: { after: 0 },
            children: [new TextRun({
                text,
                bold,
                size: 16,
                color: bold ? '1E3A8A' : '1E293B',
                font: 'Malgun Gothic',
            })],
        })],
    });

    return new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        columnWidths: [1300, 2300, 1000, 1600, 1800, 2000],
        rows: [
            new TableRow({
                tableHeader: true,
                cantSplit: true,
                children: columns.map(column => cell(column.label, true)),
            }),
            ...findings.map(finding => new TableRow({
                children: columns.map(column => cell(finding[column.key])),
            })),
        ],
    });
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

export function resolveKoreanFontPath(): string {
    const windowsFonts = path.join(process.env.WINDIR || 'C:\\Windows', 'Fonts');
    const candidates = [
        path.join(process.cwd(), 'dist/assets/fonts/NotoSansKR.otf'),
        path.join(process.cwd(), 'src/assets/fonts/NotoSansKR.otf'),
        path.join(process.cwd(), 'dist/assets/fonts/NotoSansKR-Regular.ttf'),
        path.join(process.cwd(), 'src/assets/fonts/NotoSansKR-Regular.ttf'),
        '/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc',
        path.join(windowsFonts, 'malgun.ttf'),
        path.join(windowsFonts, 'malgunsl.ttf'),
        path.join(windowsFonts, 'malgunbd.ttf'),
    ];
    const fontPath = candidates.find(candidate => fs.existsSync(candidate));
    if (!fontPath) {
        throw new Error('한글 PDF 글꼴을 찾을 수 없습니다. 컨테이너에 fonts-noto-cjk를 설치하세요.');
    }
    return fontPath;
}
