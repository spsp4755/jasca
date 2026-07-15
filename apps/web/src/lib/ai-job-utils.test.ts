import test from 'node:test';
import assert from 'node:assert/strict';
const {
    buildAiResult,
    buildAiExportUrl,
    getDownloadFileName,
    isAiJobActive,
    partializeAiState,
    validateDownloadPayload,
} = await import('./ai-job-utils' + '.ts');

test('queued and running jobs are active while terminal states are not', () => {
    assert.equal(isAiJobActive('QUEUED'), true);
    assert.equal(isAiJobActive('RUNNING'), true);
    assert.equal(isAiJobActive('SUCCESS'), false);
    assert.equal(isAiJobActive('CANCELLED'), false);
});

test('successful job response becomes a compatible AI result', () => {
    const result = buildAiResult({
        id: 'job-1',
        action: 'scan.analysis',
        status: 'SUCCESS',
        result: '# 분석 결과',
        model: 'internal-model',
        inputTokens: 10,
        outputTokens: 20,
        durationMs: 123,
        createdAt: '2026-07-15T00:00:00.000Z',
    });

    assert.equal(result?.id, 'job-1');
    assert.equal(result?.content, '# 분석 결과');
    assert.equal(result?.metadata?.model, 'internal-model');
    assert.equal(result?.createdAt.toISOString(), '2026-07-15T00:00:00.000Z');
});

test('empty or JSON download payload is rejected', async () => {
    await assert.rejects(
        validateDownloadPayload(new Blob([]), 'application/pdf'),
        /비어 있습니다/,
    );
    await assert.rejects(
        validateDownloadPayload(
            new Blob([JSON.stringify({ message: 'export failed' })], { type: 'application/json' }),
            'application/json',
        ),
        /export failed/,
    );
});

test('non-empty document payload is accepted', async () => {
    const blob = new Blob(['document'], { type: 'application/pdf' });
    assert.equal(await validateDownloadPayload(blob, 'application/pdf'), blob);
});

test('persisted AI state contains serializable pending metadata but no controller', () => {
    const state = {
        results: {},
        pendingJobs: {
            'job-1': {
                id: 'job-1',
                contextKey: 'scan.analysis:scan-1',
                action: 'scan.analysis' as const,
                status: 'RUNNING' as const,
                createdAt: '2026-07-15T00:00:00.000Z',
                updatedAt: '2026-07-15T00:00:01.000Z',
            },
        },
        abortControllers: { 'job-1': new AbortController() },
    };

    const persisted = partializeAiState(state);
    assert.deepEqual(Object.keys(persisted), ['results', 'pendingJobs']);
    assert.doesNotThrow(() => JSON.stringify(persisted));
    assert.equal('abortControllers' in persisted, false);
});

test('download filename prefers UTF-8 Content-Disposition value', () => {
    assert.equal(
        getDownloadFileName(
            "attachment; filename=report.pdf; filename*=UTF-8''JASCA-%EB%B3%B4%EA%B3%A0%EC%84%9C.pdf",
            'fallback.pdf',
        ),
        'JASCA-보고서.pdf',
    );
    assert.equal(getDownloadFileName(null, 'fallback.pdf'), 'fallback.pdf');
});

test('AI export URL always includes the selected scope', () => {
    assert.equal(
        buildAiExportUrl('job/1', 'docx', 'full'),
        '/api/ai/history/job%2F1/export?format=docx&scope=full',
    );
});
