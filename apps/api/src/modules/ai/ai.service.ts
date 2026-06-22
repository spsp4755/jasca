import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { AiActionType, AI_PROMPTS, AI_ACTION_METADATA } from './ai-actions';

export interface RiskSummary {
    projectId: string;
    projectName: string;
    summary: string;
    riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    keyFindings: string[];
    recommendations: string[];
    generatedAt: Date;
}

export interface RemediationGuide {
    cveId: string;
    title: string;
    severity: string;
    description: string;
    steps: string[];
    references: string[];
    estimatedEffort: 'LOW' | 'MEDIUM' | 'HIGH';
    generatedAt: Date;
}

export interface AiExecutionResult {
    id: string;
    action: AiActionType;
    content: string;
    summary?: string;
    model?: string;
    inputTokens?: number;
    outputTokens?: number;
    usedPrompt?: string;
    /** Whether mock data was used instead of real AI */
    isMock?: boolean;
    /** Reason for using mock data (if applicable) */
    mockReason?: string;
}

export interface TokenEstimate {
    inputTokens: number;
    outputTokens: number;
}

@Injectable()
export class AiService {
    private readonly logger = new Logger(AiService.name);

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Get AI settings from database
     */
    private async getAiSettings(): Promise<{
        provider: string;
        apiUrl: string;
        apiKey?: string;
        model: string;
        enabled: boolean;
        timeout: number;
        maxTokens: number;
    } | null> {
        try {
            const settings = await this.prisma.systemSettings.findUnique({
                where: { key: 'ai' },
            });
            if (!settings) return null;

            const value = settings.value as Record<string, unknown>;
            return {
                provider: (value.provider as string) || 'ollama',
                apiUrl: (value.apiUrl as string) || 'http://localhost:11434',
                apiKey: value.apiKey as string | undefined,
                // Use summaryModel or remediationModel field from settings
                model: (value.summaryModel as string) || (value.model as string) || 'llama3.2',
                enabled: (value.enableAutoSummary as boolean) ?? (value.enabled as boolean) ?? true,
                // Timeout in seconds, default 60s
                timeout: (value.timeout as number) || 60,
                // Validate maxTokens: minimum 100, maximum 16000, default 2048
                maxTokens: Math.max(100, Math.min(16000, (value.maxTokens as number) || 2048)),
            };
        } catch (error) {
            this.logger.warn('Failed to fetch AI settings:', error);
            return null;
        }
    }

    /**
     * Get AI settings for public access (without sensitive data like API key)
     */
    async getPublicSettings(): Promise<{
        provider: string;
        apiUrl: string;
        apiKey?: string;
        model: string;
        enabled: boolean;
        timeout: number;
        maxTokens: number;
    } | null> {
        return this.getAiSettings();
    }

    /**
     * Get prompt for action (custom from DB or default)
     */
    async getPromptForAction(action: AiActionType): Promise<string> {
        try {
            const customPrompts = await this.prisma.systemSettings.findUnique({
                where: { key: 'ai_prompts' },
            });

            if (customPrompts) {
                const prompts = customPrompts.value as Record<string, string>;
                if (prompts[action]) {
                    return prompts[action];
                }
            }
        } catch (error) {
            this.logger.warn('Failed to fetch custom prompts:', error);
        }

        // Return default prompt
        return AI_PROMPTS[action] || '';
    }

    /**
     * Get all prompts (custom + defaults)
     */
    async getAllPrompts(): Promise<Record<string, { prompt: string; isCustom: boolean; label: string; description: string }>> {
        let customPrompts: Record<string, string> = {};

        try {
            const settings = await this.prisma.systemSettings.findUnique({
                where: { key: 'ai_prompts' },
            });
            if (settings) {
                customPrompts = settings.value as Record<string, string>;
            }
        } catch (error) {
            this.logger.warn('Failed to fetch custom prompts:', error);
        }

        const result: Record<string, { prompt: string; isCustom: boolean; label: string; description: string }> = {};

        for (const action of Object.values(AiActionType)) {
            const metadata = AI_ACTION_METADATA[action];
            result[action] = {
                prompt: customPrompts[action] || AI_PROMPTS[action] || '',
                isCustom: !!customPrompts[action],
                label: metadata?.label || action,
                description: metadata?.description || '',
            };
        }

        return result;
    }

    /**
     * Update prompt for action
     */
    async updatePrompt(action: AiActionType, prompt: string): Promise<void> {
        let customPrompts: Record<string, string> = {};

        try {
            const settings = await this.prisma.systemSettings.findUnique({
                where: { key: 'ai_prompts' },
            });
            if (settings) {
                customPrompts = settings.value as Record<string, string>;
            }
        } catch (error) {
            // Continue with empty prompts
        }

        customPrompts[action] = prompt;

        await this.prisma.systemSettings.upsert({
            where: { key: 'ai_prompts' },
            update: { value: customPrompts as any },
            create: { key: 'ai_prompts', value: customPrompts as any },
        });
    }

    /**
     * Reset prompt to default
     */
    async resetPrompt(action: AiActionType): Promise<void> {
        try {
            const settings = await this.prisma.systemSettings.findUnique({
                where: { key: 'ai_prompts' },
            });

            if (settings) {
                const customPrompts = settings.value as Record<string, string>;
                delete customPrompts[action];

                await this.prisma.systemSettings.update({
                    where: { key: 'ai_prompts' },
                    data: { value: customPrompts as any },
                });
            }
        } catch (error) {
            this.logger.warn('Failed to reset prompt:', error);
        }
    }

    /**
     * Get AI execution history
     */
    async getExecutionHistory(options: {
        action?: string;
        status?: string;
        userId?: string;
        limit?: number;
        offset?: number;
    } = {}) {
        const where: any = {};
        if (options.action) where.action = options.action;
        if (options.status) where.status = options.status;
        if (options.userId) where.userId = options.userId;

        const [results, total] = await Promise.all([
            this.prisma.aiExecution.findMany({
                where,
                orderBy: { createdAt: 'desc' },
                take: options.limit || 50,
                skip: options.offset || 0,
            }),
            this.prisma.aiExecution.count({ where }),
        ]);

        return { results, total };
    }

    /**
     * Get AI usage statistics
     */
    async getExecutionStats(days = 7) {
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - days);

        const executions = await this.prisma.aiExecution.findMany({
            where: {
                createdAt: { gte: startDate },
            },
            orderBy: { createdAt: 'desc' },
        });

        const byAction: Record<string, number> = {};
        const byStatus: Record<string, number> = {};
        const byDay: Record<string, number> = {};
        let totalTokens = 0;
        let totalDuration = 0;

        for (const exec of executions) {
            byAction[exec.action] = (byAction[exec.action] || 0) + 1;
            byStatus[exec.status] = (byStatus[exec.status] || 0) + 1;
            
            const day = exec.createdAt.toISOString().split('T')[0];
            byDay[day] = (byDay[day] || 0) + 1;

            totalTokens += exec.inputTokens + exec.outputTokens;
            totalDuration += exec.durationMs;
        }

        return {
            total: executions.length,
            totalTokens,
            avgDuration: executions.length > 0 ? Math.round(totalDuration / executions.length) : 0,
            successRate: executions.length > 0 
                ? Math.round(((byStatus['SUCCESS'] || 0) / executions.length) * 100) 
                : 0,
            byAction,
            byStatus,
            trend: Object.entries(byDay)
                .map(([date, count]) => ({ date, count }))
                .sort((a, b) => a.date.localeCompare(b.date)),
        };
    }
    /**
     * Execute AI action with given context
     */
    async executeAction(
        action: AiActionType,
        context: Record<string, unknown>,
        userId: string,
    ): Promise<AiExecutionResult> {
        this.logger.log(`Executing AI action: ${action} for user: ${userId}`);
        const startTime = Date.now();

        // Get AI settings from database
        const aiSettings = await this.getAiSettings();

        // Get the prompt template (custom or default)
        const promptTemplate = await this.getPromptForAction(action);
        const metadata = AI_ACTION_METADATA[action];

        // Build the full prompt with context
        const maskedContext = this.maskPii(JSON.stringify(context, null, 2));
        const fullPrompt = `${promptTemplate}\n\n**컨텍스트 데이터:**\n\`\`\`json\n${maskedContext}\n\`\`\``;

        let content: string;
        let modelName: string;
        let providerName: string = 'mock';
        let status: 'SUCCESS' | 'ERROR' | 'TIMEOUT' = 'SUCCESS';
        let errorMessage: string | undefined;
        let isMock = false;
        let mockReason: string | undefined;

        // If AI settings exist and enabled, use real AI
        if (aiSettings?.enabled && aiSettings.apiUrl) {
            providerName = aiSettings.provider;
            try {
                const result = await this.callAiProvider(aiSettings, fullPrompt);
                content = result.content;
                modelName = result.model;
                this.logger.log(`AI call successful using ${aiSettings.provider}/${modelName}`);
            } catch (error) {
                this.logger.error('AI call failed, falling back to mock:', error);
                content = await this.generateMockResponse(action, context);
                modelName = 'mock-model-v1 (fallback)';
                status = 'ERROR';
                errorMessage = error instanceof Error ? error.message : 'Unknown error';
                isMock = true;
                mockReason = `AI API 호출 실패: ${errorMessage}`;
                if (errorMessage.includes('timed out')) {
                    status = 'TIMEOUT';
                    mockReason = 'AI 서버 응답 시간 초과';
                }
            }
        } else {
            // Fallback to mock response
            this.logger.warn('AI settings not configured, using mock response');
            content = await this.generateMockResponse(action, context);
            modelName = 'mock-model-v1';
            isMock = true;
            mockReason = !aiSettings ? 'AI 설정이 구성되지 않았습니다' : 'AI 기능이 비활성화되어 있습니다';
        }

        // Estimate tokens
        const estimate = this.estimateTokens(action, context);
        const durationMs = Date.now() - startTime;

        // Log execution to database
        try {
            await this.prisma.aiExecution.create({
                data: {
                    userId,
                    action,
                    actionLabel: metadata?.label || action,
                    provider: providerName,
                    model: modelName,
                    inputTokens: estimate.inputTokens,
                    outputTokens: estimate.outputTokens,
                    durationMs,
                    status,
                    error: errorMessage,
                    result: content.substring(0, 5000), // Limit result size
                },
            });
        } catch (dbError) {
            this.logger.warn('Failed to log AI execution to database:', dbError);
        }

        // Log the execution
        this.logger.log(`AI execution completed. Model: ${modelName}, Duration: ${durationMs}ms, Tokens: ${estimate.inputTokens}/${estimate.outputTokens}`);

        return {
            id: crypto.randomUUID(),
            action,
            content,
            summary: this.generateSummaryFromContent(content),
            model: modelName,
            inputTokens: estimate.inputTokens,
            outputTokens: estimate.outputTokens,
            usedPrompt: promptTemplate,
            isMock,
            mockReason,
        };
    }

    /**
     * Call AI provider (Ollama, vLLM, OpenAI, etc.)
     */
    private async callAiProvider(
        settings: { provider: string; apiUrl: string; apiKey?: string; model: string; timeout?: number; maxTokens: number },
        prompt: string,
    ): Promise<{ content: string; model: string }> {
        const controller = new AbortController();
        // Use configurable timeout from settings (default: 60s)
        const timeoutSeconds = settings.timeout || 60;
        const timeoutMs = timeoutSeconds * 1000;
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

        try {
            switch (settings.provider) {
                case 'ollama':
                    return await this.callOllama(settings.apiUrl, settings.model, prompt, settings.maxTokens, controller.signal);
                case 'vllm':
                    return await this.callVllm(settings.apiUrl, settings.model, prompt, settings.apiKey, settings.maxTokens, controller.signal);
                case 'custom':
                    return await this.callVllm(settings.apiUrl, settings.model, prompt, settings.apiKey, settings.maxTokens, controller.signal);
                case 'openai':
                    return await this.callOpenAi(settings.apiUrl, settings.model, prompt, settings.apiKey!, settings.maxTokens, controller.signal);
                case 'anthropic':
                    return await this.callAnthropic(settings.apiUrl, settings.model, prompt, settings.apiKey!, settings.maxTokens, controller.signal);
                default:
                    throw new Error(`Unsupported AI provider: ${settings.provider}`);
            }
        } catch (error) {
            if (error instanceof Error && error.name === 'AbortError') {
                throw new Error(`AI provider request timed out after ${timeoutSeconds} seconds`);
            }
            throw error;
        } finally {
            clearTimeout(timeoutId);
        }
    }

    /**
     * Call Anthropic API
     */
    private async callAnthropic(
        apiUrl: string,
        model: string,
        prompt: string,
        apiKey: string,
        maxTokens: number,
        signal: AbortSignal,
    ): Promise<{ content: string; model: string }> {
        const response = await fetch(`${apiUrl}/v1/messages`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': apiKey,
                'anthropic-version': '2023-06-01',
            },
            body: JSON.stringify({
                model,
                max_tokens: maxTokens,
                messages: [
                    { role: 'user', content: prompt },
                ],
            }),
            signal,
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Anthropic API error: ${response.status} - ${errorText}`);
        }

        const data = await response.json() as { content: Array<{ text: string }>; model: string };
        return {
            content: data.content[0]?.text || '',
            model: data.model || model,
        };
    }

    /**
     * Call Ollama API
     */
    private async callOllama(
        apiUrl: string,
        model: string,
        prompt: string,
        maxTokens: number,
        signal: AbortSignal,
    ): Promise<{ content: string; model: string }> {
        const systemPrompt = '당신은 보안 취약점 분석 전문가입니다. 반드시 한국어로 답변하세요. 절대로 JSON이나 코드 형식으로 답변하지 마세요. 마크다운 형식(##, -, 이모지 등)을 사용하여 읽기 쉬운 자연어 보고서 형태로 작성하세요.';
        
        const response = await fetch(`${apiUrl}/api/generate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                model,
                system: systemPrompt,
                prompt,
                stream: false,
                options: {
                    temperature: 0.7,
                    top_p: 0.9,
                    num_predict: maxTokens,
                },
            }),
            signal,
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Ollama API error: ${response.status} - ${errorText}`);
        }

        const data = await response.json() as { response: string; model: string };
        return {
            content: data.response,
            model: data.model || model,
        };
    }

    /**
     * Call vLLM API (OpenAI-compatible)
     */
    private async callVllm(
        apiUrl: string,
        model: string,
        prompt: string,
        apiKey: string | undefined,
        maxTokens: number,
        signal: AbortSignal,
    ): Promise<{ content: string; model: string }> {
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;

        // Normalize API URL (remove trailing slash)
        const normalizedUrl = apiUrl.replace(/\/$/, '');
        const v1BaseUrl = normalizedUrl.endsWith('/v1') ? normalizedUrl : `${normalizedUrl}/v1`;
        const rootBaseUrl = normalizedUrl.endsWith('/v1') ? normalizedUrl.slice(0, -3) : normalizedUrl;
        
        // Try chat completions first (newer vLLM versions), fallback to completions
        const endpoints = [
            `${v1BaseUrl}/chat/completions`,
            `${v1BaseUrl}/completions`,
            `${rootBaseUrl}/chat/completions`,
            `${rootBaseUrl}/completions`,
        ];
        
        let lastError: Error | null = null;
        
        for (const endpoint of endpoints) {
            try {
                const isChatEndpoint = endpoint.includes('/chat/');
                const body = isChatEndpoint
                    ? {
                        model,
                        messages: [
                            { role: 'system', content: '당신은 보안 취약점 분석 전문가입니다. 반드시 한국어로 답변하세요. 절대로 JSON이나 코드 형식으로 답변하지 마세요. 마크다운 형식(##, -, 이모지 등)을 사용하여 읽기 쉬운 자연어 보고서 형태로 작성하세요.' },
                            { role: 'user', content: prompt },
                        ],
                        max_tokens: maxTokens,
                        temperature: 0.7,
                    }
                    : {
                        model,
                        prompt,
                        max_tokens: maxTokens,
                        temperature: 0.7,
                    };

                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers,
                    body: JSON.stringify(body),
                    signal,
                });

                if (!response.ok) {
                    const errorText = await response.text().catch(() => 'Unknown error');
                    // If 404, try next endpoint
                    if (response.status === 404) {
                        lastError = new Error(`Endpoint not found: ${endpoint}`);
                        continue;
                    }
                    throw new Error(`vLLM API error: ${response.status} - ${errorText}`);
                }

                const data = await response.json();
                
                // Handle chat completions response
                if (isChatEndpoint && data.choices?.[0]?.message?.content) {
                    return {
                        content: data.choices[0].message.content,
                        model: data.model || model,
                    };
                }
                
                // Handle completions response
                if (data.choices?.[0]?.text) {
                    return {
                        content: data.choices[0].text,
                        model: data.model || model,
                    };
                }
                
                throw new Error('vLLM returned unexpected response format');
            } catch (error) {
                lastError = error instanceof Error ? error : new Error(String(error));
                
                // Network errors - don't try next endpoint
                if (lastError.message.includes('ECONNREFUSED') || 
                    lastError.message.includes('ENOTFOUND') ||
                    lastError.message.includes('ETIMEDOUT') ||
                    lastError.message.includes('fetch failed') ||
                    lastError.name === 'AbortError') {
                    throw new Error(`vLLM 서버 연결 실패: ${normalizedUrl} - 서버가 실행 중인지 확인하세요.`);
                }
                
                // Continue to try next endpoint for other errors
                continue;
            }
        }
        
        throw lastError || new Error('vLLM API call failed');
    }

    /**
     * Call OpenAI API
     */
    private async callOpenAi(
        apiUrl: string,
        model: string,
        prompt: string,
        apiKey: string,
        maxTokens: number,
        signal: AbortSignal,
    ): Promise<{ content: string; model: string }> {
        const normalizedUrl = apiUrl.replace(/\/$/, '');
        const v1BaseUrl = normalizedUrl.endsWith('/v1') ? normalizedUrl : `${normalizedUrl}/v1`;

        const response = await fetch(`${v1BaseUrl}/chat/completions`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`,
            },
            body: JSON.stringify({
                model,
                messages: [
                    { role: 'system', content: '당신은 보안 취약점 분석 전문가입니다. 반드시 한국어로 답변하세요. 절대로 JSON이나 코드 형식으로 답변하지 마세요. 마크다운 형식(##, -, 이모지 등)을 사용하여 읽기 쉬운 자연어 보고서 형태로 작성하세요.' },
                    { role: 'user', content: prompt },
                ],
                max_tokens: maxTokens,
                temperature: 0.7,
            }),
            signal,
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`OpenAI API error: ${response.status} - ${errorText}`);
        }

        const data = await response.json() as { choices: Array<{ message: { content: string } }>; model: string };
        return {
            content: data.choices[0]?.message?.content || '',
            model: data.model || model,
        };
    }

    /**
     * Estimate tokens for given action and context
     */
    estimateTokens(action: AiActionType, context: Record<string, unknown>): TokenEstimate {
        const metadata = AI_ACTION_METADATA[action];
        const contextStr = JSON.stringify(context);

        // Rough estimation: ~4 characters per token
        const contextTokens = Math.ceil(contextStr.length / 4);
        const promptTokens = 500; // Base prompt tokens

        return {
            inputTokens: Math.min(contextTokens + promptTokens, metadata?.maxContextTokens || 2000),
            outputTokens: metadata?.expectedOutputTokens || 500,
        };
    }

    /**
     * Mask PII in text
     */
    private maskPii(text: string): string {
        // Mask email addresses
        let masked = text.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[EMAIL]');
        // Mask phone numbers (Korean format)
        masked = masked.replace(/\d{2,3}-\d{3,4}-\d{4}/g, '[PHONE]');
        // Mask IP addresses
        masked = masked.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, '[IP]');
        return masked;
    }

    /**
     * Generate summary from content (first meaningful sentence)
     */
    private generateSummaryFromContent(content: string): string {
        const lines = content.split('\n').filter(line => line.trim().length > 0);
        if (lines.length === 0) return '';

        // Find first non-header line
        for (const line of lines) {
            if (!line.startsWith('#') && !line.startsWith('-') && line.length > 20) {
                return line.slice(0, 150) + (line.length > 150 ? '...' : '');
            }
        }
        return lines[0].slice(0, 150);
    }

    /**
     * Generate mock response for development
     * TODO: Replace with actual LLM integration
     */
    private async generateMockResponse(
        action: AiActionType,
        context: Record<string, unknown>,
    ): Promise<string> {
        // Short delay for mock response
        await new Promise(resolve => setTimeout(resolve, 100));

        switch (action) {
            case 'dashboard.summary':
                return this.generateDashboardSummaryMock(context);
            case 'dashboard.riskAnalysis':
                return this.generateRiskAnalysisMock(context);
            case 'project.analysis':
                return this.generateProjectAnalysisMock(context);
            case 'vuln.actionGuide':
                return this.generateVulnActionGuideMock(context);
            case 'vuln.priorityReorder':
                return this.generatePriorityReorderMock(context);
            case 'policy.interpretation':
                return this.generatePolicyInterpretationMock(context);
            case 'notification.summary':
                return this.generateNotificationSummaryMock(context);
            case 'guide.trivyCommand':
                return this.generateTrivyCommandMock(context);
            default:
                return this.generateGenericMock(action, context);
        }
    }

    private generateDashboardSummaryMock(context: Record<string, unknown>): string {
        const overview = context.overview as Record<string, unknown> | undefined;
        return `## 취약점 현황 요약

현재 시스템의 보안 상태를 분석한 결과, 전반적인 보안 수준은 **주의 필요** 단계입니다.

### 주요 발견 사항
- Critical 등급 취약점이 발견되어 즉각적인 조치가 필요합니다
- 최근 7일간 취약점 추이가 증가하는 양상을 보이고 있습니다
- 특정 프로젝트에 취약점이 집중되어 있습니다

### 권장 조치
1. Critical 취약점에 대한 긴급 패치 적용
2. High 취약점 해결을 위한 7일 내 계획 수립
3. 취약점 발생 패턴 분석 및 예방 조치 강화

*이 분석은 AI가 자동 생성한 것으로, 상세 검토가 필요합니다.*`;
    }

    private generateRiskAnalysisMock(context: Record<string, unknown>): string {
        return `## 조직 위험 분석 결과

### Top 5 위험 요인

1. **오래된 의존성 패키지 (위험도: 높음)**
   - 다수의 프로젝트에서 업데이트되지 않은 npm 패키지 사용
   - 알려진 취약점을 포함한 버전 사용 중

2. **Critical CVE 미조치 (위험도: 높음)**
   - 30일 이상 미해결된 Critical 취약점 존재
   - 공개 익스플로잇 존재 가능성

3. **컨테이너 이미지 취약점 (위험도: 중간)**
   - 베이스 이미지 업데이트 필요
   - alpine 기반 이미지로 전환 권장

4. **일관성 없는 정책 적용 (위험도: 중간)**
   - 프로젝트별 보안 정책 편차 존재
   - 통합 보안 기준 필요

5. **스캔 주기 불규칙 (위험도: 낮음)**
   - 일부 프로젝트 스캔 미실행
   - 자동화된 스캔 파이프라인 구축 권장`;
    }

    private generateProjectAnalysisMock(context: Record<string, unknown>): string {
        return `## 프로젝트 보안 분석

### 분석 개요
프로젝트의 보안 상태를 종합적으로 분석했습니다.

### 주요 리스크 원인
1. **오래된 Node.js 패키지**: lodash, moment 등 deprecated 패키지 사용
2. **알려진 CVE**: 3개의 Critical CVE가 미해결 상태
3. **컨테이너 구성**: root 사용자로 실행되는 컨테이너 발견

### 권장 조치
- 패키지 업데이트 또는 대체 라이브러리로 마이그레이션
- 컨테이너 보안 모범 사례 적용
- 정기적인 보안 스캔 자동화`;
    }

    private generateVulnActionGuideMock(context: Record<string, unknown>): string {
        return `## 취약점 조치 가이드

### 취약점 개요
해당 취약점은 원격 코드 실행(RCE)을 허용할 수 있는 심각한 보안 문제입니다.

### 조치 단계

#### 1단계: 영향 범위 파악
\`\`\`bash
trivy image --severity CRITICAL your-image:tag
\`\`\`

#### 2단계: 패키지 업데이트
\`\`\`bash
npm update affected-package
# 또는
yarn upgrade affected-package
\`\`\`

#### 3단계: 테스트 및 검증
- 단위 테스트 실행
- 통합 테스트로 기능 확인
- 재스캔으로 취약점 해결 확인

### 임시 완화 조치
패치가 즉시 어려운 경우:
- 네트워크 접근 제한
- WAF 규칙 추가
- 모니터링 강화

### 참고 자료
- [NVD 상세 정보](https://nvd.nist.gov)
- [패키지 보안 권고](https://github.com/advisories)`;
    }

    private generatePriorityReorderMock(context: Record<string, unknown>): string {
        return `## AI 기반 취약점 우선순위

### 재정렬 기준
- EPSS 점수 (익스플로잇 예측)
- 공개 익스플로잇 존재 여부
- 자산 노출 정도
- 비즈니스 영향도

### 우선순위 목록

| 순위 | CVE ID | 기존 순위 | EPSS | 재정렬 사유 |
|------|--------|-----------|------|-------------|
| 1 | CVE-2024-0001 | 3 | 0.92 | 공개 익스플로잇 존재 |
| 2 | CVE-2024-0002 | 1 | 0.78 | 인터넷 노출 서비스 |
| 3 | CVE-2024-0003 | 2 | 0.45 | 내부망 한정 |

*EPSS 데이터는 실시간으로 업데이트됩니다.*`;
    }

    private generatePolicyInterpretationMock(context: Record<string, unknown>): string {
        return `## 정책 차단 사유 설명

### 적용된 정책
**"Critical 취약점 차단 정책"**

### 차단 이유
이 배포가 차단된 이유는 컨테이너 이미지에서 **Critical 등급의 취약점**이 발견되었기 때문입니다.

### 상세 설명
1. 스캔 결과 2개의 Critical 취약점 발견
2. 조직 정책에 따라 Critical 취약점이 있는 이미지는 프로덕션 배포 불가
3. 해당 취약점은 원격 코드 실행 위험이 있음

### 해결 방법
1. 발견된 취약점 패치 후 재스캔
2. 또는 예외 승인 요청 (비즈니스 사유 필요)

*정책 문의: security@company.com*`;
    }

    private generateNotificationSummaryMock(context: Record<string, unknown>): string {
        const notifications = context.notifications as unknown[] | undefined;
        const count = notifications?.length || 0;

        return `## 알림 요약 (${count}건)

### 긴급 조치 필요
- 🔴 Critical 취약점 2건 신규 발견

### 검토 필요
- 🟡 정책 위반 3건
- 🟡 스캔 완료 5건

### 정보성
- 🔵 프로젝트 업데이트 2건

### 권장 조치
1. Critical 취약점 먼저 검토
2. 정책 위반 항목 확인 후 조치
3. 나머지는 일일 리뷰 시 처리`;
    }

    private generateTrivyCommandMock(context: Record<string, unknown>): string {
        return `## Trivy 명령어

### 컨테이너 이미지 스캔
\`\`\`bash
trivy image --format json --output result.json your-image:tag
\`\`\`

### 파일시스템 스캔
\`\`\`bash
trivy fs --format sarif --output result.sarif ./
\`\`\`

### CI/CD 통합 (GitHub Actions)
\`\`\`yaml
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: '\${{ env.IMAGE }}'
    format: 'json'
    output: 'trivy-results.json'
    severity: 'CRITICAL,HIGH'
\`\`\`

### 옵션 설명
- \`--format json\`: JASCA 호환 형식
- \`--severity CRITICAL,HIGH\`: 심각도 필터
- \`--ignore-unfixed\`: 패치 없는 취약점 제외`;
    }

    private generateGenericMock(action: AiActionType, context: Record<string, unknown>): string {
        const metadata = AI_ACTION_METADATA[action];
        return `## ${metadata?.label || 'AI 분석 결과'}

AI 분석이 완료되었습니다.

### 분석 내용
요청하신 "${action}" 작업에 대한 분석을 수행했습니다.

### 컨텍스트 요약
입력된 데이터를 기반으로 분석을 진행했습니다.

*상세 분석 기능은 AI 모델 연동 후 제공됩니다.*`;
    }


    /**
     * Generate AI-powered risk summary for a project
     * Note: In production, this would call an LLM API
     */
    async generateRiskSummary(projectId: string): Promise<RiskSummary> {
        const project = await this.prisma.project.findUnique({
            where: { id: projectId },
            include: {
                scanResults: {
                    orderBy: { createdAt: 'desc' },
                    take: 1,
                    include: {
                        vulnerabilities: {
                            include: { vulnerability: true },
                        },
                    },
                },
            },
        });

        if (!project || project.scanResults.length === 0) {
            return {
                projectId,
                projectName: project?.name || 'Unknown',
                summary: 'No scan data available for risk assessment.',
                riskLevel: 'LOW',
                keyFindings: [],
                recommendations: [],
                generatedAt: new Date(),
            };
        }

        const latestScan = project.scanResults[0];
        const vulns = latestScan.vulnerabilities;

        let criticalCount = 0;
        let highCount = 0;
        let mediumCount = 0;

        for (const sv of vulns) {
            const sev = sv.vulnerability.severity;
            if (sev === 'CRITICAL') criticalCount++;
            else if (sev === 'HIGH') highCount++;
            else if (sev === 'MEDIUM') mediumCount++;
        }

        // Determine risk level
        let riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';
        if (criticalCount > 0) riskLevel = 'CRITICAL';
        else if (highCount > 3) riskLevel = 'HIGH';
        else if (highCount > 0 || mediumCount > 5) riskLevel = 'MEDIUM';

        // Generate summary (in production, this would be LLM-generated)
        const summary = this.generateSummaryText(project.name, criticalCount, highCount, mediumCount, vulns.length);

        const keyFindings = this.extractKeyFindings(vulns);
        const recommendations = this.generateRecommendations(criticalCount, highCount, vulns);

        return {
            projectId,
            projectName: project.name,
            summary,
            riskLevel,
            keyFindings,
            recommendations,
            generatedAt: new Date(),
        };
    }

    /**
     * Generate remediation guide for a CVE
     * Note: In production, this would call an LLM API
     */
    async generateRemediationGuide(cveId: string): Promise<RemediationGuide | null> {
        const vulnerability = await this.prisma.vulnerability.findUnique({
            where: { cveId },
        });

        if (!vulnerability) return null;

        // In production, this would use LLM to generate context-aware steps
        const steps = this.generateRemediationSteps(vulnerability);
        const estimatedEffort = this.estimateEffort(vulnerability.severity);

        return {
            cveId,
            title: vulnerability.title || cveId,
            severity: vulnerability.severity,
            description: vulnerability.description || 'No description available.',
            steps,
            references: [
                `https://nvd.nist.gov/vuln/detail/${cveId}`,
                ...(vulnerability.references || []).slice(0, 3),
            ],
            estimatedEffort,
            generatedAt: new Date(),
        };
    }

    /**
     * Batch generate remediation guides for a scan
     */
    async batchGenerateGuides(scanResultId: string): Promise<RemediationGuide[]> {
        const scan = await this.prisma.scanResult.findUnique({
            where: { id: scanResultId },
            include: {
                vulnerabilities: {
                    include: { vulnerability: true },
                    where: {
                        vulnerability: {
                            severity: { in: ['CRITICAL', 'HIGH'] },
                        },
                    },
                },
            },
        });

        if (!scan) return [];

        const guides: RemediationGuide[] = [];
        const seen = new Set<string>();

        for (const sv of scan.vulnerabilities) {
            if (seen.has(sv.vulnerability.cveId)) continue;
            seen.add(sv.vulnerability.cveId);

            const guide = await this.generateRemediationGuide(sv.vulnerability.cveId);
            if (guide) guides.push(guide);
        }

        return guides;
    }

    // Helper methods

    private generateSummaryText(
        projectName: string,
        critical: number,
        high: number,
        medium: number,
        total: number,
    ): string {
        if (critical > 0) {
            return `${projectName} has ${critical} critical vulnerabilities that require immediate attention. ` +
                `Total vulnerabilities: ${total} (${critical} critical, ${high} high, ${medium} medium).`;
        }
        if (high > 0) {
            return `${projectName} has ${high} high-severity vulnerabilities. ` +
                `Total vulnerabilities: ${total}. Consider prioritizing remediation.`;
        }
        return `${projectName} has ${total} vulnerabilities. No critical issues detected.`;
    }

    private extractKeyFindings(vulns: { vulnerability: { cveId: string; severity: string; title: string | null } }[]): string[] {
        const findings: string[] = [];
        const criticals = vulns.filter(v => v.vulnerability.severity === 'CRITICAL');

        for (const cv of criticals.slice(0, 3)) {
            findings.push(`${cv.vulnerability.cveId}: ${cv.vulnerability.title || 'Critical vulnerability'}`);
        }

        if (criticals.length > 3) {
            findings.push(`...and ${criticals.length - 3} more critical vulnerabilities`);
        }

        return findings;
    }

    private generateRecommendations(
        critical: number,
        high: number,
        vulns: { vulnerability: { severity: string; cweIds: string[] | null } }[],
    ): string[] {
        const recs: string[] = [];

        if (critical > 0) {
            recs.push('Immediately patch or mitigate critical vulnerabilities');
            recs.push('Review network exposure to affected components');
        }
        if (high > 0) {
            recs.push('Schedule high-severity vulnerability remediation within 7 days');
        }

        // Check for common patterns
        const cweIds = vulns.flatMap(v => v.vulnerability.cweIds || []);
        if (cweIds.includes('CWE-79')) {
            recs.push('Review input sanitization practices to prevent XSS');
        }
        if (cweIds.includes('CWE-89')) {
            recs.push('Audit database queries for SQL injection vulnerabilities');
        }

        return recs.slice(0, 5);
    }

    private generateRemediationSteps(vuln: { severity: string; cweIds: string[] | null }): string[] {
        const steps: string[] = [
            'Identify all instances of this vulnerability in your codebase',
            'Review the affected component and its dependencies',
        ];

        const cweIds = vuln.cweIds || [];

        if (cweIds.includes('CWE-79')) {
            steps.push('Implement proper output encoding for user-supplied data');
            steps.push('Use Content Security Policy headers');
        } else if (cweIds.includes('CWE-89')) {
            steps.push('Use parameterized queries or prepared statements');
            steps.push('Validate and sanitize all user inputs');
        } else if (cweIds.some(c => c.includes('119') || c.includes('120'))) {
            steps.push('Update to the latest patched version of the affected library');
            steps.push('Review buffer handling code for bounds checking');
        } else {
            steps.push('Update the affected package to the latest patched version');
            steps.push('Review vendor advisories for specific mitigation steps');
        }

        steps.push('Test the fix in a staging environment');
        steps.push('Deploy the fix and verify remediation with a rescan');

        return steps;
    }

    private estimateEffort(severity: string): 'LOW' | 'MEDIUM' | 'HIGH' {
        switch (severity) {
            case 'CRITICAL':
                return 'HIGH';
            case 'HIGH':
                return 'MEDIUM';
            default:
                return 'LOW';
        }
    }
}
