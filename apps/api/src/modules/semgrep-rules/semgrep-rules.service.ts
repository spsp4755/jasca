import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import * as yaml from 'js-yaml';
import { PrismaService } from '../../prisma/prisma.service';

export interface SemgrepRuleDto {
    name: string;
    description?: string;
    yaml: string;
    isActive?: boolean;
}

const ALLOWED_SEVERITIES = new Set(['ERROR', 'WARNING', 'INFO', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);

@Injectable()
export class SemgrepRulesService {
    constructor(private readonly prisma: PrismaService) { }

    async findAll(isActive?: boolean) {
        return this.prisma.semgrepRule.findMany({
            where: isActive === undefined ? {} : { isActive },
            orderBy: { updatedAt: 'desc' },
            include: { createdBy: { select: { id: true, name: true, email: true } } },
        });
    }

    async create(dto: SemgrepRuleDto, userId?: string) {
        this.validateDto(dto);
        return this.prisma.semgrepRule.create({
            data: {
                name: dto.name.trim(),
                description: dto.description?.trim() || null,
                yaml: dto.yaml,
                isActive: dto.isActive !== false,
                createdById: userId,
            },
        });
    }

    async update(id: string, dto: Partial<SemgrepRuleDto>) {
        const existing = await this.prisma.semgrepRule.findUnique({ where: { id } });
        if (!existing) throw new NotFoundException('Semgrep rule not found');

        if (dto.yaml !== undefined || dto.name !== undefined) {
            this.validateDto({
                name: dto.name ?? existing.name,
                yaml: dto.yaml ?? existing.yaml,
            });
        }

        return this.prisma.semgrepRule.update({
            where: { id },
            data: {
                ...(dto.name !== undefined ? { name: dto.name.trim() } : {}),
                ...(dto.description !== undefined ? { description: dto.description?.trim() || null } : {}),
                ...(dto.yaml !== undefined ? { yaml: dto.yaml } : {}),
                ...(dto.isActive !== undefined ? { isActive: dto.isActive } : {}),
            },
        });
    }

    async remove(id: string) {
        const existing = await this.prisma.semgrepRule.findUnique({ where: { id } });
        if (!existing) throw new NotFoundException('Semgrep rule not found');
        await this.prisma.semgrepRule.delete({ where: { id } });
        return { success: true };
    }

    /** Active rule YAML contents, for merging into a scan. */
    async getActiveRuleYamls(): Promise<Array<{ id: string; name: string; yaml: string }>> {
        const rules = await this.prisma.semgrepRule.findMany({
            where: { isActive: true },
            select: { id: true, name: true, yaml: true },
        });
        return rules;
    }

    /**
     * Structural validation of a semgrep rule file. Full semantic validation
     * happens when semgrep loads the rules at scan time; this catches the
     * common mistakes (broken YAML, missing required fields) at save time.
     */
    validateDto(dto: SemgrepRuleDto): void {
        if (!dto.name?.trim()) {
            throw new BadRequestException('룰 이름을 입력해주세요.');
        }
        if (!dto.yaml?.trim()) {
            throw new BadRequestException('룰 YAML 내용을 입력해주세요.');
        }

        let parsed: any;
        try {
            parsed = yaml.load(dto.yaml);
        } catch (error) {
            throw new BadRequestException(`YAML 문법 오류: ${(error as Error).message}`);
        }

        const rules = parsed?.rules;
        if (!Array.isArray(rules) || rules.length === 0) {
            throw new BadRequestException('최상위에 rules 배열이 필요합니다. (semgrep 룰 파일 형식: rules: [...])');
        }

        for (const [index, rule] of rules.entries()) {
            const where = `rules[${index}]`;
            if (!rule || typeof rule !== 'object') {
                throw new BadRequestException(`${where}가 객체가 아닙니다.`);
            }
            if (!rule.id || typeof rule.id !== 'string') {
                throw new BadRequestException(`${where}에 id가 필요합니다.`);
            }
            if (!rule.message) {
                throw new BadRequestException(`${where} (${rule.id})에 message가 필요합니다.`);
            }
            if (!rule.severity || !ALLOWED_SEVERITIES.has(String(rule.severity).toUpperCase())) {
                throw new BadRequestException(`${where} (${rule.id})의 severity는 ERROR/WARNING/INFO 중 하나여야 합니다.`);
            }
            if (!rule.languages || !Array.isArray(rule.languages) || rule.languages.length === 0) {
                throw new BadRequestException(`${where} (${rule.id})에 languages 배열이 필요합니다.`);
            }
            const hasPattern = ['pattern', 'patterns', 'pattern-either', 'pattern-regex', 'mode', 'taint']
                .some((key) => rule[key] !== undefined);
            if (!hasPattern) {
                throw new BadRequestException(`${where} (${rule.id})에 pattern 계열 필드(pattern, patterns, pattern-either, pattern-regex)가 필요합니다.`);
            }
        }
    }
}
