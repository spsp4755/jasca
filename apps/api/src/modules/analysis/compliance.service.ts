import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * Static CWE-based compliance mapping (OWASP Top 10 2021, CWE Top 25 2024)
 * and remediation guidance. All data is bundled — no external calls, so it
 * works in air-gapped deployments. Same pattern as MitreAttackService.
 */

export interface OwaspCategorySummary {
    id: string;
    name: string;
    count: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    cweIds: string[];
    sampleCveIds: string[];
}

export interface CweTop25Summary {
    rank: number;
    cweId: string;
    name: string;
    count: number;
}

// Official OWASP Top 10 2021 CWE mappings (abbreviated names)
const OWASP_TOP10_2021: Array<{ id: string; name: string; cwes: number[] }> = [
    {
        id: 'A01', name: 'Broken Access Control',
        cwes: [22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275],
    },
    {
        id: 'A02', name: 'Cryptographic Failures',
        cwes: [261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916],
    },
    {
        id: 'A03', name: 'Injection',
        cwes: [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 100, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917],
    },
    {
        id: 'A04', name: 'Insecure Design',
        cwes: [73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173],
    },
    {
        id: 'A05', name: 'Security Misconfiguration',
        cwes: [2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032, 1174],
    },
    {
        id: 'A06', name: 'Vulnerable and Outdated Components',
        cwes: [937, 1035, 1104],
    },
    {
        id: 'A07', name: 'Identification and Authentication Failures',
        cwes: [255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940, 1216],
    },
    {
        id: 'A08', name: 'Software and Data Integrity Failures',
        cwes: [345, 353, 426, 494, 502, 565, 784, 829, 830, 915],
    },
    {
        id: 'A09', name: 'Security Logging and Monitoring Failures',
        cwes: [117, 223, 532, 778],
    },
    {
        id: 'A10', name: 'Server-Side Request Forgery (SSRF)',
        cwes: [918],
    },
];

// CWE Top 25 (2024), rank order
const CWE_TOP25_2024: Array<{ cweId: string; name: string }> = [
    { cweId: 'CWE-79', name: 'Cross-site Scripting (XSS)' },
    { cweId: 'CWE-787', name: 'Out-of-bounds Write' },
    { cweId: 'CWE-89', name: 'SQL Injection' },
    { cweId: 'CWE-352', name: 'Cross-Site Request Forgery (CSRF)' },
    { cweId: 'CWE-22', name: 'Path Traversal' },
    { cweId: 'CWE-125', name: 'Out-of-bounds Read' },
    { cweId: 'CWE-78', name: 'OS Command Injection' },
    { cweId: 'CWE-416', name: 'Use After Free' },
    { cweId: 'CWE-862', name: 'Missing Authorization' },
    { cweId: 'CWE-434', name: 'Unrestricted Upload of Dangerous File' },
    { cweId: 'CWE-94', name: 'Code Injection' },
    { cweId: 'CWE-20', name: 'Improper Input Validation' },
    { cweId: 'CWE-77', name: 'Command Injection' },
    { cweId: 'CWE-287', name: 'Improper Authentication' },
    { cweId: 'CWE-269', name: 'Improper Privilege Management' },
    { cweId: 'CWE-502', name: 'Deserialization of Untrusted Data' },
    { cweId: 'CWE-200', name: 'Exposure of Sensitive Information' },
    { cweId: 'CWE-863', name: 'Incorrect Authorization' },
    { cweId: 'CWE-918', name: 'Server-Side Request Forgery (SSRF)' },
    { cweId: 'CWE-119', name: 'Improper Restriction of Memory Buffer Operations' },
    { cweId: 'CWE-476', name: 'NULL Pointer Dereference' },
    { cweId: 'CWE-798', name: 'Use of Hard-coded Credentials' },
    { cweId: 'CWE-190', name: 'Integer Overflow or Wraparound' },
    { cweId: 'CWE-400', name: 'Uncontrolled Resource Consumption' },
    { cweId: 'CWE-306', name: 'Missing Authentication for Critical Function' },
];

// Remediation guidance for frequently seen CWEs (offline Veracode-Fix analog)
const REMEDIATION_GUIDANCE: Record<string, string> = {
    'CWE-79': '출력 시 컨텍스트에 맞는 인코딩(HTML/속성/JS)을 적용하고, 프레임워크의 자동 이스케이프를 우회(innerHTML, dangerouslySetInnerHTML 등)하지 마세요.',
    'CWE-89': '문자열 연결 대신 파라미터 바인딩(Prepared Statement)이나 ORM 쿼리 빌더를 사용하세요. 동적 식별자는 화이트리스트로 검증하세요.',
    'CWE-78': '쉘 호출 대신 인자 배열 방식의 API(execFile 등)를 사용하고, 사용자 입력이 명령에 포함되면 화이트리스트로 검증하세요.',
    'CWE-22': '사용자 입력으로 만든 경로를 정규화(realpath)한 뒤 허용 기준 디렉토리 내부인지 검증하세요.',
    'CWE-352': '상태 변경 요청에 CSRF 토큰을 요구하고, 세션 쿠키에 SameSite 속성을 설정하세요.',
    'CWE-287': '검증된 인증 프레임워크를 사용하고, 인증 실패 시 계정 잠금·지연을 적용하세요. 자체 구현 인증 로직을 피하세요.',
    'CWE-306': '민감한 기능·API 엔드포인트마다 인증 가드가 적용되는지 확인하세요. 기본 거부(deny-by-default)로 설계하세요.',
    'CWE-862': '모든 요청 핸들러에서 리소스 소유권/역할을 서버 측에서 검증하세요. 클라이언트가 보낸 ID를 신뢰하지 마세요.',
    'CWE-863': '권한 검사가 리소스 단위로 정확한 조건을 확인하는지 검토하세요. 역할 상속과 예외 케이스를 테스트로 고정하세요.',
    'CWE-798': '하드코딩된 비밀번호/키를 제거하고 환경변수나 시크릿 관리 도구로 이전한 뒤, 노출된 자격증명은 반드시 교체(rotate)하세요.',
    'CWE-200': '오류 응답·로그에 내부 정보(스택트레이스, 경로, 버전)를 노출하지 않도록 하고, 민감 필드는 응답 직렬화에서 제외하세요.',
    'CWE-502': '신뢰할 수 없는 데이터의 역직렬화를 피하고, 필요하면 타입 화이트리스트 기반의 안전한 포맷(JSON 등)으로 대체하세요.',
    'CWE-611': 'XML 파서의 외부 엔티티(DTD) 처리를 비활성화하세요.',
    'CWE-918': '사용자 입력 URL로의 서버측 요청은 허용 호스트 화이트리스트로 제한하고, 내부망 대역·메타데이터 IP를 차단하세요.',
    'CWE-434': '업로드 파일의 확장자·MIME·매직바이트를 검증하고, 실행 권한이 없는 별도 저장소에 무작위 이름으로 저장하세요.',
    'CWE-327': '검증된 최신 암호화 알고리즘(AES-GCM, SHA-256 이상)을 사용하고, MD5/SHA-1/DES 등 취약 알고리즘을 교체하세요.',
    'CWE-319': '전송 구간에 TLS를 적용하고 평문 프로토콜(HTTP, FTP)을 차단하세요.',
    'CWE-20': '입력을 신뢰 경계에서 스키마 기반으로 검증하세요(타입, 길이, 범위, 형식). 거부 목록보다 허용 목록이 안전합니다.',
    'CWE-94': '사용자 입력을 eval/Function/템플릿 엔진 코드 실행 경로에 넣지 마세요.',
    'CWE-400': '요청 크기·속도 제한, 페이지네이션, 타임아웃을 적용해 자원 고갈을 방지하세요.',
    'CWE-532': '로그에 비밀번호, 토큰, 개인정보가 기록되지 않도록 마스킹하세요.',
    'CWE-522': '자격증명은 저장 시 강한 해시(bcrypt/argon2)나 암호화를 적용하고 전송 시 TLS를 사용하세요.',
    'CWE-190': '산술 연산 전 범위를 검증하거나 오버플로 안전 타입/함수를 사용하세요.',
    'CWE-476': '역참조 전 null 여부를 확인하고, 널 가능성을 타입 시스템으로 표현하세요.',
};

// CWE number -> OWASP category ids (a CWE can map to one category in the 2021 list)
const CWE_TO_OWASP = new Map<number, { id: string; name: string }>();
for (const category of OWASP_TOP10_2021) {
    for (const cwe of category.cwes) {
        CWE_TO_OWASP.set(cwe, { id: category.id, name: category.name });
    }
}

const CWE_TOP25_RANK = new Map(CWE_TOP25_2024.map((c, i) => [c.cweId, { rank: i + 1, name: c.name }]));

@Injectable()
export class ComplianceService {
    constructor(private readonly prisma: PrismaService) { }

    /**
     * Aggregate a project's open vulnerabilities into OWASP Top 10 2021
     * categories and CWE Top 25 2024 membership.
     */
    async getComplianceReport(projectId: string) {
        const vulns = await this.prisma.scanVulnerability.findMany({
            where: {
                scanResult: { projectId },
                status: { notIn: ['FIXED', 'FALSE_POSITIVE', 'CLOSED'] },
            },
            include: {
                vulnerability: { select: { cveId: true, severity: true, cweIds: true } },
            },
        });

        const owasp = new Map<string, OwaspCategorySummary>();
        const top25 = new Map<string, CweTop25Summary>();
        let unmappedCount = 0;

        for (const v of vulns) {
            const cweIds = v.vulnerability.cweIds || [];
            const severity = v.vulnerability.severity;
            const matchedCategories = new Set<string>();
            let mapped = false;

            for (const cweId of cweIds) {
                const cweNum = Number(String(cweId).replace(/^CWE-/i, ''));

                const category = CWE_TO_OWASP.get(cweNum);
                if (category && !matchedCategories.has(category.id)) {
                    matchedCategories.add(category.id);
                    mapped = true;
                    const entry = owasp.get(category.id) || {
                        id: category.id,
                        name: category.name,
                        count: 0, critical: 0, high: 0, medium: 0, low: 0,
                        cweIds: [], sampleCveIds: [],
                    };
                    entry.count += 1;
                    if (severity === 'CRITICAL') entry.critical += 1;
                    else if (severity === 'HIGH') entry.high += 1;
                    else if (severity === 'MEDIUM') entry.medium += 1;
                    else if (severity === 'LOW') entry.low += 1;
                    const normalizedCwe = `CWE-${cweNum}`;
                    if (!entry.cweIds.includes(normalizedCwe)) entry.cweIds.push(normalizedCwe);
                    if (entry.sampleCveIds.length < 10 && !entry.sampleCveIds.includes(v.vulnerability.cveId)) {
                        entry.sampleCveIds.push(v.vulnerability.cveId);
                    }
                    owasp.set(category.id, entry);
                }

                const top25Info = CWE_TOP25_RANK.get(`CWE-${cweNum}`);
                if (top25Info) {
                    const entry = top25.get(`CWE-${cweNum}`) || {
                        rank: top25Info.rank,
                        cweId: `CWE-${cweNum}`,
                        name: top25Info.name,
                        count: 0,
                    };
                    entry.count += 1;
                    top25.set(`CWE-${cweNum}`, entry);
                }
            }

            if (!mapped) unmappedCount += 1;
        }

        return {
            projectId,
            generatedAt: new Date().toISOString(),
            totalOpenVulnerabilities: vulns.length,
            owaspTop10: [...owasp.values()].sort((a, b) => a.id.localeCompare(b.id)),
            cweTop25: [...top25.values()].sort((a, b) => a.rank - b.rank),
            unmappedCount,
        };
    }

    /** Offline remediation guidance for the given CWE ids. */
    getRemediationGuidance(cweIds: string[]) {
        return cweIds
            .map((raw) => {
                const cweId = `CWE-${String(raw).replace(/^CWE-/i, '')}`;
                const guidance = REMEDIATION_GUIDANCE[cweId];
                return guidance ? { cweId, guidance } : null;
            })
            .filter((g): g is { cweId: string; guidance: string } => g !== null);
    }
}
