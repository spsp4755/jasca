import { Injectable, Logger } from '@nestjs/common';
import { ScanArtifactType } from '@prisma/client';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { PrismaService } from '../../../prisma/prisma.service';
import { ClustaraService } from '../../clustara/clustara.service';

@Injectable()
export class ScanArtifactService {
    private readonly logger = new Logger(ScanArtifactService.name);
    private readonly scanResultDir = process.env.SCAN_RESULT_DIR || '/app/jasca/scan-results';

    constructor(
        private readonly prisma: PrismaService,
        private readonly clustaraService: ClustaraService,
    ) { }

    async persistCycloneDx(scanResultId: string, sbom: string) {
        const artifactDir = path.join(this.scanResultDir, 'artifacts');
        const filePath = path.join(artifactDir, `${scanResultId}.cdx.json`);
        const temporaryPath = `${filePath}.tmp-${process.pid}-${Date.now()}`;
        await fs.promises.mkdir(artifactDir, { recursive: true });
        await fs.promises.writeFile(temporaryPath, sbom, 'utf-8');
        await fs.promises.rename(temporaryPath, filePath);

        const artifact = await this.prisma.scanArtifact.upsert({
            where: {
                scanResultId_type: {
                    scanResultId,
                    type: ScanArtifactType.CYCLONEDX_JSON,
                },
            },
            create: {
                scanResultId,
                type: ScanArtifactType.CYCLONEDX_JSON,
                filePath,
                sha256: crypto.createHash('sha256').update(sbom).digest('hex'),
                generator: 'syft',
                generatorVersion: this.getSyftVersion(sbom),
            },
            update: {
                filePath,
                sha256: crypto.createHash('sha256').update(sbom).digest('hex'),
                generator: 'syft',
                generatorVersion: this.getSyftVersion(sbom),
            },
        });

        this.clustaraService.queueAutomatic(scanResultId).catch((error: Error) => {
            this.logger.warn(`Failed to queue Clustara SBOM delivery for ${scanResultId}: ${error.message}`);
        });
        return artifact;
    }

    async deleteForScan(scanResultId: string) {
        const artifacts = await this.prisma.scanArtifact.findMany({
            where: { scanResultId },
            select: { filePath: true },
        });
        await Promise.all(artifacts.map((artifact) =>
            fs.promises.rm(artifact.filePath, { force: true }).catch(() => undefined),
        ));
    }

    private getSyftVersion(sbom: string): string | null {
        try {
            const parsed = JSON.parse(sbom);
            const components = parsed?.metadata?.tools?.components;
            if (Array.isArray(components)) {
                const syft = components.find((tool: any) => String(tool?.name || '').toLowerCase() === 'syft');
                return syft?.version ? String(syft.version) : null;
            }
            const legacyTools = parsed?.metadata?.tools;
            if (Array.isArray(legacyTools)) {
                const syft = legacyTools.find((tool: any) => String(tool?.name || '').toLowerCase() === 'syft');
                return syft?.version ? String(syft.version) : null;
            }
        } catch {
            return null;
        }
        return null;
    }
}
