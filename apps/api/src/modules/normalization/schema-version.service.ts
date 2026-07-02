import { Injectable, Logger } from '@nestjs/common';
import { TRIVY_SCHEMA_MAPPINGS, TrivySchemaMapping } from './schemas/normalized-vulnerability.schema';

export interface SchemaCompatibility {
    version: string;
    isSupported: boolean;
    recommendedVersion?: string;
    breakingChanges?: string[];
}

@Injectable()
export class SchemaVersionService {
    private readonly logger = new Logger(SchemaVersionService.name);

    /**
     * Check if a schema version is supported
     */
    isSchemaVersionSupported(schemaVersion: string): boolean {
        return TRIVY_SCHEMA_MAPPINGS.some(m => m.schemaVersion === schemaVersion);
    }

    /**
     * Get schema mapping for a specific version
     */
    getSchemaMapping(schemaVersion: string): TrivySchemaMapping | undefined {
        return TRIVY_SCHEMA_MAPPINGS.find(m => m.schemaVersion === schemaVersion);
    }

    /**
     * Check schema compatibility and provide migration info
     */
    checkSchemaCompatibility(schemaVersion: string): SchemaCompatibility {
        const mapping = this.getSchemaMapping(schemaVersion);

        if (mapping) {
            return {
                version: schemaVersion,
                isSupported: true,
            };
        }

        // Find closest supported version
        const latestMapping = TRIVY_SCHEMA_MAPPINGS[0];
        return {
            version: schemaVersion,
            isSupported: false,
            recommendedVersion: latestMapping.schemaVersion,
            breakingChanges: this.detectBreakingChanges(schemaVersion),
        };
    }

    /**
     * Detect potential breaking changes between schema versions
     */
    private detectBreakingChanges(schemaVersion: string): string[] {
        const changes: string[] = [];
        const versionNum = parseInt(schemaVersion, 10);

        if (versionNum < 2) {
            changes.push('Missing CVSS metadata in older format');
            changes.push('Different vulnerability structure');
        }

        return changes;
    }

    /**
     * Get all supported schema versions
     */
    getSupportedVersions(): { schemaVersion: string; scannerVersions: string[] }[] {
        return TRIVY_SCHEMA_MAPPINGS.map(m => ({
            schemaVersion: m.schemaVersion,
            scannerVersions: m.supportedVersions,
        }));
    }

    /**
     * Validate raw result against schema
     */
    validateSchemaStructure(rawResult: any, schemaVersion: string): {
        isValid: boolean;
        errors: string[];
        warnings: string[];
    } {
        const errors: string[] = [];
        const warnings: string[] = [];

        // Check required fields based on schema version
        if (!rawResult) {
            errors.push('Empty result');
            return { isValid: false, errors, warnings };
        }

        // Common validations
        if (!rawResult.Results && !rawResult.runs) {
            errors.push('Missing Results or runs array');
        }

        if (!rawResult.ArtifactName && !rawResult.runs) {
            warnings.push('Missing ArtifactName - will default to "unknown"');
        }

        // Schema-version-specific validations
        if (schemaVersion === '2') {
            if (!rawResult.SchemaVersion) {
                warnings.push('Missing SchemaVersion field');
            }
        }

        return {
            isValid: errors.length === 0,
            errors,
            warnings,
        };
    }
}
