import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';

@Injectable()
export class IpControlService {
    private readonly logger = new Logger(IpControlService.name);

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Check if IP is allowed for organization
     */
    async isIpAllowed(organizationId: string, ipAddress: string): Promise<boolean> {
        // Get all active whitelist entries
        const whitelistEntries = await this.prisma.ipWhitelist.findMany({
            where: {
                organizationId,
                isActive: true,
            },
        });

        // If no whitelist configured, allow all IPs
        if (whitelistEntries.length === 0) {
            return true;
        }

        // Check if IP matches any whitelist entry
        for (const entry of whitelistEntries) {
            if (this.matchesIpOrCidr(ipAddress, entry.ipAddress)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Add IP to whitelist
     */
    async addToWhitelist(
        organizationId: string,
        ipAddress: string,
        description?: string,
    ): Promise<void> {
        await this.prisma.ipWhitelist.upsert({
            where: {
                organizationId_ipAddress: {
                    organizationId,
                    ipAddress,
                },
            },
            create: {
                organizationId,
                ipAddress,
                description,
                isActive: true,
            },
            update: {
                description,
                isActive: true,
            },
        });
    }

    /**
     * Remove IP from whitelist
     */
    async removeFromWhitelist(organizationId: string, ipAddress: string): Promise<void> {
        await this.prisma.ipWhitelist.deleteMany({
            where: {
                organizationId,
                ipAddress,
            },
        });
    }

    /**
     * Disable IP in whitelist (soft delete)
     */
    async disableWhitelistEntry(id: string): Promise<void> {
        await this.prisma.ipWhitelist.update({
            where: { id },
            data: { isActive: false },
        });
    }

    /**
     * Get all whitelist entries for organization
     */
    async getWhitelist(organizationId: string): Promise<Array<{
        id: string;
        ipAddress: string;
        description: string | null;
        isActive: boolean;
        createdAt: Date;
    }>> {
        return this.prisma.ipWhitelist.findMany({
            where: { organizationId },
            orderBy: { createdAt: 'desc' },
        });
    }

    /**
     * Check if IP matches a specific IP or CIDR range
     */
    private matchesIpOrCidr(ip: string, pattern: string): boolean {
        // Direct match
        if (ip === pattern) {
            return true;
        }

        // CIDR match
        if (pattern.includes('/')) {
            return this.matchesCidr(ip, pattern);
        }

        return false;
    }

    /**
     * Check if IP matches CIDR range
     */
    private matchesCidr(ip: string, cidr: string): boolean {
        try {
            const [range, bits] = cidr.split('/');
            const maskBits = parseInt(bits, 10);

            if (isNaN(maskBits) || maskBits < 0 || maskBits > 32) {
                return false;
            }

            const ipNum = this.ipToNumber(ip);
            const rangeNum = this.ipToNumber(range);

            if (ipNum === null || rangeNum === null) {
                return false;
            }

            const mask = maskBits === 0 ? 0 : (~0 << (32 - maskBits)) >>> 0;
            return (ipNum & mask) === (rangeNum & mask);
        } catch {
            return false;
        }
    }

    /**
     * Convert IP address to number
     */
    private ipToNumber(ip: string): number | null {
        const parts = ip.split('.');
        if (parts.length !== 4) {
            return null;
        }

        let result = 0;
        for (const part of parts) {
            const num = parseInt(part, 10);
            if (isNaN(num) || num < 0 || num > 255) {
                return null;
            }
            result = (result << 8) + num;
        }

        return result >>> 0;
    }

    /**
     * Validate IP address format
     */
    isValidIp(ip: string): boolean {
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

        if (cidrRegex.test(ip)) {
            const [address, bits] = ip.split('/');
            const maskBits = parseInt(bits, 10);
            return this.isValidIp(address) && maskBits >= 0 && maskBits <= 32;
        }

        if (!ipv4Regex.test(ip)) {
            return false;
        }

        const parts = ip.split('.').map(p => parseInt(p, 10));
        return parts.every(p => p >= 0 && p <= 255);
    }
}
