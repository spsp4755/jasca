import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

export interface BookmarkInfo {
    id: string;
    cveId: string;
    title: string;
    severity: string;
    note?: string;
    createdAt: Date;
}

@Injectable()
export class BookmarkService {
    private readonly logger = new Logger(BookmarkService.name);

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Add a bookmark for a vulnerability
     */
    async addBookmark(
        userId: string,
        vulnerabilityId: string,
        note?: string,
    ): Promise<BookmarkInfo> {
        const vulnerability = await this.prisma.vulnerability.findUnique({
            where: { id: vulnerabilityId },
        });

        if (!vulnerability) {
            throw new BadRequestException('Vulnerability not found');
        }

        const bookmark = await this.prisma.vulnerabilityBookmark.upsert({
            where: {
                userId_vulnerabilityId: { userId, vulnerabilityId },
            },
            create: {
                userId,
                vulnerabilityId,
                note,
            },
            update: {
                note,
            },
        });

        return {
            id: bookmark.id,
            cveId: vulnerability.cveId,
            title: vulnerability.title || vulnerability.cveId,
            severity: vulnerability.severity,
            note: bookmark.note || undefined,
            createdAt: bookmark.createdAt,
        };
    }

    /**
     * Remove a bookmark
     */
    async removeBookmark(userId: string, vulnerabilityId: string): Promise<void> {
        await this.prisma.vulnerabilityBookmark.deleteMany({
            where: { userId, vulnerabilityId },
        });
    }

    /**
     * Get all bookmarks for a user
     */
    async getUserBookmarks(userId: string): Promise<BookmarkInfo[]> {
        const bookmarks = await this.prisma.vulnerabilityBookmark.findMany({
            where: { userId },
            include: {
                vulnerability: true,
            },
            orderBy: { createdAt: 'desc' },
        });

        return bookmarks.map(b => ({
            id: b.id,
            cveId: b.vulnerability.cveId,
            title: b.vulnerability.title || b.vulnerability.cveId,
            severity: b.vulnerability.severity,
            note: b.note || undefined,
            createdAt: b.createdAt,
        }));
    }

    /**
     * Check if vulnerability is bookmarked
     */
    async isBookmarked(userId: string, vulnerabilityId: string): Promise<boolean> {
        const bookmark = await this.prisma.vulnerabilityBookmark.findUnique({
            where: {
                userId_vulnerabilityId: { userId, vulnerabilityId },
            },
        });

        return !!bookmark;
    }

    /**
     * Get bookmark count for a vulnerability
     */
    async getBookmarkCount(vulnerabilityId: string): Promise<number> {
        return this.prisma.vulnerabilityBookmark.count({
            where: { vulnerabilityId },
        });
    }

    /**
     * Update bookmark note
     */
    async updateNote(
        userId: string,
        vulnerabilityId: string,
        note: string,
    ): Promise<void> {
        await this.prisma.vulnerabilityBookmark.update({
            where: {
                userId_vulnerabilityId: { userId, vulnerabilityId },
            },
            data: { note },
        });
    }
}
