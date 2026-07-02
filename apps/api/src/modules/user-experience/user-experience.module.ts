import { Module } from '@nestjs/common';
import { TimelineService } from './timeline.service';
import { BookmarkService } from './bookmark.service';
import { ScanDiffService } from './scan-diff.service';
import { PrismaModule } from '../../prisma/prisma.module';

@Module({
    imports: [PrismaModule],
    providers: [TimelineService, BookmarkService, ScanDiffService],
    exports: [TimelineService, BookmarkService, ScanDiffService],
})
export class UserExperienceModule { }
