'use client';

import { useRouter } from 'next/navigation';
import { UploadScanModal } from '@/components/upload-scan-modal';

export default function NewScanPage() {
    const router = useRouter();

    return (
        <UploadScanModal
            isOpen
            onClose={() => {
                router.push('/dashboard/scans');
            }}
        />
    );
}
