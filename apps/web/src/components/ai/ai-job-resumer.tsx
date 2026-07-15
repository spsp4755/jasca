'use client';

import { useEffect } from 'react';
import { refreshAiJob } from '@/lib/ai-job-client';
import { useAiStore } from '@/stores/ai-store';

const POLL_INTERVAL_MS = 2_500;

export function AiJobResumer() {
    const pendingJobs = useAiStore(state => state.pendingJobs);
    const jobIds = Object.keys(pendingJobs).sort().join(',');

    useEffect(() => {
        if (!jobIds) return;
        const refresh = () => jobIds.split(',').forEach(id => void refreshAiJob(id));
        refresh();
        const timer = window.setInterval(refresh, POLL_INTERVAL_MS);
        return () => window.clearInterval(timer);
    }, [jobIds]);

    return null;
}
