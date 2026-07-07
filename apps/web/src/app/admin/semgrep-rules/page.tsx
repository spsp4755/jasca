'use client';

import { useState } from 'react';
import { AlertTriangle, Code2, Edit, Loader2, Plus, Trash2, X } from 'lucide-react';
import {
    SemgrepRule,
    SemgrepRuleInput,
    useCreateSemgrepRule,
    useDeleteSemgrepRule,
    useSemgrepRules,
    useUpdateSemgrepRule,
} from '@/lib/api-hooks';

const YAML_TEMPLATE = `rules:
  - id: company.example.no-eval
    message: eval() 사용은 코드 인젝션 위험이 있어 금지됩니다.
    severity: ERROR
    languages: [javascript, typescript]
    pattern: eval(...)
`;

const emptyForm: SemgrepRuleInput = { name: '', description: '', yaml: YAML_TEMPLATE, isActive: true };

export default function AdminSemgrepRulesPage() {
    const { data: rules, isLoading, error } = useSemgrepRules();
    const createMutation = useCreateSemgrepRule();
    const updateMutation = useUpdateSemgrepRule();
    const deleteMutation = useDeleteSemgrepRule();

    const [showForm, setShowForm] = useState(false);
    const [editingId, setEditingId] = useState<string | null>(null);
    const [form, setForm] = useState<SemgrepRuleInput>(emptyForm);
    const [formError, setFormError] = useState('');

    const openCreate = () => {
        setEditingId(null);
        setForm(emptyForm);
        setFormError('');
        setShowForm(true);
    };

    const openEdit = (rule: SemgrepRule) => {
        setEditingId(rule.id);
        setForm({ name: rule.name, description: rule.description || '', yaml: rule.yaml, isActive: rule.isActive });
        setFormError('');
        setShowForm(true);
    };

    const handleSubmit = async () => {
        setFormError('');
        try {
            if (editingId) {
                await updateMutation.mutateAsync({ id: editingId, ...form });
            } else {
                await createMutation.mutateAsync(form);
            }
            setShowForm(false);
        } catch (e: any) {
            setFormError(e.message || '저장에 실패했습니다.');
        }
    };

    const handleToggle = (rule: SemgrepRule) => {
        updateMutation.mutate({ id: rule.id, isActive: !rule.isActive });
    };

    const handleDelete = async (rule: SemgrepRule) => {
        if (!window.confirm(`룰 "${rule.name}"을(를) 삭제할까요?`)) return;
        deleteMutation.mutate(rule.id);
    };

    const saving = createMutation.isPending || updateMutation.isPending;

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
                        <Code2 className="h-6 w-6 text-violet-600" />
                        커스텀 Semgrep 룰
                    </h1>
                    <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                        조직 고유의 소스코드 취약 패턴을 정의합니다. 활성화된 룰은 Semgrep 스캔 시 기본 룰과 함께 적용됩니다.
                    </p>
                </div>
                <button
                    onClick={openCreate}
                    className="flex items-center gap-2 px-4 py-2 text-sm bg-violet-600 text-white rounded-lg hover:bg-violet-700 transition-colors"
                >
                    <Plus className="h-4 w-4" />
                    룰 추가
                </button>
            </div>

            {isLoading && (
                <div className="flex items-center justify-center py-12 text-slate-500">
                    <Loader2 className="h-6 w-6 animate-spin mr-2" /> 불러오는 중...
                </div>
            )}

            {!!error && (
                <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 flex items-center gap-2 text-red-700 dark:text-red-300 text-sm">
                    <AlertTriangle className="h-4 w-4" /> 룰 목록을 불러오지 못했습니다.
                </div>
            )}

            {rules && (
                <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 overflow-hidden">
                    {rules.length === 0 ? (
                        <p className="px-6 py-10 text-sm text-slate-500 text-center">
                            등록된 커스텀 룰이 없습니다. "룰 추가"로 조직 고유 패턴을 정의해 보세요.
                        </p>
                    ) : (
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="text-left text-xs text-slate-500 uppercase border-b border-slate-200 dark:border-slate-700">
                                    <th className="px-6 py-3">이름</th>
                                    <th className="px-6 py-3">설명</th>
                                    <th className="px-4 py-3 text-center">활성</th>
                                    <th className="px-4 py-3">수정일</th>
                                    <th className="px-4 py-3 text-right">동작</th>
                                </tr>
                            </thead>
                            <tbody>
                                {rules.map((rule) => (
                                    <tr key={rule.id} className="border-b border-slate-100 dark:border-slate-700/50 last:border-0">
                                        <td className="px-6 py-3 font-medium text-slate-900 dark:text-white">{rule.name}</td>
                                        <td className="px-6 py-3 text-slate-600 dark:text-slate-400">{rule.description || '-'}</td>
                                        <td className="px-4 py-3 text-center">
                                            <button
                                                onClick={() => handleToggle(rule)}
                                                className={`px-2 py-1 rounded-full text-xs font-medium transition-colors ${
                                                    rule.isActive
                                                        ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                                                        : 'bg-slate-100 text-slate-500 dark:bg-slate-700 dark:text-slate-400'
                                                }`}
                                            >
                                                {rule.isActive ? '활성' : '비활성'}
                                            </button>
                                        </td>
                                        <td className="px-4 py-3 text-slate-500">{new Date(rule.updatedAt).toLocaleDateString('ko-KR')}</td>
                                        <td className="px-4 py-3 text-right">
                                            <button onClick={() => openEdit(rule)} className="p-1.5 text-slate-500 hover:text-blue-600 transition-colors" title="편집">
                                                <Edit className="h-4 w-4" />
                                            </button>
                                            <button onClick={() => handleDelete(rule)} className="p-1.5 text-slate-500 hover:text-red-600 transition-colors" title="삭제">
                                                <Trash2 className="h-4 w-4" />
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </div>
            )}

            {showForm && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
                    <div className="w-full max-w-2xl bg-white dark:bg-slate-800 rounded-xl shadow-xl border border-slate-200 dark:border-slate-700 max-h-[90vh] overflow-y-auto">
                        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-700">
                            <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
                                {editingId ? '룰 편집' : '새 커스텀 룰'}
                            </h2>
                            <button onClick={() => setShowForm(false)} className="p-1 text-slate-500 hover:text-slate-700">
                                <X className="h-5 w-5" />
                            </button>
                        </div>
                        <div className="p-6 space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">이름 *</label>
                                <input
                                    value={form.name}
                                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                                    placeholder="예: no-eval-policy"
                                    className="w-full px-3 py-2 border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-900 text-slate-900 dark:text-white text-sm"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">설명</label>
                                <input
                                    value={form.description || ''}
                                    onChange={(e) => setForm({ ...form, description: e.target.value })}
                                    placeholder="룰의 목적을 간단히 설명"
                                    className="w-full px-3 py-2 border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-900 text-slate-900 dark:text-white text-sm"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                                    룰 YAML * <span className="font-normal text-slate-400">(semgrep 룰 형식, 저장 시 검증됩니다)</span>
                                </label>
                                <textarea
                                    value={form.yaml}
                                    onChange={(e) => setForm({ ...form, yaml: e.target.value })}
                                    rows={14}
                                    spellCheck={false}
                                    className="w-full px-3 py-2 border border-slate-200 dark:border-slate-600 rounded-lg bg-slate-50 dark:bg-slate-900 text-slate-900 dark:text-white text-xs font-mono"
                                />
                            </div>
                            <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
                                <input
                                    type="checkbox"
                                    checked={form.isActive !== false}
                                    onChange={(e) => setForm({ ...form, isActive: e.target.checked })}
                                />
                                활성화 (스캔에 즉시 적용)
                            </label>
                            {formError && (
                                <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3 text-sm text-red-700 dark:text-red-300">
                                    {formError}
                                </div>
                            )}
                        </div>
                        <div className="flex justify-end gap-2 px-6 py-4 border-t border-slate-200 dark:border-slate-700">
                            <button
                                onClick={() => setShowForm(false)}
                                className="px-4 py-2 text-sm text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
                            >
                                취소
                            </button>
                            <button
                                onClick={handleSubmit}
                                disabled={saving}
                                className="flex items-center gap-2 px-4 py-2 text-sm bg-violet-600 text-white rounded-lg hover:bg-violet-700 disabled:opacity-50 transition-colors"
                            >
                                {saving && <Loader2 className="h-4 w-4 animate-spin" />}
                                {editingId ? '저장' : '추가'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
