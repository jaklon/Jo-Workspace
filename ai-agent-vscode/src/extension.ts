import * as vscode from 'vscode';
import { readAnswer } from './sse';

function resolveBase(): URL | undefined {
    const configured = vscode.workspace.getConfiguration('ai-agent').get<string>('apiBaseUrl', 'http://127.0.0.1:8010');
    try {
        const base = new URL(configured);
        if (base.username || base.password || base.search || base.hash ||
            (base.protocol !== 'https:' && !(base.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(base.hostname)))) {
            throw new Error('invalid');
        }
        return base;
    } catch {
        void vscode.window.showErrorMessage('URL backend tidak valid. Gunakan HTTPS atau http://127.0.0.1:8010.');
        return undefined;
    }
}

interface SecurityDiagnostic {
    file: string;
    line_start: number;
    line_end: number;
    severity: string;
    code: string;
    message: string;
    source_tool: string;
    confidence?: string;
}

export function activate(context: vscode.ExtensionContext) {
    const securityDiagnostics = vscode.languages.createDiagnosticCollection('jo-security');
    context.subscriptions.push(securityDiagnostics);
    const configure = async () => {
        const token = await vscode.window.showInputBox({ title: 'Token akses Jo Workspace', password: true, ignoreFocusOut: true, prompt: 'Token dari data/runtime/api-token pada server lokal.' });
        if (token) {
            await context.secrets.store('agent-api-token', token);
        }
        return token;
    };
    context.subscriptions.push(vscode.commands.registerCommand('ai-agent.configureConnection', configure));
    context.subscriptions.push(vscode.commands.registerCommand('ai-agent.refactorCode', async () => {
        const editor = vscode.window.activeTextEditor;
        const selection = editor?.document.getText(editor.selection);
        if (!selection) {
            void vscode.window.showWarningMessage('Sorot kode yang ingin direview atau direfactor.');
            return;
        }
        if (selection.length > 5000) {
            void vscode.window.showWarningMessage('Pilihan terlalu panjang. Pilih satu fungsi atau bagian kode.');
            return;
        }
        const token = await context.secrets.get('agent-api-token') || await configure();
        if (!token) { return; }
        const configured = vscode.workspace.getConfiguration('ai-agent').get<string>('apiBaseUrl', 'http://127.0.0.1:8010');
        let base: URL;
        try {
            base = new URL(configured);
            if (base.username || base.password || base.search || base.hash ||
                (base.protocol !== 'https:' && !(base.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(base.hostname)))) {
                throw new Error('Gunakan HTTPS atau HTTP loopback lokal.');
            }
        } catch {
            void vscode.window.showErrorMessage('URL backend tidak valid. Gunakan HTTPS atau http://127.0.0.1:8010.');
            return;
        }
        try {
            await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'Jo Workspace: review kode', cancellable: true }, async (progress, cancellation) => {
                const controller = new AbortController();
                const subscription = cancellation.onCancellationRequested(() => controller.abort());
                const timeout = setTimeout(() => controller.abort(), 180000);
                try {
                    const response = await fetch(new URL('/api/chat', base), {
                        method: 'POST', signal: controller.signal,
                        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                        body: JSON.stringify({ target: 'coding', prompt: 'Review dan usulkan refactor kode berikut secara ringkas:\n' + selection })
                    });
                    if (response.status === 401) {
                        await context.secrets.delete('agent-api-token');
                        throw new Error('Token ditolak. Jalankan “Jo Workspace: Set API Token” lalu coba lagi.');
                    }
                    const answer = await readAnswer(response, () => progress.report({ message: 'Menerima jawaban...' }));
                    if (cancellation.isCancellationRequested) { return; }
                    const doc = await vscode.workspace.openTextDocument({ content: answer, language: 'markdown' });
                    await vscode.window.showTextDocument(doc, vscode.ViewColumn.Beside);
                } finally { clearTimeout(timeout); subscription.dispose(); }
            });
        } catch (error: unknown) {
            const reason = error instanceof Error ? error.message : String(error);
            void vscode.window.showErrorMessage(reason.includes('abort') ? 'Permintaan dibatalkan atau melebihi batas waktu.' : 'Jo Workspace: ' + reason);
        }
    }));
    context.subscriptions.push(vscode.commands.registerCommand('ai-agent.loadSecurityDiagnostics', async () => {
        const folder = vscode.workspace.workspaceFolders?.[0];
        if (!folder) {
            void vscode.window.showWarningMessage('Buka folder workspace untuk memetakan diagnostik keamanan.');
            return;
        }
        const cfg = vscode.workspace.getConfiguration('ai-agent');
        const uuid = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
        let projectId = (cfg.get<string>('projectId', '') || '').trim();
        let engagementId = (cfg.get<string>('engagementId', '') || '').trim();
        if (!projectId) { projectId = ((await vscode.window.showInputBox({ title: 'Project ID (UUID)', ignoreFocusOut: true })) || '').trim(); }
        if (!engagementId) { engagementId = ((await vscode.window.showInputBox({ title: 'Engagement ID (UUID)', ignoreFocusOut: true })) || '').trim(); }
        if (!uuid.test(projectId) || !uuid.test(engagementId)) {
            void vscode.window.showErrorMessage('Project ID dan Engagement ID harus berupa UUID yang valid.');
            return;
        }
        const base = resolveBase();
        if (!base) { return; }
        const token = await context.secrets.get('agent-api-token') || await configure();
        if (!token) { return; }
        try {
            const response = await fetch(new URL(`/api/security/projects/${projectId}/engagements/${engagementId}/diagnostics`, base), {
                headers: { 'Authorization': 'Bearer ' + token }
            });
            if (response.status === 401) {
                await context.secrets.delete('agent-api-token');
                throw new Error('Token ditolak. Jalankan “Jo Workspace: Set API Token” lalu coba lagi.');
            }
            if (!response.ok) { throw new Error('Backend menolak permintaan diagnostik (HTTP ' + response.status + ').'); }
            const data = await response.json() as { diagnostics: SecurityDiagnostic[] };
            securityDiagnostics.clear();
            const byFile = new Map<string, vscode.Diagnostic[]>();
            for (const d of data.diagnostics || []) {
                const rel = (d.file || '').replace(/\\/g, '/').replace(/^\/+/, '');
                if (!rel || rel.includes('..')) { continue; }
                const start = Math.max(0, (d.line_start || 1) - 1);
                const end = Math.max(start, (d.line_end || d.line_start || 1) - 1);
                const range = new vscode.Range(start, 0, end, 500);
                const severity = d.severity === 'high' ? vscode.DiagnosticSeverity.Error
                    : d.severity === 'medium' ? vscode.DiagnosticSeverity.Warning
                        : vscode.DiagnosticSeverity.Information;
                const label = `[${d.source_tool}${d.confidence ? '/' + d.confidence : ''}] ${d.message}`;
                const diagnostic = new vscode.Diagnostic(range, label, severity);
                diagnostic.source = 'Jo Workspace';
                if (d.code) { diagnostic.code = d.code; }
                const list = byFile.get(rel) || [];
                list.push(diagnostic);
                byFile.set(rel, list);
            }
            let total = 0;
            for (const [rel, list] of byFile) {
                securityDiagnostics.set(vscode.Uri.joinPath(folder.uri, ...rel.split('/')), list);
                total += list.length;
            }
            void vscode.window.showInformationMessage(`Jo Workspace: ${total} diagnostik keamanan dimuat ke Problems.`);
        } catch (error: unknown) {
            const reason = error instanceof Error ? error.message : String(error);
            void vscode.window.showErrorMessage('Jo Workspace: ' + reason);
        }
    }));
}

export function deactivate() {}
