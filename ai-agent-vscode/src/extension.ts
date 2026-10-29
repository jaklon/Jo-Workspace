import * as vscode from 'vscode';
import { readAnswer } from './sse';

export function activate(context: vscode.ExtensionContext) {
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
}

export function deactivate() {}
