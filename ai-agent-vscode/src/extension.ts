import * as vscode from 'vscode';

export function activate(context: vscode.ExtensionContext) {
    let disposable = vscode.commands.registerCommand('ai-agent.refactorCode', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('Buka file kode terlebih dahulu.');
            return;
        }

        const selection = editor.document.getText(editor.selection);
        if (!selection) {
            vscode.window.showWarningMessage('Silakan sorot (blok) kode yang ingin di-refactor.');
            return;
        }

        vscode.window.showInformationMessage('AI Agent: Mengirim kode ke model lokal...');

        try {
            const response = await fetch('http://127.0.0.1:8000/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target: 'coding',
                    prompt: `Refactor dan jelaskan kode berikut secara ringkas:\n\`\`\`\n${selection}\n\`\`\``
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status} ${response.statusText}`);
            }

            const rawText = await response.text();

            // Buka tab editor baru di samping (split editor) untuk menampilkan hasil
            const doc = await vscode.workspace.openTextDocument({
                content: rawText,
                language: 'markdown'
            });
            await vscode.window.showTextDocument(doc, vscode.ViewColumn.Beside);

        } catch (error: any) {
            vscode.window.showErrorMessage(`Gagal terhubung ke AI lokal: ${error.message}`);
        }
    });

    context.subscriptions.push(disposable);
}

export function deactivate() {}