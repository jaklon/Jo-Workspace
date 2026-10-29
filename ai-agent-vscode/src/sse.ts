export async function readAnswer(response: Response, onToken: () => void = () => {}): Promise<string> {
    if (!response.ok) {
        const body = await response.json().catch(() => ({})) as { detail?: unknown };
        throw new Error(typeof body.detail === 'string' ? body.detail : `HTTP ${response.status}`);
    }
    if (!response.body || !response.headers.get('content-type')?.includes('text/event-stream')) {
        throw new Error('Respons backend bukan SSE.');
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '', answer = '';
    let complete = false;
    const process = (block: string) => {
        const data = block.split(/\r?\n/).filter(line => line.startsWith('data:')).map(line => line.slice(5).trimStart()).join('\n');
        if (!data) { return; }
        const event = JSON.parse(data);
        if (event.type === 'error') { throw new Error(event.detail || 'Inferensi gagal.'); }
        if (event.type === 'token') { answer += event.token || ''; onToken(); }
        if (event.type === 'result') { answer = event.result || ''; }
        if (event.type === 'done') { complete = true; }
    };
    try {
        while (true) {
            const { value, done } = await reader.read();
            buffer += done ? decoder.decode() : decoder.decode(value, { stream: true });
            let match: RegExpExecArray | null;
            while ((match = /\r?\n\r?\n/.exec(buffer))) {
                process(buffer.slice(0, match.index));
                buffer = buffer.slice(match.index + match[0].length);
            }
            if (done) { break; }
        }
        if (buffer.trim()) { process(buffer); }
        if (!complete || !answer) { throw new Error('Stream terputus atau tidak memiliki jawaban akhir.'); }
        return answer;
    } finally { await reader.cancel().catch(() => undefined); reader.releaseLock(); }
}
