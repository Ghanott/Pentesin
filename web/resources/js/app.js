for (const form of document.querySelectorAll('form[data-confirm]')) {
    form.addEventListener('submit', event => {
        if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
}

for (const form of document.querySelectorAll('form[data-model-test]')) {
    form.addEventListener('submit', async event => {
        event.preventDefault();
        const button = form.querySelector('button[type="submit"]');
        const status = form.querySelector('[data-test-status]');
        if (button.disabled) return;
        button.disabled = true;
        button.textContent = 'Menguji…';
        status.textContent = 'Menguji…';
        try {
            const response = await fetch(form.action, {
                method: 'POST', body: new FormData(form),
                headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(20000),
            });
            if (!response.ok) throw new Error(response.status === 401 || response.status === 419 ? 'Sesi berakhir. Muat ulang halaman.' : 'Tidak dapat memulai tes koneksi.');
            const result = await response.json();
            const latency = result.latency_ms ? ` (${result.latency_ms} ms)` : '';
            status.textContent = result.status === 'connected' ? `Terhubung${latency}` : `Gagal terhubung${result.error ? ': ' + result.error : ''}`;
            status.dataset.state = result.status;
        } catch (error) {
            status.textContent = `Gagal terhubung: ${error.message}`;
            status.dataset.state = 'failed';
        } finally {
            button.disabled = false;
            button.textContent = 'Tes koneksi';
        }
    });
}

const workspace = document.getElementById('scan-workspace');
if (workspace) {
    import('./agent-graph').then(({ startScanWorkspace }) => startScanWorkspace(workspace));
}
