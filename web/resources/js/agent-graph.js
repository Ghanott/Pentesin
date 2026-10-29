import cytoscape from 'cytoscape';

const statuses = { queued: 'Antrean', preparing: 'Persiapan', running: 'Berjalan', waiting: 'Menunggu', completed: 'Selesai', stopped: 'Dihentikan', failed: 'Gagal', crashed: 'Gagal', interrupted: 'Terputus' };
const terminal = new Set(['completed', 'failed', 'stopped', 'interrupted']);
const severityLabels = { critical: 'KRITIS', high: 'TINGGI', medium: 'SEDANG', low: 'RENDAH', info: 'INFORMASIONAL' };
const text = (value) => typeof value === 'string' ? value : JSON.stringify(value ?? '', null, 2);
const make = (tag, className, value) => { const el = document.createElement(tag); if (className) el.className = className; if (value !== undefined) el.textContent = text(value); return el; };

export function startScanWorkspace(root) {
    const get = (id) => document.getElementById(id);
    const modal = get('agent-modal'), transcript = get('agent-transcript'), findingsModal = get('finding-modal');
    const colors = getComputedStyle(document.documentElement);
    const color = (token) => colors.getPropertyValue(token).trim();
    let agents = new Map(), events = new Map(), selected = null, rendered = new Set();
    let status = root.dataset.status, cursor = 0, failures = 0, stopped = false, pendingCommand = null;
    let opener = null, follow = true, topology = '', foundSnapshot = '', previousCount = 0;
    const cy = cytoscape({ container: get('agent-graph'), elements: [], minZoom: 0.1, maxZoom: 2.2, wheelSensitivity: 0.2, style: [
        { selector: 'node', style: {
            shape: 'round-rectangle', width: 176, height: 44, 'corner-radius': 9,
            'background-fill': 'linear-gradient', 'background-gradient-direction': 'to-bottom',
            'background-gradient-stop-colors': '#152433 #0d1722',
            'border-color': '#22364a', 'border-width': 1.5,
            'shadow-blur': 14, 'shadow-color': '#000', 'shadow-opacity': 0.4, 'shadow-offset-y': 3,
            label: 'data(label)', 'text-wrap': 'wrap', 'text-max-width': 158,
            'font-family': 'Poppins, ui-sans-serif, system-ui, sans-serif', 'font-size': 11.5, 'font-weight': 500,
            color: '#e2e8f0', 'text-valign': 'center', 'text-halign': 'center',
        } },
        { selector: 'node[?is_root]', style: {
            width: 192, height: 48, 'corner-radius': 10, 'border-width': 2,
            'font-size': 12, 'font-weight': 600,
        } },
        { selector: 'edge', style: {
            width: 1.5, 'curve-style': 'round-taxi', 'taxi-direction': 'downward',
            'taxi-radius': 12, 'taxi-turn': 28, 'taxi-turn-min-distance': 12,
            'line-color': '#24374b', 'target-arrow-shape': 'triangle',
            'target-arrow-color': '#334c66', 'arrow-scale': 0.75,
        } },
        { selector: 'edge[status = "running"]', style: {
            'line-color': color('--accent'), 'target-arrow-color': color('--accent'),
            width: 2, 'line-style': 'dashed', 'line-dash-pattern': [6, 4]
        } },
        { selector: 'edge[status = "completed"]', style: {
            'line-color': '#234732', 'target-arrow-color': '#3fae5a', width: 1.5
        } },
        { selector: 'edge[status = "failed"], edge[status = "crashed"]', style: {
            'line-color': '#4a2128', 'target-arrow-color': color('--critical'), width: 1.5
        } },
        { selector: 'edge[status = "waiting"], edge[status = "queued"]', style: {
            'line-color': '#3d341c', 'target-arrow-color': color('--warning'),
            width: 1.2, 'line-style': 'dashed', 'line-dash-pattern': [4, 4]
        } },
        { selector: 'node[status = "running"]', style: {
            'border-color': color('--accent'), 'border-width': 2,
            'shadow-color': color('--accent'), 'shadow-opacity': 0.25, 'shadow-blur': 22,
            'background-gradient-stop-colors': '#13303a #0c1c24'
        } },
        { selector: 'node[status = "waiting"], node[status = "queued"]', style: {
            'border-color': color('--warning'), 'border-width': 1.5, 'border-style': 'dashed',
            'border-dash-pattern': [5, 3], 'shadow-color': color('--warning'), 'shadow-opacity': 0.16, 'shadow-blur': 14,
            'background-gradient-stop-colors': '#272013 #14110a'
        } },
        { selector: 'node[status = "completed"]', style: {
            'border-color': '#3fae5a', 'border-width': 1.5,
            'shadow-color': '#3fae5a', 'shadow-opacity': 0.2, 'shadow-blur': 16,
            'background-gradient-stop-colors': '#13281c #0c1812'
        } },
        { selector: 'node[status = "failed"], node[status = "crashed"]', style: {
            'border-color': color('--critical'), 'border-width': 2,
            'shadow-color': color('--critical'), 'shadow-opacity': 0.25, 'shadow-blur': 20,
            'background-gradient-stop-colors': '#32161f #1a0b11'
        } },
        { selector: 'node:active', style: { 'border-color': color('--accent'), 'border-width': 2 } },
        { selector: 'node:selected', style: {
            'border-color': '#ffffff', 'border-width': 2.5,
            'shadow-color': '#ffffff', 'shadow-opacity': 0.45, 'shadow-blur': 24
        } },
        { selector: 'node.dense', style: { width: 112, height: 34, 'font-size': 9, 'text-max-width': 100, 'corner-radius': 7 } },
        { selector: 'node.tight', style: { width: 84, height: 28, 'font-size': 0, 'corner-radius': 6 } },
        { selector: 'node.unlabeled', style: { label: '' } },
    ] });
    const canSteer = () => Boolean(selected && ['running', 'queued', 'completed', 'failed', 'interrupted'].includes(status));
    const updateComposer = () => {
        const enabled = canSteer();
        const agentStatus = agents.get(selected)?.status;
        get('agent-message').disabled = !enabled;
        if (!enabled) {
            get('message-status').textContent = 'Scan sudah berhenti; riwayat tetap dapat dibaca.';
        } else if (['completed', 'failed', 'interrupted'].includes(status) || ['completed', 'failed', 'crashed'].includes(agentStatus)) {
            get('message-status').textContent = 'Kirim instruksi untuk melanjutkan agent. Pastikan koneksi dan kuota model sudah tersedia.';
        } else {
            get('message-status').textContent = 'Instruksi dikirim ke agent, bukan shell server.';
        }
    };
    const appendTranscript = () => {
        if (!selected) return;
        let added = false;
        const items = [...events.values()].filter(e => String(e.agent_id) === selected).sort((a, b) => Number(a.id) - Number(b.id));
        if (items.length && transcript.querySelector('.transcript-empty')) transcript.replaceChildren();
        for (const event of items) {
            const eventId = String(event.source_id ?? event.id);
            const key = `${eventId}:${event.version ?? 0}`;
            if (rendered.has(key)) continue;
            rendered.add(key); added = true;
            const data = event.data ?? {};
            const previous = [...transcript.children].find(node => node.dataset.eventId === eventId);
            const item = make('article', `event ${event.type === 'user_message' || data.role === 'user' ? 'user' : ''} ${data.metadata?.source === 'agent_error' || data.status === 'failed' ? 'is-error' : ''}`);
            item.dataset.eventId = eventId;
            const meta = make('div', 'event-meta');
            const toolName = data.name ?? data.tool_name ?? event.type ?? 'Aktivitas';
            const statusLabel = data.status === 'running' ? 'berjalan' : data.status === 'completed' ? 'selesai' : data.status === 'failed' ? 'gagal' : '';
            meta.append(make('strong', '', statusLabel ? `${toolName} · ${statusLabel}` : toolName), make('span', '', event.created_at ? new Date(event.created_at).toLocaleTimeString('id-ID') : `#${event.id}`));
            let body;
            if (event.type === 'tool') {
                let args = data.args;
                if (typeof args === 'string') { try { args = JSON.parse(args); } catch { /* Keep plain command text. */ } }
                body = args?.cmd ?? args?.command ?? (Array.isArray(args?.commands) ? args.commands.map(command => command.command ?? command).join('\n') : text(args ?? '(argumen tidak tersedia)'));
            } else {
                body = typeof data === 'string' ? data : text(data.content ?? data.text ?? data.message ?? data);
                if (typeof body === 'object' && body !== null) body = text(body.content ?? body.text ?? body);
            }
            item.append(meta, make('pre', '', body));
            if (event.type === 'tool' && data.result !== undefined && data.result !== null) {
                const output = make('details', 'command-output');
                output.open = text(data.result).length < 1200 || data.status === 'failed';
                output.append(make('summary', '', 'Hasil command'), make('pre', '', text(data.result)));
                item.append(output);
            }
            if (previous) previous.replaceWith(item); else transcript.append(item);
        }
        if (!items.length && !transcript.children.length) transcript.append(make('p', 'muted transcript-empty', 'Belum ada aktivitas tercatat untuk agent ini.'));
        if (added && follow) transcript.scrollTop = transcript.scrollHeight;
    };
    function openAgent(id, source = null) {
        selected = String(id); opener = source ?? document.activeElement;
        const agent = agents.get(selected); if (!agent) return;
        cy.nodes().unselect(); cy.getElementById(selected).select();
        if (cy.zoom() < 0.42) { cy.animate({ center: { eles: cy.getElementById(selected) }, zoom: 0.75, duration: 220 }); }
        get('agent-modal-title').textContent = agent.name ?? selected;
        get('agent-modal-status').textContent = statuses[agent.status] ?? agent.status;
        rendered = new Set(); transcript.replaceChildren(); follow = true;
        get('agent-message').value = ''; pendingCommand = null;
        get('message-status').textContent = 'Instruksi dikirim ke agent, bukan shell server.';
        appendTranscript(); updateComposer(); if (!modal.open) modal.showModal();
    }
    cy.on('tap', 'node', event => openAgent(event.target.id()));
    for (const dialog of [modal, findingsModal]) {
        dialog.querySelector('[data-close-dialog]').addEventListener('click', () => dialog.close());
        dialog.addEventListener('click', event => { if (event.target === dialog) { const r = dialog.getBoundingClientRect(); if (event.clientX < r.left || event.clientX > r.right || event.clientY < r.top || event.clientY > r.bottom) dialog.close(); } });
        dialog.addEventListener('close', () => { if (dialog === modal) selected = null; opener?.focus?.(); });
    }
    transcript.addEventListener('scroll', () => { follow = transcript.scrollHeight - transcript.scrollTop - transcript.clientHeight < 80; });
    get('scroll-latest').addEventListener('click', () => { follow = true; transcript.scrollTop = transcript.scrollHeight; });
    get('graph-fit').addEventListener('click', () => fitReadable());
    get('graph-zoom-in').addEventListener('click', () => cy.zoom(Math.min(2, cy.zoom() * 1.2)));
    get('graph-zoom-out').addEventListener('click', () => cy.zoom(Math.max(0.2, cy.zoom() / 1.2)));
    let fitPending = false;
    const fitReadable = () => {
        if (cy.nodes().empty()) return;
        cy.fit(undefined, 52);
        if (cy.zoom() > 1.0) cy.zoom(1.0);
        cy.center();
    };
    const refit = () => fitReadable();
    const syncDensity = () => {
        cy.nodes().toggleClass('unlabeled', cy.zoom() < 0.34);
    };
    const applyDensity = (count) => {
        const dense = count > 12 && count <= 30, tight = count > 30;
        cy.nodes().toggleClass('dense', dense).toggleClass('tight', tight);
        syncDensity();
    };
    cy.on('zoom', syncDensity);
    const resize = new ResizeObserver(() => { cy.resize(); if (fitPending) { fitPending = false; refit(); } });
    resize.observe(get('agent-graph'));
    const updateAgents = (list) => {
        agents = new Map(list.map(a => [String(a.id), a]));
        const signature = list.map(a => `${a.id}:${a.parent_id ?? ''}`).sort().join('|'), first = cy.nodes().empty();
        cy.batch(() => {
            for (const node of cy.nodes()) if (!agents.has(node.id())) cy.remove(node);
            for (const a of list) {
                const name = a.name ?? a.id;
                const data = {
                    id: String(a.id),
                    label: name,
                    status: a.status,
                    is_root: !a.parent_id
                };
                const node = cy.getElementById(data.id);
                if (node.empty()) cy.add({ group: 'nodes', data }); else node.data(data);
            }
            cy.edges().remove();
            for (const a of list) {
                if (a.parent_id && agents.has(String(a.parent_id)) && String(a.parent_id) !== String(a.id)) {
                    cy.add({
                        group: 'edges',
                        data: { id: `edge:${a.id}`, source: String(a.parent_id), target: String(a.id), status: a.status }
                    });
                }
            }
        });
        if (topology !== signature) {
            const keepView = !first && list.length === previousCount;
            const zoom = cy.zoom(), pan = cy.pan();
            applyDensity(list.length);
            cy.layout({ name: 'breadthfirst', directed: true, padding: 50, spacingFactor: list.length > 12 ? 1.05 : 1.15, fit: false, animate: false, avoidOverlap: true }).run();
            if (keepView) { cy.zoom(zoom); cy.pan(pan); }
            else { fitReadable(); fitPending = true; }
            topology = signature;
        }
        previousCount = list.length;
        get('graph-empty').hidden = list.length > 0; get('agent-count').textContent = String(list.length);
        if (!list.length) {
            const empty = get('graph-empty'), heading = empty.querySelector('h3'), note = empty.querySelector('p');
            if (terminal.has(status)) {
                heading.textContent = 'Tidak ada agent tercatat';
                note.textContent = 'Runner berhenti sebelum sempat menjalankan agent.';
            } else {
                heading.textContent = 'Menunggu agent pertama';
                note.textContent = 'Peta muncul setelah runner memulai pengujian.';
            }
        }
        const accessible = get('agent-list');
        const focusedId = accessible.contains(document.activeElement) ? document.activeElement.dataset.agentId : null;
        accessible.replaceChildren();
        for (const a of list) {
            const btn = make('button', 'agent-row'); btn.type = 'button'; btn.dataset.agentId = String(a.id);
            const dot = make('span', 'agent-dot'); dot.dataset.status = a.status ?? '';
            const label = make('span', 'agent-row-name', a.name ?? a.id);
            const state = make('span', 'agent-row-state', statuses[a.status] ?? a.status ?? '—'); state.dataset.status = a.status ?? '';
            btn.append(dot, label, state);
            btn.addEventListener('click', () => openAgent(a.id, btn));
            accessible.append(btn);
            if (focusedId === String(a.id)) btn.focus();
        }
        if (!list.length) accessible.append(make('p', 'side-empty', 'Belum ada agent.'));
        get('agent-list-count').textContent = String(list.length);
        if (selected) { get('agent-modal-status').textContent = statuses[agents.get(selected)?.status] ?? 'Tidak aktif'; updateComposer(); }
    };
    const showFinding = (f, source) => {
        opener = source; get('finding-modal-title').textContent = f.title ?? 'Kerentanan';
        const detail = get('finding-detail'); detail.replaceChildren();
        const sev = make('span', 'severity', severityLabels[f.severity] ?? f.severity ?? '—'); sev.dataset.severity = f.severity; detail.append(sev);
        for (const [key, label] of [['target', 'Sasaran'], ['cvss', 'Skor CVSS'], ['cve', 'CVE'], ['cwe', 'CWE'], ['description', 'Deskripsi'], ['impact', 'Dampak'], ['technical_analysis', 'Analisis Teknis'], ['evidence', 'Bukti'], ['poc_description', 'Langkah reproduksi'], ['poc_script_code', 'Kode PoC'], ['remediation_steps', 'Rekomendasi perbaikan'], ['assumptions', 'Asumsi']]) {
            if (f[key] === undefined || f[key] === null || f[key] === '') continue;
            detail.append(make('h3', '', label), make(key === 'poc_script_code' ? 'pre' : 'div', 'report-text', text(f[key])));
        }
        findingsModal.showModal();
    };
    const updateArtifacts = (list) => {
        const container = get('scan-artifacts');
        container.replaceChildren();
        const allowed = new Set(['penetration_test_report.md', 'vulnerabilities.json', 'findings.sarif', 'coverage.json']);
        for (const name of list) {
            if (!allowed.has(name)) continue;
            const link = make('a', 'report-btn', name);
            link.href = `${location.pathname}/artifacts/${encodeURIComponent(name)}`;
            link.insertAdjacentHTML('afterbegin', '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>');
            container.append(link);
        }
    };
    const updateFindings = (list) => {
        get('finding-count').textContent = String(list.length);
        const signature = JSON.stringify(list); if (signature === foundSnapshot) return; foundSnapshot = signature;
        const container = get('findings'); container.replaceChildren();
        if (!list.length) { const empty = make('div', 'empty-state panel'); empty.append(make('h3', '', 'Belum ada temuan.'), make('p', '', 'Ini bukan pernyataan bahwa target aman.')); container.append(empty); }
        for (const f of list) {
            const btn = make('button', 'finding-card'); btn.type = 'button';
            const sev = make('span', 'severity', severityLabels[f.severity] ?? f.severity ?? '—'); sev.dataset.severity = f.severity;
            const info = make('span'); info.append(make('strong', '', f.title ?? 'Kerentanan'), make('small', '', f.target ?? f.endpoint ?? f.id));
            btn.append(sev, info); btn.addEventListener('click', () => showFinding(f, btn)); container.append(btn);
        }
    };
    const sendMessage = async () => {
        if (!canSteer()) return;
        const input = get('agent-message');
        const message = input.value.trim(); if (!message) return;
        if (input.disabled) return;
        const targetAgent = selected;
        input.disabled = true; get('message-status').textContent = 'Mengantrekan instruksi…';
        try {
            const response = await fetch(root.dataset.messages, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content }, body: JSON.stringify({ agent_id: targetAgent, message }) });
            if (!response.ok) throw new Error(response.status === 419 ? 'Sesi berakhir. Muat ulang halaman.' : 'Instruksi ditolak. Periksa status agent atau koneksi.');
            const result = await response.json(); pendingCommand = result.command?.id ?? result.id;
            if (stopped) { status = 'queued'; stopped = false; poll(); }
            else if (['completed', 'failed', 'interrupted'].includes(status)) status = 'queued';
            input.value = ''; get('message-status').textContent = 'Instruksi tersimpan di antrean; menunggu worker mengambilnya.';
        } catch (error) { get('message-status').textContent = error.message; }
        finally { input.disabled = !canSteer(); if (canSteer()) input.focus(); }
    };
    get('agent-message-form').addEventListener('submit', event => { event.preventDefault(); sendMessage(); });
    get('agent-message').addEventListener('keydown', event => {
        if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
            event.preventDefault(); sendMessage();
        }
    });
    async function poll() {
        if (stopped) return;
        if (document.hidden) { setTimeout(poll, 5000); return; }
        let delay = 1000;
        try {
            const response = await fetch(`${root.dataset.feed}?after=${cursor}`, { headers: { Accept: 'application/json' }, cache: 'no-store' });
            if (!response.ok) throw new Error(response.status === 401 || response.status === 419 ? 'Sesi berakhir. Muat ulang halaman untuk masuk.' : 'Koneksi terputus; mencoba kembali.');
            const data = await response.json(); failures = 0;
            status = data.scan.status; get('scan-status-label').textContent = statuses[status] ?? status; get('scan-status').dataset.status = status;
            get('scan-phase').textContent = data.scan.phase ?? '—';
            get('scan-error').hidden = !data.scan.error; get('scan-error').textContent = data.scan.error ?? '';
            updateAgents(data.agents ?? []);
            updateArtifacts(data.scan.artifacts ?? []);
            for (const e of data.events ?? []) {
                const key = String(e.source_id ?? e.id), current = events.get(key);
                if (!current || Number(e.version ?? 0) >= Number(current.version ?? 0)) events.set(key, e);
            }
            cursor = Math.max(cursor, Number(data.cursor ?? 0), ...(data.events ?? []).map(e => Number(e.id)));
            appendTranscript(); updateFindings(data.findings ?? []);
            if (pendingCommand) { const cmd = (data.commands ?? []).find(c => String(c.id) === String(pendingCommand)); if (cmd) get('message-status').textContent = cmd.status === 'delivered' ? 'Instruksi diterima mailbox agent. Menunggu agent memprosesnya.' : cmd.status === 'failed' ? 'Instruksi gagal dikirim.' : 'Instruksi dalam antrean; menunggu runner.'; }
            if (data.scan.test_result) {
                const result = get('model-test-result'), test = data.scan.test_result;
                result.hidden = false;
                result.querySelector('[data-test="connection"]').textContent = test.connection ? 'Berhasil' : 'Gagal';
                result.querySelector('[data-test="latency_ms"]').textContent = `${Number(test.latency_ms) || 0} ms`;
                result.querySelector('[data-test="error"]').textContent = test.error ?? '';
            }
            get('connection-status').dataset.state = 'ok'; get('connection-status').textContent = terminal.has(status) ? 'Riwayat tersimpan · mode baca saja' : `Terhubung · diperbarui ${new Date().toLocaleTimeString('id-ID')}`;
            const stop = root.querySelector('form[data-confirm]'); if (stop && terminal.has(status)) stop.hidden = true;
            if (terminal.has(status) && (data.events ?? []).length < 200) stopped = true;
        } catch (error) { failures++; delay = Math.min(30000, 1000 * 2 ** Math.min(failures, 5)); get('connection-status').dataset.state = 'error'; get('connection-status').textContent = error.message; }
        if (!stopped) setTimeout(poll, delay);
    }
    poll();
    window.addEventListener('pagehide', () => { stopped = true; cy.destroy(); resize.disconnect(); }, { once: true });
}
