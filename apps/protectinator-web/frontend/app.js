function app() {
    return {
        view: 'dashboard',
        previousView: null,
        status: {},
        statusText: '',
        hosts: [],
        allScans: [],
        hostScans: [],
        selectedHost: '',
        currentScan: null,
        scanFindings: [],
        advisories: [],
        sbomNames: [],
        fleet: {},
        hostSearch: '',
        hostFilter: '',
        hostTypeFilter: '',
        hostTagFilter: '',
        findingSearch: '',
        filterSeverity: '',
        filterCategory: '',
        sortField: 'severity',
        sortAsc: true,
        filterActionability: '',
        penaltyBoxProfiles: [],
        sbomSearch: '',
        sbomSearchResults: [],
        trendChart: null,
        user: null,

        async init() {
            // History-based routing
            this._handleRoute(window.location.hash.slice(1));

            window.addEventListener('popstate', () => {
                this._skipPush = true;
                this._handleRoute(window.location.hash.slice(1));
                this._skipPush = false;
            });

            await Promise.all([
                this.loadStatus(),
                this.loadHosts(),
                this.loadFleetSummary(),
                this.loadPenaltyBox(),
                this.loadUser(),
            ]);

            // Load data for initial hash view
            if (hash === 'scans') this.loadAllScans();
            if (hash === 'advisories') this.loadAdvisories();
            if (hash === 'sboms') this.loadSboms();
        },

        navigate(view) {
            this.view = view;
            if (!this._skipPush) {
                history.pushState(null, '', '#' + view);
            }
            if (view === 'scans') this.loadAllScans();
            if (view === 'advisories') this.loadAdvisories();
            if (view === 'sboms') this.loadSboms();
        },

        goBack() {
            history.back();
        },

        _handleRoute(hash) {
            if (!hash || hash === '') {
                this.view = 'dashboard';
                return;
            }
            // Handle parameterized routes: host/NAME, scan/ID
            if (hash.startsWith('host/')) {
                const name = decodeURIComponent(hash.slice(5));
                this.viewHost(name);
                return;
            }
            if (hash.startsWith('scan/')) {
                const id = parseInt(hash.slice(5), 10);
                if (!isNaN(id)) {
                    this.viewScan(id);
                    return;
                }
            }
            this.view = hash;
            if (hash === 'scans') this.loadAllScans();
            if (hash === 'advisories') this.loadAdvisories();
            if (hash === 'sboms') this.loadSboms();
        },

        async loadUser() {
            try {
                const res = await fetch('/api/me');
                if (res.ok) {
                    this.user = await res.json();
                }
            } catch (e) {
                // Auth may be disabled
            }
        },

        async loadStatus() {
            try {
                const res = await fetch('/api/status');
                this.status = await res.json();
                this.statusText = `${this.status.scan_count} scans, ${this.status.finding_count} findings`;
            } catch (e) {
                this.statusText = 'Error loading status';
            }
        },

        async loadFleetSummary() {
            try {
                const res = await fetch('/api/fleet/summary');
                this.fleet = await res.json();
            } catch (e) {
                this.fleet = {};
            }
        },

        async loadPenaltyBox() {
            try {
                const res = await fetch('/api/penalty-box');
                this.penaltyBoxProfiles = await res.json();
            } catch (e) {
                this.penaltyBoxProfiles = [];
            }
        },

        async loadHosts() {
            try {
                const res = await fetch('/api/hosts');
                this.hosts = await res.json();
            } catch (e) {
                this.hosts = [];
            }
        },

        async loadAllScans() {
            try {
                const res = await fetch('/api/scans?limit=50');
                this.allScans = await res.json();
            } catch (e) {
                this.allScans = [];
            }
        },

        async viewHost(name) {
            this.selectedHost = name;
            this.view = 'host';
            if (!this._skipPush) {
                history.pushState(null, '', '#host/' + encodeURIComponent(name));
            }
            try {
                const res = await fetch(`/api/hosts/${encodeURIComponent(name)}/timeline?limit=20`);
                this.hostScans = await res.json();
            } catch (e) {
                this.hostScans = [];
            }
            // Load and render trend chart
            await this.loadTrendChart(name);
        },

        async loadTrendChart(name) {
            try {
                const res = await fetch(`/api/hosts/${encodeURIComponent(name)}/trends?limit=30`);
                const data = await res.json();
                if (data.length === 0) return;

                // Destroy previous chart
                if (this.trendChart) {
                    this.trendChart.destroy();
                    this.trendChart = null;
                }

                // Wait for DOM to render
                await this.$nextTick();

                const canvas = document.getElementById('trendChart');
                if (!canvas) return;

                const labels = data.map(s => {
                    const d = new Date(s.scanned_at);
                    return d.toLocaleDateString();
                });

                this.trendChart = new Chart(canvas, {
                    type: 'line',
                    data: {
                        labels,
                        datasets: [
                            {
                                label: 'Critical',
                                data: data.map(s => s.critical),
                                borderColor: '#f87171',
                                backgroundColor: 'rgba(248, 113, 113, 0.1)',
                                tension: 0.3,
                                fill: true,
                            },
                            {
                                label: 'High',
                                data: data.map(s => s.high),
                                borderColor: '#fbbf24',
                                backgroundColor: 'rgba(251, 191, 36, 0.1)',
                                tension: 0.3,
                                fill: true,
                            },
                            {
                                label: 'Medium',
                                data: data.map(s => s.medium),
                                borderColor: '#eab308',
                                backgroundColor: 'rgba(234, 179, 8, 0.05)',
                                tension: 0.3,
                                fill: true,
                            },
                            {
                                label: 'Low',
                                data: data.map(s => s.low),
                                borderColor: '#38bdf8',
                                backgroundColor: 'rgba(56, 189, 248, 0.05)',
                                tension: 0.3,
                                fill: true,
                            },
                        ],
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                labels: { color: '#9ca3af', font: { size: 11 } }
                            }
                        },
                        scales: {
                            x: {
                                ticks: { color: '#6b7280' },
                                grid: { color: 'rgba(75, 85, 99, 0.3)' }
                            },
                            y: {
                                beginAtZero: true,
                                ticks: { color: '#6b7280', stepSize: 1 },
                                grid: { color: 'rgba(75, 85, 99, 0.3)' }
                            }
                        }
                    }
                });
            } catch (e) {
                console.error('Failed to load trend chart:', e);
            }
        },

        async viewScan(id) {
            this.view = 'scan';
            if (!this._skipPush) {
                history.pushState(null, '', '#scan/' + id);
            }
            this.findingSearch = '';
            this.filterSeverity = '';
            this.filterCategory = '';
            this.filterActionability = '';
            this.sortField = 'severity';
            this.sortAsc = true;
            try {
                const res = await fetch(`/api/scans/${id}`);
                const data = await res.json();
                this.currentScan = data.scan;
                this.scanFindings = (data.findings || []).map(f => ({ ...f, _expanded: false }));
            } catch (e) {
                this.currentScan = null;
                this.scanFindings = [];
            }
        },

        async loadAdvisories() {
            try {
                const res = await fetch('/api/advisories?limit=100');
                this.advisories = await res.json();
            } catch (e) {
                this.advisories = [];
            }
        },

        async loadSboms() {
            try {
                const res = await fetch('/api/sboms');
                this.sbomNames = await res.json();
            } catch (e) {
                this.sbomNames = [];
            }
        },

        async searchSbomPackages() {
            if (!this.sbomSearch.trim()) return;
            try {
                const res = await fetch(`/api/sboms/search?q=${encodeURIComponent(this.sbomSearch)}`);
                this.sbomSearchResults = await res.json();
            } catch (e) {
                this.sbomSearchResults = [];
            }
        },

        formatDate(dateStr) {
            if (!dateStr) return '';
            try {
                const d = new Date(dateStr);
                return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            } catch {
                return dateStr;
            }
        },

        getHostType(name) {
            if (name.startsWith('remote:')) return 'remote';
            if (name.startsWith('container:')) return 'container';
            if (name.startsWith('local:')) return 'local';
            if (name.startsWith('iot:')) return 'iot';
            if (name.startsWith('/')) return 'repo';
            return 'other';
        },

        getHostTypeLabel(type) {
            const labels = { remote: 'Host', container: 'Container', repo: 'Repo', local: 'Local', iot: 'IoT' };
            return labels[type] || type;
        },

        getHostDisplayName(name) {
            if (name.startsWith('remote:')) return name.slice(7);
            if (name.startsWith('container:')) return name.slice(10);
            if (name.startsWith('/')) {
                // Show last path component(s) for repos
                const parts = name.split('/');
                return parts.slice(-2).join('/');
            }
            return name;
        },

        get hostTypes() {
            const types = new Set();
            for (const h of this.hosts) {
                types.add(this.getHostType(h.name));
            }
            return [...types].sort();
        },

        get hostTags() {
            const tags = new Set();
            for (const h of this.hosts) {
                for (const t of (h.tags || [])) {
                    tags.add(t);
                }
            }
            return [...tags].sort();
        },

        get filteredHosts() {
            let results = this.hosts;

            // Text search
            if (this.hostSearch.trim()) {
                const q = this.hostSearch.toLowerCase();
                results = results.filter(h => h.name.toLowerCase().includes(q));
            }

            // Type filter
            if (this.hostTypeFilter) {
                results = results.filter(h => this.getHostType(h.name) === this.hostTypeFilter);
            }

            // Tag filter
            if (this.hostTagFilter) {
                results = results.filter(h => (h.tags || []).includes(this.hostTagFilter));
            }

            // Severity filter
            if (this.hostFilter === 'critical') {
                results = results.filter(h => h.latest_critical > 0);
            } else if (this.hostFilter === 'high') {
                results = results.filter(h => h.latest_high > 0);
            } else if (this.hostFilter === 'clean') {
                results = results.filter(h => h.latest_critical === 0 && h.latest_high === 0);
            }

            return results;
        },

        get scanCategories() {
            const cats = new Set();
            for (const f of this.scanFindings) {
                if (f.check_category) cats.add(f.check_category);
            }
            return [...cats].sort();
        },

        get filteredFindings() {
            const sevOrder = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };
            let results = this.scanFindings;

            // Text search
            if (this.findingSearch.trim()) {
                const q = this.findingSearch.toLowerCase();
                results = results.filter(f =>
                    f.title.toLowerCase().includes(q) ||
                    (f.resource || '').toLowerCase().includes(q) ||
                    (f.check_category || '').toLowerCase().includes(q) ||
                    f.finding_id.toLowerCase().includes(q)
                );
            }

            // Severity filter (data is lowercase, filter values are capitalized)
            if (this.filterSeverity) {
                const sev = this.filterSeverity.toLowerCase();
                results = results.filter(f => f.severity.toLowerCase() === sev);
            }

            // Category filter
            if (this.filterCategory) {
                results = results.filter(f => f.check_category === this.filterCategory);
            }

            // Actionability filter
            if (this.filterActionability) {
                results = results.filter(f => (f.actionability || '') === this.filterActionability);
            }

            // Sort
            results = [...results].sort((a, b) => {
                let cmp = 0;
                if (this.sortField === 'severity') {
                    cmp = (sevOrder[a.severity] || 9) - (sevOrder[b.severity] || 9);
                } else if (this.sortField === 'title') {
                    cmp = a.title.localeCompare(b.title);
                } else if (this.sortField === 'check_category') {
                    cmp = (a.check_category || '').localeCompare(b.check_category || '');
                }
                return this.sortAsc ? cmp : -cmp;
            });

            return results;
        },

        actionabilityColor(cls) {
            switch (cls) {
                case 'patchable_now': return 'bg-green-600 text-white';
                case 'waiting_on_upstream': return 'bg-yellow-600 text-white';
                case 'accepted_risk': return 'bg-gray-600 text-white';
                case 'disputed': return 'bg-red-600 text-white';
                default: return 'bg-gray-700 text-gray-300';
            }
        },

        actionabilityLabel(cls) {
            switch (cls) {
                case 'patchable_now': return 'Patchable';
                case 'waiting_on_upstream': return 'Waiting';
                case 'accepted_risk': return 'Accepted';
                case 'disputed': return 'Disputed';
                default: return '';
            }
        },

        get activePenaltyBoxProfiles() {
            return this.penaltyBoxProfiles.filter(p => p.active);
        },

        toggleSort(field) {
            if (this.sortField === field) {
                this.sortAsc = !this.sortAsc;
            } else {
                this.sortField = field;
                this.sortAsc = true;
            }
        },
    };
}
