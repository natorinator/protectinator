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
        findingSearch: '',
        filterSeverity: '',
        filterCategory: '',
        sortField: 'severity',
        sortAsc: true,
        sbomSearch: '',
        sbomSearchResults: [],
        trendChart: null,

        async init() {
            await Promise.all([
                this.loadStatus(),
                this.loadHosts(),
                this.loadFleetSummary(),
            ]);
        },

        navigate(view) {
            this.previousView = this.view;
            this.view = view;
            if (view === 'scans') this.loadAllScans();
            if (view === 'advisories') this.loadAdvisories();
            if (view === 'sboms') this.loadSboms();
        },

        goBack() {
            if (this.previousView) {
                this.view = this.previousView;
                this.previousView = null;
            } else {
                this.view = 'dashboard';
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
            this.previousView = this.view;
            this.view = 'host';
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
            this.previousView = this.view;
            this.view = 'scan';
            this.findingSearch = '';
            this.filterSeverity = '';
            this.filterCategory = '';
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

        get hostTypes() {
            const types = new Set();
            for (const h of this.hosts) {
                types.add(this.getHostType(h.name));
            }
            return [...types].sort();
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
            const sevOrder = { Critical: 1, High: 2, Medium: 3, Low: 4, Info: 5 };
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

            // Severity filter
            if (this.filterSeverity) {
                results = results.filter(f => f.severity === this.filterSeverity);
            }

            // Category filter
            if (this.filterCategory) {
                results = results.filter(f => f.check_category === this.filterCategory);
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
