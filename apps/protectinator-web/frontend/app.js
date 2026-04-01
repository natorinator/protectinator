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
        sbomSearch: '',
        sbomSearchResults: [],
        trendChart: null,

        async init() {
            await this.loadStatus();
            await this.loadHosts();
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
        }
    };
}
