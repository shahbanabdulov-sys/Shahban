// Класс для управления направлениями продуктивности
class ProductivityTracker {
    constructor() {
        this.directions = this.loadDirections();
        this.chart = null;
        this.overallChart = null;
        this.chartUpdateTimer = null;
        this.candlesCache = new Map();
        // Auth & Cloud sync state
        this.firebase = { app: null, auth: null, db: null };
        this.currentUser = null;
        this.lastAuthUid = null;
        this.cloudSaveTimer = null;
        this.lastCloudSavedAt = null;
        // Идентификатор экземпляра и флаги синхронизации
        this.instanceId = (() => {
            try {
                const key = 'productivityInstanceId';
                let id = localStorage.getItem(key);
                if (!id) {
                    id = Date.now() + '-' + Math.random().toString(36).slice(2,10);
                    localStorage.setItem(key, id);
                }
                return id;
            } catch (_) {
                return Date.now() + '-' + Math.random().toString(36).slice(2,10);
            }
        })();
        this.isApplyingRemote = false;
        this.cloudUnsubscribe = null;
        
        // Новая система зума - управление временным диапазоном
        this.zoomState = {
            visibleCandlesCount: 50,    // Количество видимых свечей (как в TradingView)
            centerIndex: null,          // Центральная точка просмотра
            minCandlesCount: 10,        // Минимум свечей (максимальный зум)
            maxCandlesCount: 1000       // Максимум свечей на экране для производительности
        };
        // Отдельное состояние зума для общего графика
        this.overallZoomState = {
            visibleCandlesCount: 50,
            centerIndex: null,
            minCandlesCount: 10,
            maxCandlesCount: 1000
        };
        this.maxRenderedCandles = 800; // Жесткий потолок отрисовываемых свечей для производительности
        
        // Категории для организации направлений
        this.categories = this.loadCategories() || [
            { id: 'daily100', name: '100% ежедневно!', icon: '🔥', priority: 1 },
            { id: 'daily80', name: '80% ежедневно!', icon: '⚡', priority: 2 },
            { id: 'daily50', name: '50% ежедневно!', icon: '📈', priority: 3 },
            { id: 'other1', name: 'Прочее 1', icon: '📝', priority: 4 },
            { id: 'other2', name: 'Прочее 2', icon: '📋', priority: 5 },
            { id: 'other3', name: 'Прочее 3', icon: '📊', priority: 6 },
            { id: 'other4', name: 'Прочее 4', icon: '📌', priority: 7 }
        ];

        // Режим отображения списка направлений: 'horizontal' | 'compact'
        this.layoutMode = this.loadLayoutMode();

        // Ежедневные задания: локальное состояние
        this.tasks = this.loadTasks();
        
        this.initializeElements();
        this.bindEvents();
        this.setupFirebase();
        this.setupLifecycleGuards();
        // Гарантируем наличие хотя бы одной валидной категории и перенос «осиротевших» направлений
        this.ensureValidCategories();
        this.reassignOrphanDirections();
        this.render();
        this.updateChart();
        this.startChartAutoUpdate();
        // Хранилище для автообновления таймфреймов
        this.lastIntervalStartMs = null;
        this.frameScheduled = false;
    }

    updateDirectionAvgGrade(direction) {
        if (!this.detailDirectionAvgGrade) return;
        const grades = (direction.scores || []).map(s => s.meta && typeof s.meta.grade === 'number' ? s.meta.grade : null).filter(g => g != null);
        if (!grades.length) { this.detailDirectionAvgGrade.textContent = '-'; return; }
        const avg = grades.reduce((a,b)=>a+b,0) / grades.length;
        this.detailDirectionAvgGrade.textContent = avg.toFixed(1);
    }

    updatePeriodGradeBadge(directionId, period, isOverall = false) {
        const badge = document.getElementById('periodGradeBadge');
        const valEl = document.getElementById('periodGradeValue');
        const labelEl = document.getElementById('periodGradeLabel');
        if (!badge || !valEl || !labelEl) return;
        const full = this.getFullChartData(isOverall ? 'ALL' : directionId, period);
        if (!full || !full.candlestickData || !full.candlestickData.length) { badge.style.display = 'none'; return; }
        // Определим даты интервала отображения
        const candles = full.candlestickData;
        const start = candles[0];
        const end = candles[candles.length - 1];
        const startMs = start.intervalStart ? new Date(start.intervalStart).getTime() : new Date(start.x).getTime();
        const endMs = end.intervalEnd ? new Date(end.intervalEnd).getTime() : new Date(end.x).getTime();
        // Считаем среднюю оценку по скорам в диапазоне
        const directions = isOverall ? this.directions : this.directions.filter(d => String(d.id) === String(directionId));
        const grades = [];
        directions.forEach(d => {
            (d.scores || []).forEach(s => {
                const t = new Date(s.date).getTime();
                if (t >= startMs && t <= endMs && s.meta && typeof s.meta.grade === 'number') grades.push(s.meta.grade);
            });
        });
        if (!grades.length) { badge.style.display = 'none'; return; }
        const avg = grades.reduce((a,b)=>a+b,0) / grades.length;
        valEl.textContent = avg.toFixed(1);
        labelEl.textContent = 'Оценка за период';
        // Цвета по диапазонам
        const n = avg;
        let bg = '#444', color = '#fff', shadow = '0 0 0px transparent';
        if (n < 3) { bg = '#ef4444'; shadow = '0 0 16px rgba(239,68,68,0.6)'; }
        else if (n < 6) { bg = '#f97316'; shadow = '0 0 16px rgba(249,115,22,0.6)'; }
        else if (n < 8) { bg = '#f59e0b'; shadow = '0 0 16px rgba(245,158,11,0.6)'; }
        else if (n < 9) { bg = '#22c55e'; shadow = '0 0 16px rgba(34,197,94,0.6)'; }
        else { bg = 'linear-gradient(135deg,#06b6d4,#a78bfa,#f472b6)'; color = '#0b0e11'; shadow = '0 0 20px rgba(167,139,250,0.8)'; }
        valEl.style.background = bg;
        valEl.style.color = color;
        valEl.style.boxShadow = shadow;
        badge.style.display = 'block';
    }
    // На закрытии вкладки дожидаемся записи в облако
    setupLifecycleGuards() {
        const flush = async () => {
            try {
                if (this.cloudSaveTimer) {
                    clearTimeout(this.cloudSaveTimer);
                    this.cloudSaveTimer = null;
                }
                await this.saveToCloud();
            } catch(_) {}
        };
        const onBeforeUnload = (e) => {
            if (this.currentUser) {
                // Синхронный хук: запускаем flush и не блокируем закрытие
                navigator.sendBeacon && this.trySendBeacon();
            }
        };
        const onVisibility = async () => {
            if (document.visibilityState === 'hidden' && this.currentUser) {
                await flush();
            }
        };
        window.addEventListener('beforeunload', onBeforeUnload);
        document.addEventListener('visibilitychange', onVisibility);
        this._lifecycleCleanup = () => {
            window.removeEventListener('beforeunload', onBeforeUnload);
            document.removeEventListener('visibilitychange', onVisibility);
        };
    }

    trySendBeacon() {
        try {
            // Минимальный snapshot состояния
            const ref = this.getCloudDocRef();
            if (!ref) return false;
            // Firestore не поддерживает sendBeacon напрямую; полагаемся на предыдущие flush
            return false;
        } catch(_) { return false; }
    }

    // Возвращает ключ хранения, привязанный к текущему пользователю или 'guest'
    getStorageKey(baseKey) {
        const uid = (this.currentUser && this.currentUser.uid) ? this.currentUser.uid : 'guest';
        return `${baseKey}:${uid}`;
    }

    // === Ежедневные задания: состояние и хранилище ===
    loadTasks() {
        try {
            const keyed = localStorage.getItem(this.getStorageKey('productivityTasks'));
            const plain = localStorage.getItem('productivityTasksPlain');
            const raw = keyed || plain || '{}';
            const parsed = JSON.parse(raw);
            return (parsed && typeof parsed === 'object') ? parsed : {};
        } catch(_) { return {}; }
    }
    saveTasks() {
        try {
            const s = JSON.stringify(this.tasks);
            localStorage.setItem(this.getStorageKey('productivityTasks'), s);
            localStorage.setItem('productivityTasksPlain', s);
        } catch(_) {}
        if (this.currentUser) this.scheduleCloudSave(300);
    }

    // История событий по задачам
    loadTasksHistory() {
        try {
            const keyed = localStorage.getItem(this.getStorageKey('productivityTasksHistory'));
            const plain = localStorage.getItem('productivityTasksHistoryPlain');
            const raw = keyed || plain || '[]';
            const parsed = JSON.parse(raw);
            return Array.isArray(parsed) ? parsed : [];
        } catch(_) { return []; }
    }
    saveTasksHistory(list) {
        try {
            const s = JSON.stringify(list || []);
            localStorage.setItem(this.getStorageKey('productivityTasksHistory'), s);
            localStorage.setItem('productivityTasksHistoryPlain', s);
        } catch(_) {}
        if (this.currentUser) this.scheduleCloudSave(300);
    }
    logTaskEvent(type, dayKey, taskId, text) {
        const list = this.loadTasksHistory();
        list.push({ type, day: dayKey, taskId, text, timestamp: Date.now() });
        this.saveTasksHistory(list);
    }
    clearTasksHistory() {
        if (!confirm('Очистить историю заданий?')) return;
        this.saveTasksHistory([]);
        this.renderTasksHistory();
    }
    openTasksHistory() {
        if (!this.tasksHistoryModal) return;
        this.renderTasksHistory();
        this.tasksHistoryModal.style.display = 'flex';
    }
    closeTasksHistory() { if (this.tasksHistoryModal) this.tasksHistoryModal.style.display = 'none'; }
    renderTasksHistory() {
        if (!this.tasksHistoryList) return;
        const list = this.loadTasksHistory();
        // Агрегируем по тексту задачи
        const map = new Map();
        list.forEach(ev => {
            const key = (ev.text || '').trim();
            if (!key) return;
            const agg = map.get(key) || { text: key, done: 0, failed: 0, created: 0, deleted: 0 };
            if (ev.type === 'done') agg.done++;
            else if (ev.type === 'failed') agg.failed++;
            else if (ev.type === 'created') agg.created++;
            else if (ev.type === 'deleted') agg.deleted++;
            map.set(key, agg);
        });
        let rows = Array.from(map.values());
        const sort = this.tasksHistorySortSelect?.value || 'done_desc';
        const cmp = {
            'done_desc': (a,b) => b.done - a.done,
            'done_asc': (a,b) => a.done - b.done,
            'failed_desc': (a,b) => b.failed - a.failed,
            'failed_asc': (a,b) => a.failed - b.failed,
            'name_asc': (a,b) => a.text.localeCompare(b.text, 'ru')
        }[sort] || ((a,b)=> b.done - a.done);
        rows.sort(cmp);
        this.tasksHistoryList.innerHTML = '';
        rows.forEach(r => {
            const el = document.createElement('div');
            el.className = 'trash-item';
            const title = document.createElement('div');
            title.className = 'trash-item-title';
            title.textContent = r.text;
            const meta = document.createElement('div');
            meta.className = 'trash-item-meta';
            meta.innerHTML = `<span style="color:#16a34a; font-weight:600;">Выполнено: ${r.done}</span> • <span style="color:#ef4444; font-weight:600;">Провалено: ${r.failed}</span>`;
            el.appendChild(title); el.appendChild(meta);
            this.tasksHistoryList.appendChild(el);
        });
    }

    // Ключ дня недели (0-6): 0 - Пн, 6 - Вс; но JS getDay() даёт 0 - Вс
    getWeekdayKeys() {
        return ['mon','tue','wed','thu','fri','sat','sun'];
    }
    getWeekdayLabel(key) {
        const map = { mon: 'Понедельник', tue: 'Вторник', wed: 'Среда', thu: 'Четверг', fri: 'Пятница', sat: 'Суббота', sun: 'Воскресенье' };
        return map[key] || key;
    }

    toggleTasksSection() {
        if (!this.tasksSection) return;
        const visible = this.tasksSection.style.display !== 'none';
        // Переключаем только видимость секции задач, не скрывая остальные разделы
        const placement = this.getTasksPlacement();
        if (placement === 'modal') {
            this.renderTasksWeek(true);
            this.showTasksModal();
            return;
        }
        this.tasksSection.style.display = visible ? 'none' : 'block';
        if (!visible) {
            this.renderTasksWeek();
            this.applyTasksPlacement();
            try { this.tasksSection.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch(_) {}
        }
    }

    // Структура тасков: { mon: [ { id, text, status: 'pending'|'done'|'failed' } ], ... }
    ensureTasksWeek() {
        const keys = this.getWeekdayKeys();
        if (!this.tasks || typeof this.tasks !== 'object') this.tasks = {};
        for (const k of keys) if (!Array.isArray(this.tasks[k])) this.tasks[k] = [];
    }

    addTask(dayKey, text) {
        this.ensureTasksWeek();
        const trimmed = (text || '').trim();
        if (!trimmed) {
            this.showNotification('Введите текст задания', 'error');
            return;
        }
        const task = { id: Date.now() + Math.random().toString(36).slice(2,8), text: trimmed, status: 'pending' };
        this.logTaskEvent('created', dayKey, task.id, trimmed);
        this.tasks[dayKey].push(task);
        this.saveTasks();
        this.renderTasksWeek();
    }

    setTaskStatus(dayKey, taskId, status) {
        this.ensureTasksWeek();
        const list = this.tasks[dayKey] || [];
        const item = list.find(t => t.id === taskId);
        if (!item) return;
        item.status = status; // 'done' | 'failed' | 'pending'
        if (status === 'done' || status === 'failed') this.logTaskEvent(status, dayKey, taskId, item.text);
        this.saveTasks();
        this.renderTasksWeek();
    }

    deleteTask(dayKey, taskId) {
        this.ensureTasksWeek();
        const list = this.tasks[dayKey] || [];
        const item = list.find(t => t.id === taskId);
        if (item) this.logTaskEvent('deleted', dayKey, taskId, item.text);
        this.tasks[dayKey] = list.filter(t => t.id !== taskId);
        this.saveTasks();
        this.renderTasksWeek();
    }

    renderTasksWeek(toModal = false) {
        const container = toModal ? this.tasksModalGrid : this.tasksWeekGrid;
        if (!container) return;
        this.ensureTasksWeek();
        container.innerHTML = '';
        const dayKeys = this.getWeekdayKeys();

        dayKeys.forEach((key) => {
            const dayCol = document.createElement('div');
            dayCol.className = 'tasks-day';

            const header = document.createElement('div');
            header.className = 'tasks-day-header';
            const title = document.createElement('div');
            title.className = 'tasks-day-title';
            title.textContent = this.getWeekdayLabel(key);
            const addBtn = document.createElement('button');
            addBtn.className = 'tasks-add-btn';
            addBtn.innerHTML = '<i class="fas fa-plus"></i>';
            addBtn.title = 'Добавить задание';
            addBtn.addEventListener('click', () => {
                const text = prompt(`Новое задание (${this.getWeekdayLabel(key)}):`);
                if (text != null) this.addTask(key, text);
            });
            header.appendChild(title);
            header.appendChild(addBtn);

            const listEl = document.createElement('div');
            listEl.className = 'tasks-list';
            for (const t of this.tasks[key]) {
                listEl.appendChild(this.renderTaskItem(key, t));
            }

            dayCol.appendChild(header);
            dayCol.appendChild(listEl);
            container.appendChild(dayCol);
        });
    }

    renderTaskItem(dayKey, task) {
        const item = document.createElement('div');
        item.className = `task-item task-${task.status || 'pending'}`;

        const text = document.createElement('div');
        text.className = 'task-text';
        text.textContent = task.text;

        const actions = document.createElement('div');
        actions.className = 'task-actions';

        const doneBtn = document.createElement('button');
        doneBtn.className = 'task-btn done';
        doneBtn.title = 'Отметить как выполнено';
        doneBtn.innerHTML = '<i class="fas fa-check"></i>';
        doneBtn.addEventListener('click', () => this.setTaskStatus(dayKey, task.id, 'done'));

        const failBtn = document.createElement('button');
        failBtn.className = 'task-btn fail';
        failBtn.title = 'Отметить как не выполнено';
        failBtn.innerHTML = '<i class="fas fa-times"></i>';
        failBtn.addEventListener('click', () => this.setTaskStatus(dayKey, task.id, 'failed'));

        const pendingBtn = document.createElement('button');
        pendingBtn.className = 'task-btn pending';
        pendingBtn.title = 'Сбросить статус';
        pendingBtn.innerHTML = '<i class="fas fa-undo"></i>';
        pendingBtn.addEventListener('click', () => this.setTaskStatus(dayKey, task.id, 'pending'));

        const delBtn = document.createElement('button');
        delBtn.className = 'task-btn delete';
        delBtn.title = 'Удалить';
        delBtn.innerHTML = '<i class="fas fa-trash"></i>';
        delBtn.addEventListener('click', () => this.deleteTask(dayKey, task.id));

        actions.appendChild(doneBtn);
        actions.appendChild(failBtn);
        actions.appendChild(pendingBtn);
        actions.appendChild(delBtn);

        item.appendChild(text);
        item.appendChild(actions);
        return item;
    }

    applyTasksPlacement() {
        if (!this.tasksSection) return;
        const placement = this.getTasksPlacement();
        // Перемещаем секцию задач в DOM
        try {
            const container = document.querySelector('.container');
            if (!container) return;
            // Удаляем и вставляем заново в нужное место
            if (placement === 'top') {
                // после шапки
                const header = document.querySelector('.header');
                if (header && header.nextSibling) {
                    container.insertBefore(this.tasksSection, header.nextSibling);
                }
            } else if (placement === 'bottom') {
                // перед футером
                const footer = document.querySelector('.footer');
                if (footer) {
                    container.insertBefore(this.tasksSection, footer);
                }
            }
        } catch(_) {}
    }

    onTasksPlacementChange() {
        this.applyTasksPlacement();
        const placement = this.getTasksPlacement();
        if (placement === 'modal') {
            // Скрываем секцию и открываем модалку
            if (this.tasksSection) this.tasksSection.style.display = 'none';
            this.showTasksModal();
        }
    }

    getTasksPlacement() {
        try {
            const selectValue = this.tasksPlacementSelect ? this.tasksPlacementSelect.value : null;
            const saved = localStorage.getItem(this.getStorageKey('productivityTasksPlacement'));
            return selectValue || saved || 'top';
        } catch(_) { return 'top'; }
    }

    // (Недавние направления удалены по запросу)

    showTasksModal() {
        if (!this.tasksModal) return;
        this.renderTasksWeek(true);
        this.tasksModal.style.display = 'flex';
        if (this.tasksPlacementSelect && this.tasksPlacementSelectModal) {
            this.tasksPlacementSelectModal.value = this.tasksPlacementSelect.value || 'modal';
        }
    }
    hideTasksModal() {
        if (!this.tasksModal) return;
        this.tasksModal.style.display = 'none';
    }

    toggleTasksModalFullscreen() {
        if (!this.tasksModal) return;
        const modal = this.tasksModal.querySelector('.modal');
        if (!modal) return;
        const isFull = modal.classList.toggle('modal-fullscreen');
        if (this.tasksModalResizeButton) {
            this.tasksModalResizeButton.innerHTML = isFull ? '<i class="fas fa-compress"></i>' : '<i class="fas fa-expand"></i>';
        }
    }

    syncTasksPlacementFromModal() {
        if (!this.tasksPlacementSelectModal) return;
        const value = this.tasksPlacementSelectModal.value;
        if (this.tasksPlacementSelect) this.tasksPlacementSelect.value = value;
        if (value === 'modal') {
            this.showTasksModal();
        } else {
            // Закрываем модалку и применяем позиционирование секции
            this.hideTasksModal();
            this.tasksSection.style.display = 'block';
            this.renderTasksWeek(false);
            this.applyTasksPlacement();
            try { this.tasksSection.scrollIntoView({ behavior: 'smooth', block: value === 'top' ? 'start' : 'end' }); } catch(_) {}
        }
        // Сохраним выбор в localStorage
        try { localStorage.setItem(this.getStorageKey('productivityTasksPlacement'), value); } catch(_) {}
    }

    // Открытие модалки разбивки для общей свечи
    openBreakdownForOverallCandle(rawCandle, period) {
        if (!this.breakdownModal) return;
        // Для временных таймфреймов у нас есть intervalStart/intervalEnd
        const startMs = rawCandle.intervalStart ? new Date(rawCandle.intervalStart).getTime() : new Date(rawCandle.x).getTime();
        const endMs = rawCandle.intervalEnd ? new Date(rawCandle.intervalEnd).getTime() : startMs;

        // Собираем вклад из каждого направления
        const items = [];
        for (const dir of this.directions) {
            const inInterval = (dir.scores || []).filter(s => {
                const t = new Date(s.date).getTime();
                if (rawCandle.intervalStart) {
                    return t >= startMs && t < endMs;
                }
                // Для дневного режима сравним по дню даты свечи и записи
                const dayKey = new Date(rawCandle.x).toISOString().slice(0,10);
                return new Date(s.date).toISOString().slice(0,10) === dayKey;
            });
            if (inInterval.length) {
                const sum = inInterval.reduce((acc, s) => acc + (s.value || 0), 0);
                items.push({
                    directionId: dir.id,
                    directionName: dir.name,
                    sum,
                    count: inInterval.length,
                    scores: inInterval
                });
            }
        }

        // Заголовок и список
        if (this.breakdownModalTitle) {
            if (rawCandle.intervalStart) {
                const start = new Date(startMs).toLocaleString('ru-RU');
                const end = new Date(endMs).toLocaleString('ru-RU');
                this.breakdownModalTitle.textContent = `Разбивка по направлениям: ${start} - ${end}`;
            } else {
                this.breakdownModalTitle.textContent = `Разбивка по направлениям: ${new Date(rawCandle.x).toLocaleDateString('ru-RU')}`;
            }
        }

        const totalSum = items.reduce((a,b) => a + b.sum, 0);
        if (this.breakdownSummary) {
            this.breakdownSummary.textContent = `Итого изменений: ${totalSum.toFixed(2)} • Записей: ${items.reduce((a,b)=>a+b.count,0)}`;
        }

        if (this.breakdownList) {
            this.breakdownList.innerHTML = '';
            items.sort((a,b) => Math.abs(b.sum) - Math.abs(a.sum));
            items.forEach(it => {
                const el = document.createElement('div');
                el.className = 'breakdown-item';
                const title = document.createElement('div');
                title.className = 'breakdown-item-title';
                const sign = it.sum > 0 ? '+' : '';
                title.textContent = `${it.directionName}: ${sign}${it.sum.toFixed(2)} (записей: ${it.count})`;
                const meta = document.createElement('div');
                meta.className = 'breakdown-item-meta';
                meta.textContent = it.scores.map(s => `${(s.value>0?'+':'')}${s.value}`).join(', ');
                el.appendChild(title);
                el.appendChild(meta);
                this.breakdownList.appendChild(el);
            });
        }

        this.breakdownModal.style.display = 'flex';
    }

    closeBreakdownModal() {
        if (this.breakdownModal) this.breakdownModal.style.display = 'none';
    }

    // Инициализация DOM элементов
    initializeElements() {
        this.directionInput = document.getElementById('directionInput');
        this.addButton = document.getElementById('addButton');
        this.directionsList = document.getElementById('directionsList');
        this.emptyState = document.getElementById('emptyState');
        // Auth UI
        this.openAuthButton = document.getElementById('openAuthButton');
        this.logoutButton = document.getElementById('logoutButton');
        this.authStatus = document.getElementById('authStatus');
        this.authModal = document.getElementById('authModal');
        this.closeAuthButton = document.getElementById('closeAuthButton');
        this.signInButton = document.getElementById('signInButton');
        this.signUpButton = document.getElementById('signUpButton');
        this.authEmailInput = document.getElementById('authEmail');
        this.authPasswordInput = document.getElementById('authPassword');
        this.layoutToggleButton = null;
        // Tasks UI
        this.openTasksButton = document.getElementById('openTasksButton');
        this.tasksSection = document.getElementById('tasksSection');
        this.tasksWeekGrid = document.getElementById('tasksWeekGrid');
        this.directionsSectionEl = document.querySelector('.directions-section');
        this.tasksPlacementSelect = document.getElementById('tasksPlacementSelect');
        this.tasksModal = document.getElementById('tasksModal');
        this.tasksModalGrid = document.getElementById('tasksModalGrid');
        this.closeTasksModal = document.getElementById('closeTasksModal');
        this.closeTasksModalFooter = document.getElementById('closeTasksModalFooter');
        this.tasksPlacementSelectModal = document.getElementById('tasksPlacementSelectModal');
        this.tasksModalResizeButton = document.getElementById('tasksModalResizeButton');
        // History UI
        this.openTasksHistoryButton = document.getElementById('openTasksHistoryButton');
        this.tasksHistoryModal = document.getElementById('tasksHistoryModal');
        this.closeTasksHistoryButton = document.getElementById('closeTasksHistoryButton');
        this.tasksHistorySortSelect = document.getElementById('tasksHistorySortSelect');
        this.tasksHistoryList = document.getElementById('tasksHistoryList');
        this.clearTasksHistoryButton = document.getElementById('clearTasksHistoryButton');
        this.addCategoryButton = document.getElementById('addCategoryButton');
        this.openTrashButton = document.getElementById('openTrashButton');
        this.trashModal = document.getElementById('trashModal');
        this.closeTrashButton = document.getElementById('closeTrashButton');
        this.trashDirectionsList = document.getElementById('trashDirectionsList');
        this.trashCategoriesList = document.getElementById('trashCategoriesList');
        this.emptyTrashButton = document.getElementById('emptyTrashButton');
        this.chartSection = document.getElementById('chartSection');
        this.directionSelect = document.getElementById('directionSelect');
        this.periodSelect = document.getElementById('periodSelect');
        this.productivityChart = document.getElementById('productivityChart');
        this.overallChartSection = document.getElementById('overallChartSection');
        this.overallChartCanvas = document.getElementById('overallChart');
        this.overallPeriodSelect = document.getElementById('overallPeriodSelect');
        this.overallIntervalInfo = document.getElementById('overallIntervalInfo');
        this.overallTimeLeftElement = document.getElementById('overallTimeLeft');
        this.intervalInfo = document.getElementById('intervalInfo');
        this.timeLeftElement = document.getElementById('timeLeft');
        
        // Элементы управления зумом
        this.candlesCountSelect = document.getElementById('candlesCountSelect');
        this.zoomInButton = document.getElementById('zoomInButton');
        this.zoomOutButton = document.getElementById('zoomOutButton');
        this.resetZoomButton = document.getElementById('resetZoomButton');
        
        // Элементы навигации
        this.navStepSelect = document.getElementById('navStepSelect');
        this.navLeftButton = document.getElementById('navLeftButton');
        this.navRightButton = document.getElementById('navRightButton');
        this.navToEndButton = document.getElementById('navToEndButton');
        
        // Индикатор позиции
        this.positionIndicator = document.getElementById('positionIndicator');
        this.positionText = document.getElementById('positionText');
        
        // Элементы управления данными
        this.exportButton = document.getElementById('exportButton');
        this.importButton = document.getElementById('importButton');
        this.importFileInput = document.getElementById('importFileInput');
        this.clearAllValuesButton = document.getElementById('clearAllValuesButton');
        // Draft UI
        this.openDraftButton = document.getElementById('openDraftButton');
        this.draftModal = document.getElementById('draftModal');
        this.closeDraftButton = document.getElementById('closeDraftButton');
        this.saveDraftButton = document.getElementById('saveDraftButton');
        this.clearDraftButton = document.getElementById('clearDraftButton');
        this.draftText = document.getElementById('draftText');
        
        // Элементы детальной панели
        this.directionDetailPanel = document.getElementById('directionDetailPanel');
        this.closeDetailPanel = document.getElementById('closeDetailPanel');
        this.detailDirectionName = document.getElementById('detailDirectionName');
        this.detailDirectionScore = document.getElementById('detailDirectionScore');
        this.detailCategorySelect = document.getElementById('detailCategorySelect');
        this.detailScoreInput = document.getElementById('detailScoreInput');
        this.detailDescriptionInput = document.getElementById('detailDescriptionInput');
        this.detailDescriptionColor = document.getElementById('detailDescriptionColor');
        this.saveDescriptionButton = document.getElementById('saveDescriptionButton');
        this.detailColorPicker = document.getElementById('detailColorPicker');
        this.detailPercentPicker = null;
        this.detailAddScoreButton = document.getElementById('detailAddScoreButton');
        this.detailDeleteButton = document.getElementById('detailDeleteButton');
        this.detailClearAllScoresButton = document.getElementById('detailClearAllScoresButton');
        this.detailDirectionAvgGrade = document.getElementById('detailDirectionAvgGrade');
        // Настройки scoring (динамические)
        this.scoringMetricsList = document.getElementById('scoringMetricsList');
        this.addMetricButton = document.getElementById('addMetricButton');
        this.detailTotalMaxPointsInput = document.getElementById('detailTotalMaxPointsInput');
        // Калькулятор (динамические инпуты)
        this.sessionMetricsInputs = document.getElementById('sessionMetricsInputs');
        this.calcPreview = document.getElementById('calcPreview');
        this.calcManualGradeInput = document.getElementById('calcManualGradeInput');
        this.calcApplyButton = document.getElementById('calcApplyButton');
        
        // Состояние текущего выбранного направления для детальной панели
        this.currentDetailDirection = null;

        // Комментарии к свечам: элементы модалки
        this.commentModal = document.getElementById('commentModal');
        this.commentModalTitle = document.getElementById('commentModalTitle');
        this.commentInfo = document.getElementById('commentInfo');
        this.commentText = document.getElementById('commentText');
        this.saveCommentButton = document.getElementById('saveCommentButton');
        this.deleteCommentButton = document.getElementById('deleteCommentButton');
        this.closeCommentButton = document.getElementById('closeCommentButton');
        this.currentCommentKey = null;

        // Модалка разбивки общей свечи
        this.breakdownModal = document.getElementById('breakdownModal');
        this.breakdownModalTitle = document.getElementById('breakdownModalTitle');
        this.breakdownSummary = document.getElementById('breakdownSummary');
        this.breakdownList = document.getElementById('breakdownList');
        this.closeBreakdownButton = document.getElementById('closeBreakdownButton');
        this.closeBreakdownFooterButton = document.getElementById('closeBreakdownFooterButton');
    }

    // Привязка событий
    bindEvents() {
        this.addButton.addEventListener('click', () => this.addDirection());
        this.directionInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.addDirection();
            }
        });
        
        this.directionSelect.addEventListener('change', () => this.updateChart());
        this.periodSelect.addEventListener('change', () => {
            this.updateChart();
            // Перезапускаем автообновление при смене периода
            this.startChartAutoUpdate();
        });
        
        // Обработчики событий для кнопок управления зумом
        this.candlesCountSelect.addEventListener('change', () => this.setCandlesCount());
        this.zoomInButton.addEventListener('click', () => this.zoomIn());
        this.zoomOutButton.addEventListener('click', () => this.zoomOut());
        this.resetZoomButton.addEventListener('click', () => this.resetZoom());

        // Открыть/закрыть ежедневные задания
        if (this.openTasksButton) {
            this.openTasksButton.addEventListener('click', () => this.toggleTasksSection());
        }
        if (this.tasksPlacementSelect) {
            this.tasksPlacementSelect.addEventListener('change', () => this.onTasksPlacementChange());
        }
        if (this.closeTasksModal) this.closeTasksModal.addEventListener('click', () => this.hideTasksModal());
        if (this.closeTasksModalFooter) this.closeTasksModalFooter.addEventListener('click', () => this.hideTasksModal());
        if (this.tasksPlacementSelectModal) {
            this.tasksPlacementSelectModal.addEventListener('change', () => this.syncTasksPlacementFromModal());
        }
        if (this.tasksModalResizeButton) {
            this.tasksModalResizeButton.addEventListener('click', () => this.toggleTasksModalFullscreen());
        }
        // History handlers
        if (this.openTasksHistoryButton) this.openTasksHistoryButton.addEventListener('click', () => this.openTasksHistory());
        if (this.closeTasksHistoryButton) this.closeTasksHistoryButton.addEventListener('click', () => this.closeTasksHistory());
        if (this.clearTasksHistoryButton) this.clearTasksHistoryButton.addEventListener('click', () => this.clearTasksHistory());
        if (this.tasksHistorySortSelect) this.tasksHistorySortSelect.addEventListener('change', () => this.renderTasksHistory());
        // Recent vertical — удалено
        
        // Обработчики событий для навигации
        this.navLeftButton.addEventListener('click', () => this.navigateLeft());
        this.navRightButton.addEventListener('click', () => this.navigateRight());
        this.navToEndButton.addEventListener('click', () => this.navigateToEnd());
        if (this.overallPeriodSelect) {
            this.overallPeriodSelect.addEventListener('change', () => this.updateOverallChart(this.overallPeriodSelect.value));
        }
        
        // Обработчики событий для колеса мыши и прокрутки (как в TradingView)
        this.productivityChart.addEventListener('wheel', (e) => this.handleWheel(e));
        this.productivityChart.addEventListener('mousedown', (e) => this.handleMouseDown(e));
        this.productivityChart.addEventListener('mousemove', (e) => this.handleMouseMove(e));
        this.productivityChart.addEventListener('mouseup', (e) => this.handleMouseUp(e));

        // Навигация/зум для общего графика
        if (this.overallChartCanvas) {
            this.overallChartCanvas.addEventListener('wheel', (e) => this.handleWheelOverall(e));
            this.overallChartCanvas.addEventListener('mousedown', (e) => this.handleMouseDownOverall(e));
            this.overallChartCanvas.addEventListener('mousemove', (e) => this.handleMouseMoveOverall(e));
            this.overallChartCanvas.addEventListener('mouseup', (e) => this.handleMouseUpOverall(e));
        }
        
        // Состояние мыши для прокрутки
        this.isDragging = false;
        this.lastMouseX = 0;
        this.isDraggingOverall = false;
        this.lastMouseXOverall = 0;
        
        // Обработчики клавиатуры для навигации
        document.addEventListener('keydown', (e) => this.handleKeyDown(e));
        
        // Обработчики событий для экспорта/импорта
        this.exportButton.addEventListener('click', () => this.exportData());
        this.importButton.addEventListener('click', () => this.importFileInput.click());
        this.importFileInput.addEventListener('change', (e) => this.importData(e));
        if (this.clearAllValuesButton) this.clearAllValuesButton.addEventListener('click', () => this.clearAllValues());
        // Draft handlers
        if (this.openDraftButton) this.openDraftButton.addEventListener('click', () => this.openDraft());
        if (this.closeDraftButton) this.closeDraftButton.addEventListener('click', () => this.closeDraft());
        if (this.saveDraftButton) this.saveDraftButton.addEventListener('click', () => this.saveDraft());
        if (this.clearDraftButton) this.clearDraftButton.addEventListener('click', () => this.clearDraft());
        
        // Обработчики событий для детальной панели
        this.closeDetailPanel.addEventListener('click', () => this.closeDetailView());
        this.detailCategorySelect.addEventListener('change', () => this.changeDetailDirectionCategory());
        this.detailAddScoreButton.addEventListener('click', () => this.addDetailScore());
        this.detailDeleteButton.addEventListener('click', () => this.deleteDetailDirection());
        if (this.detailClearAllScoresButton) this.detailClearAllScoresButton.addEventListener('click', () => this.clearAllScoresOfCurrentDirection());
        this.detailScoreInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.addDetailScore();
            }
        });
        if (this.saveDescriptionButton) this.saveDescriptionButton.addEventListener('click', () => this.saveDetailDescription());
        if (this.detailDescriptionColor) this.detailDescriptionColor.addEventListener('input', () => this.applyDescriptionColorLive());
        if (this.detailColorPicker) this.detailColorPicker.addEventListener('click', (e) => this.handleColorPick(e));
        // no-op: percent picker and custom style are removed

        // Динамика метрик
        if (this.addMetricButton) this.addMetricButton.addEventListener('click', () => this.addScoringMetric());
        if (this.detailTotalMaxPointsInput) {
            this.detailTotalMaxPointsInput.addEventListener('change', () => this.saveCurrentDirectionScoring());
            this.detailTotalMaxPointsInput.addEventListener('input', () => this.saveCurrentDirectionScoring());
        }

        // Калькулятор предпросмотра и применение
        const updatePreview = () => this.updateCalcPreview();
        if (this.calcFocusPercentInput) this.calcFocusPercentInput.addEventListener('input', updatePreview);
        if (this.calcMinutesInput) this.calcMinutesInput.addEventListener('input', updatePreview);
        if (this.calcResultPercentInput) this.calcResultPercentInput.addEventListener('input', updatePreview);
        if (this.calcApplyButton) this.calcApplyButton.addEventListener('click', () => this.applyCalcToCurrentDirection());

        // Кнопки переключения вида удалены — теперь используем раздел задач

        // Добавление категории
        if (this.addCategoryButton) {
            this.addCategoryButton.addEventListener('click', () => this.promptAddCategory());
        }

        // Корзина
        this.trash = this.loadTrash();
        if (this.openTrashButton) this.openTrashButton.addEventListener('click', () => this.openTrash());
        if (this.closeTrashButton) this.closeTrashButton.addEventListener('click', () => this.closeTrash());
        if (this.emptyTrashButton) this.emptyTrashButton.addEventListener('click', () => this.emptyTrash());

        // Комментарии к свечам: обработчики модалки
        if (this.closeCommentButton) this.closeCommentButton.addEventListener('click', () => this.closeCommentModal());
        if (this.saveCommentButton) this.saveCommentButton.addEventListener('click', () => this.saveCandleComment());
        if (this.deleteCommentButton) this.deleteCommentButton.addEventListener('click', () => this.deleteCandleComment());

        // Разбивка общей свечи — закрытие модалки
        if (this.closeBreakdownButton) this.closeBreakdownButton.addEventListener('click', () => this.closeBreakdownModal());
        if (this.closeBreakdownFooterButton) this.closeBreakdownFooterButton.addEventListener('click', () => this.closeBreakdownModal());

        // Auth events
        if (this.openAuthButton) this.openAuthButton.addEventListener('click', () => this.openAuthModal());
        if (this.closeAuthButton) this.closeAuthButton.addEventListener('click', () => this.closeAuthModal());
        if (this.signInButton) this.signInButton.addEventListener('click', () => this.handleSignIn());
        if (this.signUpButton) this.signUpButton.addEventListener('click', () => this.handleSignUp());
        if (this.logoutButton) this.logoutButton.addEventListener('click', () => this.handleLogout());
        if (this.calcManualGradeInput) this.calcManualGradeInput.addEventListener('input', () => this.updateCalcPreview());
    }

    // ===== Аутентификация и облачная синхронизация =====
    setupFirebase() {
        try {
            if (!window.FIREBASE_CONFIG) {
                this.updateAuthUI();
                return;
            }
            if (!this.firebase.app) {
                this.firebase.app = firebase.initializeApp(window.FIREBASE_CONFIG);
                this.firebase.auth = firebase.auth();
                this.firebase.db = firebase.firestore();
                try {
                    this.firebase.db.settings({
                        experimentalForceLongPolling: true,
                        useFetchStreams: false
                    });
                } catch (_) {}
                try { this.firebase.auth.setPersistence(firebase.auth.Auth.Persistence.LOCAL); } catch(_) {}
            }
            this.firebase.auth.onAuthStateChanged(async (user) => {
                const previousUid = this.lastAuthUid;
                this.currentUser = user || null;
                this.lastAuthUid = this.currentUser ? this.currentUser.uid : null;
                this.updateAuthUI();
                if (this.currentUser) {
                    try {
                        // Вариант A: на входе чистим гостевой кэш и ничего не мёрджим
                        this.clearGuestLocalData();
                        // Очищаем текущее состояние, чтобы не мигало гостевыми данными
                        this.resetInMemoryStateToDefaults();
                        this.render();
                        // Подключаем realtime и загружаем данные аккаунта
                        this.startCloudListener();
                        await this.loadFromCloud();
                    } catch (e) {
                        console.error('Load from cloud failed:', e);
                    }
                } else {
                    // user == null
                    this.stopCloudListener();
                    if (previousUid) {
                        // Это реальный выход из аккаунта
                        this.clearSpecificLocalData(previousUid);
                        // По требованиям Variant A: показываем пусто после выхода
                        this.resetInMemoryStateToDefaults();
                        this.render();
                    } else {
                        // Инициализация как гость — не очищаем и не трогаем гостевые данные
                        // Оставляем состояние, загруженное в конструкторе из localStorage
                    }
                }
            });
        } catch (e) {
            console.error('Firebase init failed:', e);
            this.showNotification('Не удалось инициализировать облачную синхронизацию', 'error');
        }
    }

    updateAuthUI() {
        const isAuthed = !!this.currentUser;
        if (this.authStatus) {
            if (isAuthed) {
                this.authStatus.textContent = `Вошли: ${this.currentUser.email || this.currentUser.uid}`;
                this.authStatus.style.display = '';
            } else {
                this.authStatus.textContent = window.FIREBASE_CONFIG ? 'Не вошли' : 'Синхронизация отключена';
                this.authStatus.style.display = '';
            }
        }
        if (this.openAuthButton) this.openAuthButton.style.display = isAuthed ? 'none' : '';
        if (this.logoutButton) this.logoutButton.style.display = isAuthed ? '' : 'none';
        if (this.authModal && this.authModal.style.display !== 'none' && isAuthed) {
            this.closeAuthModal();
        }
    }

    openAuthModal() { if (this.authModal) this.authModal.style.display = 'flex'; }
    closeAuthModal() { if (this.authModal) this.authModal.style.display = 'none'; }

    async handleSignIn() {
        if (!this.firebase.auth) {
            this.showNotification('Облако не настроено', 'error');
            return;
        }
        const email = (this.authEmailInput?.value || '').trim();
        const password = (this.authPasswordInput?.value || '').trim();
        if (!email || !password) {
            this.showNotification('Введите email и пароль', 'error');
            return;
        }
        try {
            await this.firebase.auth.signInWithEmailAndPassword(email, password);
            this.showNotification('Вход выполнен', 'success');
        } catch (e) {
            console.error(e);
            this.showNotification('Ошибка входа: ' + (e.message || ''), 'error');
        }
    }

    async handleSignUp() {
        if (!this.firebase.auth) {
            this.showNotification('Облако не настроено', 'error');
            return;
        }
        const email = (this.authEmailInput?.value || '').trim();
        const password = (this.authPasswordInput?.value || '').trim();
        if (!email || !password) {
            this.showNotification('Введите email и пароль', 'error');
            return;
        }
        try {
            await this.firebase.auth.createUserWithEmailAndPassword(email, password);
            this.showNotification('Регистрация выполнена', 'success');
            // При первой регистрации сразу сохраним текущие локальные данные в облако
            this.scheduleCloudSave(0);
        } catch (e) {
            console.error(e);
            this.showNotification('Ошибка регистрации: ' + (e.message || ''), 'error');
        }
    }

    async handleLogout() {
        if (!this.firebase.auth) return;
        try {
            await this.firebase.auth.signOut();
            this.showNotification('Вы вышли из аккаунта', 'success');
        } catch (e) {
            console.error(e);
            this.showNotification('Ошибка выхода: ' + (e.message || ''), 'error');
        }
    }

    getCloudDocRef() {
        if (!this.firebase.db || !this.currentUser) return null;
        return this.firebase.db.collection('productivityData').doc(this.currentUser.uid);
    }

    buildCloudPayload() {
        return {
            version: '1.1',
            updatedAt: new Date().toISOString(),
            lastUpdatedBy: this.instanceId,
            productivityData: {
                directions: this.directions,
                categories: this.categories,
                trash: this.trash,
                comments: this.loadComments(),
                layoutMode: this.layoutMode,
                zoomState: { visibleCandlesCount: this.zoomState?.visibleCandlesCount || 50 },
                tasks: this.tasks,
                tasksPlacement: (() => { try { return localStorage.getItem(this.getStorageKey('productivityTasksPlacement')) || this.tasksPlacementSelect?.value || 'top'; } catch(_) { return 'top'; } })(),
                draft: this.loadDraft(),
                tasksHistory: this.loadTasksHistory()
            }
        };
    }

    scheduleCloudSave(delayMs = 0) {
        if (!this.currentUser || !this.firebase.db) return;
        if (this.isApplyingRemote) return; // не инициируем сохранение во время применения удалённых данных
        if (this.cloudSaveTimer) { clearTimeout(this.cloudSaveTimer); this.cloudSaveTimer = null; }
        // Сохраняем сразу без задержки, чтобы пережить быстрые перезагрузки
        this.saveToCloud().catch(()=>{});
    }

    async saveToCloud() {
        if (!this.currentUser || !this.firebase.db) return;
        const ref = this.getCloudDocRef();
        if (!ref) return;
        const payload = this.buildCloudPayload();
        await ref.set(payload, { merge: true });
        this.lastCloudSavedAt = Date.now();
        // Не спамим уведомлениями, но можно логировать
        // this.showNotification('Данные синхронизированы', 'success');
    }

    async loadFromCloud() {
        const ref = this.getCloudDocRef();
        if (!ref) return;
        const snap = await ref.get();
        if (!snap.exists) {
            // У аккаунта пока нет данных — оставим пустое локально, не загружаем и не заливаем ничто
            return;
        }
        const data = snap.data();
        const payload = data && data.productivityData;
        if (!payload) return;
        // Всегда используем данные аккаунта без подтверждений и без перезаписи облака локальными
        this.applyCloudPayload(payload, /*showToast*/true);
    }

    // Применение облачных данных без подтверждения (для realtime)
    applyCloudPayload(payload, showToast = false) {
        if (!payload) return;
        this.isApplyingRemote = true;
        try {
            this.directions = Array.isArray(payload.directions) ? payload.directions : this.directions || [];
            this.categories = Array.isArray(payload.categories) && payload.categories.length ? payload.categories : (this.categories || []);
            this.trash = payload.trash && typeof payload.trash === 'object' ? payload.trash : (this.trash || { directions: [], categories: [] });
            if (payload.comments && typeof payload.comments === 'object') {
                this.saveComments(payload.comments);
            }
            // Восстановим ежедневные задания и их размещение, если есть
            if (payload.tasks && typeof payload.tasks === 'object') {
                this.tasks = payload.tasks;
                this.saveTasks();
                this.renderTasksWeek();
            }
            if (payload.tasksPlacement) {
                try { localStorage.setItem(this.getStorageKey('productivityTasksPlacement'), payload.tasksPlacement); } catch(_) {}
                if (this.tasksPlacementSelect) this.tasksPlacementSelect.value = payload.tasksPlacement;
                this.applyTasksPlacement();
            }
            if (typeof payload.draft === 'string') {
                this.saveDraft(payload.draft, /*silent*/true);
                this.updateDraftUI();
            }
            if (Array.isArray(payload.tasksHistory)) {
                this.saveTasksHistory(payload.tasksHistory);
            }
            if (payload.layoutMode === 'compact' || payload.layoutMode === 'horizontal') {
                this.layoutMode = payload.layoutMode;
                this.saveLayoutMode();
            }
            if (payload.zoomState && payload.zoomState.visibleCandlesCount) {
                this.zoomState.visibleCandlesCount = payload.zoomState.visibleCandlesCount;
                if (this.candlesCountSelect) this.candlesCountSelect.value = String(payload.zoomState.visibleCandlesCount);
            }
            // Обновляем UI
            this.saveDirections(); // Триггерит scheduleCloudSave, но мы не хотим обратно перезаписывать сервер сразу
            this.saveCategories();
            this.saveTrash();
            this.render();
            this.updateDetailCategorySelectIfOpen?.();
            this.updateDirectionSelect?.();
            this.updateChart?.();
            this.updateOverallChart?.();
            if (showToast) this.showNotification('Данные загружены из облака', 'success');
        } finally {
            // Небольшая задержка, чтобы отложенные save* не стартовали немедленно
            setTimeout(() => { this.isApplyingRemote = false; }, 100);
        }
    }

    // Полная очистка локального хранилища приложения
    clearAllLocalData() {
        const suffixes = [
            'productivityDirections',
            'productivityCategories',
            'productivityTrash',
            'productivityComments',
            'productivityTasks',
            'productivityTasksPlacement'
        ];
        const uid = (this.currentUser && this.currentUser.uid) ? this.currentUser.uid : 'guest';
        for (const s of suffixes) {
            try { localStorage.removeItem(`${s}:${uid}`); } catch(_) {}
        }
        // layoutMode оставим, т.к. это предпочтение интерфейса, но при желании можно очистить:
        // try { localStorage.removeItem('productivityLayoutMode'); } catch(_) {}
    }

    // Очистка локальных данных для конкретного uid
    clearSpecificLocalData(uid) {
        const suffixes = [
            'productivityDirections',
            'productivityCategories',
            'productivityTrash',
            'productivityComments',
            'productivityTasks',
            'productivityTasksPlacement'
        ];
        for (const s of suffixes) {
            try { localStorage.removeItem(`${s}:${uid}`); } catch(_) {}
        }
    }

    // Очистка именно гостевых ключей (при входе)
    clearGuestLocalData() {
        const suffixes = [
            'productivityDirections',
            'productivityCategories',
            'productivityTrash',
            'productivityComments',
            'productivityTasks',
            'productivityTasksPlacement'
        ];
        for (const s of suffixes) {
            try { localStorage.removeItem(`${s}:guest`); } catch(_) {}
        }
    }

    // Логика миграции гостя удалена — разделение гостя и аккаунта жёсткое

    // Сброс всех in-memory структур к дефолтным пустым
    resetInMemoryStateToDefaults() {
        this.directions = [];
        this.categories = [
            { id: 'daily100', name: '100% ежедневно!', icon: '🔥', priority: 1 },
            { id: 'daily80', name: '80% ежедневно!', icon: '⚡', priority: 2 },
            { id: 'daily50', name: '50% ежедневно!', icon: '📈', priority: 3 },
            { id: 'other1', name: 'Прочее 1', icon: '📝', priority: 4 },
            { id: 'other2', name: 'Прочее 2', icon: '📋', priority: 5 },
            { id: 'other3', name: 'Прочее 3', icon: '📊', priority: 6 },
            { id: 'other4', name: 'Прочее 4', icon: '📌', priority: 7 }
        ];
        this.trash = { directions: [], categories: [] };
        this.tasks = {};
        this.render();
        this.updateChart?.();
        this.updateOverallChart?.();
    }

    // Подписка на изменения в Firestore для мгновенной синхронизации
    startCloudListener() {
        if (!this.firebase.db || !this.currentUser) return;
        const ref = this.getCloudDocRef();
        if (!ref) return;
        this.stopCloudListener();
        this.cloudUnsubscribe = ref.onSnapshot((doc) => {
            if (!doc.exists) return;
            const data = doc.data();
            if (!data) return;
            // Больше не игнорируем «свои» изменения, всегда применяем серверное состояние
            const payload = data.productivityData;
            if (!payload) return;
            this.applyCloudPayload(payload, /*showToast*/false);
        }, (error) => {
            console.error('Cloud listener error:', error);
        });
    }

    stopCloudListener() {
        if (typeof this.cloudUnsubscribe === 'function') {
            try { this.cloudUnsubscribe(); } catch(_) {}
        }
        this.cloudUnsubscribe = null;
    }

    // Получение и сохранение настроек начисления
    getDefaultScoring() {
        return { metrics: [
            { id: 'focus', name: 'Сосредоточенность', type: 'percent', maxPoints: 10 },
            { id: 'time', name: 'Время', type: 'time', timeMaxMinutes: 60, timeMaxPoints: 6 },
            { id: 'result', name: 'Результат обучения', type: 'percent', maxPoints: 5 }
        ], totalMaxPoints: null };
    }
    loadDirectionScoring(direction) {
        const s = direction.scoring || this.getDefaultScoring();
        // миграция старого формата в динамический
        if (!s.metrics) {
            const metrics = [];
            if (s.focusMaxPoints != null) metrics.push({ id: 'focus', name: 'Сосредоточенность', type: 'percent', maxPoints: s.focusMaxPoints });
            if (s.timeMaxMinutes != null || s.timeMaxPoints != null) metrics.push({ id: 'time', name: 'Время', type: 'time', timeMaxMinutes: s.timeMaxMinutes || 60, timeMaxPoints: s.timeMaxPoints || 0 });
            if (s.resultMaxPoints != null) metrics.push({ id: 'result', name: 'Результат обучения', type: 'percent', maxPoints: s.resultMaxPoints });
            return { metrics, totalMaxPoints: s.totalMaxPoints ?? null };
        }
        return s;
    }
    saveCurrentDirectionScoring() {
        const dir = this.getFreshCurrentDetailDirection();
        if (!dir) return;
        const s = this.loadDirectionScoring(dir);
        s.totalMaxPoints = (() => { const n = parseFloat(this.detailTotalMaxPointsInput?.value); return isNaN(n) ? null : n; })();
        dir.scoring = s;
        this.saveDirections();
        this.updateCalcPreview();
    }
    addScoringMetric() {
        const dir = this.getFreshCurrentDetailDirection();
        if (!dir) return;
        const s = this.loadDirectionScoring(dir);
        const name = prompt('Название метрики (например, Активность):', 'Новая метрика');
        if (!name) return;
        const type = prompt('Тип: percent или time', 'percent');
        let metric = null;
        if (type === 'time') {
            const minutes = parseFloat(prompt('Макс. минуты:', '60')) || 60;
            const points = parseFloat(prompt('Баллы за макс. минуты:', '10')) || 10;
            metric = { id: 'm_'+Date.now(), name: name.trim(), type: 'time', timeMaxMinutes: minutes, timeMaxPoints: points };
        } else {
            const points = parseFloat(prompt('Макс. баллы:', '10')) || 10;
            metric = { id: 'm_'+Date.now(), name: name.trim(), type: 'percent', maxPoints: points };
        }
        s.metrics.push(metric);
        dir.scoring = s;
        this.saveDirections();
        this.renderScoringMetricsUI(dir);
        this.renderSessionInputsUI(dir);
        this.updateCalcPreview();
    }
    removeScoringMetric(metricId) {
        const dir = this.getFreshCurrentDetailDirection();
        if (!dir) return;
        const s = this.loadDirectionScoring(dir);
        s.metrics = s.metrics.filter(m => m.id !== metricId);
        dir.scoring = s;
        this.saveDirections();
        this.renderScoringMetricsUI(dir);
        this.renderSessionInputsUI(dir);
        this.updateCalcPreview();
    }
    renderScoringMetricsUI(direction) {
        if (!this.scoringMetricsList) return;
        const s = this.loadDirectionScoring(direction);
        this.scoringMetricsList.innerHTML = '';
        s.metrics.forEach(metric => {
            const wrap = document.createElement('div');
            wrap.className = 'scoring-field';
            if (metric.type === 'percent') {
                wrap.innerHTML = `<label>${metric.name}: максимум (баллы)</label>`;
                const input = document.createElement('input');
                input.type = 'number'; input.className = 'scoring-input'; input.min = '0'; input.step = '0.1';
                input.value = metric.maxPoints ?? 0;
                input.addEventListener('input', () => { metric.maxPoints = parseFloat(input.value)||0; this.saveCurrentDirectionScoring(); });
                const del = document.createElement('button'); del.className = 'danger-button'; del.innerHTML = '<i class="fas fa-trash"></i>';
                del.title = 'Удалить метрику'; del.addEventListener('click', () => this.removeScoringMetric(metric.id));
                wrap.appendChild(input); wrap.appendChild(del);
            } else if (metric.type === 'time') {
                wrap.innerHTML = `<label>${metric.name}: время (мин) ➜ баллы</label>`;
                const minInput = document.createElement('input'); minInput.type='number'; minInput.className='scoring-input'; minInput.min='1'; minInput.step='1'; minInput.value = metric.timeMaxMinutes ?? 60;
                const ptsInput = document.createElement('input'); ptsInput.type='number'; ptsInput.className='scoring-input'; ptsInput.min='0'; ptsInput.step='0.1'; ptsInput.value = metric.timeMaxPoints ?? 0;
                minInput.addEventListener('input', () => { metric.timeMaxMinutes = parseFloat(minInput.value)||60; this.saveCurrentDirectionScoring(); });
                ptsInput.addEventListener('input', () => { metric.timeMaxPoints = parseFloat(ptsInput.value)||0; this.saveCurrentDirectionScoring(); });
                const del = document.createElement('button'); del.className = 'danger-button'; del.innerHTML = '<i class="fas fa-trash"></i>';
                del.title = 'Удалить метрику'; del.addEventListener('click', () => this.removeScoringMetric(metric.id));
                wrap.appendChild(minInput); wrap.appendChild(ptsInput); wrap.appendChild(del);
            }
            this.scoringMetricsList.appendChild(wrap);
        });
        if (this.detailTotalMaxPointsInput) this.detailTotalMaxPointsInput.value = this.loadDirectionScoring(direction).totalMaxPoints ?? '';
    }
    renderSessionInputsUI(direction) {
        if (!this.sessionMetricsInputs) return;
        const s = this.loadDirectionScoring(direction);
        this.sessionMetricsInputs.innerHTML = '';
        s.metrics.forEach(metric => {
            const field = document.createElement('div');
            field.className = 'scoring-field';
            const label = document.createElement('label');
            if (metric.type === 'percent') label.textContent = `${metric.name} (%)`;
            else label.textContent = `${metric.name} (мин)`;
            const input = document.createElement('input');
            input.type = 'number'; input.className = 'scoring-input';
            input.step = metric.type === 'percent' ? '1' : '1';
            if (metric.type === 'percent') { input.min = '-100'; input.max = '100'; input.placeholder = '80'; }
            else { input.min = '0'; input.placeholder = '40'; }
            input.dataset.metricId = metric.id;
            input.addEventListener('input', () => this.updateCalcPreview());
            field.appendChild(label); field.appendChild(input);
            this.sessionMetricsInputs.appendChild(field);
        });
    }

    // Калькуляция
    calculateSessionPoints(scoring, inputs) {
        const clamp = (x, min, max) => Math.max(min, Math.min(max, x));
        let breakdown = [];
        let total = 0;
        (scoring.metrics || []).forEach(metric => {
            if (metric.type === 'percent') {
                const percent = clamp((inputs[metric.id] || 0), -100, 100);
                const pts = (metric.maxPoints || 0) * (percent / 100);
                breakdown.push({ id: metric.id, name: metric.name, value: pts });
                total += pts;
            } else if (metric.type === 'time') {
                const minutes = Math.max(0, inputs[metric.id] || 0);
                const ratio = (metric.timeMaxMinutes > 0) ? clamp(minutes / metric.timeMaxMinutes, 0, 1) : 0;
                const pts = (metric.timeMaxPoints || 0) * ratio;
                breakdown.push({ id: metric.id, name: metric.name, value: pts });
                total += pts;
            }
        });
        if (typeof scoring.totalMaxPoints === 'number' && scoring.totalMaxPoints >= 0) total = Math.min(total, scoring.totalMaxPoints);
        return { total, breakdown };
    }

    getMaxSessionPoints(scoring) {
        if (!scoring) return 0;
        const maxSum = (scoring.metrics || []).reduce((acc, m) => {
            if (m.type === 'percent') return acc + (m.maxPoints || 0);
            if (m.type === 'time') return acc + (m.timeMaxPoints || 0);
            return acc;
        }, 0);
        if (typeof scoring.totalMaxPoints === 'number' && scoring.totalMaxPoints >= 0) {
            return Math.min(maxSum, scoring.totalMaxPoints);
        }
        return maxSum;
    }

    updateCalcPreview() {
        const dir = this.getFreshCurrentDetailDirection();
        if (!dir || !this.calcPreview) return;
        const scoring = this.loadDirectionScoring(dir);
        const inputs = {};
        if (this.sessionMetricsInputs) {
            this.sessionMetricsInputs.querySelectorAll('input[data-metric-id]').forEach(inp => {
                const id = inp.dataset.metricId; inputs[id] = parseFloat(inp.value) || 0;
            });
        }
        const r = this.calculateSessionPoints(scoring, inputs);
        const parts = r.breakdown.map(b => `${b.name}: ${b.value.toFixed(2)}`);
        const maxPossible = this.getMaxSessionPoints(scoring);
        const suggested = maxPossible > 0 ? Math.max(0, Math.min(10, (r.total / maxPossible) * 10)) : null;
        const manualGrade = parseFloat(this.calcManualGradeInput?.value);
        const manualText = Number.isFinite(manualGrade) ? ` | Оценка: ${manualGrade.toFixed(1)}` : '';
        const suggestedText = (suggested != null) ? ` | Предв. оценка: ${suggested.toFixed(1)}/10` : '';
        this.calcPreview.textContent = `${parts.join(' | ')} | Итого: ${r.total.toFixed(2)}${suggestedText}${manualText}`;
    }

    applyCalcToCurrentDirection() {
        const dir = this.getFreshCurrentDetailDirection();
        if (!dir) return;
        const scoring = this.loadDirectionScoring(dir);
        const inputs = {};
        if (this.sessionMetricsInputs) {
            this.sessionMetricsInputs.querySelectorAll('input[data-metric-id]').forEach(inp => {
                const id = inp.dataset.metricId; inputs[id] = parseFloat(inp.value) || 0;
            });
        }
        const r = this.calculateSessionPoints(scoring, inputs);
        const total = Number.isFinite(r.total) ? r.total : 0;
        const manualGrade = parseFloat(this.calcManualGradeInput?.value);
        const newScore = {
            value: total,
            date: new Date().toISOString(),
            timestamp: Date.now(),
            meta: {
                type: 'sessionCalc',
                breakdown: r,
                inputs,
                scoring,
                grade: Number.isFinite(manualGrade) ? manualGrade : undefined
            }
        };
        dir.scores.push(newScore);
        dir.totalScore = (dir.totalScore || 0) + total;
        this.saveDirections();
        this.renderDirectionsOnly();
        this.updateChart();
        this.updateCalcPreview();
        this.updateDirectionAvgGrade(dir);
        this.showNotification(`Начислено ${total.toFixed(2)} баллов по сессии`, 'success');
    }

    

    // Загрузка направлений из LocalStorage
    loadDirections() {
        const saved = localStorage.getItem(this.getStorageKey('productivityDirections'));
        const directions = saved ? JSON.parse(saved) : [];
        
        // Миграция старых данных - добавляем поля scores, totalScore, category и description если их нет
        return directions.map(direction => ({
            ...direction,
            scores: direction.scores || [],
            totalScore: direction.totalScore || 0,
            category: direction.category || 'other1', // По умолчанию в "Прочее 1"
            description: typeof direction.description === 'string' ? direction.description : '',
            color: direction.color || null
        }));
    }

    // Категории: хранение
    loadCategories() {
        try {
            const saved = localStorage.getItem(this.getStorageKey('productivityCategories'));
            return saved ? JSON.parse(saved) : null;
        } catch (_) { return null; }
    }

    saveCategories() {
        try { localStorage.setItem(this.getStorageKey('productivityCategories'), JSON.stringify(this.categories)); } catch (_) {}
        if (this.currentUser) this.scheduleCloudSave(0);
    }

    // Если нет ни одной категории — создаём fallback. Если удалён fallback, создаём новый
    ensureValidCategories() {
        if (!Array.isArray(this.categories) || this.categories.length === 0) {
            this.categories = [{ id: 'other1', name: 'Прочее 1', icon: '📝', priority: 1 }];
            this.saveCategories();
            return;
        }
        // Убедимся, что существует хотя бы одна категория для назначения по умолчанию
        if (!this.categories.find(c => c.id === 'other1')) {
            const maxPriority = Math.max(...this.categories.map(c => c.priority || 0), 0);
            this.categories.push({ id: 'other1', name: 'Прочее 1', icon: '📝', priority: maxPriority + 1 });
            this.saveCategories();
        }
    }

    // Переназначаем направления с невалидной категорией в fallback
    reassignOrphanDirections() {
        const validIds = new Set(this.categories.map(c => c.id));
        let changed = false;
        this.directions.forEach(d => {
            if (!validIds.has(d.category)) {
                d.category = 'other1';
                changed = true;
            }
        });
        if (changed) this.saveDirections();
    }

    // Добавление категории с запросом имени и эмодзи-иконки
    promptAddCategory() {
        const name = prompt('Название категории:', 'Новая категория');
        if (!name) return;
        const icon = prompt('Иконка (эмодзи):', '📁') || '📁';
        const id = 'cat_' + Date.now();
        const priority = (this.categories[this.categories.length - 1]?.priority || 0) + 1;
        this.categories.push({ id, name: name.trim(), icon, priority });
        this.saveCategories();
        this.renderDirectionsOnly();
        this.updateDetailCategorySelectIfOpen();
        this.showNotification(`Категория "${name}" добавлена`, 'success');
    }

    promptRenameCategory(categoryId) {
        const cat = this.categories.find(c => c.id === categoryId);
        if (!cat) return;
        const newName = prompt('Новое имя категории:', cat.name);
        if (!newName || newName.trim() === cat.name) return;
        cat.name = newName.trim();
        this.saveCategories();
        this.renderDirectionsOnly();
        this.updateDetailCategorySelectIfOpen();
        this.showNotification('Категория переименована', 'success');
    }

    startInlineRenameCategory(categoryId, nameEl) {
        const cat = this.categories.find(c => c.id === categoryId);
        if (!cat) return;
        nameEl.setAttribute('contenteditable', 'true');
        nameEl.focus();
        const onFinish = () => {
            nameEl.removeAttribute('contenteditable');
            const text = nameEl.textContent.trim();
            if (text && text !== cat.name) {
                cat.name = text;
                this.saveCategories();
                this.updateDetailCategorySelectIfOpen();
                this.showNotification('Категория переименована', 'success');
            } else {
                nameEl.textContent = cat.name;
            }
            nameEl.removeEventListener('blur', onFinish);
            nameEl.removeEventListener('keydown', onKey);
        };
        const onKey = (e) => {
            if (e.key === 'Enter') { e.preventDefault(); nameEl.blur(); }
            if (e.key === 'Escape') { nameEl.textContent = cat.name; nameEl.blur(); }
        };
        nameEl.addEventListener('blur', onFinish);
        nameEl.addEventListener('keydown', onKey);
    }

    deleteCategory(categoryId) {
        const cat = this.categories.find(c => c.id === categoryId);
        if (!cat) return;
        if (categoryId === 'other1' && this.categories.length > 1) {
            this.showNotification('Нельзя удалить базовую категорию "Прочее 1". Переименуйте её при необходимости.', 'error');
            return;
        }
        const dirs = this.directions.filter(d => d.category === categoryId).length;
        if (!confirm(`Удалить категорию "${cat.name}"?${dirs ? `\nВ ней ${dirs} направлений. Они будут перенесены в "Прочее 1".`: ''}`)) return;
        // Перенос направлений в fallback категорию
        const fallback = this.categories.find(c => c.id === 'other1') || this.categories[0];
        this.directions.forEach(d => { if (d.category === categoryId) d.category = fallback.id; });
        // Удаляем категорию (в корзину)
        this.addToTrash({ type: 'category', item: cat });
        this.categories = this.categories.filter(c => c.id !== categoryId);
        this.saveCategories();
        this.saveDirections();
        this.renderDirectionsOnly();
        this.updateDetailCategorySelectIfOpen();
        this.showNotification('Категория удалена', 'success');
    }

    updateDetailCategorySelectIfOpen() {
        if (this.directionDetailPanel && this.directionDetailPanel.style.display !== 'none' && this.currentDetailDirection) {
            const dir = this.getFreshCurrentDetailDirection();
            if (dir) this.detailCategorySelect.innerHTML = this.getCategoryOptions(dir.category);
        }
    }

    // Всегда возвращаем «свежую» ссылку на текущий объект направления из this.directions
    // Это важно после облачной синхронизации, импорта и т.п., когда массив заменяется новым
    getFreshCurrentDetailDirection() {
        if (!this.currentDetailDirection) return null;
        const id = this.currentDetailDirection.id;
        const fresh = this.directions.find(d => d.id === id);
        if (fresh && fresh !== this.currentDetailDirection) this.currentDetailDirection = fresh;
        return fresh || null;
    }

    // Сохранение направлений в LocalStorage
    saveDirections() {
        localStorage.setItem(this.getStorageKey('productivityDirections'), JSON.stringify(this.directions));
        // Не отправляем в облако, если нет текущего пользователя (чтобы гость не перезаписывал ничьи данные)
        if (this.currentUser) this.scheduleCloudSave(0);
    }

    // Добавление нового направления
    addDirection() {
        const inputValue = this.directionInput.value.trim();
        
        if (inputValue === '') {
            this.showNotification('Пожалуйста, введите название направления', 'error');
            return;
        }

        // Проверка на дублирование
        const isDuplicate = this.directions.some(
            direction => direction.name.toLowerCase() === inputValue.toLowerCase()
        );

        if (isDuplicate) {
            this.showNotification('Такое направление уже существует', 'error');
            return;
        }

        // Создание нового направления
        // Выбираем существующую категорию по умолчанию
        const fallbackCategory = this.categories.find(c => c.id === 'other1')?.id
            || (this.categories[0]?.id);

        const newDirection = {
            id: Date.now(),
            name: inputValue,
            createdAt: new Date().toISOString(),
            scores: [],
            totalScore: 0,
            category: fallbackCategory
        };

        this.directions.push(newDirection);
        this.saveDirections();
        this.directionInput.value = '';
        this.render();
        this.updateDirectionSelect();
        
        // Обновляем график только для дневных периодов
        const selectedPeriod = this.periodSelect.value;
        if (['30m','1h','6h','12h','1d','3d','7d','10d','1M','3M','6M','1Y'].includes(selectedPeriod)) {
            this.updateChart();
        }
        
        this.showNotification(`Направление "${inputValue}" добавлено!`, 'success');
    }

    // Удаление направления
    deleteDirection(id) {
        const dir = this.directions.find(d => d.id === id);
        const directionName = dir?.name;
        if (dir) {
            this.addToTrash({ type: 'direction', item: dir });
        }
        this.directions = this.directions.filter(direction => direction.id !== id);
        this.saveDirections();
        this.saveTrash();
        this.render();
        this.updateDirectionSelect();
        
        // Обновляем график только для дневных периодов
        const selectedPeriod = this.periodSelect.value;
        if (['30m','1h','6h','12h','1d','3d','7d','10d','1M','3M','6M','1Y'].includes(selectedPeriod)) {
            this.updateChart();
        }
        
        if (directionName) {
            this.showNotification(`Направление "${directionName}" удалено`, 'success');
        }
    }

    // Отображение списка направлений по категориям
    render() {
        this.directionsList.innerHTML = '';
        this.applyLayoutClass();
        
        if (this.directions.length === 0) {
            this.emptyState.classList.remove('hidden');
            if (this.chartSection) this.chartSection.style.display = 'none';
        } else {
            this.emptyState.classList.add('hidden');
            // Не меняем видимость графика здесь, чтобы он не пропадал при обновлениях
            
            // Группируем направления по категориям
            this.categories.forEach(category => {
                const categoryDirections = this.directions.filter(d => d.category === category.id);
                const categoryBlock = this.createCategoryBlock(category, categoryDirections);
                this.directionsList.appendChild(categoryBlock);
            });
        }
    }

    // Создание блока категории
    createCategoryBlock(category, directions) {
        const categoryDiv = document.createElement('div');
        categoryDiv.className = 'category-block';
        categoryDiv.setAttribute('data-category', category.id);
        
        const headerDiv = document.createElement('div');
        headerDiv.className = 'category-header';
        headerDiv.innerHTML = `
            <span class="category-icon">${category.icon}</span>
            <span class="category-name" data-editable="true">${category.name}</span>
            <span class="category-count">(${directions.length})</span>
            <div class="category-actions">
                <button class="category-action-btn" title="Переименовать" data-action="rename"><i class="fas fa-pen"></i></button>
                <button class="category-action-btn" title="Удалить" data-action="delete"><i class="fas fa-trash"></i></button>
            </div>
            <span class="chevron"><i class="fas fa-chevron-down"></i></span>
        `;

        // (цвето-пикер категорий удалён)
        
        const contentDiv = document.createElement('div');
        contentDiv.className = 'category-content';
        
        if (directions.length === 0) {
            contentDiv.innerHTML = `
                <div class="category-empty">
                    Пока нет направлений в этой категории
                </div>
            `;
        } else {
            const directionsDiv = document.createElement('div');
            directionsDiv.className = 'category-directions';
            
            const maxVisible = 12;
            const hasMore = directions.length > maxVisible;
            const visibleItems = directions.slice(0, maxVisible);
            const hiddenItems = directions.slice(maxVisible);

            visibleItems.forEach(direction => {
                const directionElement = this.createDirectionElement(direction);
                directionsDiv.appendChild(directionElement);
            });

            if (hasMore) {
                const moreChip = document.createElement('div');
                moreChip.className = 'show-more-chip';
                moreChip.textContent = `Показать ещё (${hiddenItems.length})`;
                let expanded = false;
                moreChip.addEventListener('click', () => {
                    expanded = !expanded;
                    if (expanded) {
                        hiddenItems.forEach(direction => {
                            const el = this.createDirectionElement(direction);
                            el.classList.add('revealed');
                            directionsDiv.insertBefore(el, moreChip);
                        });
                        moreChip.textContent = 'Скрыть';
                    } else {
                        // удалить добавленные элементы
                        directionsDiv.querySelectorAll('.direction-item.revealed').forEach(el => el.remove());
                        moreChip.textContent = `Показать ещё (${hiddenItems.length})`;
                    }
                });
                directionsDiv.appendChild(moreChip);
            }
            
            contentDiv.appendChild(directionsDiv);
        }
        
        categoryDiv.appendChild(headerDiv);
        categoryDiv.appendChild(contentDiv);
        
        // Сворачивание/разворачивание по клику на заголовок
        headerDiv.addEventListener('click', (e) => {
            const btn = e.target.closest('.category-action-btn');
            if (btn) {
                const action = btn.getAttribute('data-action');
                if (action === 'rename') this.promptRenameCategory(category.id);
                if (action === 'delete') this.deleteCategory(category.id);
                e.stopPropagation();
                return;
            }
            // сворачивать только при клике не по кнопкам/редактированию
            if (e.target.closest('[contenteditable="true"]')) return;
            categoryDiv.classList.toggle('collapsed');
            contentDiv.style.display = categoryDiv.classList.contains('collapsed') ? 'none' : '';
        });

        // Редактирование названия по клику на имя
        const nameEl = headerDiv.querySelector('.category-name');
        nameEl.addEventListener('dblclick', (e) => {
            e.stopPropagation();
            this.startInlineRenameCategory(category.id, nameEl);
        });
        
        return categoryDiv;
    }

    // Применить класс разметки к списку направлений
    applyLayoutClass() {
        if (!this.directionsList) return;
        this.directionsList.classList.remove('horizontal-directions', 'compact-directions');
        if (this.layoutMode === 'compact') {
            this.directionsList.classList.add('compact-directions');
        } else {
            this.directionsList.classList.add('horizontal-directions');
        }
    }

    loadLayoutMode() {
        try {
            const saved = localStorage.getItem('productivityLayoutMode');
            return saved === 'compact' ? 'compact' : 'horizontal';
        } catch (_) {
            return 'horizontal';
        }
    }

    saveLayoutMode() {
        try {
            localStorage.setItem('productivityLayoutMode', this.layoutMode);
        } catch (_) {}
        this.scheduleCloudSave();
    }

    // Создание элемента направления
    createDirectionElement(direction) {
        const div = document.createElement('div');
        div.className = 'direction-item';
        if (direction.color) div.classList.add(`color-${direction.color}`);
        // кастом-стиль удалён
        div.setAttribute('data-id', direction.id);
        
        const totalScore = direction.totalScore || 0;
        const scoreClass = totalScore > 0 ? 'score-positive' : totalScore < 0 ? 'score-negative' : 'score-neutral';
        const scoreText = totalScore > 0 ? `+${totalScore}` : totalScore.toString();
        
        div.innerHTML = `
            <div class="direction-header">
                <div class="direction-info">
                    <div class="direction-name">🎯 ${this.escapeHtml(direction.name)}</div>
                    <div class="direction-score ${scoreClass}">
                        ${scoreText}
                    </div>
                </div>
                <div class="direction-actions">
                    <select class="category-select" onchange="tracker.changeDirectionCategory(${direction.id}, this.value)">
                        ${this.getCategoryOptions(direction.category)}
                    </select>
                    <div class="score-input-container">
                        <input 
                            type="number" 
                            class="score-input" 
                            placeholder="+11 или -5"
                            id="scoreInput${direction.id}"
                        >
                        <button class="add-score-button" onclick="tracker.addScore(${direction.id})">
                            <i class="fas fa-plus"></i>
                        </button>
                    </div>
                    <button class="delete-button" onclick="tracker.deleteDirection(${direction.id})">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
            <div class="direction-percent">${this.getDirectionPercentText(direction.color)}</div>
        `;
        
        // Добавляем обработчик клика для открытия детальной панели
        div.addEventListener('click', (e) => {
            // Не закрывать/сбрасывать график при взаимодействии с внутренними контролами
            const target = e.target;
            if (target.closest('select') || target.closest('input') || target.closest('button')) {
                return;
            }
            this.openDetailView(direction.id);
        });
        
        // Добавляем обработчик для Enter в поле ввода баллов
        setTimeout(() => {
            const scoreInput = document.getElementById(`scoreInput${direction.id}`);
            if (scoreInput) {
                scoreInput.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') {
                        this.addScore(direction.id);
                    }
                });
            }
        }, 0);
        
        return div;
    }

    // Получение опций для селектора категорий
    getCategoryOptions(currentCategory) {
        return this.categories.map(category => 
            `<option value="${category.id}" ${category.id === currentCategory ? 'selected' : ''}>
                ${category.icon} ${category.name}
            </option>`
        ).join('');
    }

    // Изменение категории направления
    changeDirectionCategory(directionId, newCategory) {
        const direction = this.directions.find(d => d.id === directionId);
        if (!direction) return;
        
        direction.category = newCategory;
        this.saveDirections();
        this.render();
        
        const categoryName = this.categories.find(c => c.id === newCategory)?.name || newCategory;
        this.showNotification(`"${direction.name}" перемещено в "${categoryName}"`, 'success');
    }

    // Экранирование HTML для безопасности
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Показ уведомлений
    showNotification(message, type) {
        // Удаление предыдущих уведомлений
        const existingNotifications = document.querySelectorAll('.notification');
        existingNotifications.forEach(notification => notification.remove());

        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        
        // Стили для уведомления
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 25px;
            border-radius: 10px;
            color: white;
            font-weight: 500;
            z-index: 1000;
            max-width: 300px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
            transform: translateX(100%);
            transition: transform 0.3s ease;
            ${type === 'error' 
                ? 'background: linear-gradient(45deg, #ff6b6b, #ee5a52);' 
                : 'background: linear-gradient(45deg, #51cf66, #40c057);'
            }
        `;

        document.body.appendChild(notification);

        // Анимация появления
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 100);

        // Автоматическое удаление через 3 секунды
        setTimeout(() => {
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }

    // Добавление баллов к направлению
    addScore(directionId) {
        const scoreInput = document.getElementById(`scoreInput${directionId}`);
        const scoreValue = parseInt(scoreInput.value);
        
        if (isNaN(scoreValue) || scoreValue === 0) {
            this.showNotification('Введите корректное значение баллов', 'error');
            return;
        }
        
        const direction = this.directions.find(d => d.id === directionId);
        if (!direction) return;
        
        // Добавляем новый балл с датой
        const newScore = {
            value: scoreValue,
            date: new Date().toISOString(),
            timestamp: Date.now()
        };
        
        direction.scores.push(newScore);
        direction.totalScore = (direction.totalScore || 0) + scoreValue;
        
        this.saveDirections();
        // Обновляем только список направлений без скрытия графика
        this.renderDirectionsOnly();
        
        // НЕ обновляем график при добавлении баллов для таймфреймов!
        // График обновляется только автоматически каждую секунду
        const selectedPeriod = this.periodSelect.value;
        // Обновляем график для любого периода, не разрушая выбор
            this.updateChart();
        
        scoreInput.value = '';
        
        const action = scoreValue > 0 ? 'добавлены' : 'вычтены';
        const absValue = Math.abs(scoreValue);
        this.showNotification(`${absValue} баллов ${action} к "${direction.name}"`, 'success');
    }

    // Частичный ререндер только списка направлений (без трогания секции графика)
    renderDirectionsOnly() {
        this.directionsList.innerHTML = '';
        this.applyLayoutClass();
        this.categories.forEach(category => {
            const categoryDirections = this.directions.filter(d => d.category === category.id);
            const categoryBlock = this.createCategoryBlock(category, categoryDirections);
            this.directionsList.appendChild(categoryBlock);
        });
        this.emptyState.classList.toggle('hidden', this.directions.length > 0);
    }

    // Обновление селектора направлений
    updateDirectionSelect() {
        const prev = this.directionSelect.value;
        this.directionSelect.innerHTML = '<option value="">Выберите направление</option>';
        // Специальная опция: сумма всех направлений
        const allOpt = document.createElement('option');
        allOpt.value = 'ALL';
        allOpt.textContent = 'Все направления (сумма)';
        this.directionSelect.appendChild(allOpt);
        
        this.directions.forEach(direction => {
            const option = document.createElement('option');
            option.value = direction.id;
            option.textContent = direction.name;
            this.directionSelect.appendChild(option);
        });
        // Восстановить предыдущий выбор, если он есть в списке
        if (prev && (prev === 'ALL' || this.directions.some(d => String(d.id) === String(prev)))) {
            this.directionSelect.value = prev;
        }
    }

    // ===== Комментарии к свечам =====
    getCandleKey(rawCandle) {
        // Используем "направление|period|время-интервала"
        const dirId = this.directionSelect.value || 'dir';
        const period = this.periodSelect.value || 'period';
        // Для таймфреймов у нас есть intervalStart; иначе используем x
        const ts = rawCandle.intervalStart ? new Date(rawCandle.intervalStart).getTime() : new Date(rawCandle.x).getTime();
        return `${dirId}|${period}|${ts}`;
    }
    loadComments() {
        try { return JSON.parse(localStorage.getItem(this.getStorageKey('productivityComments')) || '{}'); } catch(_) { return {}; }
    }
    saveComments(map) {
        try { localStorage.setItem(this.getStorageKey('productivityComments'), JSON.stringify(map)); } catch(_) {}
        if (this.currentUser) this.scheduleCloudSave();
    }
    getCandleComment(key) {
        const map = this.loadComments();
        return map[key] || '';
    }
    setCandleComment(key, text) {
        const map = this.loadComments();
        if (text && text.trim().length) {
            map[key] = text.trim();
        } else {
            delete map[key];
        }
        this.saveComments(map);
    }
    openCommentModal(key, rawCandle) {
        this.currentCommentKey = key;
        const dateStr = rawCandle.intervalStart ? new Date(rawCandle.intervalStart).toLocaleString('ru-RU') : new Date(rawCandle.x).toLocaleString('ru-RU');
        if (this.commentModalTitle) this.commentModalTitle.textContent = `Комментарий к свече ${dateStr}`;
        const existing = this.getCandleComment(key);
        if (this.commentText) this.commentText.value = existing;
        if (this.commentInfo) this.commentInfo.textContent = existing ? 'Есть сохранённый комментарий — можно отредактировать.' : 'Комментариев нет — введите новый.';
        if (this.deleteCommentButton) this.deleteCommentButton.style.display = existing ? '' : 'none';
        if (this.commentModal) this.commentModal.style.display = 'flex';
    }
    closeCommentModal() {
        if (this.commentModal) this.commentModal.style.display = 'none';
        this.currentCommentKey = null;
    }
    saveCandleComment() {
        if (!this.currentCommentKey) return;
        const text = (this.commentText?.value) || '';
        this.setCandleComment(this.currentCommentKey, text);
        this.closeCommentModal();
        // Перерисовать график для применения индикатора
        this.updateChartWithZoom();
        this.showNotification('Комментарий сохранён', 'success');
    }
    deleteCandleComment() {
        if (!this.currentCommentKey) return;
        this.setCandleComment(this.currentCommentKey, '');
        this.closeCommentModal();
        this.updateChartWithZoom();
        this.showNotification('Комментарий удалён', 'success');
    }
    applyCommentStyles(candles) {
        // Здесь нельзя напрямую красить отдельные свечи, но мы можем помечать raw-объекты флагом,
        // а в tooltip уже показали, что комментарий есть. Плюс можно изменить прозрачность.
        // В качестве видимого индикатора используем label-добавку к tooltip (уже есть) и bodyOpacity.
        const map = this.loadComments();
        const ds = this.chart.data.datasets[0];
        ds.data = candles.map(c => ({ ...c }));
        // Накладываем стиль через скрытую метку: меняем цвет свечи, если есть комментарий
        const hasComment = (raw) => !!map[this.getCandleKey(raw)];
        ds.color = {
            up: 'rgba(76, 175, 80, 1.0)',
            down: 'rgba(244, 67, 54, 1.0)',
            unchanged: 'rgba(128, 128, 128, 1.0)'
        };
        ds.borderColor = ds.borderColor || {};
        // Дополнительно увеличим непрозрачность границы для свечей с комментарием
        // Chartjs-financial не поддерживает массив цветов по свечам, поэтому оставим tooltip-индикатор.
        // Альтернатива: добавить вторую dataset поверх для иконок — можно позже.
        return;
    }

    // Получение данных для графика в формате японских свечей с фиксированными таймфреймами
    getChartData(directionId, period) {
        const fullData = this.getFullChartData(directionId, period);
        if (!fullData) return null;
        
        // Применяем зум - фильтруем данные по временному диапазону
        const filteredData = directionId === 'ALL'
            ? this.applyZoomFilter(fullData, true)
            : this.applyZoomFilter(fullData, false);
        // Ограничение количества свечей в данных (safety cap)
        const cap = this.maxRenderedCandles || 800;
        if (filteredData && filteredData.candlestickData && filteredData.candlestickData.length > cap) {
            filteredData.candlestickData = filteredData.candlestickData.slice(-cap);
        }
        return filteredData;
    }

    // Получение полных данных без фильтрации зума (с кешированием по интервалу)
    getFullChartData(directionId, period) {
        const cacheKey = this.getCacheKey(directionId, period);
        if (cacheKey && this.candlesCache.has(cacheKey)) {
            return this.candlesCache.get(cacheKey);
        }

        // Общий график: агрегируем все направления как одно
        if (directionId === 'ALL') {
            const allScores = [];
            const liveIds = new Set(this.directions.map(d => d.id));
            // Текущие направления
            this.directions.forEach(d => (d.scores || []).forEach(s => allScores.push({ ...s, _sourceDirectionId: d.id, _sourceDirectionName: d.name })));
            // Удалённые направления (корзина), не дублируем id
            if (this.trash && Array.isArray(this.trash.directions)) {
                this.trash.directions.forEach(td => {
                    if (liveIds.has(td.id)) return;
                    (td.scores || []).forEach(s => allScores.push({ ...s, _sourceDirectionId: td.id, _sourceDirectionName: td.name }));
                });
            }
            if (!allScores.length) return null;
            const direction = { id: 'ALL', name: 'Все направления (сумма)', scores: allScores };
            const result = this.buildCandlesForDirection(direction, period);
            if (result && cacheKey) this.candlesCache.set(cacheKey, result);
            return result;
        }

        const direction = this.directions.find(d => d.id == directionId);
        if (!direction || !direction.scores.length) return null;
        const result = this.buildCandlesForDirection(direction, period);
        if (result && cacheKey) this.candlesCache.set(cacheKey, result);
        return result;
    }

    getCacheKey(directionId, period) {
        const intervalMs = this.getIntervalMs(period);
        if (!intervalMs) return `${directionId}|${period}`;
        const now = Date.now();
        const currentIntervalStart = Math.floor(now / intervalMs) * intervalMs;
        return `${directionId}|${period}|${currentIntervalStart}`;
    }

    getIntervalMs(period) {
        const minute = 60 * 1000; const hour = 60 * minute; const day = 24 * hour;
        const map = {
            '30m': 30 * minute,
            '1h': 1 * hour,
            '6h': 6 * hour,
            '12h': 12 * hour,
            '1d': 1 * day,
            '3d': 3 * day,
            '7d': 7 * day,
            '10d': 10 * day,
            '1M': 30 * day,
            '3M': 90 * day,
            '6M': 180 * day,
            '1Y': 365 * day
        };
        return map[period] || null;
    }

    buildCandlesForDirection(direction, period) {
        const now = new Date();
        const minute = 60 * 1000;
        const hour = 60 * minute;
        const day = 24 * hour;
        const periodConfig = {
            '30m': { interval: 30 * minute, showLast: Infinity, unit: 'minute' },
            '1h':  { interval: 1 * hour, showLast: Infinity, unit: 'hour' },
            '6h':  { interval: 6 * hour, showLast: Infinity, unit: 'hour' },
            '12h': { interval: 12 * hour, showLast: Infinity, unit: 'hour' },
            '1d':  { interval: 1 * day, showLast: Infinity, unit: 'day' },
            '3d':  { interval: 3 * day, showLast: Infinity, unit: 'day' },
            '7d':  { interval: 7 * day, showLast: Infinity, unit: 'day' },
            '10d': { interval: 10 * day, showLast: Infinity, unit: 'day' },
            '1M':  { interval: 30 * day, showLast: Infinity, unit: 'month' },
            '3M':  { interval: 90 * day, showLast: Infinity, unit: 'month' },
            '6M':  { interval: 180 * day, showLast: Infinity, unit: 'month' },
            '1Y':  { interval: 365 * day, showLast: Infinity, unit: 'year' }
        };
        
        const config = periodConfig[period];
        if (!config) return null;
        
        const sortedScores = direction.scores
            .sort((a, b) => new Date(a.date) - new Date(b.date));
        
        if (!sortedScores.length) return null;
        
        let candlestickData = [];
        
        const isTimeframe = ['30m','1h','6h','12h','1d','3d','7d','10d','1M','3M','6M','1Y'].includes(period);
        if (isTimeframe) {
            // Таймфрейм режим - фиксированные интервалы времени
            const intervalMs = config.interval;
            const currentTime = now.getTime();
            
            // Находим самую раннюю запись и выравниваем по границе таймфрейма
            const firstScoreTime = new Date(sortedScores[0].date).getTime();
            const startTime = Math.floor(firstScoreTime / intervalMs) * intervalMs;
            
            // Создаём фиксированные интервалы
            let globalRunningTotal = 0;
            let intervalStart = startTime;
            
            // Добавляем текущий активный интервал к циклу
            const currentIntervalStart = Math.floor(currentTime / intervalMs) * intervalMs;
            const endTime = Math.max(currentTime, currentIntervalStart + intervalMs);
            
            while (intervalStart <= currentIntervalStart && candlestickData.length < config.showLast) {
                const intervalEnd = intervalStart + intervalMs;
                
                // Собираем все баллы в этом интервале
                const intervalScores = sortedScores.filter(score => {
                    const scoreTime = new Date(score.date).getTime();
                    return scoreTime >= intervalStart && scoreTime < intervalEnd;
                });
                
                // Создаем свечу ВСЕГДА для каждого интервала (как в TradingView)
                const open = globalRunningTotal;
                let runningTotalInInterval = globalRunningTotal;
                let high = globalRunningTotal;
                let low = globalRunningTotal;
                
                if (intervalScores.length > 0) {
                    // Если есть баллы - рассчитываем High/Low
                    intervalScores.forEach(score => {
                        runningTotalInInterval += score.value;
                        high = Math.max(high, runningTotalInInterval);
                        low = Math.min(low, runningTotalInInterval);
                    });
                }
                // Если нет баллов - остаются open = close = high = low (doji свеча)
                
                const close = runningTotalInInterval;
                const isCurrentInterval = intervalStart === currentIntervalStart;
                const isCompleted = !isCurrentInterval;
                
                candlestickData.push({
                    x: intervalStart,  // Используем точное время начала интервала
                    o: open,
                    h: high,
                    l: low,
                    c: close,
                    intervalStart: new Date(intervalStart),
                    intervalEnd: new Date(intervalEnd),
                    scoresCount: intervalScores.length,
                    scoresInInterval: intervalScores,
                    totalChange: close - open,
                    isCompleted: isCompleted,
                    isActive: isCurrentInterval, // Только текущий интервал активный
                    isEmpty: intervalScores.length === 0 // Пустой интервал (doji)
                });
                
                globalRunningTotal = close;
                intervalStart = intervalEnd;
            }
        } else {
            // Дневной режим - группируем по дням
            const dailyGroups = Object.create(null);
            
            sortedScores.forEach(score => {
                const dateKey = new Date(score.date).toISOString().split('T')[0];
                if (!dailyGroups[dateKey]) {
                    dailyGroups[dateKey] = [];
                }
                dailyGroups[dateKey].push(score);
            });
            
            const sortedDates = Object.keys(dailyGroups).sort();
            let runningTotal = 0;
            
            const showDates = period === 'all' ? sortedDates : sortedDates.slice(-config.showLast);
            
            showDates.forEach(dateKey => {
                const dayScores = dailyGroups[dateKey].sort((a, b) => new Date(a.date) - new Date(b.date));
                const open = runningTotal;
                let dayRunningTotal = runningTotal;
                let high = runningTotal;
                let low = runningTotal;
                
                dayScores.forEach(score => {
                    dayRunningTotal += score.value;
                    high = Math.max(high, dayRunningTotal);
                    low = Math.min(low, dayRunningTotal);
                });
                
                const close = dayRunningTotal;
                
                candlestickData.push({
                    x: new Date(dateKey + 'T12:00:00'),
                    o: open,
                    h: high,
                    l: low,
                    c: close,
                    scoresCount: dayScores.length
                });
                
                runningTotal = close;
            });
        }
        
        return {
            candlestickData,
            directionName: direction.name,
            timeframe: period,
            intervalMs: config.interval
        };
    }

    // Применение зум-фильтра к данным (как в TradingView)
    applyZoomFilter(fullData, isOverall = false) {
        if (!fullData || !fullData.candlestickData.length) return fullData;
        
        const allCandles = fullData.candlestickData;
        const totalCandles = allCandles.length;
        
        // Определяем количество видимых свечей
        const zoom = isOverall ? this.overallZoomState : this.zoomState;
        const visibleCount = Math.min(zoom.visibleCandlesCount, totalCandles);
        
        let startIndex, endIndex;
        
        // Если centerIndex не установлен - показываем последние свечи
        if (zoom.centerIndex === null) {
            endIndex = totalCandles - 1;
            startIndex = Math.max(0, endIndex - visibleCount + 1);
        } else {
            // Если centerIndex установлен - сохраняем стабильную позицию
            const centerIndex = Math.min(zoom.centerIndex, totalCandles - 1);
            const halfVisible = Math.floor(visibleCount / 2);
            
            startIndex = Math.max(0, centerIndex - halfVisible);
            endIndex = Math.min(totalCandles - 1, startIndex + visibleCount - 1);
            
            // Корректируем только если действительно необходимо
            if (endIndex - startIndex + 1 < visibleCount && startIndex > 0) {
                startIndex = Math.max(0, endIndex - visibleCount + 1);
            }
        }
        
        // НЕ обновляем centerIndex автоматически - только при явных действиях пользователя
        
        // Возвращаем отфильтрованные данные
        const visibleCandles = allCandles.slice(startIndex, endIndex + 1);
        
        return {
            ...fullData,
            candlestickData: visibleCandles,
            zoomInfo: {
                startIndex,
                endIndex,
                totalCandles,
                visibleCount: visibleCandles.length
            }
        };
    }

    // Получение единицы времени для оси X
    getTimeUnit(period) {
        switch(period) {
            case '30m': return 'minute';
            case '1h':
            case '6h':
            case '12h': return 'hour';
            case '1d':
            case '3d':
            case '7d':
            case '10d': return 'day';
            case '1M':
            case '3M':
            case '6M': return 'month';
            case '1Y': return 'year';
            default: return 'minute';
        }
    }

    // Получение подписи для оси времени
    getTimeAxisLabel(period) {
        switch(period) {
            case '30m': return '30 мин';
            case '1h': return '1 ч';
            case '6h': return '6 ч';
            case '12h': return '12 ч';
            case '1d': return '1 день';
            case '3d':
            case '7d':
            case '10d': return 'Дни';
            case '1M':
            case '3M':
            case '6M': return 'Месяцы';
            case '1Y': return 'Год';
            default: return 'Время';
        }
    }

    // Обновление графика
    updateChart() {
        const selectedDirection = this.directionSelect.value;
        const selectedPeriod = this.periodSelect.value;
        
        // Обновляем информацию о текущем интервале
        this.updateIntervalInfo(selectedPeriod);
        
        if (!selectedDirection || !this.directions.length) {
            if (this.chart) {
                this.chart.destroy();
                this.chart = null;
            }
            // Не скрываем общий график — наоборот, обновляем его из directions + trash
            this.updateOverallChart();
            return;
        }
        
        const chartData = this.getChartData(selectedDirection, selectedPeriod);
        
        if (!chartData) {
            if (this.chart) {
                this.chart.destroy();
                this.chart = null;
            }
            return;
        }
        
        const ctx = this.productivityChart.getContext('2d');
        this.updatePeriodGradeBadge(selectedDirection, selectedPeriod);
        
        // Просто уничтожаем старый график
        if (this.chart) {
            this.chart.destroy();
        }
        
        const self = this;
        this.chart = new Chart(ctx, {
            type: 'candlestick',
            data: {
                datasets: [{
                    label: `${chartData.directionName} - Продуктивность`,
                    data: chartData.candlestickData,
                    // Цветовая схема для candlestick
                    color: {
                        up: 'rgba(76, 175, 80, 1.0)',      // Зеленый для роста
                        down: 'rgba(244, 67, 54, 1.0)',    // Красный для падения
                        unchanged: 'rgba(128, 128, 128, 1.0)'
                    },
                    borderColor: {
                        up: 'rgba(56, 142, 60, 1.0)',      // Темно-зеленая граница
                        down: 'rgba(211, 47, 47, 1.0)',    // Темно-красная граница
                        unchanged: 'rgba(96, 96, 96, 1.0)'
                    },
                    borderWidth: 2,
                    // Настройки ширины свечей
                    barPercentage: 0.8,
                    categoryPercentage: 0.9
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                devicePixelRatio: 1,
                // Принудительная темная тема как на Bybit
                backgroundColor: '#0b0e11',
                layout: {
                    padding: 0
                },
                // Клик по свече
                onClick: (evt, elements, chart) => {
                    try {
                        const points = chart.getElementsAtEventForMode(evt, 'nearest', { intersect: true }, false);
                        if (!points || !points.length) return;
                        const first = points[0];
                        const raw = chart.data.datasets[first.datasetIndex].data[first.index];
                        if (!raw) return;
                        const key = self.getCandleKey(raw);
                        self.openCommentModal(key, raw);
                    } catch (e) {
                        console.error('onClick candle error', e);
                    }
                },
                // Регистрируем плагин для черного фона
                plugins: [
                    {
                        id: 'darkBackground',
                        beforeDraw: function(chart) {
                            const ctx = chart.ctx;
                            ctx.save();
                            ctx.fillStyle = '#0b0e11';  // Принудительно черный фон как на Bybit
                            ctx.fillRect(0, 0, chart.width, chart.height);
                            ctx.restore();
                        }
                    }
                ],
                plugins: {
                    title: {
                        display: true,
                        text: `График продуктивности: ${chartData.directionName} (Японские свечи)`,
                        font: {
                            size: 16,
                            weight: 'bold'
                        },
                        color: '#f0f0f0'  // Светлый текст заголовка для темной темы
                    },
                    legend: {
                        display: true,
                        position: 'top',
                        labels: {
                            filter: function(item, chart) {
                                return item.text !== undefined;
                            },
                            color: '#f0f0f0'  // Светлый цвет легенды
                        }
                    },
                                         tooltip: {
                         callbacks: {
                             title: function(context) {
                                 const date = context[0].parsed.x;
                                 const rawData = context[0].raw;
                                 
                                 if (selectedPeriod === '10s' || selectedPeriod === '1m' || selectedPeriod === '10m') {
                                     const start = rawData.intervalStart ? new Date(rawData.intervalStart).toLocaleTimeString('ru-RU') : '';
                                     const end = rawData.intervalEnd ? new Date(rawData.intervalEnd).toLocaleTimeString('ru-RU') : '';
                                     return `${start} - ${end}`;
                                 }
                                 return new Date(date).toLocaleDateString('ru-RU');
                             },
                             label: function(context) {
                                 const data = context.parsed;
                                 const rawData = context[0].raw;
                                 const change = data.c - data.o;
                                 const changeText = change > 0 ? `+${change}` : change.toString();
                                 
                                 let labels = [
                                     `Открытие: ${data.o}`,
                                     `Максимум: ${data.h}`, 
                                     `Минимум: ${data.l}`,
                                     `Закрытие: ${data.c}`,
                                     `Изменение: ${changeText}`
                                 ];
                                 
                                 if (rawData.scoresCount !== undefined) {
                                     labels.push(`Записей: ${rawData.scoresCount}`);
                                 }
                                 
                                 if (rawData.isActive) {
                                     labels.push(`🔵 АКТИВНЫЙ ИНТЕРВАЛ`);
                                 } else if (rawData.isEmpty) {
                                     labels.push(`📭 Пустой интервал (doji)`);
                                 } else {
                                     labels.push(`✅ Завершен`);
                                 }
                                 
                                 return labels;
                             }
                         }
                    },
                    // Добавим визуальный индикатор наличия комментария в tooltip
                    tooltip: {
                        callbacks: {
                            afterBody: (items) => {
                                try {
                                    const p = items[0];
                                    const raw = p.raw;
                                    const key = self.getCandleKey(raw);
                                    const comment = self.getCandleComment(key);
                                    return comment ? ['Комментарий: есть'] : [];
                                } catch (_) { return []; }
                            }
                        }
                     }
                },
                                scales: {
                    x: {
                        type: 'time',
                        time: {
                            unit: this.getTimeUnit(selectedPeriod),
                            displayFormats: {
                                second: 'HH:mm:ss',
                                minute: 'HH:mm',
                                day: 'dd/MM'
                            }
                        },
                        title: {
                            display: true,
                            text: this.getTimeAxisLabel(selectedPeriod),
                            color: '#f0f0f0'  // Светлый цвет подписи оси X
                        },
                        grid: {
                            color: '#1e2329',  // Очень темные линии сетки как на Bybit
                            display: true,
                            lineWidth: 0.5,    // Тонкие линии
                            drawBorder: false   // Убираем границы
                        },
                        ticks: {
                            source: 'data',
                            maxRotation: 0,
                            autoSkip: true,
                            maxTicksLimit: 15,
                            color: '#b7bdc6'  // Светло-серые подписи значений оси X
                        },
                        offset: true, // ✅ Добавляем отступы между свечами
                        bounds: 'data'  // Привязываем к данным для корректного зума
                    },
                    y: {
                        title: {
                            display: true,
                            text: 'Баллы продуктивности',
                            color: '#f0f0f0'  // Светлый цвет подписи оси Y
                        },
                        grid: {
                            color: '#1e2329',  // Очень темные линии сетки как на Bybit
                            lineWidth: 0.5,    // Тонкие линии
                            drawBorder: false   // Убираем границы
                        },
                        ticks: {
                            color: '#b7bdc6',  // Светло-серые подписи значений оси Y
                            callback: function(value) {
                                return value > 0 ? '+' + value : value;
                            }
                        },
                        // Автоматическая подгонка под видимые данные при зуме
                        bounds: 'data',
                        beginAtZero: false  // Не заставлять начинать с нуля для лучшего масштабирования
                    }
                },
                                interaction: {
                    mode: 'index',
                    intersect: false
                },
                elements: {
                    candlestick: {
                        bodyWidth: 0.6,        // Ширина тела свечи
                        wickWidth: 2,          // Ширина теней
                        borderWidth: 2,        // Толщина границы
                        wickBorderWidth: 2,    // Толщина границы теней
                        // Принудительно делаем тела непрозрачными
                        backgroundOpacity: 1.0,
                        borderOpacity: 1.0
                    }
                },
                layout: {
                    padding: {
                        left: 10,
                        right: 10,
                        top: 10,
                        bottom: 10
                    }
                }
            },
            // Клик по свече для открытия модалки комментариев
            onClick(evt, activeEls) {
                const points = self.chart.getElementsAtEventForMode(evt, 'nearest', { intersect: true }, false);
                if (!points || !points.length) return;
                const first = points[0];
                const datasetIndex = first.datasetIndex;
                const index = first.index;
                const raw = self.chart.data.datasets[datasetIndex].data[index];
                if (!raw) return;
                const key = self.getCandleKey(raw);
                self.openCommentModal(key, raw);
             }
         });
         
         // Новый график уже учитывает текущий зум через фильтрацию данных
        // Обновляем/рисуем общий график ниже
        this.updateOverallChart();
    }

    // Создать/обновить общий график (ALL) ниже основного
    updateOverallChart(selectedPeriod) {
        // Не показываем общий график, если выбран режим ALL в основном графике
        if (this.directionSelect && this.directionSelect.value === 'ALL') {
            if (this.overallChart) { this.overallChart.destroy(); this.overallChart = null; }
            if (this.overallChartSection) this.overallChartSection.style.display = 'none';
            return;
        }
        if (!this.overallChartCanvas || !this.overallChartSection) return;
        const period = selectedPeriod || this.overallPeriodSelect?.value || this.periodSelect.value;
        const overallFull = this.getFullChartData('ALL', period);
        if (!overallFull || !overallFull.candlestickData || overallFull.candlestickData.length === 0) {
            // Если нет данных вообще — скрываем
            if (this.overallChart) { this.overallChart.destroy(); this.overallChart = null; }
            this.overallChartSection.style.display = 'none';
            return;
        }

        // Показать секцию
        this.overallChartSection.style.display = 'block';

        const ctx = this.overallChartCanvas.getContext('2d');
        if (this.overallChart) {
            this.overallChart.destroy();
        }
        const self = this;
        // Применяем независимый зум для общего графика
        const filteredOverall = this.applyZoomFilter(overallFull, true);
        const cap = this.maxRenderedCandles || 800;
        const overallDataCandles = filteredOverall.candlestickData.slice(-cap);
        this.overallChart = new Chart(ctx, {
            type: 'candlestick',
            data: {
                datasets: [{
                    label: `${overallFull.directionName} - Продуктивность`,
                    data: overallDataCandles,
                    color: { up: 'rgba(76, 175, 80, 1.0)', down: 'rgba(244, 67, 54, 1.0)', unchanged: 'rgba(128, 128, 128, 1.0)' },
                    borderColor: { up: 'rgba(56, 142, 60, 1.0)', down: 'rgba(211, 47, 47, 1.0)', unchanged: 'rgba(96, 96, 96, 1.0)' },
                    borderWidth: 2,
                    barPercentage: 0.8,
                    categoryPercentage: 0.9
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                devicePixelRatio: 1,
                backgroundColor: '#0b0e11',
                onClick(evt, activeEls) {
                    const points = self.overallChart.getElementsAtEventForMode(evt, 'nearest', { intersect: true }, false);
                    if (!points || !points.length) return;
                    const first = points[0];
                    const raw = self.overallChart.data.datasets[first.datasetIndex].data[first.index];
                    if (!raw) return;
                    self.openBreakdownForOverallCandle(raw, period);
                },
                plugins: {
                    title: {
                        display: true,
                        text: `Общий график: ${overallFull.directionName}`,
                        font: { size: 16, weight: 'bold' },
                        color: '#f0f0f0'
                    },
                    legend: {
                        display: true,
                        position: 'top',
                        labels: { color: '#f0f0f0' }
                    },
                    tooltip: {
                        callbacks: {
                            title: (context) => {
                                const raw = context[0].raw;
                                if (['30m','1h','6h','12h','1d','3d','7d','10d','1M','3M','6M','1Y'].includes(period)) {
                                    const start = raw.intervalStart ? new Date(raw.intervalStart).toLocaleTimeString('ru-RU') : '';
                                    const end = raw.intervalEnd ? new Date(raw.intervalEnd).toLocaleTimeString('ru-RU') : '';
                                    return `${start} - ${end}`;
                                }
                                return new Date(context[0].parsed.x).toLocaleDateString('ru-RU');
                            },
                            label: (context) => {
                                const d = context.parsed;
                                const change = d.c - d.o;
                                const changeText = change > 0 ? `+${change}` : change.toString();
                                const raw = context.raw;
                                const base = [
                                    `Открытие: ${d.o}`,
                                    `Максимум: ${d.h}`,
                                    `Минимум: ${d.l}`,
                                    `Закрытие: ${d.c}`,
                                    `Изменение: ${changeText}`
                                ];
                                if (raw && raw.scoresCount !== undefined) base.push(`Записей: ${raw.scoresCount}`);
                                return base;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        type: 'time',
                        time: {
                            unit: this.getTimeUnit(selectedPeriod),
                            displayFormats: { second: 'HH:mm:ss', minute: 'HH:mm', day: 'dd/MM' }
                        },
                        title: { display: true, text: this.getTimeAxisLabel(selectedPeriod), color: '#f0f0f0' },
                        grid: { color: '#1e2329', display: true, lineWidth: 0.5, drawBorder: false },
                        ticks: { source: 'data', maxRotation: 0, autoSkip: true, maxTicksLimit: 15, color: '#b7bdc6' },
                        offset: true,
                        bounds: 'data'
                    },
                    y: {
                        title: { display: true, text: 'Баллы продуктивности', color: '#f0f0f0' },
                        grid: { color: '#1e2329', lineWidth: 0.5, drawBorder: false },
                        ticks: { color: '#b7bdc6', callback: (v) => (v > 0 ? '+' + v : v) },
                        bounds: 'data',
                        beginAtZero: false
                    }
                },
                interaction: { mode: 'index', intersect: false },
                elements: { candlestick: { bodyWidth: 0.6, wickWidth: 2, borderWidth: 2, wickBorderWidth: 2, backgroundOpacity: 1.0, borderOpacity: 1.0 } },
                layout: { padding: { left: 10, right: 10, top: 10, bottom: 10 } }
            }
        });

        // Обновим бэдж средней оценки по всем направлениям
        this.updateOverallPeriodGradeBadge(period);
    }

    updateOverallPeriodGradeBadge(period) {
        const badge = document.getElementById('overallPeriodGradeBadge');
        const valEl = document.getElementById('overallPeriodGradeValue');
        const labelEl = document.getElementById('overallPeriodGradeLabel');
        if (!badge || !valEl || !labelEl) return;
        const full = this.getFullChartData('ALL', period);
        if (!full || !full.candlestickData || !full.candlestickData.length) { badge.style.display = 'none'; return; }
        const candles = full.candlestickData;
        const start = candles[0];
        const end = candles[candles.length - 1];
        const startMs = start.intervalStart ? new Date(start.intervalStart).getTime() : new Date(start.x).getTime();
        const endMs = end.intervalEnd ? new Date(end.intervalEnd).getTime() : new Date(end.x).getTime();
        const grades = [];
        this.directions.forEach(d => {
            (d.scores || []).forEach(s => {
                const t = new Date(s.date).getTime();
                if (t >= startMs && t <= endMs && s.meta && typeof s.meta.grade === 'number') grades.push(s.meta.grade);
            });
        });
        if (!grades.length) { badge.style.display = 'none'; return; }
        const avg = grades.reduce((a,b)=>a+b,0) / grades.length;
        valEl.textContent = avg.toFixed(1);
        labelEl.textContent = 'Оценка за период (все направления)';
        let bg = '#444', color = '#fff', shadow = '0 0 0px transparent';
        if (avg < 3) { bg = '#ef4444'; shadow = '0 0 16px rgba(239,68,68,0.6)'; }
        else if (avg < 6) { bg = '#f97316'; shadow = '0 0 16px rgba(249,115,22,0.6)'; }
        else if (avg < 8) { bg = '#f59e0b'; shadow = '0 0 16px rgba(245,158,11,0.6)'; }
        else if (avg < 9) { bg = '#22c55e'; shadow = '0 0 16px rgba(34,197,94,0.6)'; }
        else { bg = 'linear-gradient(135deg,#06b6d4,#a78bfa,#f472b6)'; color = '#0b0e11'; shadow = '0 0 20px rgba(167,139,250,0.8)'; }
        valEl.style.background = bg;
        valEl.style.color = color;
        valEl.style.boxShadow = shadow;
        badge.style.display = 'block';
    }

    // Автоматическое обновление графика для показа новых завершенных свечей
    startChartAutoUpdate() {
        // Очищаем предыдущий таймер
        if (this.chartUpdateTimer) {
            clearInterval(this.chartUpdateTimer);
        }
        
        // Обновляем график каждую секунду ТОЛЬКО для таймфреймов
        this.chartUpdateTimer = setInterval(() => {
            const selectedPeriod = this.periodSelect.value;
            if (!['10s', '1m', '10m'].includes(selectedPeriod)) {
                // Все равно обновляем плашку для периодов >1m раз в 0.5с для корректного ТТЛ
                this.updateIntervalInfo(selectedPeriod);
                // И также обновим нижнюю плашку, если выбрана для общего графика
                this.updateOverallIntervalInfo();
                return;
            }
                const selectedDirection = this.directionSelect.value;
            if (!selectedDirection || !this.chart) return;

            // Дешёвая проверка смены интервала: вычисляем старт текущего интервала и обновляем только при изменении
            const info = this.getCurrentIntervalInfo(selectedPeriod);
            if (!info) return;
            const currentStartMs = info.intervalStart.getTime();
            if (this.lastIntervalStartMs === currentStartMs) return;
            this.lastIntervalStartMs = currentStartMs;

            // Обновляем данными без разрушения графика
                    this.updateChartDataOnly();
            // Обновляем таймер закрытия свечной
            this.updateIntervalInfo(selectedPeriod);
            this.updateOverallIntervalInfo();
        }, 500);
    }

    updateOverallIntervalInfo() {
        const period = this.overallPeriodSelect?.value || this.periodSelect.value;
        if (!['30m','1h','6h','12h','1d','3d','7d','10d','1M','3M','6M','1Y'].includes(period)) {
            if (this.overallIntervalInfo) this.overallIntervalInfo.style.display = 'none';
            return;
        }
        const info = this.getCurrentIntervalInfo(period);
        if (!info || !this.overallIntervalInfo || !this.overallTimeLeftElement) return;
        const now = new Date();
        const end = info.intervalEnd;
        const diffMs = end - now;
        const sec = Math.max(0, Math.ceil(diffMs / 1000));
        const hh = Math.floor(sec / 3600);
        const mm = Math.floor((sec % 3600) / 60);
        const ss = sec % 60;
        const pad = (n) => String(n).padStart(2, '0');
        const label = `${info.periodName} • до закрытия: ${hh>0? pad(hh)+':':''}${pad(mm)}:${pad(ss)}`;
        this.overallIntervalInfo.style.display = 'block';
        this.overallTimeLeftElement.textContent = label;
    }

    // Обновление информации о текущем интервале
    updateIntervalInfo(period) {
        if (['30m','1h','6h','12h','1d','3d','7d','10d','1M','3M','6M','1Y'].includes(period)) {
            const info = this.getCurrentIntervalInfo(period);
            if (info && this.intervalInfo && this.timeLeftElement) {
                const now = new Date();
                const end = info.intervalEnd;
                const diffMs = end - now;
                const sec = Math.max(0, Math.ceil(diffMs / 1000));
                const hh = Math.floor(sec / 3600);
                const mm = Math.floor((sec % 3600) / 60);
                const ss = sec % 60;
                const pad = (n) => String(n).padStart(2, '0');
                const label = `${info.periodName} • до закрытия: ${hh>0? pad(hh)+':':''}${pad(mm)}:${pad(ss)}`;
                this.intervalInfo.style.display = 'block';
                this.timeLeftElement.textContent = label;
            }
        } else {
            if (this.intervalInfo) this.intervalInfo.style.display = 'none';
        }
    }

    // Получение информации о текущем активном интервале
    getCurrentIntervalInfo(period) {
        if (!['30m','1h','6h','12h','1d','3d','7d','10d','1M','3M','6M','1Y'].includes(period)) return null;
        
        const minute = 60 * 1000; const hour = 60 * minute; const day = 24 * hour;
        const periodConfig = {
            '10s': { interval: 10 * 1000, name: '10 секунд' },
            '1m': { interval: 1 * minute, name: '1 минута' },
            '5m': { interval: 5 * minute, name: '5 минут' },
            '30m': { interval: 30 * minute, name: '30 минут' },
            '1h': { interval: 1 * hour, name: '1 час' },
            '2h': { interval: 2 * hour, name: '2 часа' },
            '6h': { interval: 6 * hour, name: '6 часов' },
            '12h': { interval: 12 * hour, name: '12 часов' },
            '1d': { interval: 1 * day, name: '1 день' },
            '3d': { interval: 3 * day, name: '3 дня' },
            '7d': { interval: 7 * day, name: '7 дней' },
            '10d': { interval: 10 * day, name: '10 дней' },
            '1M': { interval: 30 * day, name: '1 месяц' },
            '3M': { interval: 90 * day, name: '3 месяца' },
            '6M': { interval: 180 * day, name: '6 месяцев' },
            '1Y': { interval: 365 * day, name: '1 год' }
        };
        
        const config = periodConfig[period];
        const now = new Date().getTime();
        const intervalMs = config.interval;
        
        // Находим начало текущего интервала
        const currentIntervalStart = Math.floor(now / intervalMs) * intervalMs;
        const currentIntervalEnd = currentIntervalStart + intervalMs;
        const timeLeft = currentIntervalEnd - now;
        
        return {
            intervalStart: new Date(currentIntervalStart),
            intervalEnd: new Date(currentIntervalEnd),
            timeLeftMs: timeLeft,
            timeLeftSeconds: Math.ceil(timeLeft / 1000),
            periodName: config.name
        };
    }

    // Методы управления зумом - как в TradingView (управление временным диапазоном)
    zoomIn() {
        // Получаем полные данные для корректного определения центра
        const selectedDirection = this.directionSelect.value;
        const selectedPeriod = this.periodSelect.value;
        if (!selectedDirection) return;
        
        const fullData = this.getFullChartData(selectedDirection, selectedPeriod);
        if (!fullData) return;
        
        const totalCandles = fullData.candlestickData.length;
        
        // Если centerIndex не установлен, устанавливаем его в текущую позицию
        if (this.zoomState.centerIndex === null) {
            this.zoomState.centerIndex = totalCandles - Math.floor(this.zoomState.visibleCandlesCount / 2);
        }
        
        // Уменьшаем количество видимых свечей = приближение
        const newCount = Math.max(
            this.zoomState.minCandlesCount,
            Math.floor(this.zoomState.visibleCandlesCount * 0.7)
        );
        this.zoomState.visibleCandlesCount = newCount;
        
        // Обновляем селектор к ближайшему значению
        this.updateCandlesCountSelector(newCount);
        
        // Корректируем centerIndex чтобы не выйти за границы
        const halfVisible = Math.floor(newCount / 2);
        this.zoomState.centerIndex = Math.max(
            halfVisible,
            Math.min(totalCandles - 1 - halfVisible, this.zoomState.centerIndex)
        );
        
        this.updateChartWithZoom();
    }

     zoomInOverall() {
         const selectedPeriod = this.periodSelect.value;
         const fullData = this.getFullChartData('ALL', selectedPeriod);
         if (!fullData) return;
         const totalCandles = fullData.candlestickData.length;
         if (this.overallZoomState.centerIndex === null) {
             this.overallZoomState.centerIndex = totalCandles - Math.floor(this.overallZoomState.visibleCandlesCount / 2);
         }
         const newCount = Math.max(this.overallZoomState.minCandlesCount, Math.floor(this.overallZoomState.visibleCandlesCount * 0.7));
         this.overallZoomState.visibleCandlesCount = newCount;
         const halfVisible = Math.floor(newCount / 2);
         this.overallZoomState.centerIndex = Math.max(
             halfVisible,
             Math.min(totalCandles - 1 - halfVisible, this.overallZoomState.centerIndex)
         );
         this.updateOverallChart(selectedPeriod);
     }

    zoomOut() {
        // Получаем полные данные для корректного определения центра
        const selectedDirection = this.directionSelect.value;
        const selectedPeriod = this.periodSelect.value;
        if (!selectedDirection) return;
        
        const fullData = this.getFullChartData(selectedDirection, selectedPeriod);
        if (!fullData) return;
        
        const totalCandles = fullData.candlestickData.length;
        
        // Если centerIndex не установлен, устанавливаем его в текущую позицию
        if (this.zoomState.centerIndex === null) {
            this.zoomState.centerIndex = totalCandles - Math.floor(this.zoomState.visibleCandlesCount / 2);
        }
        
        // Увеличиваем количество видимых свечей = отдаление
        const newCount = Math.min(
            this.zoomState.maxCandlesCount,
            Math.floor(this.zoomState.visibleCandlesCount * 1.4)
        );
        this.zoomState.visibleCandlesCount = newCount;
        
        // Обновляем селектор к ближайшему значению
        this.updateCandlesCountSelector(newCount);
        
        // Корректируем centerIndex чтобы не выйти за границы
        const halfVisible = Math.floor(newCount / 2);
        this.zoomState.centerIndex = Math.max(
            halfVisible,
            Math.min(totalCandles - 1 - halfVisible, this.zoomState.centerIndex)
        );
        
        this.updateChartWithZoom();
    }

     zoomOutOverall() {
         const selectedPeriod = this.periodSelect.value;
         const fullData = this.getFullChartData('ALL', selectedPeriod);
         if (!fullData) return;
         const totalCandles = fullData.candlestickData.length;
         if (this.overallZoomState.centerIndex === null) {
             this.overallZoomState.centerIndex = totalCandles - Math.floor(this.overallZoomState.visibleCandlesCount / 2);
         }
         const newCount = Math.min(this.overallZoomState.maxCandlesCount, Math.floor(this.overallZoomState.visibleCandlesCount * 1.4));
         this.overallZoomState.visibleCandlesCount = newCount;
         const halfVisible = Math.floor(newCount / 2);
         this.overallZoomState.centerIndex = Math.max(
             halfVisible,
             Math.min(totalCandles - 1 - halfVisible, this.overallZoomState.centerIndex)
         );
         this.updateOverallChart(selectedPeriod);
     }

    resetZoom() {
        // Сброс к состоянию по умолчанию - показываем последние свечи
        const selectedCount = parseInt(this.candlesCountSelect.value) || 50;
        this.zoomState.visibleCandlesCount = selectedCount;
        this.zoomState.centerIndex = null; // null означает "показать последние свечи"
        
        // Обновляем селектор если необходимо
        if (this.candlesCountSelect.value !== selectedCount.toString()) {
            this.candlesCountSelect.value = selectedCount.toString();
        }
        
        this.updateChartWithZoom();
    }

     resetZoomOverall() {
         const selectedCount = parseInt(this.candlesCountSelect.value) || 50;
         this.overallZoomState.visibleCandlesCount = selectedCount;
         this.overallZoomState.centerIndex = null;
         this.updateOverallChart(this.periodSelect.value);
     }

    // Установка количества видимых свечей
    setCandlesCount() {
        const selectedCount = parseInt(this.candlesCountSelect.value);
        if (!selectedCount || selectedCount === this.zoomState.visibleCandlesCount) return;
        
        // Получаем полные данные для корректного позиционирования
        const selectedDirection = this.directionSelect.value;
        const selectedPeriod = this.periodSelect.value;
        if (!selectedDirection) return;
        
        const fullData = this.getFullChartData(selectedDirection, selectedPeriod);
        if (!fullData) return;
        
        const totalCandles = fullData.candlestickData.length;
        
        // Сохраняем старое количество для расчета
        const oldCount = this.zoomState.visibleCandlesCount;
        this.zoomState.visibleCandlesCount = selectedCount;
        
        // Корректируем centerIndex при изменении количества свечей
        if (this.zoomState.centerIndex !== null) {
            const halfVisible = Math.floor(selectedCount / 2);
            this.zoomState.centerIndex = Math.max(
                halfVisible,
                Math.min(totalCandles - 1 - halfVisible, this.zoomState.centerIndex)
            );
        }
        
        this.updateChartWithZoom();
    }

    // Обновление графика с применением зума
    updateChartWithZoom() {
        if (this.frameScheduled) return;
        this.frameScheduled = true;
        setTimeout(() => {
            this.frameScheduled = false;
        if (!this.chart) return;
        const selectedDirection = this.directionSelect.value;
        const selectedPeriod = this.periodSelect.value;
        if (!selectedDirection) return;
        const chartData = this.getChartData(selectedDirection, selectedPeriod);
        if (!chartData) return;
        this.chart.data.datasets[0].data = chartData.candlestickData;
        this.chart.data.datasets[0].label = `${chartData.directionName} - Продуктивность`;
        this.applyCommentStyles(chartData.candlestickData);
        this.chart.update('none');
        this.updateIntervalInfo(selectedPeriod);
        this.updatePositionIndicator(chartData);
        // Обновляем бэдж оценки для выбранного направления после зума/перерисовки
        this.updatePeriodGradeBadge(selectedDirection, selectedPeriod);
        }, 0);
    }

        // НОВЫЙ МЕТОД: Обновление только данных без пересоздания графика
    updateChartDataOnly() {
        // Проверяем, находится ли пользователь в конце данных
        this.checkAndFollowNewData();
        
        // Обновляем график с учетом зума
        this.updateChartWithZoom();
    }

    // Проверка и автоследование за новыми данными
    checkAndFollowNewData() {
        // Получаем полные данные
        const selectedDirection = this.directionSelect.value;
        const selectedPeriod = this.periodSelect.value;
        if (!selectedDirection) return;
        
        const fullData = this.getFullChartData(selectedDirection, selectedPeriod);
        if (!fullData) return;
        
        const totalCandles = fullData.candlestickData.length;
        
        // Если centerIndex не установлен - пользователь смотрит на последние свечи
        if (this.zoomState.centerIndex === null) {
            return; // Уже настроено на автоследование
        }
        
        // Проверяем, близок ли пользователь к концу данных
        const halfVisible = Math.floor(this.zoomState.visibleCandlesCount / 2);
        const distanceFromEnd = totalCandles - 1 - this.zoomState.centerIndex;
        
        // Если пользователь находится очень близко к концу (в пределах половины экрана)
        // то переключаем на автоследование за новыми данными
        if (distanceFromEnd <= halfVisible) {
            this.zoomState.centerIndex = null; // Переключаем на режим "последние свечи"
        }
    }

     // Обработчик колеса мыши (зум как в TradingView)
     handleWheel(event) {
         event.preventDefault();
         
         // Получаем положение мыши на графике для определения точки зума
          const rect = this.productivityChart.getBoundingClientRect();
         const mouseX = event.clientX - rect.left;
         const chartWidth = rect.width;
         const mousePosition = mouseX / chartWidth; // От 0 до 1
         
         // Устанавливаем центр зума на основе позиции мыши
         this.setZoomCenter(mousePosition);
         
         const delta = event.deltaY;
         if (delta < 0) {
             // Прокрутка вверх = приближение
             this.zoomIn();
         } else {
             // Прокрутка вниз = отдаление
             this.zoomOut();
         }
     }

     // Обработчики для общего графика
     handleWheelOverall(event) {
         event.preventDefault();
         if (!this.overallChartCanvas || !this.overallChart) return;
         const rect = this.overallChartCanvas.getBoundingClientRect();
         const mouseX = event.clientX - rect.left;
         const chartWidth = rect.width;
         const mousePosition = mouseX / chartWidth;
         this.setZoomCenterOverall(mousePosition);
         const delta = event.deltaY;
         if (delta < 0) {
             this.zoomInOverall();
         } else {
             this.zoomOutOverall();
         }
     }

     // Установка центра зума на основе позиции мыши
     setZoomCenter(mousePosition) {
         const selectedDirection = this.directionSelect.value;
         const selectedPeriod = this.periodSelect.value;
         if (!selectedDirection) return;
         
         const fullData = this.getFullChartData(selectedDirection, selectedPeriod);
         if (!fullData) return;
         
         const totalCandles = fullData.candlestickData.length;
         
         // Если centerIndex не установлен, вычисляем текущий центр
         if (this.zoomState.centerIndex === null) {
             this.zoomState.centerIndex = totalCandles - Math.floor(this.zoomState.visibleCandlesCount / 2);
         }
         
         // Вычисляем текущие границы видимых свечей
         const halfVisible = Math.floor(this.zoomState.visibleCandlesCount / 2);
         const currentStart = Math.max(0, this.zoomState.centerIndex - halfVisible);
         const currentEnd = Math.min(totalCandles - 1, currentStart + this.zoomState.visibleCandlesCount - 1);
         
         // Вычисляем новый центр на основе позиции мыши
         const targetIndex = Math.floor(currentStart + mousePosition * (currentEnd - currentStart));
         this.zoomState.centerIndex = Math.max(
             halfVisible,
             Math.min(totalCandles - 1 - halfVisible, targetIndex)
         );
     }

     setZoomCenterOverall(mousePosition) {
         const selectedPeriod = this.periodSelect.value;
         const fullData = this.getFullChartData('ALL', selectedPeriod);
         if (!fullData) return;
         const totalCandles = fullData.candlestickData.length;
         if (this.overallZoomState.centerIndex === null) {
             this.overallZoomState.centerIndex = totalCandles - Math.floor(this.overallZoomState.visibleCandlesCount / 2);
         }
         const halfVisible = Math.floor(this.overallZoomState.visibleCandlesCount / 2);
         const currentStart = Math.max(0, this.overallZoomState.centerIndex - halfVisible);
         const currentEnd = Math.min(totalCandles - 1, currentStart + this.overallZoomState.visibleCandlesCount - 1);
         const targetIndex = Math.floor(currentStart + mousePosition * (currentEnd - currentStart));
         this.overallZoomState.centerIndex = Math.max(
             halfVisible,
             Math.min(totalCandles - 1 - halfVisible, targetIndex)
         );
     }

     // Обработчик нажатия мыши (начало прокрутки)
     handleMouseDown(event) {
         if (event.button === 0) { // Левая кнопка мыши
             this.isDragging = true;
             this.lastMouseX = event.clientX;
             this.productivityChart.style.cursor = 'grabbing';
         }
     }

     // Обработчик движения мыши (прокрутка)
     handleMouseMove(event) {
         if (!this.isDragging) return;
         
         const deltaX = event.clientX - this.lastMouseX;
         this.lastMouseX = event.clientX;
         
         // Прокрутка (pan) - смещение центрального индекса
         this.panChart(deltaX);
     }

     // Обработчик отпускания мыши
     handleMouseUp(event) {
         if (this.isDragging) {
             this.isDragging = false;
             this.productivityChart.style.cursor = 'default';
         }
     }

     // Общий график: mouse handlers
     handleMouseDownOverall(event) {
         if (event.button === 0) {
             this.isDraggingOverall = true;
             this.lastMouseXOverall = event.clientX;
             this.overallChartCanvas.style.cursor = 'grabbing';
         }
     }
     handleMouseMoveOverall(event) {
         if (!this.isDraggingOverall) return;
         const deltaX = event.clientX - this.lastMouseXOverall;
         this.lastMouseXOverall = event.clientX;
         this.panOverallChart(deltaX);
     }
     handleMouseUpOverall(event) {
         if (this.isDraggingOverall) {
             this.isDraggingOverall = false;
             this.overallChartCanvas.style.cursor = 'default';
         }
     }

     // Прокрутка графика (как в TradingView)
     panChart(deltaPixels) {
         // Конвертируем пиксели в количество свечей
         const candlesPerPixel = Math.max(0.02, this.zoomState.visibleCandlesCount / 800); // более плавная прокрутка
         const candlesDelta = Math.round(deltaPixels * candlesPerPixel);
         
         // Получаем полные данные для определения границ
         const selectedDirection = this.directionSelect.value;
         const selectedPeriod = this.periodSelect.value;
         if (!selectedDirection) return;
         
         const fullData = this.getFullChartData(selectedDirection, selectedPeriod);
         if (!fullData) return;
         
         const totalCandles = fullData.candlestickData.length;
         
         // Обновляем центральный индекс
         if (this.zoomState.centerIndex === null) {
             this.zoomState.centerIndex = totalCandles - 1;
         }
         
         const newCenterIndex = Math.max(
             Math.floor(this.zoomState.visibleCandlesCount / 2),
             Math.min(
                 totalCandles - 1 - Math.floor(this.zoomState.visibleCandlesCount / 2),
                 this.zoomState.centerIndex - candlesDelta
             )
         );
         
                   this.zoomState.centerIndex = newCenterIndex;
          this.updateChartWithZoom();
      }

      panOverallChart(deltaPixels) {
          const candlesPerPixel = Math.max(0.02, this.overallZoomState.visibleCandlesCount / 800);
          const candlesDelta = Math.round(deltaPixels * candlesPerPixel);
          const selectedPeriod = this.periodSelect.value;
          const fullData = this.getFullChartData('ALL', selectedPeriod);
          if (!fullData) return;
          const totalCandles = fullData.candlestickData.length;
          if (this.overallZoomState.centerIndex === null) {
              this.overallZoomState.centerIndex = totalCandles - 1;
          }
          const newCenterIndex = Math.max(
              Math.floor(this.overallZoomState.visibleCandlesCount / 2),
              Math.min(
                  totalCandles - 1 - Math.floor(this.overallZoomState.visibleCandlesCount / 2),
                  this.overallZoomState.centerIndex - candlesDelta
              )
          );
          this.overallZoomState.centerIndex = newCenterIndex;
          this.updateOverallChart(selectedPeriod);
      }

      // Получение текущего шага навигации
      getNavigationStep() {
          return parseInt(this.navStepSelect.value) || 5;
      }

      // Навигация влево (к более старым свечам)
      navigateLeft() {
          const step = this.getNavigationStep();
          
          // Получаем полные данные для определения границ
          const selectedDirection = this.directionSelect.value;
          const selectedPeriod = this.periodSelect.value;
          if (!selectedDirection) return;
          
          const fullData = this.getFullChartData(selectedDirection, selectedPeriod);
          if (!fullData) return;
          
          const totalCandles = fullData.candlestickData.length;
          
          // Инициализируем centerIndex если не установлен
          if (this.zoomState.centerIndex === null) {
              this.zoomState.centerIndex = totalCandles - 1;
          }
          
          // Смещаем влево (к более старым данным)
          const minCenterIndex = Math.floor(this.zoomState.visibleCandlesCount / 2);
          const newCenterIndex = Math.max(
              minCenterIndex,
              this.zoomState.centerIndex - step
          );
          
          this.zoomState.centerIndex = newCenterIndex;
          this.updateChartWithZoom();
      }

      // Навигация вправо (к более новым свечам)
      navigateRight() {
          const step = this.getNavigationStep();
          
          // Получаем полные данные для определения границ
          const selectedDirection = this.directionSelect.value;
          const selectedPeriod = this.periodSelect.value;
          if (!selectedDirection) return;
          
          const fullData = this.getFullChartData(selectedDirection, selectedPeriod);
          if (!fullData) return;
          
          const totalCandles = fullData.candlestickData.length;
          
          // Инициализируем centerIndex если не установлен
          if (this.zoomState.centerIndex === null) {
              this.zoomState.centerIndex = totalCandles - 1;
          }
          
          // Смещаем вправо (к более новым данным)
          const maxCenterIndex = totalCandles - 1 - Math.floor(this.zoomState.visibleCandlesCount / 2);
          const newCenterIndex = Math.min(
              maxCenterIndex,
              this.zoomState.centerIndex + step
          );
          
          this.zoomState.centerIndex = newCenterIndex;
          this.updateChartWithZoom();
      }

             // Навигация к последним свечам
       navigateToEnd() {
           this.zoomState.centerIndex = null; // null означает "показать последние свечи"
           this.updateChartWithZoom();
       }

       // Обработчик клавиатуры для навигации
       handleKeyDown(event) {
           // Не перехватываем клавиши при вводе в полях ввода/выбора/текстовых областях или contenteditable
           const tag = event.target.tagName;
           if (tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA' || event.target.isContentEditable) {
               return;
           }
           
           switch(event.key) {
               case 'ArrowLeft':
                   event.preventDefault();
                   this.navigateLeft();
                   break;
               case 'ArrowRight':
                   event.preventDefault();
                   this.navigateRight();
                   break;
               case 'Home':
                   event.preventDefault();
                   // Перейти к началу данных
                   this.navigateToStart();
                   break;
               case 'End':
                   event.preventDefault();
                   this.navigateToEnd();
                   break;
               case '=':
               case '+':
                   event.preventDefault();
                   this.zoomIn();
                   break;
               case '-':
                   event.preventDefault();
                   this.zoomOut();
                   break;
               case '0':
                   event.preventDefault();
                   this.resetZoom();
                   break;
           }
       }

               // Навигация к началу данных
        navigateToStart() {
            const halfVisible = Math.floor(this.zoomState.visibleCandlesCount / 2);
            this.zoomState.centerIndex = halfVisible;
            this.updateChartWithZoom();
        }

                 // Обновление индикатора позиции
         updatePositionIndicator(chartData) {
             if (!chartData || !chartData.zoomInfo || !this.positionIndicator) {
                 if (this.positionIndicator) {
                     this.positionIndicator.style.display = 'none';
                 }
                 return;
             }
             
             const { startIndex, endIndex, totalCandles, visibleCount } = chartData.zoomInfo;
             
             // Показываем индикатор только если есть зум или навигация
             if (visibleCount < totalCandles || startIndex > 0) {
                 this.positionIndicator.style.display = 'block';
                 this.positionText.textContent = 
                     `Позиция: свечи ${startIndex + 1}-${endIndex + 1} из ${totalCandles} • Зум: ${visibleCount} свечей`;
             } else {
                 this.positionIndicator.style.display = 'none';
             }
         }

         // Обновление селектора количества свечей к ближайшему значению
         updateCandlesCountSelector(targetCount) {
             const options = [10, 25, 50, 100, 200, 300, 500, 1000, 10000];
             
             // Находим ближайшее значение
             const closest = options.reduce((prev, curr) => 
                 Math.abs(curr - targetCount) < Math.abs(prev - targetCount) ? curr : prev
             );
             
             // Обновляем селектор если значение изменилось
             if (this.candlesCountSelect.value !== closest.toString()) {
                 this.candlesCountSelect.value = closest.toString();
                 // Синхронизируем внутреннее состояние с селектором
                 this.zoomState.visibleCandlesCount = closest;
             }
         }

    // Экспорт данных в JSON файл
    exportData() {
        try {
            // Подготавливаем данные для экспорта
            const exportData = {
                version: "1.1",
                exportDate: new Date().toISOString(),
                productivityData: {
                    directions: this.directions,
                    categories: this.categories,
                    trash: this.trash,
                    comments: this.loadComments(),
                    layoutMode: this.layoutMode,
                    zoomState: {
                        visibleCandlesCount: this.zoomState.visibleCandlesCount
                    },
                    tasks: this.tasks,
                    tasksPlacement: (() => { try { return localStorage.getItem(this.getStorageKey('productivityTasksPlacement')) || this.tasksPlacementSelect?.value || 'top'; } catch(_) { return 'top'; } })(),
                    draft: this.loadDraft(),
                    tasksHistory: this.loadTasksHistory()
                }
            };

            // Создаем JSON строку
            const jsonString = JSON.stringify(exportData, null, 2);
            
            // Создаем blob и ссылку для скачивания
            const blob = new Blob([jsonString], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            
            // Создаем временную ссылку для скачивания
            const link = document.createElement('a');
            link.href = url;
            
            // Генерируем имя файла с датой
            const now = new Date();
            const dateStr = now.toISOString().slice(0, 10); // YYYY-MM-DD
            const timeStr = now.toTimeString().slice(0, 5).replace(':', '-'); // HH-MM
            link.download = `productivity-tracker-${dateStr}-${timeStr}.json`;
            
            // Добавляем в DOM, кликаем и удаляем
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            // Освобождаем память
            URL.revokeObjectURL(url);
            
            this.showNotification('Данные успешно экспортированы!', 'success');
        } catch (error) {
            console.error('Ошибка экспорта:', error);
            this.showNotification('Ошибка при экспорте данных', 'error');
        }
    }

    // Импорт данных из JSON файла
    importData(event) {
        const file = event.target.files[0];
        if (!file) return;

        // Проверяем тип файла
        if (!file.name.endsWith('.json')) {
            this.showNotification('Пожалуйста, выберите JSON файл', 'error');
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const jsonData = JSON.parse(e.target.result);
                
                // Валидация структуры данных
                if (!this.validateImportData(jsonData)) {
                    this.showNotification('Неверный формат файла данных', 'error');
                    return;
                }

                // Подтверждение импорта
                const confirmImport = confirm(
                    'Импорт данных заменит все текущие направления и их историю. ' +
                    'Вы уверены, что хотите продолжить?'
                );

                if (!confirmImport) {
                    return;
                }

                const data = jsonData.productivityData || {};
                // Импортируем данные
                this.directions = Array.isArray(data.directions) ? data.directions : [];
                this.categories = Array.isArray(data.categories) && data.categories.length ? data.categories : (this.categories || []);
                this.trash = data.trash && typeof data.trash === 'object' ? data.trash : (this.trash || { directions: [], categories: [] });
                if (data.comments && typeof data.comments === 'object') {
                    this.saveComments(data.comments);
                }
                if (data.layoutMode === 'compact' || data.layoutMode === 'horizontal') {
                    this.layoutMode = data.layoutMode;
                    this.saveLayoutMode();
                }
                // Восстанавливаем настройки зума если есть
                if (data.zoomState && data.zoomState.visibleCandlesCount) {
                    this.zoomState.visibleCandlesCount = data.zoomState.visibleCandlesCount;
                    if (this.candlesCountSelect) this.candlesCountSelect.value = data.zoomState.visibleCandlesCount.toString();
                }

                // Сбрасываем позицию для показа последних данных
                this.zoomState.centerIndex = null;

                // Восстановим задачи/размещение/черновик/историю
                if (data.tasks && typeof data.tasks === 'object') {
                    this.tasks = data.tasks;
                    this.saveTasks();
                    this.renderTasksWeek();
                }
                if (data.tasksPlacement) {
                    try { localStorage.setItem(this.getStorageKey('productivityTasksPlacement'), data.tasksPlacement); } catch(_) {}
                    if (this.tasksPlacementSelect) this.tasksPlacementSelect.value = data.tasksPlacement;
                    this.applyTasksPlacement();
                }
                if (typeof data.draft === 'string') {
                    this.saveDraft(data.draft, /*silent*/true);
                    this.updateDraftUI();
                }
                if (Array.isArray(data.tasksHistory)) {
                    this.saveTasksHistory(data.tasksHistory);
                }

                // Сохраняем в localStorage
                this.saveDirections();
                this.saveCategories();
                this.saveTrash();
                
                // Обновляем интерфейс
                this.render();
                this.applyLayoutClass();
                this.updateDetailCategorySelectIfOpen();
                this.updateDirectionSelect();
                this.updateChart();

                this.showNotification(
                    `Импорт завершён: направлений ${this.directions.length}`, 
                    'success'
                );

            } catch (error) {
                console.error('Ошибка импорта:', error);
                this.showNotification('Ошибка при чтении файла данных', 'error');
            } finally {
                // Очищаем input для возможности повторного выбора того же файла
                event.target.value = '';
            }
        };

        reader.readAsText(file);
    }

    // Очистка всех значений (всех направлений)
    clearAllValues() {
        if (!confirm('Очистить ВСЕ значения у всех направлений? Это действие необратимо.')) return;
        // Очищаем в активных направлениях
        this.directions.forEach(d => { d.scores = []; d.totalScore = 0; });
        // Очищаем в корзине у направлений (чтобы общий график тоже обнулился)
        if (this.trash && Array.isArray(this.trash.directions)) {
            this.trash.directions.forEach(d => { d.scores = []; d.totalScore = 0; });
        }
        // Инвалидируем кеш
        this.candlesCache.clear();
        // Сохранить
        this.saveDirections();
        this.saveTrash();
        // Обновить UI
        this.renderDirectionsOnly();
        this.updateChart();
        this.updateOverallChart();
        this.showNotification('Все значения очищены', 'success');
    }

    // Очистка всех значений выбранного направления
    clearAllScoresOfCurrentDirection() {
        const dir = this.getFreshCurrentDetailDirection();
        if (!dir) return;
        if (!confirm(`Очистить все значения у направления "${dir.name}"?`)) return;
        dir.scores = [];
        dir.totalScore = 0;
        // Инвалидируем кеш
        this.candlesCache.clear();
        // Сохранить и обновить
        this.saveDirections();
        this.renderDirectionsOnly();
        // Обновляем детальную панель счёт
        const totalScore = 0;
        const scoreClass = 'score-neutral';
        this.detailDirectionScore.textContent = `Общий счёт: 0 баллов`;
        this.detailDirectionScore.className = `detail-direction-score ${scoreClass}`;
        // Обновление графиков
        this.updateChart();
        this.updateOverallChart();
        this.showNotification('Значения направления очищены', 'success');
    }

    // Валидация импортируемых данных
    validateImportData(data) {
        // Базовая структура
        if (!data || typeof data !== 'object') return false;
        if (!data.productivityData || typeof data.productivityData !== 'object') return false;

        const pd = data.productivityData;
        // directions обязательно
        if (!Array.isArray(pd.directions)) return false;
        for (const direction of pd.directions) {
            if (!direction || typeof direction !== 'object') return false;
            if (!direction.id || !direction.name || !direction.createdAt) return false;
            if (!Array.isArray(direction.scores)) return false;
            for (const score of direction.scores) {
                if (!score || typeof score !== 'object') return false;
                if (typeof score.value !== 'number' || !score.date) return false;
            }
        }
        // Остальное — опционально (categories, trash, comments, layoutMode, zoomState)
        return true;
    }

    // Корзина: хранение и операции
    loadTrash() {
        try { return JSON.parse(localStorage.getItem('productivityTrash') || '{"directions":[],"categories":[]}'); } catch(_) { return { directions: [], categories: [] }; }
    }
    saveTrash() {
        try { localStorage.setItem(this.getStorageKey('productivityTrash'), JSON.stringify(this.trash)); } catch(_) {}
        if (this.currentUser) this.scheduleCloudSave(0);
    }

    // ===== Черновик =====
    loadDraft() {
        try {
            const keyed = localStorage.getItem(this.getStorageKey('productivityDraft'));
            const plain = localStorage.getItem('productivityDraftPlain');
            return keyed ?? plain ?? '';
        } catch(_) { return ''; }
    }
    saveDraft(value, silent = false) {
        const text = typeof value === 'string' ? value : (this.draftText?.value || '');
        try {
            localStorage.setItem(this.getStorageKey('productivityDraft'), text);
            localStorage.setItem('productivityDraftPlain', text);
        } catch(_) {}
        if (!silent) this.showNotification('Черновик сохранён', 'success');
        if (this.currentUser) this.scheduleCloudSave(300);
    }
    clearDraft() {
        if (!confirm('Очистить черновик?')) return;
        try { localStorage.removeItem(this.getStorageKey('productivityDraft')); } catch(_) {}
        if (this.draftText) this.draftText.value = '';
        this.showNotification('Черновик очищен', 'success');
    }
    openDraft() {
        if (!this.draftModal) return;
        if (this.draftText) this.draftText.value = this.loadDraft();
        this.draftModal.style.display = 'flex';
    }
    closeDraft() { if (this.draftModal) this.draftModal.style.display = 'none'; }
    updateDraftUI() { if (this.draftText) this.draftText.value = this.loadDraft(); }
    addToTrash(entry) {
        if (!this.trash) this.trash = { directions: [], categories: [] };
        if (entry.type === 'direction') {
            // помечаем временем удаления
            this.trash.directions.push({ ...entry.item, _deletedAt: Date.now() });
        } else if (entry.type === 'category') {
            this.trash.categories.push({ ...entry.item, _deletedAt: Date.now() });
        }
        this.saveTrash();
    }
    openTrash() {
        if (!this.trash) this.trash = { directions: [], categories: [] };
        // Заполнить списки
        if (this.trashDirectionsList) {
            this.trashDirectionsList.innerHTML = '';
            this.trash.directions
                .sort((a,b) => (b._deletedAt||0)-(a._deletedAt||0))
                .forEach(dir => this.trashDirectionsList.appendChild(this.renderTrashItem(dir, 'direction')));
        }
        if (this.trashCategoriesList) {
            this.trashCategoriesList.innerHTML = '';
            this.trash.categories
                .sort((a,b) => (b._deletedAt||0)-(a._deletedAt||0))
                .forEach(cat => this.trashCategoriesList.appendChild(this.renderTrashItem(cat, 'category')));
        }
        if (this.trashModal) this.trashModal.style.display = 'flex';
    }
    closeTrash() { if (this.trashModal) this.trashModal.style.display = 'none'; }
    emptyTrash() {
        if (!confirm('Очистить корзину без возможности восстановления?')) return;
        this.trash = { directions: [], categories: [] };
        this.saveTrash();
        this.openTrash();
        this.showNotification('Корзина очищена', 'success');
    }
    renderTrashItem(item, type) {
        const el = document.createElement('div');
        el.className = 'trash-item';
        const title = document.createElement('div');
        title.className = 'trash-item-title';
        title.textContent = type === 'direction' ? (item.name || 'Без названия') : `${item.icon||''} ${item.name}`;
        const meta = document.createElement('div');
        meta.className = 'trash-item-meta';
        const date = item._deletedAt ? new Date(item._deletedAt).toLocaleString('ru-RU') : '';
        meta.textContent = `Удалено: ${date}`;
        const actions = document.createElement('div');
        actions.className = 'trash-actions';
        const restoreBtn = document.createElement('button');
        restoreBtn.className = 'restore-button';
        restoreBtn.innerHTML = '<i class="fas fa-undo"></i> Восстановить';
        restoreBtn.addEventListener('click', () => this.restoreFromTrash(item, type));
        const removeBtn = document.createElement('button');
        removeBtn.className = 'remove-button';
        removeBtn.innerHTML = '<i class="fas fa-times"></i> Удалить навсегда';
        removeBtn.addEventListener('click', () => this.removeFromTrash(item, type));
        actions.appendChild(restoreBtn);
        actions.appendChild(removeBtn);
        el.appendChild(title); el.appendChild(meta); el.appendChild(actions);
        return el;
    }
    restoreFromTrash(item, type) {
        if (type === 'direction') {
            // избегаем дубликатов по id
            if (!this.directions.find(d => d.id === item.id)) {
                this.directions.push({ ...item });
                this.saveDirections();
                this.updateDirectionSelect();
                this.renderDirectionsOnly();
            }
            this.trash.directions = this.trash.directions.filter(d => d.id !== item.id);
        } else if (type === 'category') {
            if (!this.categories.find(c => c.id === item.id)) {
                this.categories.push({ ...item });
                this.saveCategories();
                this.updateDetailCategorySelectIfOpen();
                this.renderDirectionsOnly();
            }
            this.trash.categories = this.trash.categories.filter(c => c.id !== item.id);
        }
        this.saveTrash();
        this.openTrash();
        this.showNotification('Восстановлено из корзины', 'success');
    }
    removeFromTrash(item, type) {
        if (type === 'direction') {
            this.trash.directions = this.trash.directions.filter(d => d.id !== item.id);
        } else if (type === 'category') {
            this.trash.categories = this.trash.categories.filter(c => c.id !== item.id);
        }
        this.saveTrash();
        this.openTrash();
        this.showNotification('Удалено навсегда', 'success');
    }

    // Открытие детальной панели для направления
    openDetailView(directionId) {
        const direction = this.directions.find(d => d.id == directionId);
        if (!direction) return;

        this.currentDetailDirection = direction;
        
        // Заполняем данные в детальной панели
        this.detailDirectionName.textContent = direction.name;
        
        const totalScore = direction.totalScore || 0;
        const scoreClass = totalScore > 0 ? 'score-positive' : totalScore < 0 ? 'score-negative' : 'score-neutral';
        const scoreText = totalScore > 0 ? `+${totalScore}` : totalScore.toString();
        this.detailDirectionScore.textContent = `Общий счёт: ${scoreText} баллов`;
        this.detailDirectionScore.className = `detail-direction-score ${scoreClass}`;
        
        // Заполняем селектор категорий
        this.detailCategorySelect.innerHTML = this.getCategoryOptions(direction.category);
        
        // Очищаем поле ввода баллов
        this.detailScoreInput.value = '';

        // Подставляем описание
        if (this.detailDescriptionInput) {
            this.detailDescriptionInput.value = direction.description || '';
        }
        // Применяем сохранённый цвет описания, если есть
        if (this.detailDescriptionColor) {
            const color = (direction.descriptionColor || '#111111');
            this.detailDescriptionColor.value = color;
            if (this.detailDescriptionInput) this.detailDescriptionInput.style.color = color;
        }

        // Подсветка выбранного цвета
        this.updateColorPickerUI(direction.color);

        // кастом-стиль удалён — ничего не подставляем
        
        // Показываем панель
        this.directionDetailPanel.style.display = 'block';
        
        // Показываем основной график
        this.chartSection.style.display = 'block';
        
        // Обновляем основной график для выбранного направления
        this.directionSelect.value = direction.id;
        this.updateChart();

        // Заполняем UI настроек начисления и предпросмотр
        this.renderScoringMetricsUI(direction);
        this.renderSessionInputsUI(direction);
        this.updateCalcPreview();

        // Обновим среднюю оценку по направлению (если есть оценки в meta)
        this.updateDirectionAvgGrade(direction);
    }

    // Закрытие детальной панели
    closeDetailView() {
        this.directionDetailPanel.style.display = 'none';
        this.currentDetailDirection = null;
        
        // Скрываем основной график
        this.chartSection.style.display = 'none';
        // Скрываем общий график
        if (this.overallChartSection) this.overallChartSection.style.display = 'none';
    }

    // Сохранение описания из детальной панели
    saveDetailDescription() {
        const dir = this.getFreshCurrentDetailDirection();
        if (!dir || !this.detailDescriptionInput) return;
        const value = (this.detailDescriptionInput.value || '').trim();
        dir.description = value;
        if (this.detailDescriptionColor) {
            dir.descriptionColor = this.detailDescriptionColor.value || '#111111';
        }
        this.saveDirections();
        this.showNotification('Описание сохранено', 'success');
    }

    // Мгновенное применение цвета к textarea
    applyDescriptionColorLive() {
        if (!this.detailDescriptionInput || !this.detailDescriptionColor) return;
        const color = this.detailDescriptionColor.value || '#111111';
        this.detailDescriptionInput.style.color = color;
    }

    // Выбор цвета напрямую
    handleColorPick(e) {
        const btn = e.target.closest('.color-chip');
        const dir = this.getFreshCurrentDetailDirection();
        if (!btn || !dir) return;
        const color = btn.getAttribute('data-color');
        dir.color = color;
        this.saveDirections();
        this.updateColorPickerUI(color);
        this.renderDirectionsOnly();
        // Обновляем отображение процента под карточкой
        this.updateDirectionPercentInList(dir.id);
    }

    // Быстрый выбор по процентам (маппинг процентов к цветам)
    // percent picker удалён

    updateDirectionPercentInList(directionId) {
        const node = this.directionsList?.querySelector(`.direction-item[data-id="${directionId}"] .direction-percent`);
        if (!node) return;
        const dir = this.directions.find(d => d.id === directionId);
        node.textContent = this.getDirectionPercentText(dir?.color);
    }

    // кастом-стили удалены

    updateColorPickerUI(selectedColor) {
        if (!this.detailColorPicker) return;
        this.detailColorPicker.querySelectorAll('.color-chip').forEach(el => {
            el.classList.toggle('selected', el.getAttribute('data-color') === selectedColor);
        });
    }

    getDirectionPercentText(color) {
        switch(color) {
            case 'red': return '0%';
            case 'yellow': return '50%';
            case 'green': return '100%';
            case 'blue': return '100%+';
            case 'orange': return '30-50%';
            case 'purple': return '';
            default: return '';
        }
    }



    // Изменение категории в детальной панели
    changeDetailDirectionCategory() {
        const dir = this.getFreshCurrentDetailDirection();
        if (!dir) return;

        const newCategory = this.detailCategorySelect.value;
        dir.category = newCategory;
        this.saveDirections();
        this.render(); // Перерисовываем основной список
        
        const categoryName = this.categories.find(c => c.id === newCategory)?.name || newCategory;
        this.showNotification(`"${dir.name}" перемещено в "${categoryName}"`, 'success');
    }

    // Добавление баллов в детальной панели
    addDetailScore() {
        const dir = this.getFreshCurrentDetailDirection();
        if (!dir) return;

        const scoreValue = parseFloat(this.detailScoreInput.value);
        if (isNaN(scoreValue) || scoreValue === 0) {
            this.showNotification('Введите корректное значение баллов', 'error');
            return;
        }

        // Добавляем новый балл
        const newScore = {
            value: scoreValue,
            date: new Date().toISOString(),
            timestamp: Date.now()
        };
        
        dir.scores.push(newScore);
        dir.totalScore = (dir.totalScore || 0) + scoreValue;
        
        this.saveDirections();
        this.renderDirectionsOnly(); // Обновляем только список
        
        // Обновляем отображение в детальной панели
        const totalScore = dir.totalScore || 0;
        const scoreClass = totalScore > 0 ? 'score-positive' : totalScore < 0 ? 'score-negative' : 'score-neutral';
        const scoreText = totalScore > 0 ? `+${totalScore}` : totalScore.toString();
        this.detailDirectionScore.textContent = `Общий счёт: ${scoreText} баллов`;
        this.detailDirectionScore.className = `detail-direction-score ${scoreClass}`;
        
        // Обновляем основной график (сохраняя выбор направления)
        this.updateChart();
        
        // Очищаем поле ввода
        this.detailScoreInput.value = '';
        
        const action = scoreValue > 0 ? 'добавлены' : 'вычтены';
        const absValue = Math.abs(scoreValue);
        this.showNotification(`${absValue} баллов ${action} к "${dir.name}"`, 'success');
    }

    // Удаление направления из детальной панели
    deleteDetailDirection() {
        const dir = this.getFreshCurrentDetailDirection();
        if (!dir) return;

        if (confirm(`Вы уверены, что хотите удалить направление "${dir.name}"?`)) {
            const directionName = dir.name;
            // В корзину перед удалением
            this.addToTrash({ type: 'direction', item: dir });
            this.directions = this.directions.filter(d => d.id !== dir.id);
            this.saveDirections();
            this.render();
            this.updateDirectionSelect();
            this.closeDetailView();
            this.showNotification(`Направление "${directionName}" удалено`, 'success');
        }
    }
}

// Инициализация трекера при загрузке страницы
let tracker;
document.addEventListener('DOMContentLoaded', () => {
    tracker = new ProductivityTracker();
    tracker.updateDirectionSelect();
    // Делаем tracker доступным глобально для коллбеков зума
    window.tracker = tracker;
});
