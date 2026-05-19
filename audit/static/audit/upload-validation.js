/**
 * Client-side upload filename checks (mirrors audit.upload_validation).
 */
(function (global) {
    const BLOCKED = new Set([
        '7z', 'app', 'asp', 'aspx', 'bash', 'bat', 'bin', 'bz2', 'cmd', 'com', 'cpl', 'csh',
        'deb', 'dll', 'dmg', 'exe', 'gz', 'hta', 'htm', 'html', 'img', 'inf', 'iso', 'jar',
        'js', 'jse', 'jsp', 'ksh', 'lnk', 'msi', 'msp', 'msu', 'php', 'phtml', 'pkg', 'pl',
        'ps1', 'psm1', 'py', 'pyc', 'rar', 'rb', 'reg', 'rpm', 'run', 'scr', 'sh', 'svg',
        'tar', 'vbe', 'vbs', 'wsf', 'wsh', 'xhtml', 'xml', 'zsh',
    ]);

    function extensions(filename) {
        const name = (filename || '').split(/[/\\]/).pop() || '';
        if (!name || name.startsWith('.')) {
            return [];
        }
        const parts = name.split('.');
        if (parts.length < 2) {
            return [];
        }
        return parts.slice(1).map((p) => p.toLowerCase()).filter(Boolean);
    }

    function validateUploadFilename(filename, rules) {
        const allowed = new Set(rules.allowed || []);
        const label = rules.label || 'file';
        const allowedList = [...allowed].sort().map((e) => `.${e}`).join(', ');

        if (!filename || !String(filename).trim()) {
            return { ok: false, message: 'No file selected.' };
        }

        const base = (filename || '').split(/[/\\]/).pop() || '';
        if (base.startsWith('.')) {
            return { ok: false, message: 'Hidden files are not accepted.' };
        }

        const exts = extensions(base);
        if (!exts.length) {
            return { ok: false, message: `Only ${allowedList} files are accepted.` };
        }

        const blocked = exts.filter((e) => BLOCKED.has(e));
        if (blocked.length) {
            return {
                ok: false,
                message: `File type not permitted (${blocked.map((e) => `.${e}`).join(', ')}). Upload ${allowedList} only.`,
            };
        }

        const finalExt = exts[exts.length - 1];
        if (!allowed.has(finalExt)) {
            return {
                ok: false,
                message: `Only ${allowedList} files are accepted (got .${finalExt}).`,
            };
        }

        return { ok: true, message: null };
    }

    function applyAcceptAttribute(input, rules) {
        if (input && rules && rules.accept) {
            input.setAttribute('accept', rules.accept);
        }
    }

    function showFileError(container, message) {
        let el = container.querySelector('.file-type-error');
        if (!el) {
            el = document.createElement('div');
            el.className = 'file-type-error';
            el.setAttribute('role', 'alert');
            container.appendChild(el);
        }
        el.textContent = message;
        el.hidden = false;
    }

    function clearFileError(container) {
        const el = container.querySelector('.file-type-error');
        if (el) {
            el.hidden = true;
            el.textContent = '';
        }
    }

    function rejectFileInput(input, container) {
        if (input) {
            input.value = '';
        }
        const nameEl = container.querySelector('.file-name');
        if (nameEl) {
            nameEl.textContent = '';
        }
        const label = container.querySelector('.file-upload-label');
        if (label) {
            label.classList.remove('has-file');
        }
        setFileClearVisible(container, false);
    }

    function setFileClearVisible(container, visible) {
        const btn = container.querySelector('.file-clear-btn');
        if (btn) {
            btn.hidden = !visible;
        }
    }

    function clearFileSelection(container) {
        const input = container.querySelector('input[type="file"]');
        clearFileError(container);
        rejectFileInput(input, container);
    }

    global.AuditUploadValidation = {
        validateUploadFilename,
        applyAcceptAttribute,
        showFileError,
        clearFileError,
        rejectFileInput,
        setFileClearVisible,
        clearFileSelection,
    };
})(window);
