'use strict';

// to add a language: drop i18n/<code>.json, add the code here and a flag button in index.html
const SUPPORTED = ['en', 'fr'];
const DEFAULT_LANG = 'en';
const STORAGE_KEY = 'hush.lang';

const dictionaries = {};
let lang = DEFAULT_LANG;

// stored choice first, then the browser's languages by primary subtag (fr-CA -> fr), then English
function detectLanguage(stored, languages) {
    if (SUPPORTED.includes(stored)) return stored;
    for (const tag of languages || []) {
        const primary = String(tag).toLowerCase().split('-')[0];
        if (SUPPORTED.includes(primary)) return primary;
    }
    return DEFAULT_LANG;
}

function currentLanguage() {
    return lang;
}

function readStoredLanguage() {
    try {
        return localStorage.getItem(STORAGE_KEY);
    } catch { // storage blocked (privacy settings): fall back to detection
        return null;
    }
}

function storeLanguage(value) {
    try {
        localStorage.setItem(STORAGE_KEY, value);
    } catch { /* storage blocked: the choice only lasts for this page */ }
}

async function loadDictionary(code) {
    if (dictionaries[code]) return true;
    try {
        const res = await fetch(`/i18n/${code}.json`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        dictionaries[code] = await res.json();
        return true;
    } catch (err) {
        console.error(`[i18n] cannot load ${code}`, err);
        return false;
    }
}

function lookup(key) {
    const find = (dict) => key.split('.').reduce((node, part) => node?.[part], dict);
    return find(dictionaries[lang]) ?? find(dictionaries[DEFAULT_LANG]);
}

// missing key: current language -> English -> the key itself
function t(key, params = {}) {
    let value = lookup(key);
    if (value && typeof value === 'object' && typeof params.count === 'number') {
        value = lookup(`${key}.${new Intl.PluralRules(lang).select(params.count)}`) ?? lookup(`${key}.other`);
    }
    if (typeof value !== 'string') {
        console.warn(`[i18n] missing key: ${key}`);
        return key;
    }
    return value.replace(/\{(\w+)}/g, (match, name) => {
        const param = params[name];
        if (param === undefined) return match;
        return typeof param === 'number' ? param.toLocaleString(lang) : String(param);
    });
}

// remembers key + params on the element so a language switch re-translates it in place
function setText(el, key, params) {
    if (key === null) {
        delete el.dataset.i18n;
        delete el.dataset.i18nParams;
        el.textContent = '';
        return;
    }
    el.dataset.i18n = key;
    if (params) el.dataset.i18nParams = JSON.stringify(params);
    else delete el.dataset.i18nParams;
    el.textContent = t(key, params);
}

function formatDate(iso) {
    return new Intl.DateTimeFormat(lang, {dateStyle: 'full', timeStyle: 'short'}).format(new Date(iso));
}

function applyTranslations() {
    document.documentElement.lang = lang;
    document.title = t('meta.title');
    document.querySelectorAll('[data-i18n]').forEach(el => {
        el.textContent = t(el.dataset.i18n, el.dataset.i18nParams ? JSON.parse(el.dataset.i18nParams) : undefined);
    });
    // innerHTML is safe here: the text only ever comes from our own same-origin JSON, never from user data
    document.querySelectorAll('[data-i18n-html]').forEach(el => el.innerHTML = t(el.dataset.i18nHtml));
    document.querySelectorAll('[data-i18n-attr]').forEach(el => {
        el.dataset.i18nAttr.split(';').forEach(pair => {
            const [attr, key] = pair.split(':').map(s => s.trim());
            el.setAttribute(attr, t(key));
        });
    });
    document.querySelectorAll('time[data-date]').forEach(el => {
        if (el.dateTime) el.textContent = formatDate(el.dateTime);
    });
    document.querySelectorAll('[data-lang]').forEach(button => {
        button.setAttribute('aria-pressed', String(button.dataset.lang === lang));
    });
}

async function setLanguage(code) {
    if (!SUPPORTED.includes(code) || !await loadDictionary(code)) return;
    lang = code;
    storeLanguage(code);
    applyTranslations();
}

async function initI18n() {
    try {
        const languages = navigator.languages?.length ? navigator.languages : [navigator.language || ''];
        lang = detectLanguage(readStoredLanguage(), languages);
        const [loaded] = await Promise.all([loadDictionary(lang), loadDictionary(DEFAULT_LANG)]);
        if (!loaded) lang = DEFAULT_LANG;
        applyTranslations();
    } finally {
        document.documentElement.classList.remove('i18n-pending'); // never leave the page hidden
    }
}

document.addEventListener('click', (event) => {
    const button = event.target.closest('[data-lang]');
    if (button) setLanguage(button.dataset.lang);
});
