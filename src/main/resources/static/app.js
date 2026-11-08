'use strict';

const MAX_LENGTH = 10000;
const $ = (id) => document.getElementById(id);
const dateFormat = new Intl.DateTimeFormat('fr-FR', {dateStyle: 'full', timeStyle: 'short'});
const views = ['view-create', 'view-created', 'view-open'];

// the server answers the same way for unknown, expired and already read secrets, so does the UI
const UNAVAILABLE = {icon: '?', title: 'Secret indisponible',
    text: "Ce lien n'existe pas, a expiré ou a déjà été ouvert. Vérifiez que le lien est complet ; si vous ne l'avez " +
        "pas ouvert vous-même, prévenez l'expéditeur."};
const DESTROYED = {icon: '✕', title: 'Secret détruit',
    text: "Trop d'essais incorrects : ce secret a été définitivement détruit. Prévenez l'expéditeur."};

class ApiError extends Error {
    constructor(status, body) {
        super(body?.errorMessage || `HTTP ${status}`);
        this.status = status;
        this.body = body;
    }
}

async function api(method, path, body) {
    let res;
    try {
        res = await fetch('/api/secrets' + path, {
            method,
            headers: body ? {'Content-Type': 'application/json'} : {},
            body: body ? JSON.stringify(body) : undefined
        });
    } catch {
        throw new ApiError(0, null); // network down / server unreachable
    }
    const data = await res.json().catch(() => null);
    if (!res.ok) throw new ApiError(res.status, data);
    return data;
}

// --- UI helpers ---

function show(viewId) {
    views.forEach(v => $(v).hidden = v !== viewId);
    hideBanner();
}

function showBanner(message) {
    $('banner').textContent = message;
    $('banner').hidden = false;
}

function hideBanner() {
    $('banner').hidden = true;
}

let toastTimer;
function toast(message) {
    const el = $('toast');
    el.textContent = message;
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), 2000);
}

function setLoading(button, loading) {
    button.disabled = loading;
    button.classList.toggle('loading', loading);
}

function genericError(err) {
    if (err.status === 0) return 'Impossible de joindre le serveur. Vérifiez votre connexion puis réessayez.';
    if (err.status === 429) return 'Trop de requêtes. Patientez quelques instants puis réessayez.';
    if (err.status >= 500) return 'Le service est momentanément indisponible. Réessayez dans quelques instants.';
    return 'Une erreur inattendue est survenue (' + err.status + ').';
}

// --- Create ---

function updateCounter() {
    const length = $('secret-text').value.length;
    const counter = $('counter');
    counter.textContent = `${length.toLocaleString('fr-FR')} / ${MAX_LENGTH.toLocaleString('fr-FR')}`;
    counter.classList.toggle('over', length > MAX_LENGTH);
    $('create-btn').disabled = $('secret-text').value.trim() === '' || length > MAX_LENGTH;
}

function clearFieldErrors() {
    document.querySelectorAll('.field-error').forEach(el => el.textContent = '');
    document.querySelectorAll('.invalid').forEach(el => el.classList.remove('invalid'));
}

function showFieldErrors(errors) {
    const fields = {secretText: $('secret-text'), ttlSeconds: $('ttl'), passphrase: $('passphrase')};
    let shown = false;
    for (const [field, message] of Object.entries(errors || {})) {
        const errorEl = $(field + '-error');
        if (!errorEl) continue;
        errorEl.textContent = message;
        fields[field]?.classList.add('invalid');
        shown = true;
    }
    if (!shown) showBanner('La requête est invalide. Vérifiez le formulaire.');
}

function syncProtect() {
    const on = $('protect').checked;
    $('passphrase-field').hidden = !on;
    if (!on) $('passphrase').value = '';
}

function resetCreate() {
    $('create-form').reset();
    syncProtect();
    clearFieldErrors();
    updateCounter();
    show('view-create');
    $('secret-text').focus();
}

async function onCreate(event) {
    event.preventDefault();
    clearFieldErrors();
    hideBanner();
    // never silently create an unprotected secret when the box is ticked
    const passphrase = $('protect').checked ? $('passphrase').value : null;
    if (passphrase === '') {
        showFieldErrors({passphrase: 'Saisissez une phrase secrète ou décochez la protection.'});
        $('passphrase').focus();
        return;
    }
    const button = $('create-btn');
    setLoading(button, true);
    try {
        const created = await api('POST', '', {
            secretText: $('secret-text').value,
            ttlSeconds: Number($('ttl').value),
            passphrase // sent as typed: the server compares it exactly
        });
        $('create-form').reset(); // don't keep the secret (nor its passphrase) in the page
        syncProtect();
        $('created-protected').hidden = !created.passphraseProtected;
        $('share-link').value = `${location.origin}/s/${created.secretId}`;
        $('expires-at').textContent = dateFormat.format(new Date(created.expiresAt));
        $('expires-at').dateTime = created.expiresAt;
        show('view-created');
        $('share-link').select();
    } catch (err) {
        if (err.status === 400) {
            // the server's only passphrase rule a user can hit is the length (a password field drops line breaks)
            if (err.body?.passphrase) err.body.passphrase = 'Phrase trop longue (72 octets maximum).';
            showFieldErrors(err.body);
        }
        else showBanner(genericError(err));
    } finally {
        setLoading(button, false);
        updateCounter();
    }
}

// --- Open / reveal ---

function showOpenState(state) {
    ['open-loading', 'open-ready', 'open-revealed', 'open-error'].forEach(id => $(id).hidden = id !== state);
}

function showOpenError({icon, title, text}) {
    $('error-icon').textContent = icon;
    $('error-title').textContent = title;
    $('error-text').textContent = text;
    showOpenState('open-error');
}

function showUnavailable() {
    showOpenError(UNAVAILABLE);
}

function updateRevealButton() {
    $('reveal-btn').disabled = !$('reveal-passphrase-field').hidden && $('reveal-passphrase').value === '';
}

async function openSecret(id) {
    show('view-open');
    showOpenState('open-loading');
    try {
        const meta = await api('GET', '/' + encodeURIComponent(id));
        $('open-expires-at').textContent = dateFormat.format(new Date(meta.expiresAt));
        $('open-expires-at').dateTime = meta.expiresAt;
        $('reveal-passphrase-field').hidden = !meta.passphraseProtected;
        $('reveal-passphrase').value = '';
        $('reveal-passphrase-error').textContent = '';
        updateRevealButton();
        showOpenState('open-ready');
        $('reveal-form').onsubmit = (event) => {
            event.preventDefault();
            if (!$('reveal-btn').disabled) reveal(id);
        };
        if (meta.passphraseProtected) $('reveal-passphrase').focus();
    } catch (err) {
        if (err.status === 404) return showUnavailable();
        showOpenState(null);
        showBanner(genericError(err));
        showRetry(() => openSecret(id));
    }
}

function showRetry(retry) {
    const banner = $('banner');
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'btn btn-secondary';
    button.textContent = 'Réessayer';
    button.onclick = retry;
    banner.append(document.createElement('br'), button);
}

async function reveal(id) {
    const button = $('reveal-btn');
    const input = $('reveal-passphrase');
    setLoading(button, true);
    hideBanner();
    try {
        const body = $('reveal-passphrase-field').hidden ? undefined : {passphrase: input.value};
        const {secretText} = await api('POST', '/' + encodeURIComponent(id) + '/reveal', body);
        input.value = '';
        $('secret-content').textContent = secretText; // textContent: never interpret the secret as HTML
        showOpenState('open-revealed');
        $('secret-content').focus();
    } catch (err) {
        if (err.status === 404) return showUnavailable();
        const left = err.body?.attemptsRemaining;
        // a 403 without our body (proxy, WAF...) says nothing about the secret: generic error, not "destroyed"
        if (err.status === 403 && typeof left === 'number') {
            input.value = '';
            if (left === 0) return showOpenError(DESTROYED);
            $('reveal-passphrase-error').textContent =
                `Phrase secrète incorrecte. Il vous reste ${left} essai${left > 1 ? 's' : ''}.`;
            input.classList.add('invalid');
            input.focus();
            return;
        }
        showBanner(genericError(err)); // secret not consumed: the button stays usable
    } finally {
        setLoading(button, false);
        updateRevealButton();
    }
}

// --- Copy ---

async function copyFrom(targetId) {
    const el = $(targetId);
    const text = 'value' in el ? el.value : el.textContent;
    try {
        await navigator.clipboard.writeText(text);
        toast('Copié dans le presse-papiers ✓');
    } catch {
        // clipboard API needs HTTPS or localhost: fall back to selecting the text
        if (el.select) el.select();
        else getSelection().selectAllChildren(el);
        toast('Appuyez sur Ctrl+C pour copier');
    }
}

// --- Routing ---

function route() {
    const match = location.pathname.match(/^\/s\/([^/]+)\/?$/);
    if (!match) return resetCreate();
    let id;
    try {
        id = decodeURIComponent(match[1]);
    } catch { // truncated or mangled link, e.g. /s/%E0
        show('view-open');
        return showUnavailable();
    }
    openSecret(id);
}

document.addEventListener('click', (event) => {
    const copy = event.target.closest('[data-copy]');
    if (copy) return copyFrom(copy.dataset.copy);
    const link = event.target.closest('a[data-link]');
    if (link && !event.ctrlKey && !event.metaKey) {
        event.preventDefault();
        history.pushState(null, '', link.getAttribute('href'));
        route();
    }
});

window.addEventListener('popstate', route);
$('secret-text').addEventListener('input', updateCounter);
$('create-form').addEventListener('submit', onCreate);
$('protect').addEventListener('change', () => {
    syncProtect();
    if ($('protect').checked) $('passphrase').focus();
});
$('reveal-passphrase').addEventListener('input', () => {
    $('reveal-passphrase').classList.remove('invalid');
    updateRevealButton();
});
route();
