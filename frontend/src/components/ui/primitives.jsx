/**
 * Primitives UI partagées — Smart SIEM Design System
 *
 * Ces composants garantissent la cohérence visuelle sur l'ensemble de
 * l'application : mêmes rayons, mêmes espacements, mêmes états (chargement,
 * vide, erreur). Toute nouvelle vue doit les réutiliser plutôt que redéfinir
 * ses propres styles ad hoc.
 */

const SEVERITY_STYLES = {
    CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/25',
    HIGH: 'text-orange-400 bg-orange-500/10 border-orange-500/25',
    WARNING: 'text-amber-400 bg-amber-500/10 border-amber-500/25',
    INFO: 'text-sky-400 bg-sky-500/10 border-sky-500/25',
    SUCCESS: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/25',
    NEUTRAL: 'text-slate-400 bg-slate-500/10 border-slate-500/25',
};

/** Carte conteneur standard : fond, bordure, rayon, ombre cohérents partout. */
export function Card({ children, className = '', padded = true }) {
    return (
        <div
            className={`rounded-2xl border ${className}`}
            style={{
                background: 'var(--surface-2)',
                borderColor: 'var(--border-subtle)',
                boxShadow: 'var(--shadow-card)',
                padding: padded ? undefined : 0,
            }}
        >
            <div className={padded ? 'p-5' : ''}>{children}</div>
        </div>
    );
}

/** En-tête de page uniforme : surtitre, titre, description, actions à droite. */
export function PageHeader({ eyebrow, title, description, actions }) {
    return (
        <div className="flex flex-col gap-4 border-b pb-5 md:flex-row md:items-end md:justify-between"
             style={{ borderColor: 'var(--border-subtle)' }}>
            <div>
                {eyebrow && (
                    <p className="mb-1.5 text-xs font-semibold uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                        {eyebrow}
                    </p>
                )}
                <h1 className="text-2xl font-semibold tracking-tight" style={{ color: 'var(--text-primary)' }}>{title}</h1>
                {description && (
                    <p className="mt-1.5 text-sm" style={{ color: 'var(--text-secondary)' }}>{description}</p>
                )}
            </div>
            {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </div>
    );
}

/** Badge de sévérité/statut — palette sémantique unique, cohérente partout. */
export function Badge({ tone = 'NEUTRAL', children, className = '' }) {
    const style = SEVERITY_STYLES[tone] || SEVERITY_STYLES.NEUTRAL;
    return (
        <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${style} ${className}`}>
            {children}
        </span>
    );
}

const BUTTON_VARIANTS = {
    primary: 'text-white border-transparent hover:brightness-110',
    secondary: '',
    danger: 'text-red-400 border-red-500/30 hover:bg-red-500/10',
    ghost: 'border-transparent hover:bg-[var(--surface-3)]',
};

/** Bouton standard — quatre variantes, un seul système de tailles/rayons. */
export function Button({ variant = 'secondary', className = '', style = {}, children, disabled, ...props }) {
    const variantClass = BUTTON_VARIANTS[variant] || BUTTON_VARIANTS.secondary;
    const baseStyle = variant === 'primary'
        ? { background: disabled ? 'var(--border-strong)' : 'var(--accent)', ...style }
        : variant === 'secondary'
            ? { background: 'var(--surface-3)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)', ...style }
            : style;

    return (
        <button
            className={`inline-flex items-center justify-center gap-2 rounded-lg border px-3.5 py-2 text-sm font-medium transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-50 ${variantClass} ${className}`}
            style={baseStyle}
            disabled={disabled}
            {...props}
        >
            {children}
        </button>
    );
}

/** État vide honnête — jamais de placeholder trompeur. */
export function EmptyState({ title, description, icon: Icon }) {
    return (
        <div className="flex flex-col items-center justify-center gap-2 rounded-2xl border border-dashed py-14 text-center"
             style={{ borderColor: 'var(--border-subtle)' }}>
            {Icon && <Icon size={28} strokeWidth={1.5} style={{ color: 'var(--text-muted)' }} />}
            <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>{title}</p>
            {description && <p className="max-w-sm text-xs" style={{ color: 'var(--text-muted)' }}>{description}</p>}
        </div>
    );
}

/** Bandeau d'erreur réseau/backend, honnête et discret. */
export function ErrorBanner({ title = 'Backend indisponible', description }) {
    return (
        <div className="rounded-xl border px-4 py-3 text-sm"
             style={{ borderColor: 'rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.08)', color: '#fca5a5' }}>
            <p className="font-semibold">{title}</p>
            {description && <p className="mt-0.5 text-xs opacity-90">{description}</p>}
        </div>
    );
}

/** Indicateur de chargement discret, cohérent partout. */
export function LoadingState({ label = 'Chargement...' }) {
    return (
        <div className="flex items-center justify-center gap-2.5 py-14 text-sm" style={{ color: 'var(--text-muted)' }}>
            <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />
            {label}
        </div>
    );
}

/** Carte de statistique (KPI) — un seul style de chiffre-clé pour tout le produit. */
export function StatCard({ label, value, tone = 'NEUTRAL', hint, icon: Icon }) {
    const toneColor = {
        CRITICAL: '#f87171', HIGH: '#fb923c', WARNING: '#facc15',
        INFO: '#38bdf8', SUCCESS: '#34d399', NEUTRAL: 'var(--text-primary)',
    }[tone];

    return (
        <Card>
            <div className="flex items-center justify-between">
                <p className="text-xs font-semibold uppercase tracking-[0.14em]" style={{ color: 'var(--text-muted)' }}>{label}</p>
                {Icon && <Icon size={15} strokeWidth={1.75} style={{ color: 'var(--text-muted)' }} />}
            </div>
            <p className="mt-2.5 text-3xl font-semibold tabular-nums" style={{ color: toneColor }}>{value}</p>
            {hint && <p className="mt-1.5 text-xs" style={{ color: 'var(--text-secondary)' }}>{hint}</p>}
        </Card>
    );
}

/** Message RBAC uniforme pour les zones en lecture seule. */
export function ReadOnlyNotice({ role, action = 'modifier cette ressource' }) {
    return (
        <div className="flex items-center gap-2.5 rounded-xl border px-4 py-3 text-xs"
             style={{ borderColor: 'var(--accent-border)', background: 'var(--accent-soft)', color: 'var(--text-secondary)' }}>
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: 'var(--accent)' }} />
            Votre rôle actuel (<strong style={{ color: 'var(--text-primary)' }}>{role}</strong>) ne permet pas de {action}. Consultation seule.
        </div>
    );
}
