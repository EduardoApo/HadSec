import React from 'react';
import {FileCode2} from 'lucide-react';
import {formatInfo} from '../supabase/functions/_shared/formats.mjs';
export function CodeEditor({ value, onChange, readOnly = false, format = 'sql', label = 'Código da regra', filename = 'rule' }) { return <div className="code-editor"><div className="code-header"><span><FileCode2 size={15}/>{filename+'.'+formatInfo(format).extension}</span><span>{readOnly ? 'Somente leitura' : `${value.split('\n').length} linhas`}<span className="code-lang">{formatInfo(format).label}</span></span></div><div className="code-body"><pre className="line-numbers" aria-hidden="true">{value.split('\n').map((_, i) => i + 1).join('\n')}</pre><textarea aria-label={label} value={value} onChange={e => onChange?.(e.target.value)} readOnly={readOnly} spellCheck={false} wrap="off" onKeyDown={e => { if (e.key === 'Tab' && !readOnly) {
    e.preventDefault();
    const el = e.target, start = el.selectionStart, end = el.selectionEnd;
    onChange(value.slice(0, start) + '    ' + value.slice(end));
    setTimeout(() => el.selectionStart = el.selectionEnd = start + 4, 0);
} }}/></div></div>; }
