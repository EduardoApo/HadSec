import React from 'react';
import {formats} from '../supabase/functions/_shared/formats.mjs';
export function Field({label,children,hint}){const id=React.useId();return <div className="field"><label htmlFor={id}>{label}</label>{React.cloneElement(children,{id,...(hint?{'aria-describedby':id+'-hint'}:{})})}{hint&&<small id={id+'-hint'}>{hint}</small>}</div>;}
export function FormatSelect({value,onChange,disabled=false}){return <Field label="Formato"><select value={value} disabled={disabled} onChange={event=>onChange(event.target.value)}>{formats.map(format=><option key={format.id} value={format.id}>{format.label}</option>)}</select></Field>;}
