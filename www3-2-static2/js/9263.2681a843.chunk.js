"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[9263],{69764:(e,n,t)=>{t.d(n,{Z:()=>K});var s=t(81694),a=t.n(s),o=t(72791),r=t(80239),l=t(10162),i=t(75427),c=t(98328),d=t(71380);const f=function(){for(var e=arguments.length,n=new Array(e),t=0;t<e;t++)n[t]=arguments[t];return n.filter((e=>null!=e)).reduce(((e,n)=>{if("function"!==typeof n)throw new Error("Invalid Argument Type, must only provide functions, undefined, or null.");return null===e?n:function(){for(var t=arguments.length,s=new Array(t),a=0;a<t;a++)s[a]=arguments[a];e.apply(this,s),n.apply(this,s)}}),null)};var m=t(67202),u=t(14083),p=t(80184);const x={height:["marginTop","marginBottom"],width:["marginLeft","marginRight"]};function y(e,n){const t=n["offset".concat(e[0].toUpperCase()).concat(e.slice(1))],s=x[e];return t+parseInt((0,i.Z)(n,s[0]),10)+parseInt((0,i.Z)(n,s[1]),10)}const v={[c.Wj]:"collapse",[c.Ix]:"collapsing",[c.d0]:"collapsing",[c.cn]:"collapse show"},h=o.forwardRef(((e,n)=>{let{onEnter:t,onEntering:s,onEntered:r,onExit:l,onExiting:i,className:c,children:x,dimension:h="height",in:b=!1,timeout:N=300,mountOnEnter:E=!1,unmountOnExit:g=!1,appear:j=!1,getDimensionValue:w=y,...C}=e;const I="function"===typeof h?h():h,R=(0,o.useMemo)((()=>f((e=>{e.style[I]="0"}),t)),[I,t]),k=(0,o.useMemo)((()=>f((e=>{const n="scroll".concat(I[0].toUpperCase()).concat(I.slice(1));e.style[I]="".concat(e[n],"px")}),s)),[I,s]),F=(0,o.useMemo)((()=>f((e=>{e.style[I]=null}),r)),[I,r]),P=(0,o.useMemo)((()=>f((e=>{e.style[I]="".concat(w(I,e),"px"),(0,m.Z)(e)}),l)),[l,w,I]),Z=(0,o.useMemo)((()=>f((e=>{e.style[I]=null}),i)),[I,i]);return(0,p.jsx)(u.Z,{ref:n,addEndListener:d.Z,...C,"aria-expanded":C.role?b:null,onEnter:R,onEntering:k,onEntered:F,onExit:P,onExiting:Z,childRef:x.ref,in:b,timeout:N,mountOnEnter:E,unmountOnExit:g,appear:j,children:(e,n)=>o.cloneElement(x,{...n,className:a()(c,x.props.className,v[e],"width"===I&&"collapse-horizontal")})})}));function b(e,n){return Array.isArray(e)?e.includes(n):e===n}const N=o.createContext({});N.displayName="AccordionContext";const E=N,g=o.forwardRef(((e,n)=>{let{as:t="div",bsPrefix:s,className:r,children:i,eventKey:c,...d}=e;const{activeEventKey:f}=(0,o.useContext)(E);return s=(0,l.vE)(s,"accordion-collapse"),(0,p.jsx)(h,{ref:n,in:b(f,c),...d,className:a()(r,s),children:(0,p.jsx)(t,{children:o.Children.only(i)})})}));g.displayName="AccordionCollapse";const j=g,w=o.createContext({eventKey:""});w.displayName="AccordionItemContext";const C=w,I=o.forwardRef(((e,n)=>{let{as:t="div",bsPrefix:s,className:r,onEnter:i,onEntering:c,onEntered:d,onExit:f,onExiting:m,onExited:u,...x}=e;s=(0,l.vE)(s,"accordion-body");const{eventKey:y}=(0,o.useContext)(C);return(0,p.jsx)(j,{eventKey:y,onEnter:i,onEntering:c,onEntered:d,onExit:f,onExiting:m,onExited:u,children:(0,p.jsx)(t,{ref:n,...x,className:a()(r,s)})})}));I.displayName="AccordionBody";const R=I;const k=o.forwardRef(((e,n)=>{let{as:t="button",bsPrefix:s,className:r,onClick:i,...c}=e;s=(0,l.vE)(s,"accordion-button");const{eventKey:d}=(0,o.useContext)(C),f=function(e,n){const{activeEventKey:t,onSelect:s,alwaysOpen:a}=(0,o.useContext)(E);return o=>{let r=e===t?null:e;a&&(r=Array.isArray(t)?t.includes(e)?t.filter((n=>n!==e)):[...t,e]:[e]),null==s||s(r,o),null==n||n(o)}}(d,i),{activeEventKey:m}=(0,o.useContext)(E);return"button"===t&&(c.type="button"),(0,p.jsx)(t,{ref:n,onClick:f,...c,"aria-expanded":Array.isArray(m)?m.includes(d):d===m,className:a()(r,s,!b(m,d)&&"collapsed")})}));k.displayName="AccordionButton";const F=k,P=o.forwardRef(((e,n)=>{let{as:t="h2",bsPrefix:s,className:o,children:r,onClick:i,...c}=e;return s=(0,l.vE)(s,"accordion-header"),(0,p.jsx)(t,{ref:n,...c,className:a()(o,s),children:(0,p.jsx)(F,{onClick:i,children:r})})}));P.displayName="AccordionHeader";const Z=P,O=o.forwardRef(((e,n)=>{let{as:t="div",bsPrefix:s,className:r,eventKey:i,...c}=e;s=(0,l.vE)(s,"accordion-item");const d=(0,o.useMemo)((()=>({eventKey:i})),[i]);return(0,p.jsx)(C.Provider,{value:d,children:(0,p.jsx)(t,{ref:n,...c,className:a()(r,s)})})}));O.displayName="AccordionItem";const A=O,M=o.forwardRef(((e,n)=>{const{as:t="div",activeKey:s,bsPrefix:i,className:c,onSelect:d,flush:f,alwaysOpen:m,...u}=(0,r.Ch)(e,{activeKey:"onSelect"}),x=(0,l.vE)(i,"accordion"),y=(0,o.useMemo)((()=>({activeEventKey:s,onSelect:d,alwaysOpen:m})),[s,d,m]);return(0,p.jsx)(E.Provider,{value:y,children:(0,p.jsx)(t,{ref:n,...u,className:a()(c,x,f&&"".concat(x,"-flush"))})})}));M.displayName="Accordion";const K=Object.assign(M,{Button:F,Collapse:j,Item:A,Header:Z,Body:R})},29546:(e,n,t)=>{t.d(n,{Z:()=>p});var s=t(72791),a=t(52007),o=t.n(a),r=t(1444),l=t(5107),i=t(20070);const c=o().oneOf(["start","end"]),d=o().oneOfType([c,o().shape({sm:c}),o().shape({md:c}),o().shape({lg:c}),o().shape({xl:c}),o().shape({xxl:c}),o().object]);var f=t(80184);const m={id:o().string,href:o().string,onClick:o().func,title:o().node.isRequired,disabled:o().bool,align:d,menuRole:o().string,renderMenuOnMount:o().bool,rootCloseEvent:o().string,menuVariant:o().oneOf(["dark"]),flip:o().bool,bsPrefix:o().string,variant:o().string,size:o().string},u=s.forwardRef(((e,n)=>{let{title:t,children:s,bsPrefix:a,rootCloseEvent:o,variant:c,size:d,menuRole:m,renderMenuOnMount:u,disabled:p,href:x,id:y,menuVariant:v,flip:h,...b}=e;return(0,f.jsxs)(r.Z,{ref:n,...b,children:[(0,f.jsx)(l.Z,{id:y,href:x,size:d,variant:c,disabled:p,childBsPrefix:a,children:t}),(0,f.jsx)(i.Z,{role:m,renderOnMount:u,rootCloseEvent:o,variant:v,flip:h,children:s})]})}));u.displayName="DropdownButton",u.propTypes=m;const p=u},11701:(e,n,t)=>{t.d(n,{Ed:()=>o,UI:()=>a,XW:()=>r});var s=t(72791);function a(e,n){let t=0;return s.Children.map(e,(e=>s.isValidElement(e)?n(e,t++):e))}function o(e,n){let t=0;s.Children.forEach(e,(e=>{s.isValidElement(e)&&n(e,t++)}))}function r(e,n){return s.Children.toArray(e).some((e=>s.isValidElement(e)&&e.type===n))}},36638:(e,n,t)=>{t.d(n,{Z:()=>L});var s=t(81694),a=t.n(s),o=t(52007),r=t.n(o),l=t(72791),i=t(80184);const c={type:r().string,tooltip:r().bool,as:r().elementType},d=l.forwardRef(((e,n)=>{let{as:t="div",className:s,type:o="valid",tooltip:r=!1,...l}=e;return(0,i.jsx)(t,{...l,ref:n,className:a()(s,"".concat(o,"-").concat(r?"tooltip":"feedback"))})}));d.displayName="Feedback",d.propTypes=c;const f=d;var m=t(84934),u=t(10162);const p=l.forwardRef(((e,n)=>{let{id:t,bsPrefix:s,className:o,type:r="checkbox",isValid:c=!1,isInvalid:d=!1,as:f="input",...p}=e;const{controlId:x}=(0,l.useContext)(m.Z);return s=(0,u.vE)(s,"form-check-input"),(0,i.jsx)(f,{...p,ref:n,type:r,id:t||x,className:a()(o,s,c&&"is-valid",d&&"is-invalid")})}));p.displayName="FormCheckInput";const x=p,y=l.forwardRef(((e,n)=>{let{bsPrefix:t,className:s,htmlFor:o,...r}=e;const{controlId:c}=(0,l.useContext)(m.Z);return t=(0,u.vE)(t,"form-check-label"),(0,i.jsx)("label",{...r,ref:n,htmlFor:o||c,className:a()(s,t)})}));y.displayName="FormCheckLabel";const v=y;var h=t(11701);const b=l.forwardRef(((e,n)=>{let{id:t,bsPrefix:s,bsSwitchPrefix:o,inline:r=!1,reverse:c=!1,disabled:d=!1,isValid:p=!1,isInvalid:y=!1,feedbackTooltip:b=!1,feedback:N,feedbackType:E,className:g,style:j,title:w="",type:C="checkbox",label:I,children:R,as:k="input",...F}=e;s=(0,u.vE)(s,"form-check"),o=(0,u.vE)(o,"form-switch");const{controlId:P}=(0,l.useContext)(m.Z),Z=(0,l.useMemo)((()=>({controlId:t||P})),[P,t]),O=!R&&null!=I&&!1!==I||(0,h.XW)(R,v),A=(0,i.jsx)(x,{...F,type:"switch"===C?"checkbox":C,ref:n,isValid:p,isInvalid:y,disabled:d,as:k});return(0,i.jsx)(m.Z.Provider,{value:Z,children:(0,i.jsx)("div",{style:j,className:a()(g,O&&s,r&&"".concat(s,"-inline"),c&&"".concat(s,"-reverse"),"switch"===C&&o),children:R||(0,i.jsxs)(i.Fragment,{children:[A,O&&(0,i.jsx)(v,{title:w,children:I}),N&&(0,i.jsx)(f,{type:E,tooltip:b,children:N})]})})})}));b.displayName="FormCheck";const N=Object.assign(b,{Input:x,Label:v});t(42391);const E=l.forwardRef(((e,n)=>{let{bsPrefix:t,type:s,size:o,htmlSize:r,id:c,className:d,isValid:f=!1,isInvalid:p=!1,plaintext:x,readOnly:y,as:v="input",...h}=e;const{controlId:b}=(0,l.useContext)(m.Z);return t=(0,u.vE)(t,"form-control"),(0,i.jsx)(v,{...h,type:s,size:r,ref:n,readOnly:y,id:c||b,className:a()(d,x?"".concat(t,"-plaintext"):t,o&&"".concat(t,"-").concat(o),"color"===s&&"".concat(t,"-color"),f&&"is-valid",p&&"is-invalid")})}));E.displayName="FormControl";const g=Object.assign(E,{Feedback:f}),j=l.forwardRef(((e,n)=>{let{className:t,bsPrefix:s,as:o="div",...r}=e;return s=(0,u.vE)(s,"form-floating"),(0,i.jsx)(o,{ref:n,className:a()(t,s),...r})}));j.displayName="FormFloating";const w=j,C=l.forwardRef(((e,n)=>{let{controlId:t,as:s="div",...a}=e;const o=(0,l.useMemo)((()=>({controlId:t})),[t]);return(0,i.jsx)(m.Z.Provider,{value:o,children:(0,i.jsx)(s,{...a,ref:n})})}));C.displayName="FormGroup";const I=C;var R=t(53392);const k=l.forwardRef(((e,n)=>{let{bsPrefix:t,className:s,id:o,...r}=e;const{controlId:c}=(0,l.useContext)(m.Z);return t=(0,u.vE)(t,"form-range"),(0,i.jsx)("input",{...r,type:"range",ref:n,className:a()(s,t),id:o||c})}));k.displayName="FormRange";const F=k,P=l.forwardRef(((e,n)=>{let{bsPrefix:t,size:s,htmlSize:o,className:r,isValid:c=!1,isInvalid:d=!1,id:f,...p}=e;const{controlId:x}=(0,l.useContext)(m.Z);return t=(0,u.vE)(t,"form-select"),(0,i.jsx)("select",{...p,size:o,ref:n,className:a()(r,t,s&&"".concat(t,"-").concat(s),c&&"is-valid",d&&"is-invalid"),id:f||x})}));P.displayName="FormSelect";const Z=P,O=l.forwardRef(((e,n)=>{let{bsPrefix:t,className:s,as:o="small",muted:r,...l}=e;return t=(0,u.vE)(t,"form-text"),(0,i.jsx)(o,{...l,ref:n,className:a()(s,t,r&&"text-muted")})}));O.displayName="FormText";const A=O,M=l.forwardRef(((e,n)=>(0,i.jsx)(N,{...e,ref:n,type:"switch"})));M.displayName="Switch";const K=Object.assign(M,{Input:N.Input,Label:N.Label}),T=l.forwardRef(((e,n)=>{let{bsPrefix:t,className:s,children:o,controlId:r,label:l,...c}=e;return t=(0,u.vE)(t,"form-floating"),(0,i.jsxs)(I,{ref:n,className:a()(s,t),controlId:r,...c,children:[o,(0,i.jsx)("label",{htmlFor:r,children:l})]})}));T.displayName="FloatingLabel";const S=T,V={_ref:r().any,validated:r().bool,as:r().elementType},z=l.forwardRef(((e,n)=>{let{className:t,validated:s,as:o="form",...r}=e;return(0,i.jsx)(o,{...r,ref:n,className:a()(t,s&&"was-validated")})}));z.displayName="Form",z.propTypes=V;const L=Object.assign(z,{Group:I,Control:g,Floating:w,Check:N,Switch:K,Label:R.Z,Text:A,Range:F,Select:Z,FloatingLabel:S})},84934:(e,n,t)=>{t.d(n,{Z:()=>s});const s=t(72791).createContext({})},53392:(e,n,t)=>{t.d(n,{Z:()=>f});var s=t(81694),a=t.n(s),o=t(72791),r=(t(42391),t(2677)),l=t(84934),i=t(10162),c=t(80184);const d=o.forwardRef(((e,n)=>{let{as:t="label",bsPrefix:s,column:d=!1,visuallyHidden:f=!1,className:m,htmlFor:u,...p}=e;const{controlId:x}=(0,o.useContext)(l.Z);s=(0,i.vE)(s,"form-label");let y="col-form-label";"string"===typeof d&&(y="".concat(y," ").concat(y,"-").concat(d));const v=a()(m,s,f&&"visually-hidden",d&&y);return u=u||x,d?(0,c.jsx)(r.Z,{ref:n,as:"label",className:v,htmlFor:u,...p}):(0,c.jsx)(t,{ref:n,className:v,htmlFor:u,...p})}));d.displayName="FormLabel";const f=d}}]);
//# sourceMappingURL=9263.2681a843.chunk.js.map